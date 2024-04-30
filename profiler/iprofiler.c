/*
 * iprofiler.c - Instruction prpfiling code
 *
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define _GNU_SOURCE
#include <search.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/param.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"
#include "thread_pool.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_utils.h"
#include "membalancer_user.h"
#include "membalancer_lib.h"
#include "profiler_common.h"
#include "profiler_pvt.h"

#define MAX_FUNC_NAME 20

#ifdef PROFILER_LARGE
#define MAX_PIDS      (32 * 1024)
#define MAX_FUNCTIONS (8 * 1024)
#else
#define MAX_PIDS      (2 * 1024)
#define MAX_FUNCTIONS (2 * 1024)
#endif

#define MIN_FOR_LATENCY 10
static int light_semaphore;
#undef MIN_SAMPLES
#define MIN_SAMPLES 50

struct function_info {
	u64  ip;
	u32  size;
	char name[MAX_FUNC_NAME];
};

struct process_info {
	pid_t  pid;
	u32    max_functions;
	struct function_info function[MAX_FUNCTIONS];
};

#define LATENCY_IDX (MAX_LATENCY_IDX * 4)
struct code_ref {
	u64 key;
	u64 ref;
	u64 ip;
	pid_t pid;
	u32 latency_cnt;
	u32 latency[LATENCY_IDX];
	struct function_info *info;
};

static struct process_info process_info[MAX_PIDS];
static struct process_info *root_process_info;
static unsigned int next_process_info;

static struct code_ref code_ref[MAX_SAMPLES];
static struct process_info *root_code_ref;
static u32 next_code_ref;
static u64 code_sample_count;

static struct code_ref data_ref[MAX_SAMPLES];
static struct process_info *root_data_ref;
static u32 next_data_ref;
static u64 data_sample_count;

static int pid_cmp(const void *firstp, const void *secondp)
{
	const struct process_info *p1, *p2;

	p1 = firstp;
	p2 = secondp;

	return p1->pid - p2->pid;
}

static void skip_space(char *buffer, int *next, int size)
{
	int i = *next;

	while (i < size && ((buffer[i] == ' ') || (buffer[i] == '\t') ||
		(buffer[i] == '\n')))
		i++;

	*next = i;
}

static char * next_field(char *buffer, int *next, int size)
{
	int i = *next;
	char *field;

	if (i >= size)
		return NULL;

	while (i < size && ((buffer[i] != ' ') && (buffer[i] != '\t') &&
		(buffer[i] != '\n') && (buffer[i] != 0)))
		i++;

	buffer[i] = 0;

	i++;

	field = &buffer[*next];

	*next = i;

	return field;
}

static int load_function_names(pid_t pid, const char *obj_file,
			       struct process_info *info)
{
	FILE *fp;
	char buffer[1024];
	char cmd[1024];
	char *field;
	char *tmp;
	int i = 0, j, next;
	unsigned long addr, size;
	struct function_info *func;
	struct stat st;

	if (stat(obj_file, &st) < 0)
		return -errno;

	func = info->function;

	snprintf(cmd, sizeof(cmd) - 1,
		"/usr/bin/objdump -t %s|grep \" F .text\"", obj_file);

	fp = popen(cmd, "r");
	if (!fp)
		return -EINVAL;

	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		if (i >= MAX_FUNCTIONS)
			break;

		next = 0;
		field = next_field(buffer, &next, 1024);
		if (!field)
			break;

		addr = strtoul(field, &tmp, 16);
		for (j = 0;  j < 3; j++) {
			skip_space(buffer, &next, 1024);
			field = next_field(buffer, &next, 1024);
			if (!field)
				break;
		}

		if (!field)
			break;

		skip_space(buffer, &next, 1024);
		field = next_field(buffer, &next, 1024);
		if (!field)
			break;

		size = strtoul(field, &tmp, 16);;
		if (size == 0)
			continue;

		skip_space(buffer, &next, 1024);
		field = next_field(buffer, &next, 1024);
		func[i].ip = addr;
		func[i].size = size;
		snprintf(func[i].name, sizeof(func[i].name), "%s", field);
		i++;
	}
	fclose(fp);

	info->max_functions = i;

	return 0;
}

static struct process_info * process_info_get(pid_t pid, bool *exist)
{
	struct process_info *info, dummy, **new, **infopp;

	dummy.pid = pid;

	if (root_process_info != NULL) {
		infopp = tfind(&dummy, (void **)&root_process_info, pid_cmp);
		if (infopp) {
			info = *infopp;
			*exist = true;
			return info;
		}
	}

	if (next_process_info >= MAX_PIDS)
		return NULL;

	info = &process_info[next_process_info];
	info->pid = pid;

	new = tsearch(info, (void **)&root_process_info, pid_cmp);
	if (!new)
		return NULL;

	assert(*new == info);
	next_process_info++;

	*exist = false;
	return *new;
}

static int load_function_info(pid_t pid, struct process_info **infoout)
{
	struct process_info *info;
	bool exist;
	char filename[MAXPATHLEN];

	info = process_info_get(pid, &exist);
	if (info == NULL)
		return -ENOMEM;

	*infoout = info;

	if (exist)
		return 0;

	snprintf(filename, MAXPATHLEN, "/proc/%d/exe", pid);


	return load_function_names(pid, filename, info);
}

static struct function_info * function_info_get(struct process_info *info,
						u64 ip)
{
	int i;

	assert(info != NULL);

	for (i = 0; i < info->max_functions; i++) {
		if (ip >= info->function[i].ip &&
		    (ip < info->function[i].ip + info->function[i].size))
			return &info->function[i];
	}

	return NULL;
}

static int code_ref_cmp(const void *firstp, const void *secondp)
{
	const struct code_ref *r1, *r2;

	r1 = firstp;
	r2 = secondp;

	return r1->key  - r2->key;
}

static inline void latency_add(struct code_ref *ref, u32 count, u32 *latency)
{
	int i;

	if (count > MAX_LATENCY_IDX)
		count = MAX_LATENCY_IDX;

	/* skip the sample if the entire lot contains all zeroes */
	for (i = 0; i < count; i++) {
		if (latency[i] != 0)
			break;
	}

	if (i == count)
		return;

	for (i = 0; i < count; i++) {
		if (ref->latency_cnt >= LATENCY_IDX)
			break;

		ref->latency[ref->latency_cnt] += latency[i];
		ref->latency_cnt++;
	}
}

static int add_code_ref(pid_t pid, u64 key, u32 count, u32 *latency,
			struct function_info *info)
{
	struct code_ref *ref, dummy, **new, **refpp;

	dummy.key = key;

	if (root_code_ref != NULL) {
		refpp = tfind(&dummy, (void **)&root_code_ref, code_ref_cmp);
		if (refpp) {
			ref = *refpp;
			assert(ref->key == key);
			latency_add(ref, count, latency);
			code_sample_count += count;
			ref->ref += count;
			assert(ref->ref <= code_sample_count);
			return 0;
		}
	}

	if (next_code_ref >= MAX_SAMPLES)
		return -ENOMEM;

	ref = &code_ref[next_code_ref];
	memset(ref, 0, sizeof(*ref));
	ref->ip   = key;
	ref->pid  = pid;
	ref->key  = key;
	ref->ref  = 0;
	ref->info = info;
	latency_add(ref, count, latency);

	new = tsearch(ref, (void **)&root_code_ref, code_ref_cmp);
	if (!new)
		return -ENOMEM;

	assert(*new == ref);

	code_sample_count += count;
	next_code_ref++;
	ref->ref = count;

	return 0;
}

static void do_nothing(void *data)
{
}

static int add_data_ref(pid_t pid, u64 ip, u64 key, u32 count, u32 *latency,
			struct function_info *info)
{
	struct code_ref *ref, dummy, **new, **refpp;

	dummy.key = key;
	if (root_data_ref != NULL) {
		refpp = tfind(&dummy, (void **)&root_data_ref, code_ref_cmp);
		if (refpp) {
			ref = *refpp;

			assert(ref->key == key);
			ref->ref += count;
			latency_add(ref, count, latency);
			data_sample_count += count;
			return 0;
		}
	}

	if (next_data_ref >= MAX_SAMPLES)
		return -ENOMEM;

	ref = &data_ref[next_data_ref];
	memset(ref, 0, sizeof(*ref));
	ref->ip   = ip;
	ref->pid  = pid;
	ref->key  = key;
	ref->ref  = 0;
	ref->info = info;
	latency_add(ref, count, latency);

	new = tsearch(ref, (void **)&root_data_ref, code_ref_cmp);
	if (!new)
		return -ENOMEM;

	assert(*new == ref);

	data_sample_count += count;
	next_data_ref++;
	ref->ref = count;

	return 0;
}

static int add_sample(u64 tgid, u64 key, u64 ip, u32 count, u32 *latency,
		      bool code)
{
	struct process_info *info;
	struct function_info *func;
	int err;
	pid_t pid;

	if (!tgid || !key || !ip)
		return -EINVAL;

	pid = (pid_t)(tgid >> 32);

	err = load_function_info(pid, &info);
	if (err)
		return err;

	func = function_info_get(info, ip);
	if (!func && !KERN_SAMPLE(ip))
		return -EINVAL;

	if (code)
		return add_code_ref(pid, ip, count, latency, func);

	return add_data_ref(pid, ip, key, count, latency, func);
}

static int ref_cmp(const void *firstp, const void *secondp)
{
	const struct code_ref *r1, *r2;

	r1 = firstp;
	r2 = secondp;

	return r2->ref - r1->ref;
}

static void process_code_samples(unsigned long total, bool user_space_only)
{
	int i;
	u64 j, ip;

	for (i = 0; i < max_nodes; i++) {
		for (j = 0; j < code_samples_cnt[i]; j++) {
			if (code_samples[i][j].count == 0)
				continue;

			assert(code_samples[i][j].count < 100000);

			ip = code_samples[i][j].ip;
			add_sample(code_samples[i][j].tgid,
				   ip, ip,
				   code_samples[i][j].count,
				   code_samples[i][j].latency,
				   true);

			code_samples[i][j].count = 0;
		}
		code_samples_cnt[i] = 0;
	}
}

static void process_data_samples(unsigned long total, bool user_space_only)
{
	int i;
	u64 j, ip, key;

	for (i = 0; i < max_nodes; i++) {
		for (j = 0; j < data_samples_cnt[i]; j++) {
			if (data_samples[i][j].count == 0)
				continue;

			assert(data_samples[i][j].count < 100000);
			ip = data_samples[i][j].ip;
			key = data_samples[i][j].vaddr;
			add_sample(data_samples[i][j].tgid,
				   key, ip,
				   data_samples[i][j].count,
				   code_samples[i][j].latency,
				   false);

			data_samples[i][j].count = 0;
		}
		data_samples_cnt[i] = 0;
	}
}

void iprofiler_process_samples(int fd_code, int fd_data, u64 code_cnt,
			       u64 data_cnt)
{
	u64 total_freq_code, total_freq_data;

	/* No multiple instances of sampling and/or reporting */
	if (atomic_cmxchg(&light_semaphore, 0, 1))
		return;

	if (code_cnt >= MIN_CODE_SAMPLES) {
		code_cnt = get_code_samples(fd_code, &total_freq_code, false);
		process_code_samples(code_cnt, true);
	}

	if (data_cnt >= MIN_DATA_SAMPLES) {
		data_cnt = get_data_samples(fd_data, &total_freq_data, false);
		process_data_samples(data_cnt, true);
	}

	assert(atomic_cmxchg(&light_semaphore, 1, 0) == 1);
}

static u32 latency_percentile(struct code_ref *ref, float p)
{
	u32 i;

	i = (ref->latency_cnt * p) / 100;
	return ref->latency[i];
}

static void print_header(bool summary, bool code)
{
	if (code) {
		printf("%-3s %-10s %-20s %-14s %-7s %-7s %-5s %-5s",
		       "No", "PID", "FUNCTION", "INSTR_ADDR", "COUNT",
		       "PERCENT", "TYPE", "MODE");
	} else {
		printf("%-3s %-10s %-20s %-14s %-7s %-7s %-5s %-5s",
		       "No", "PID", "FUNCTION", "DATA_ADDR", "COUNT",
		       "PERCENT", "TYPE", "MODE");
	}

	if (summary) {
		printf("\n");
		return;
	}

	printf(" %-7s %-7s %-7s %-7s %-7s %-7s "
		"%-9s %-9s\n",
		"LAT_MIN",
		"LAT_MED",
		"LAT_MAX",
		"LAT_P90",
		"LAT_P95",
		"LAT_P99",
		"LAT_P99.9",
		"LAT_P99.99");
}

static int cmp_u32(const void *firstp, const void *secondp)
{
	const u32 *r1, *r2;

	r1 = firstp;
	r2 = secondp;

	return *r1 - *r2;
}

static void report_profiler_information_code(bool summary)
{
	int i, j, pct;
	char function[MAX_FUNC_NAME];
	bool print_hdr = true;

	printf("\f\r");

	qsort(code_ref, next_code_ref, sizeof(struct code_ref), ref_cmp);

	j = 0;
	for (i = 0; i < next_code_ref; i++) {
		if (code_ref[i].ref < 2) {
			code_ref[i].ref = 0;
			continue;
		}

		j++;
		if (j > iprofiler) {
			code_ref[i].ref = 0;
			continue;
		}

		if (print_hdr) {
			print_header(summary, true);
			print_hdr = false;
		}

		if (code_ref[i].info) {
			snprintf(function, MAX_FUNC_NAME, "%s",
				 code_ref[i].info->name);
		} else {
			if (KERN_SAMPLE(code_ref[i].ip)) {
				snprintf(function, MAX_FUNC_NAME,
					"KERN:0x%lX",
				 	(unsigned long)code_ref[i].ip);
			} else {
				snprintf(function, MAX_FUNC_NAME,
					"USER:0x%lX",
				 	(unsigned long)code_ref[i].ip);
			}
		}

		assert(code_ref[i].ref <= code_sample_count);
		pct = code_ref[i].ref * 100 / code_sample_count;

		printf("%-3d %-10u %-20s %-14p %-7lu %-7u %4s %5s ",
			j, code_ref[i].pid, function,
			(void *)(unsigned long)code_ref[i].ip,
			(unsigned long)code_ref[i].ref,
			pct, "CODE",
			KERN_SAMPLE(code_ref[i].ip) ? "KERN" : "USER");


		if (code_ref[i].latency_cnt < MIN_FOR_LATENCY) {
			printf("\n");
			code_ref[i].ref = 0;
			continue;
		}

		qsort(code_ref[i].latency, code_ref[i].latency_cnt,
		      sizeof(code_ref[i].latency[0]), cmp_u32);

		printf(" %-7u %-7u %-7u %-7u %-7u %-7u %-9u %-9u\n",
		code_ref[i].latency[0],
		code_ref[i].latency[code_ref[i].latency_cnt / 2],
		code_ref[i].latency[code_ref[i].latency_cnt - 1],
		latency_percentile(&code_ref[i], 90.0),
		latency_percentile(&code_ref[i], 95.0),
		latency_percentile(&code_ref[i], 99.0),
		latency_percentile(&code_ref[i], 99.9),
		latency_percentile(&code_ref[i], 99.99));

		code_ref[i].ref = 0;
	}

	if (j > 0)
		printf("\n");
}

static void report_profiler_information_data(bool summary)
{
	int i, j, pct;
	char function[MAX_FUNC_NAME];
	bool print_hdr = true;


	qsort(data_ref, next_data_ref, sizeof(struct code_ref), ref_cmp);

	j = 0;
	for (i = 0; i < next_data_ref; i++) {
		if (data_ref[i].ref < 2) {
			data_ref[i].ref = 0;
			continue;
		}


		if (print_hdr) {
			print_header(summary, false);
			print_hdr = false;
		}

		j++;
		if (j > iprofiler) {
			data_ref[i].ref = 0;
			continue;
		}

		if (data_ref[i].info) {
			snprintf(function, MAX_FUNC_NAME, "%s",
				 data_ref[i].info->name);
		} else {
			if (KERN_SAMPLE(data_ref[i].ip)) {
				snprintf(function, MAX_FUNC_NAME,
					"KERN:0x%lX",
				 	(unsigned long)data_ref[i].ip);
			} else {
				snprintf(function, MAX_FUNC_NAME,
					"USER:0x%lX",
				 	(unsigned long)data_ref[i].ip);
			}
		}

		assert(data_ref[i].ref <= data_sample_count);
		pct = data_ref[i].ref * 100 / data_sample_count;

		printf("%-3d %-10u %-20s %-14p %-7lu %-7u %4s %5s",
			j, data_ref[i].pid, function,
			(void *)(unsigned long)data_ref[i].key,
			(unsigned long)data_ref[i].ref,
			pct, "DATA",
			KERN_SAMPLE(data_ref[i].ip) ? "KERN" : "USER");

		if (data_ref[i].latency_cnt < MIN_FOR_LATENCY) {
			printf("\n");
			data_ref[i].ref = 0;
			continue;
		}

		qsort(data_ref[i].latency, data_ref[i].latency_cnt,
		      sizeof(data_ref[i].latency[0]), cmp_u32);

		printf(" %-7u %-8u %-7u %-7u %-7u %-7u %-9u %-9u\n",
		data_ref[i].latency[0],
		data_ref[i].latency[data_ref[i].latency_cnt / 2],
		data_ref[i].latency[data_ref[i].latency_cnt - 1],
		latency_percentile(&data_ref[i], 90.0),
		latency_percentile(&data_ref[i], 95.0),
		latency_percentile(&data_ref[i], 99.0),
		latency_percentile(&data_ref[i], 99.9),
		latency_percentile(&data_ref[i], 99.99));

		data_ref[i].ref = 0;
	}
}

void iprofiler_report(bool summary)
{
	static struct timeval start;
	struct timeval end;

	/* No multiple instances of sampling and/or reporting */
	if (atomic_cmxchg(&light_semaphore, 0, 1))
		return;

	if (!next_code_ref || !next_data_ref) {
		assert(atomic_cmxchg(&light_semaphore, 1, 0) == 1);
		return;
	}

	if (start.tv_sec == 0 && start.tv_usec == 0)
		gettimeofday(&start, NULL);

	gettimeofday(&end, NULL);
	if (seconds_elapsed(&start, &end) < report_frequency) {
		assert(atomic_cmxchg(&light_semaphore, 1, 0) == 1);
		return;
	}

	report_profiler_information_code(summary);

	report_profiler_information_data(summary);

	printf("\nCode samples : %lu, Data samples : %lu\n",
		(unsigned long)code_sample_count,
		(unsigned long)data_sample_count);

	next_code_ref     = 0;
	next_data_ref     = 0;
	next_process_info = 0;
	data_sample_count = 0;
	code_sample_count = 0;
	start             = end;

	tdestroy(root_code_ref, do_nothing);
	tdestroy(root_data_ref, do_nothing);
	tdestroy(root_process_info, do_nothing);

	root_code_ref     = NULL;
	root_data_ref     = NULL;
	root_process_info = NULL;

	assert(atomic_cmxchg(&light_semaphore, 1, 0) == 1);
}

int iprofiler_function(const char *kernobj, int freq, int msecs,
		       char *include_pids, char *include_ppids,
		       cpu_set_t *cpusetp, char *filter_str)
{
	int msecs_nap;
	int err;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog[TOTAL_BPF_PROGRAMS];
	struct bpf_link **code_links = NULL, **data_links = NULL;
	struct bpf_link **lbr_links = NULL;
	char filename[256];
	int map_fd[TOTAL_MAPS];
	unsigned long code_cnt, data_cnt;
	unsigned long code_cnt_old, data_cnt_old;
	unsigned long code_cnt_new, data_cnt_new;
	struct timeval start;
	struct profiler_filter filter[MAX_PROFILER_FILTERS];
	int filters;

	if (filter_str) {
		/*
		 * Returns 0 or a positive number if successful, else
		 * an error code.
		 */
		err = profiler_parse_filter(filter_str, filter,
					    MAX_PROFILER_FILTERS);
		if (err < 0)
			return err;
		filters = err;
	}

	err = -EINVAL;

	code_links = calloc(nr_cpus, sizeof(*code_links));
	if (!code_links) {
		fprintf(stderr, "ERROR: malloc of links\n");
		goto cleanup;
	}

	data_links = calloc(nr_cpus, sizeof(*data_links));
	if (!data_links) {
		fprintf(stderr, "ERROR: malloc of links\n");
		goto cleanup;
	}

	lbr_links = calloc(nr_cpus, sizeof(*lbr_links));
	if (!lbr_links) {
		fprintf(stderr, "ERROR: malloc of links\n");
		goto cleanup;
	}

	snprintf(filename, sizeof(filename), "%s/memory_profiler_kern.o",
		 ebpf_object_dir);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		obj = NULL;
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	if (filter_str) {
		err = profiler_fill_filter(obj, filter, filters);
   		if (err)
			goto cleanup;
	}

	/* Resetting BPF map fd list */
	memset(map_fd, -1, TOTAL_MAPS * sizeof(int));

	err = init_and_load_bpf_programs(prog, map_fd, obj,
					 profiler_program_names,
					 profiler_map_fd_names);

	if (err) {
		fprintf(stderr, "ERROR:(%d)Could not load all"
			"the required programs and maps!!\n", err);
		goto cleanup;
	}

	cpu_nodes = fill_cpu_nodes(obj);
	if (cpu_nodes <= 0)
		goto cleanup;

	if (process_include_pids(obj, include_pids, false))
		goto cleanup;

	if (process_include_pids(obj, include_ppids, true))
		goto cleanup;

	if (include_ppids)
		set_knob(map_fd[KNOBS], CHECK_PPID, 1);

	if ((is_tier_mode() ==  false) || is_default_tier_mode())
		set_knob(map_fd[KNOBS], PER_NUMA_ACCESS_STATS, 1);

	if (user_space_only)
		set_knob(map_fd[KNOBS], USER_SPACE_ONLY, 1);

	set_knob(map_fd[KNOBS], MY_PAGE_SIZE, MEMB_PAGE_SIZE);
	set_knob(map_fd[KNOBS], MY_OWN_PID, getpid());
	set_knob(map_fd[KNOBS], KERN_VERBOSE, verbose);

	if (l3miss)
		set_knob(map_fd[KNOBS], DEFER_PROCESS,
			 L3MISS_DEFER_PROCESS_CNT);
	else
		set_knob(map_fd[KNOBS], DEFER_PROCESS,
			 DEFER_PROCESS_CNT);

	set_knob(map_fd[KNOBS], LAST_KNOB, 1);

	err = init_heap(obj);
	if (err != 0)
		goto cleanup;

	err = parse_additional_bpf_programs(obj);
	if (err)
		goto cleanup;

	err = launch_additional_bpf_programs();
	if (err)
		goto cleanup;

	printf("\f");
	printf("%s%s", BRIGHT, BMAGENTA);
	printf("Collecting %s samples .....\n",
		(l3miss) ? "MISS Filter" : "CLASSIC");
	printf("%s", NORM);

	code_cnt_old = 0;
	code_cnt_new = 0;
	data_cnt_old = 0;
	data_cnt_new = 0;

	gettimeofday(&start, NULL);

	open_ibs_devices();
	while (!err) {
		assert(prog[DATA_SAMPLER]);
		if (ibs_op_sampling_begin(freq, prog[DATA_SAMPLER],
					data_links, cpusetp) != 0) {
			if (l3miss)
				fprintf(stderr,
					"DATA L3 miss fitlering "
					"not supported\n");
			else
				fprintf(stderr,
					"DATA sampling not supported\n");
		}

		assert(prog[CODE_SAMPLER]);
		if (ibs_fetch_sampling_begin(freq, prog[CODE_SAMPLER],
					     code_links, cpusetp) != 0) {
			if (l3miss)
				fprintf(stderr,
					"CODE L3 miss filtering "
					"not supported\n");

			else
				fprintf(stderr,
					"CODE sampling not supported\n");

		}

		if (prog[LBR_SAMPLER] &&
		    lbr_sampling_begin(freq, prog[LBR_SAMPLER],
				       lbr_links, cpusetp) != 0) {
			fprintf(stderr, "LBR sampling not supported\n");
			goto cleanup;
		}

		for (; ;)  {
			code_cnt = peek_samples(map_fd[CODE_COUNTER_MAP],
						 code_cnt_old, &code_cnt_new);

			data_cnt = peek_samples(map_fd[DATA_COUNTER_MAP],
					      data_cnt_old, &data_cnt_new);

			if ((code_cnt >= MIN_SAMPLES)) {
				code_cnt_old = code_cnt_new;
				if (data_cnt >= MIN_DATA_SAMPLES) {
					data_cnt_old = data_cnt_new;
					break;
				}
				break;
			}

			if ((data_cnt >= MIN_SAMPLES)) {
				data_cnt_old = data_cnt_new;
				if (code_cnt >= MIN_CODE_SAMPLES) {
					code_cnt_old = code_cnt_new;
					break;
				}
				break;
			}

			if ((data_cnt >= 2 * MIN_SAMPLES) ||
			    (code_cnt >= 2 * MIN_SAMPLES)) {
				data_cnt_old    = data_cnt_new;
				code_cnt_old = code_cnt_new;
				break;
			}

			msecs_nap = msecs * 1000 / 10;
			if (msecs_nap < 1000)
				msecs_nap = 1000;

			usleep(msecs_nap);
			/*
			 * Check if migration is making progress. If not
			 * break out of the processing loop.
			 */
		}

		if (code_links)
			ibs_sampling_end(code_links); /* code */

		if (data_links)
			ibs_sampling_end(data_links);    /* dat */

		iprofiler_process_samples(map_fd[CODE_MAP], map_fd[DATA_MAP],
					 code_cnt, data_cnt);
		iprofiler_report(false);

#ifdef USE_CLOSE_RANGE
		close_range(100, 8192, 0);
#endif
		usleep(msecs * 1000 / maximizer_mode);
	}

cleanup:
	profiler_cleanup(map_fd[CODE_MAP], map_fd[DATA_MAP]);
	close_ibs_devices();
	terminate_additional_bpf_programs();

	if (code_links)
		ibs_sampling_end(code_links); /* code */

	if (data_links)
		ibs_sampling_end(data_links);    /* data */

	if (lbr_links)
		ibs_sampling_end(lbr_links);  /* LBR */

	free(code_links);
	free(data_links);
	free(lbr_links);
	bpf_object__close(obj);

	return err;
}
