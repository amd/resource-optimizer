/*
 * iprofiler.c - Instruction prpfiling code
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (c) 2023 Advanced Micro Devices, Inc. All Rights Reserved.
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
y* POSSIBILITY OF SUCH DAMAGE.

 *
 */
#include<sys/param.h>
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
#include<errno.h>
#include<string.h>
#include<stdlib.h>
#include<assert.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/time.h>
#include <bpf/bpf.h>
#include "membalancer_common.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_utils.h"

#define __USE_GNU
#include <search.h>
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
#define MIN_SAMPLES 1000

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

static struct code_ref code_ref[MAX_IBS_SAMPLES];
static struct process_info *root_code_ref;
static u32 next_code_ref;
static u64 code_samples;

static struct code_ref data_ref[MAX_IBS_SAMPLES];
static struct process_info *root_data_ref;
static u32 next_data_ref;
static u64 data_samples;

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
			code_samples += count;
			ref->ref += count;
			assert(ref->ref <= code_samples);
			return 0;
		}
	}

	if (next_code_ref >= MAX_IBS_SAMPLES)
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

	code_samples += count;
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
			data_samples += count;
			return 0;
		}
	}

	if (next_data_ref >= MAX_IBS_SAMPLES)
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

	data_samples += count;
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
	if (!func && !IBS_KERN_SAMPLE(ip))
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
		for (j = 0; j < fetch_samples_cnt[i]; j++) {
			if (fetch_samples[i][j].count == 0)
				continue;

			ip = fetch_samples[i][j].ip;
			add_sample(fetch_samples[i][j].tgid,
				   ip, ip,
				   fetch_samples[i][j].count,
				   fetch_samples[i][j].latency,
				   true);

			fetch_samples[i][j].count = 0;
		}
		fetch_samples_cnt[i] = 0;
	}
}

static void process_data_samples(unsigned long total, bool user_space_only)
{
	int i;
	u64 j, ip, key;

	for (i = 0; i < max_nodes; i++) {
		for (j = 0; j < op_samples_cnt[i]; j++) {
			if (op_samples[i][j].count == 0)
				continue;

			ip = op_samples[i][j].ip;
			key = op_samples[i][j].op_regs[IBS_DC_LINADDR];
			add_sample(op_samples[i][j].tgid,
				   key, ip,
				   op_samples[i][j].count,
				   fetch_samples[i][j].latency,
				   false);

			op_samples[i][j].count = 0;
		}
		op_samples_cnt[i] = 0;
	}
}

void profiler_process_samples(int fd_fetch, int fd_op, u64 fetch_cnt,
			      u64 op_cnt)
{
	u64 total_freq_fetch, total_freq_op;

	/* No multiple instances of sampling and/or reporting */
	if (atomic_cmxchg(&light_semaphore, 0, 1))
		return;

	if (fetch_cnt >= MIN_IBS_FETCH_SAMPLES) {
		fetch_cnt = get_code_samples(fd_fetch,
					     &total_freq_fetch,
					     false);
		process_code_samples(total_freq_fetch, true);
	}

	if (op_cnt >= MIN_IBS_OP_SAMPLES) {
		op_cnt = get_data_samples(fd_op,
					  &total_freq_op,
					  false);
		process_data_samples(total_freq_op, true);
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

	printf("\f\r");

	qsort(code_ref, next_code_ref, sizeof(struct code_ref), ref_cmp);

	j = 0;
	for (i = 0; i < next_code_ref; i++) {
		if (code_ref[i].ref < 2) {
			code_ref[i].ref = 0;
			continue;
		}

		if (j++ == 0)
			print_header(summary, true);

		if (j > iprofiler) {
			code_ref[i].ref = 0;
			continue;
		}

		if (code_ref[i].info) {
			snprintf(function, MAX_FUNC_NAME, "%s",
				 code_ref[i].info->name);
		} else {
			if (IBS_KERN_SAMPLE(code_ref[i].ip)) {
				snprintf(function, MAX_FUNC_NAME,
					"KERN:0x%lX",
				 	(unsigned long)code_ref[i].ip);
			} else {
				snprintf(function, MAX_FUNC_NAME,
					"USER:0x%lX",
				 	(unsigned long)code_ref[i].ip);
			}
		}

		assert(code_ref[i].ref <= code_samples);
		pct = code_ref[i].ref * 100 / code_samples;

		printf("%-3d %-10u %-20s %-14p %-7lu %-7u %4s %5s ",
			j, code_ref[i].pid, function,
			(void *)(unsigned long)code_ref[i].ip,
			(unsigned long)code_ref[i].ref,
			pct, "CODE",
			IBS_KERN_SAMPLE(code_ref[i].ip) ? "KERN" : "USER");


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


	qsort(data_ref, next_data_ref, sizeof(struct code_ref), ref_cmp);

	j = 0;
	for (i = 0; i < next_data_ref; i++) {
		if (data_ref[i].ref < 2) {
			data_ref[i].ref = 0;
			continue;
		}

		if (j++ == 0)
			print_header(summary, false);

		if (j > iprofiler) {
			data_ref[i].ref = 0;
			continue;
		}

		if (data_ref[i].info) {
			snprintf(function, MAX_FUNC_NAME, "%s",
				 data_ref[i].info->name);
		} else {
			if (IBS_KERN_SAMPLE(data_ref[i].ip)) {
				snprintf(function, MAX_FUNC_NAME,
					"KERN:0x%lX",
				 	(unsigned long)data_ref[i].ip);
			} else {
				snprintf(function, MAX_FUNC_NAME,
					"USER:0x%lX",
				 	(unsigned long)data_ref[i].ip);
			}
		}

		assert(data_ref[i].ref <= data_samples);
		pct = data_ref[i].ref * 100 / data_samples;

		printf("%-3d %-10u %-20s %-14p %-7lu %-7u %4s %5s",
			j, data_ref[i].pid, function,
			(void *)(unsigned long)data_ref[i].key,
			(unsigned long)data_ref[i].ref,
			pct, "DATA",
			IBS_KERN_SAMPLE(data_ref[i].ip) ? "KERN" : "USER");

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

void report_profiler_information(bool summary)
{
	static struct timeval start;
	struct timeval end;

	/* No multiple instances of sampling and/or reporting */
	if (atomic_cmxchg(&light_semaphore, 0, 1))
		return;

	if (!next_code_ref && !next_data_ref) {
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
		(unsigned long)code_samples,
		(unsigned long)data_samples);

	next_code_ref     = 0;
	next_data_ref     = 0;
	next_process_info = 0;
	data_samples      = 0;
	code_samples      = 0;
	start             = end;

	tdestroy(root_code_ref, do_nothing);
	tdestroy(root_data_ref, do_nothing);
	tdestroy(root_process_info, do_nothing);

	root_code_ref     = NULL;
	root_data_ref     = NULL;
	root_process_info = NULL;

	assert(atomic_cmxchg(&light_semaphore, 1, 0) == 1);
}
