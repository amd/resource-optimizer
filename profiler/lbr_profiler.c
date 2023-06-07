/*
 * lbr_profiler.c - last branch record sampler
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
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <perf-sys.h>
#include <trace_helpers.h>
#include <assert.h>
#include <time.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/param.h>
#include <signal.h>
#include <sys/wait.h>
#include <ctype.h>
#include <search.h>
#include <linux/close_range.h>
#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"
#include "thread_pool.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_utils.h"
#include "membalancer_user.h"
#include "membalancer_lib.h"
#include "profiler_pvt.h"
#include "lbr_common.h"
#include "profiler_common.h"

struct lbr_pbe_kv {
	struct lbr_pbe_key key;
	struct lbr_pbe_val val;
};

static struct lbr_pbe_kv lbr_pbe_kv[MAX_LBR_SAMPLES + 1];
unsigned int lbr_profiler;

static int pbe_cmp(const void *first, const void *second)
{
	struct lbr_pbe_kv *s1 = (struct lbr_pbe_kv *)first;
	struct lbr_pbe_kv *s2 = (struct lbr_pbe_kv *)second;

	if (s2->val.ref > s1->val.ref)
		return 1;
	if (s2->val.ref < s1->val.ref)
		return -1;

	return 0;
}

/*
 * PBE flags containing plethora of information including branch prediction or
 * misprediction, cycles to excecute branch, type of branch etc are ignored
 * despite being collected. This will be addressed in a future change.
 */
static void lbr_profiler_process_samples_pbe_flags(int fd)
{
	struct lbr_pbe_flags_key key, next_key;

	memset(&key, 0, sizeof(key));

	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_delete_elem(fd, &next_key);
		key = next_key;
	}
}

static char * get_instruction(unsigned long ip, pid_t pid)
{
	FILE *fp;
	static char buffer[1024];
	char path[MAXPATHLEN];
	char execpath[MAXPATHLEN];
	int i, j = 0;
	struct stat st;

	snprintf(execpath, MAXPATHLEN, "/proc/%d/exe", pid);
	if (stat(execpath, &st))
		return NULL;

	snprintf(path, sizeof(path), "/usr/bin/objdump -d %s| "
		 "/usr/bin/grep \"^  %lx\"", execpath, ip);

	fp = popen(path, "r");
	if (!fp)
		return NULL;

	if (fgets(buffer, sizeof(buffer) - 1, fp) == NULL) {
		pclose(fp);
		return NULL;
	}

	for (i = 0; i < sizeof(buffer); i++) {
		if (buffer[i] == '\t') {
			++j;
			if (j == 2 && i < sizeof(buffer))
				break;
		}
	}

	pclose(fp);

	if (++i == sizeof(buffer))
		return NULL;

	for (j = i; j < 1024; j++) {
		if (buffer[j] == '\n' || ((j -i) >= 40)) {
			buffer[j] = 0;
			break;
		}
	}

	return &buffer[i];
}

static void print_hdr(void)
{
	printf("\f\r");
	printf("%4s %-6s %-50s %-35s %6s %7s\n",
	       "No." , "PID", "FROM", "TO", "COUNT", "PERCENT");
}

static void lbr_profiler_report(int count, unsigned int total_samples)
{
	int i, j;
	bool first = true;
	char *from, *to;
	char fromstr[50], tostr[35];

	j = 0;
	for (i = 0; i < count; i++) {
		from = get_instruction(
				(unsigned long)lbr_pbe_kv[i].key.from,
				lbr_pbe_kv[i].key.tgid);
		if (!from)
			continue;

		snprintf(fromstr, sizeof(fromstr), "%-#lx:%s",
			 (unsigned long)lbr_pbe_kv[i].key.from, from);

		to = get_instruction(
				(unsigned long)lbr_pbe_kv[i].key.to,
				lbr_pbe_kv[i].key.tgid);
		if (!to)
			continue;

		if (first) {
			first = false;
			print_hdr();
		}

		snprintf(tostr, sizeof(tostr), "%-#lx:%s",
			 (unsigned long)lbr_pbe_kv[i].key.to, to);

		printf("%4u %6u %-50s %-35s %6u %6u%%\n",
			++j,
			(unsigned int)lbr_pbe_kv[i].key.tgid,
			fromstr,
			tostr,
			(unsigned int)lbr_pbe_kv[i].val.ref,
			(unsigned int)lbr_pbe_kv[i].val.ref * 100 /
			(1 + total_samples));

	}
}

static void lbr_profiler_report_summary(int count, unsigned int total_samples)
{
	int i;
	printf("\f\r");

	printf("%4s %-6s %-16s %-16s %6s %7s\n",
	       "No." , "PID", "FROM", "TO", "COUNT", "PERCENT");

	for (i = 0; i < count; i++) {
		printf("%4u %6u %-#16lx %-#16lx %6u %6u%%\n",
			i + 1,
			(unsigned int)lbr_pbe_kv[i].key.tgid,
			(unsigned long)lbr_pbe_kv[i].key.from,
			(unsigned long)lbr_pbe_kv[i].key.to,
			(unsigned int)lbr_pbe_kv[i].val.ref,
			(unsigned int)lbr_pbe_kv[i].val.ref * 100 /
			(1 + total_samples));
	}
}

static void lbr_profiler_process_samples_pbe(int fd)
{
	struct lbr_pbe_key key;
	int i, count;
	unsigned int total_samples;

	memset(&key, 0, sizeof(key));

	count = 0;
	total_samples = 0;

	while (count < MAX_LBR_SAMPLES &&
		bpf_map_get_next_key(fd, &key, &lbr_pbe_kv[count].key) == 0) {

		bpf_map_lookup_elem(fd, &lbr_pbe_kv[count].key,
				    &lbr_pbe_kv[count].val);

		key = lbr_pbe_kv[count].key;
		bpf_map_delete_elem(fd, &lbr_pbe_kv[count].key);
		total_samples +=  lbr_pbe_kv[count].val.ref;

		if (user_space_only ||
		    KERN_SAMPLE(lbr_pbe_kv[count].key.from)) {
			count++;
		}

	}

	if (count == 0)
		return;

	qsort(lbr_pbe_kv, count, sizeof(struct lbr_pbe_kv), pbe_cmp);
	if (count > lbr_profiler)
		count = lbr_profiler;

	if (verbose <= 2)
		lbr_profiler_report_summary(count, total_samples);
	else
		lbr_profiler_report(count, total_samples);

}

static void lbr_profiler_process_samples(int fd_pbe, int fd_pbe_flags)
{
	lbr_profiler_process_samples_pbe(fd_pbe);
	lbr_profiler_process_samples_pbe_flags(fd_pbe);
}

int lbr_profiler_function(const char *kernobj, int freq, int msecs,
		       char *include_pids, char *include_ppids,
		       cpu_set_t *cpusetp, char *filter_str)
{
	int err;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog[TOTAL_BPF_PROGRAMS];
	struct bpf_link **lbr_links = NULL;
	char filename[256];
	int map_fd[TOTAL_MAPS];
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
					 lbr_profiler_program_names,
					 lbr_profiler_map_fd_names);
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

	if (user_space_only)
		set_knob(map_fd[KNOBS], USER_SPACE_ONLY, 1);

	set_knob(map_fd[KNOBS], MY_PAGE_SIZE, MEMB_PAGE_SIZE);
	set_knob(map_fd[KNOBS], MY_OWN_PID, getpid());
	set_knob(map_fd[KNOBS], KERN_VERBOSE, verbose);

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
	printf("Collecting LBR samples .....\n");
	printf("%s", NORM);

	gettimeofday(&start, NULL);

	open_ibs_devices();
	while (!err) {
		err = lbr_sampling_begin(freq, prog[LBR_SAMPLER], lbr_links,
				       cpusetp);
		if (err) {
			fprintf(stderr, "LBR sampling not supported\n");
			goto cleanup;
		}

		usleep(msecs * 1000);

		if (lbr_links)
			ibs_sampling_end(lbr_links);

		lbr_profiler_process_samples(map_fd[LBR_PBE],
					     map_fd[LBR_PBE_FLAGS]);

		/*
		 * TODO: Remove the workaround once the place where
		 * the file descriptors are leaked are known.
		 */
#ifdef USE_CLOSE_RANGE
		close_range(100, 8192, 0);
#endif
		usleep(msecs * 1000 / maximizer_mode);
	}

cleanup:
	close_ibs_devices();
	terminate_additional_bpf_programs();

	if (lbr_links)
		ibs_sampling_end(lbr_links);  /* LBR */

	free(lbr_links);
	bpf_object__close(obj);

	return err;
}
