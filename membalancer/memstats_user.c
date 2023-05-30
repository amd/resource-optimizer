/*
 * membalancer_user.c - Automatic NUMA memory balancer Based on IBS sampler
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
#include <math.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <perf-sys.h>
#include <trace_helpers.h>
#include <assert.h>
#include <numa.h>
#include <numaif.h>
#include <time.h>
#include <pthread.h>
#include <limits.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/wait.h>
#include <ctype.h>
#include <search.h>
#include <sched.h>
#include "memory_profiler_common.h"
#include "memory_profiler_arch.h"
#include "thread_pool.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_migrate.h"
#include "heap_user.h"
#include "membalancer_utils.h"
int iprofiler;

struct code_samples code_samples[MAX_NUMA_NODES][MAX_SAMPLES];
unsigned long code_samples_max[MAX_NUMA_NODES];
unsigned long code_samples_cnt[MAX_NUMA_NODES];

struct data_samples data_samples[MAX_NUMA_NODES][MAX_SAMPLES];
unsigned long data_samples_max[MAX_NUMA_NODES];
unsigned long data_samples_cnt[MAX_NUMA_NODES];

static int code_samples_cmp(const void *p1, const void *p2)
{
	const struct code_samples *s1 = p1, *s2 = p2;

	return s1->count - s2->count;
}

static char * get_process(__u64 tgid)
{
	return "";
}

int get_code_samples(int fd, __u64 *total_freq, bool defer)
{
	__u64 key, next_key;
	struct code_sample value;
	int i, j, max, node;
	long total = 0;
	unsigned long paddr;
	int dense_samples = 0;
	bool table_full = false;

	for (i = 0; i < max_nodes; i++) {
		code_samples_max[i] = 0;
		code_samples_cnt[i] = 0;
	}

	/* Process fetch samples from the map*/
	key = 0;
	i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

		atomic64_inc(&status_code_cnt);
#ifdef USE_PAGEMAP
		paddr = get_physaddr((pid_t)value.tgid,	value.vaddr);
		if (paddr == (unsigned long)-1) {
			key = next_key;
			bpf_map_delete_elem(fd, &next_key);
			continue;
		}

		paddr *= PAGE_SIZE;
		/*
		assert(paddr == (value.vaddr & ~(MEMB_PAGE_SIZE - 1)));
		*/
#else
		paddr = value.paddr;
#endif

		node = get_current_node(paddr);
		assert(node >= -1 && node < (long)max_nodes);
		if (node < 0 || node >= (long)max_nodes) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			continue;
		}

		if (i >= MAX_SAMPLES) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			table_full = true;
			continue;
		}

		if (defer && value.count >= MIN_DENSE_SAMPLE_FREQ)
			dense_samples++;

		code_samples[node][i].count = value.count;
		code_samples[node][i].ip    = value.ip;
		code_samples[node][i].tgid  = value.tgid;
		code_samples[node][i].vaddr = value.vaddr;
		code_samples[node][i].paddr = value.paddr;

		for (j = 0; j < max_nodes; j++)
			code_samples[node][i].counts[j] = value.counts[j];

		if (iprofiler) {
			for (j = 0; j < value.count; j++) {
				if (j > MAX_LATENCY_IDX)
					break;

				code_samples[node][i].latency[j] =
							value.latency[j];
			}
		}

		if (!IBS_KERN_SAMPLE(code_samples[node][i].ip))
			snprintf(code_samples[node][i].process,
				sizeof(code_samples[node][i].process),
					"%s",
					get_process(value.tgid));

		total += code_samples[node][i].count;
		code_samples_max[node] += code_samples[node][i].count;
		i++;

		code_samples_cnt[node]++;
		key = next_key;
	}

	/* Proceed if there are sufficient dense samples */
	if (defer && !table_full && dense_samples < MIN_DENSE_SAMPLES_CODE)
		return 0;

	key = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
		bpf_map_delete_elem(fd, &next_key);
		key = next_key;
	}

	max = i;

	/* sort samples */
       for (node = 0; node < max_nodes; node++)
                qsort(code_samples[node], code_samples_cnt[node],
                      sizeof(struct code_samples), code_samples_cmp);

	if (max >= MAX_SAMPLES) 
		printf("Processed maximum samples. "
		       "Likely to have dropped some. Increase the value of "
		       "MAX_SAMPLES\n");

	*total_freq = total;

	return max;
}

void cleanup_code_samples(int fd)
{
	__u64 key, next_key;
	struct code_sample value;
	int i, j;

	for (i = 0; i < max_nodes; i++) {
		code_samples_max[i] = 0;
		code_samples_cnt[i] = 0;
	}

	/* Process fetch samples from the map*/
	key = 0;
	i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

		bpf_map_delete_elem(fd, &next_key);
		key = next_key;

		for (j = 0; j < max_nodes; j++)
			code_samples[j][i].count = 0;

	}
}

static int data_samples_cmp(const void *p1, const void *p2)
{
	const struct data_samples *s1 = p1, *s2 = p2;

	return s1->count - s2->count;
}

int get_data_samples(int fd, __u64 *total_freq, bool defer)
{
	__u64 key, next_key;
	struct data_sample value;
	int i, j, max, node;
	long total = 0;
	unsigned long paddr;
	int dense_samples = 0;
	bool table_full = false;

	for (i = 0; i < max_nodes; i++)
		data_samples_max[i] = 0;

	/* Process op samples from the map*/
	key = 0;
	 i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

		atomic64_inc(&status_data_cnt);
#ifdef USE_PAGEMAP
		paddr = get_physaddr((pid_t)value.tgid, value.vaddr);
		if (paddr == (unsigned long)-1) {
			key = next_key;
			bpf_map_delete_elem(fd, &next_key);
			continue;
		}

		paddr *= PAGE_SIZE;

		/*
		assert(paddr == (value.paddr & ~(MEMB_PAGE_SIZE - 1)))
		*/
#else
		paddr = value.paddr;
#endif

		node = get_current_node(paddr);
		assert(node >= -1 && node < (long)max_nodes);
		if (node < 0 || node >= (long)max_nodes) {
			key = next_key;
			bpf_map_delete_elem(fd, &next_key);
			continue;
		}

		if (i >= MAX_SAMPLES) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			table_full = true;
			continue;
		}

		data_samples[node][i].count = value.count;
		data_samples[node][i].tgid  = value.tgid;
		data_samples[node][i].ip    = value.ip;
		data_samples[node][i].vaddr = value.vaddr;
		data_samples[node][i].paddr = value.paddr;

		for (j = 0; j < max_nodes; j++)
			data_samples[node][i].counts[j] = value.counts[j];

		if (iprofiler) {
			for (j = 0; j < value.count; j++) {
				if (j >= MAX_LATENCY_IDX)
					break;

				data_samples[node][i].latency[j] =
							value.latency[j];
			}
		}

		if (defer && value.count >= MIN_DENSE_SAMPLE_FREQ)
			dense_samples++;

		if (!IBS_KERN_SAMPLE(value.ip))
			snprintf(data_samples[node][i].process,
				sizeof(data_samples[node][i].process),
				"%s",
				get_process(data_samples[node][i].tgid));

		total += data_samples[node][i].count;
		data_samples_max[node] += data_samples[node][i].count;
		i++;

		data_samples_cnt[node]++;
		key = next_key;
	}

	/* Proceed if there are sufficient dense samples */
	if (defer && !table_full && dense_samples < MIN_DENSE_SAMPLES_DATA)
		return 0;

	key = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
		bpf_map_delete_elem(fd, &next_key);
		key = next_key;
	}

	max = i;

	/* sort */
	for (node = 0; node < max_nodes; node++)
		qsort(data_samples[node], data_samples_cnt[node],
		      sizeof(struct data_samples), data_samples_cmp);

	if (max >= MAX_SAMPLES) 
		printf("Processed maximum samples. "
		       "Likely to have dropped some. Increase the value of "
		       "MAX_SAMPLES\n");

	*total_freq = total;

	return max;
}

void cleanup_data_samples(int fd)
{
	__u64 key, next_key;
	struct data_sample value;
	int i, j;

	/* Process op samples from the map*/
	key = 0;
	 i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
		key = next_key;
		bpf_map_delete_elem(fd, &next_key);


		for (j = 0; j < max_nodes; j++)
			data_samples[j][i].count = 0;
	}
}
