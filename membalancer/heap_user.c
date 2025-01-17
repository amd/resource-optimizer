/*
 * heap_user.c - Initialize heap for the eBPF kernel use.
 *
 * Copyright (C) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
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
#include "heap_user.h"

int fill_process_stats_buffers(struct bpf_object *obj)
{
	int fd, i;
	struct process_stats stats[MAX_CPU_CORES];

	fd = bpf_object__find_map_fd_by_name(obj, "per_cpu_process_stats");
	if (fd < 0) {
		fprintf(stderr, "BPF cannot find per_cpu_process_stats map\n");
		return -1;
	}

	for (i = 0; i < MAX_CPU_CORES; i++) {
		memset(&stats[i], 0, sizeof(stats[i]));
		bpf_map_update_elem(fd, &i, &stats[i], BPF_NOEXIST);
	}

	return 0;
}

static int fill_data_sample_buffers(struct bpf_object *obj)
{
	int fd, i;
	struct data_sample value[MAX_CPU_CORES];

	fd = bpf_object__find_map_fd_by_name(obj, "per_cpu_data_sample");
	if (fd < 0) {
		fprintf(stderr, "BPF cannot find per_cpu_code_sample map\n");
		return -1;
	}

	for (i = 0; i < MAX_CPU_CORES; i++) {
		memset(&value[i], 0, sizeof(value[i]));
		bpf_map_update_elem(fd, &i, &value[i], BPF_NOEXIST);
	}

	close(fd);
	return 0;
}

static int fill_code_sample_buffers(struct bpf_object *obj)
{
	int fd, i;
	struct code_sample value[MAX_CPU_CORES];

	fd = bpf_object__find_map_fd_by_name(obj, "per_cpu_code_sample");
	if (fd < 0) {
		fprintf(stderr, "BPF cannot find per_cpu_code_sample map\n");
		return -1;
	}

	for (i = 0; i < MAX_CPU_CORES; i++) {
		memset(&value[i], 0, sizeof(value[i]));
		bpf_map_update_elem(fd, &i, &value[i], BPF_NOEXIST);
	}

	close(fd);
	return 0;
}

int init_heap(struct bpf_object *obj)
{
	int err;

	err = fill_process_stats_buffers(obj);
	if (err)
		return err;

	err = fill_data_sample_buffers(obj);
	if (err)
		return err;

	return fill_code_sample_buffers(obj);
}
