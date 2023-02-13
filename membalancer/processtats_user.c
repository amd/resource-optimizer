/*
 * membalancer_user.c - Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
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

#include "membalancer.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_migrate.h"

int fill_numa_address_range_map(struct bpf_object *obj)
{
	int fd, i;
	struct numa_range range;

	fd = bpf_object__find_map_fd_by_name(obj, "numa_address_range");
	if (fd < 0) {
		fprintf(stderr, "BPF cannot find numa_address_range map\n");
		return -1;
	}

	for (i = 0; i < max_nodes; i++) {
		if (numa_range_get(i, &range) != 0)
			break;

		bpf_map_update_elem(fd, &i, &range, BPF_NOEXIST);
		printf("%d first_pfn %lx last_pfn %lx\n",
			i,
			(unsigned long)range.first_pfn,
			(unsigned long)range.last_pfn);
	}

	close(fd);

	return i;
}

void process_migrate_processes(int map_fd)
{
	u32 key, next_key;
	struct process_stats stats;
	int i;
	int j = 0;
	int target_node = 0;
	u64 total_ref = 0;
	u32 max_count = 0, ref_count = 0, max_ref = 0;
	int cur_node = 0;

	memset(numa_reference, 0, sizeof(struct ibs_noderef_sample));
	key = 0;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(map_fd, &next_key, &stats);
		key = next_key;
		bpf_map_delete_elem(map_fd, &next_key);
		total_ref = 0;
		max_ref = 0;
		printf("PID %5u ", (unsigned int)key);

		for (i = 0; i < max_nodes; i++)
			printf("CPU%d %-5u ",
				i, stats.cpu[i]);
		for (i = 0; i < max_nodes; i++) {
			ref_count = stats.memory[i];
			printf("MEM%d %-5u ",
				i, ref_count);
			if (ref_count > max_ref) {
			    max_ref = ref_count;
			    target_node = i;
			}
			total_ref += ref_count;
		}
		printf("\n");

		if (((max_ref * 100)/ total_ref) > MAX_REMOTE_REF) {
		    numa_reference[j].pid = key;
		    numa_reference[j].max_ref = max_ref;
		    numa_reference[j].target_node = target_node;
		}
		j++;
	}
	max_count = j;
	move_process(max_count);
}
