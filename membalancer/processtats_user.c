/*
 * processtats_user.c - Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (c) 2023 Advanced Micro Devices, Inc.
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


struct in_mem_proc_runtime_data {
       volatile u64 pid;
       volatile u32 total_access_sample;
       volatile u32 memory[MAX_NUMA_NODES];
       volatile u32 cpu[MAX_NUMA_NODES];
};

static struct in_mem_proc_runtime_data proc_runtime_data[MAX_PROCESS_STATS_IDX];
static int proc_data_idx;

#define proc_mem_acc_threshold 70


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
	u64 key = 0, next_key;
	struct process_stats stats;
	int i;
	u32 j = 0;
	int target_node = -1;
	u64 total_ref = 0;
	u32 ref_count = 0, max_ref = 0;
	u32 max_cpu_ref;
	int	max_cpu_ref_node;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(map_fd, &next_key, &stats);
		key = next_key;
		bpf_map_delete_elem(map_fd, &next_key);

		total_ref = 0;
		max_ref = 0;
		max_cpu_ref = 0;
		max_cpu_ref_node = -1;

		if (verbose > 3)
			printf("TID %d (PID:%d)\n", (pid_t)key, (pid_t)(key >> 32));

		for (i = 0; i < max_nodes; i++) {
			if (verbose > 3)
				printf("CPU%d %-5u ",
					i, stats.cpu[i]);
			if (stats.cpu[i] > max_cpu_ref) {
				max_cpu_ref = stats.cpu[i];
				max_cpu_ref_node = i;
			}
		}

		for (i = 0; i < max_nodes; i++) {
			ref_count = stats.memory[i];
			if (verbose > 3)
				printf("MEM%d %-5u ",
					i, ref_count);
			if (ref_count > max_ref) {
			    max_ref = ref_count;
			    target_node = i;
			}
			total_ref += ref_count;
		}
		if (verbose > 3)
			printf("\n");

		if ((max_cpu_ref_node != target_node) &&
			total_ref &&
			(((max_ref * 100)/ total_ref) > MAX_REMOTE_REF)) {

		    numa_reference[j].target_node = target_node;
		    numa_reference[j].pid = key;
		    numa_reference[j].max_ref = max_ref;

			j++;
		}
	}

	if (j)
		move_process(j, true);
}

void update_process_run_data(int map_fd)
{
	u64 key = 0, next_key;
	struct process_stats stats;
	int i, found_index;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(map_fd, &next_key, &stats);
		key = next_key;
		bpf_map_delete_elem(map_fd, &next_key);

		found_index = -1;
		if (verbose > 3)
			printf("TID %d (PID:%d)\n", (pid_t)key, (pid_t)(key >> 32));

		if (proc_data_idx) {
			/* Find the slot of pid if we already have */
			for (i=0; i< proc_data_idx; i++) {
				if (proc_runtime_data[i].pid == key) {
					found_index = i;
					break;
				}
			}
		}

		if (found_index == -1) {
			if (proc_data_idx >= MAX_PROCESS_STATS_IDX) {
				/*TODO: unlikely block but handle this.*/
				assert(0);
			}
			found_index = proc_data_idx;
			proc_data_idx++;
		}

		for (i = 0; i < max_nodes; i++) {
			proc_runtime_data[found_index].pid = key;
			proc_runtime_data[found_index].cpu[i] += stats.cpu[i];
			proc_runtime_data[found_index].memory[i] += stats.memory[i];
			proc_runtime_data[found_index].total_access_sample += stats.memory[i];

			if (verbose > 3) {
				printf("CPU%d %-5u , stat[%d].CPU%d %-5u\n",
						i, stats.cpu[i], found_index, i,
						proc_runtime_data[found_index].cpu[i]);
				printf("MEM%d %-5u , stat[%d].MEM%d %-5u\n",
						i, stats.memory[i], found_index, i,
						proc_runtime_data[found_index].memory[i]);
			}
		}
	}
}

void analyze_and_set_autotune_params(u32 *curr_index)
{
	struct in_mem_proc_runtime_data proc_data;
	int mem_access_node;
	int cpu_access_node;
	u32 highest_access_val;
	u32 access_threshold_val;

	/*
	 * Find if any of the single numa node has memory access.
	 * more than proc_mem_acc_threshold (set to 70%) and if that is remote,
	 * we suggest to move the process.
	 * Otherwise we better move the memory.
	 */
	for (int i=0; i < proc_data_idx; i++) {

		mem_access_node = -1;
		cpu_access_node = -1;
		highest_access_val = 0;

		proc_data = proc_runtime_data[i];
		access_threshold_val = ( proc_data.total_access_sample *
								proc_mem_acc_threshold)/100 ;

		for (int j = 0; j < max_nodes; j++) {
			if ( proc_data.memory[j] >= access_threshold_val) {
				mem_access_node = j;
			}
			/* Find highest execution node */
			if (proc_data.cpu[j] > highest_access_val) {
				highest_access_val = proc_data.cpu[j];
				cpu_access_node = j;
			}
			/* TODO:Find the best(alternative) node based on NUMA distance table
			 * and the load on the node.
			 */
		}
		if (mem_access_node != -1 && mem_access_node != cpu_access_node) {

			if (verbose > 3)
				printf("Setting move process:TID=%d (PID:%d)"
						"highest cpu node : %d and >%d"
						"memory access node: %d\n",
						(pid_t)(proc_data.pid),
						(pid_t)(proc_data.pid >> 32),
						cpu_access_node,
						proc_mem_acc_threshold, mem_access_node);

			numa_reference[*curr_index].pid = proc_data.pid;
			numa_reference[*curr_index].target_node = mem_access_node;
			(*curr_index)++;
		}
	}
}
