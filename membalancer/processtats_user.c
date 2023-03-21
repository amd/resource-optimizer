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

#include "membalancer_common.h"
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

static int numa_range_cmp(const void *p1, const void *p2)
{
	const struct numa_range *r1 = p1, *r2 = p2;

	if (r1->first_pfn < r2->first_pfn)
		return -1;

	if (r1->first_pfn > r2->first_pfn)
		return 1;

	return 0;
}

int fill_numa_address_range_map(struct bpf_object *obj)
{
	int fd, i, j = 0;
	struct numa_range range[MAX_NUMA_NODES];

	fd = bpf_object__find_map_fd_by_name(obj, "numa_address_range");
	if (fd < 0) {
		fprintf(stderr, "BPF cannot find numa_address_range map\n");
		return -1;
	}

	for (i = 0; i < max_nodes; i++) {
		if (numa_range_get(i, &range[i]) != 0)
			break;
		j++;
	}

	qsort(range, j, sizeof(range[0]), numa_range_cmp);

	for (i = 0; i < j; i++) {
		bpf_map_update_elem(fd, &i, &range[i], BPF_NOEXIST);
		printf("%d first_pfn %lx last_pfn %lx\n",
			i,
			(unsigned long)range[i].first_pfn,
			(unsigned long)range[i].last_pfn);
	}

	close(fd);

	return i;
}

static void cpu_mem_access_summary_text(u64 total_cpu_ref,
				u64 *numa_cpu_ref,
				u64 total_mem_ref,
				u64 *numa_mem_ref)
{
	int i;
	static unsigned long counter;
	double pct;
	char buf[15];

	if (!(counter++ % 20)) {
		for (i = 0; i < max_nodes; i++) {
			snprintf(buf, sizeof(buf), "NUMA%d_CPU_MEMORY_ACCESS",
				 i);
			printf("%-12s", buf);
		}
		printf("%s\n", NORM);
	}

	print_text(total_cpu_ref, numa_cpu_ref);
	print_text(total_mem_ref, numa_mem_ref);

	printf("\n");
}

static void print_histogram(u64 total_ref, u64 *numa_ref, bool cpu)
{
	int i = 0;
	double pct = 0.0;

	for (i = 0; i < max_nodes; i++) {
		if (numa_ref[i] <= 0 || !total_ref)
			pct = 0.0;
		else
			pct = (((double)numa_ref[i]) * 100) / total_ref;

		print_bar(i, false, true, cpu, pct);
	}
}

static void cpu_mem_access_summary_histogram(u64 total_cpu_ref,
				u64* numa_cpu_ref,
				u64 total_mem_ref,
				u64* numa_mem_ref)
{
	int i;
	double pct;
	printf("\f");
	printf("%s%s%s", BRIGHT, BCYAN, ULINE);
	for (i = 0; i < 20; i++)
			printf("%c", 32);
	printf("%-40s", "NUMA PROCESS CPU AND MEMORY ACCESS PATTERN");

	for (i = 0; i < 20; i++)
		printf("%c", 32);
	printf("\n\n");
	printf("%s", NORM);

	print_histogram(total_cpu_ref, numa_cpu_ref, true);
	printf("\n");
	print_histogram(total_mem_ref, numa_mem_ref, false);
}

static void cpu_mem_access_summary(u64 total_cpu_ref,
				u64 *numa_cpu_ref,
				u64 total_mem_ref,
				u64 *numa_mem_ref)
{
	static struct timeval start;
	struct timeval end;
	static int print_summary;

	if (atomic_cmxchg(&print_summary, 0, 1))
		return;

	if (start.tv_sec == 0 && start.tv_sec == 0)
			gettimeofday(&start, NULL);

	gettimeofday(&end, NULL);

	if (seconds_elapsed(&start, &end) < report_frequency) {
			assert(atomic_cmxchg(&print_summary, 1, 0) == 1);
			return;
	}

	start = end;

	if (!total_cpu_ref && !total_mem_ref) {
			assert(atomic_cmxchg(&print_summary, 1, 0) == 1);
			return;
	}

	if (!histogram_format)
		cpu_mem_access_summary_text(total_cpu_ref, numa_cpu_ref,
					    total_mem_ref, numa_mem_ref);
	else
		cpu_mem_access_summary_histogram(total_cpu_ref, numa_cpu_ref,
						 total_mem_ref, numa_mem_ref);

	assert(atomic_cmxchg(&print_summary, 1, 0) == 1);
}

void process_migrate_processes(int map_fd)
{
	u64 key = 0, next_key;
	struct process_stats stats;
	int i;
	u32 process_cnt = 0;
	int target_node = -1;
	u64 total_ref = 0;
	u32 ref_count = 0, max_ref = 0;
	u32 max_cpu_ref;
	int max_cpu_ref_node;
	u64 total_cpu_ref = 0;
	u64 total_mem_ref = 0;
	u64 numa_cpu_ref[max_nodes];
	u64 numa_mem_ref[max_nodes];

	memset(numa_cpu_ref, 0, max_nodes * sizeof(u64));
	memset(numa_mem_ref, 0, max_nodes * sizeof(u64));

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(map_fd, &next_key, &stats);
		key = next_key;
		bpf_map_delete_elem(map_fd, &next_key);

		total_ref = 0;
		max_ref = 0;
		max_cpu_ref = 0;
		max_cpu_ref_node = -1;

		if (verbose > 3)
			printf("TID %d (PID:%d)\n",
				(pid_t)key, (pid_t)(key >> 32));

		for (i = 0; i < max_nodes; i++) {
			if (verbose > 3)
				printf("CPU%d %-5u ",
					i, stats.cpu[i]);

			if (stats.cpu[i] > max_cpu_ref) {
				max_cpu_ref = stats.cpu[i];
				max_cpu_ref_node = i;
			}
			total_cpu_ref += stats.cpu[i];
			numa_cpu_ref[i] += stats.cpu[i];

			ref_count = stats.memory[i];
			if (verbose > 3)
				printf("MEM%d %-5u ",
					i, ref_count);

			if (ref_count > max_ref) {
				max_ref = ref_count;
				target_node = i;
			}
			total_ref += ref_count;
			total_mem_ref += stats.memory[i];
			numa_mem_ref[i] += stats.memory[i];
		}
		if (verbose > 3)
			printf("\n");

		if ((max_cpu_ref_node != target_node) &&
		    total_ref &&
		    (((max_ref * 100)/ total_ref) > MAX_REMOTE_REF)) {

			numa_reference[process_cnt].target_node = target_node;
			numa_reference[process_cnt].pid = key;
			numa_reference[process_cnt].max_ref = max_ref;

			process_cnt++;
		}
	}

	if (process_cnt && do_migration)
		move_process(process_cnt, true);

	cpu_mem_access_summary(total_cpu_ref, numa_cpu_ref,
				total_mem_ref, numa_mem_ref);
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
			printf("TID %d (PID:%d)\n", (pid_t)key,
				(pid_t)(key >> 32));

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
			proc_runtime_data[found_index].memory[i] +=
							stats.memory[i];
			proc_runtime_data[found_index].total_access_sample +=
							stats.memory[i];
			if (verbose <= 3)
				continue;

			printf("CPU%d %-5u , stat[%d].CPU%d %-5u\n",
				i, stats.cpu[i], found_index, i,
				proc_runtime_data[found_index].cpu[i]);

			printf("MEM%d %-5u , stat[%d].MEM%d %-5u\n",
				i, stats.memory[i], found_index, i,
				proc_runtime_data[found_index].memory[i]);
		}
	}
}

static int find_node_for_process_migration(int cpu_access_node,
				struct in_mem_proc_runtime_data proc_data)
{
	u64 access_threshold_val;
	u64 weight_array[max_nodes];
	u64 total_weight = 0;

	memset(weight_array, 0, max_nodes * sizeof(u64));

	for (int i = 0; i < max_nodes; i++) {
		weight_array[i] = (numa_table[cpu_access_node].distance[i] *
		                   proc_data.memory[i]);
		total_weight += weight_array[i];
	}

	access_threshold_val = (total_weight *
	                        proc_mem_acc_threshold)/100;

	for (int i = 0; i < max_nodes; i++) {
		/*
		 * Find a node with concentrated highest total cost.
		 * If there is, better move the processes to that node.
		 */
		if (weight_array[i] >= access_threshold_val)
			return i;
	}

	return -1;
}

void analyze_and_set_autotune_params(u32 *curr_index)
{
	struct in_mem_proc_runtime_data proc_data;
	int mem_access_node;
	int cpu_access_node;
	u64 highest_access_val;

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
		/* First find the highest compute node */
		for (int j = 0; j < max_nodes; j++) {
			if (proc_data.cpu[j] > highest_access_val) {
				highest_access_val = proc_data.cpu[j];
				cpu_access_node = j;
			}
		}

		/*
		 * Consider the relative cost for each NUMA node to compute ,
		 * weight in respect to highest compute node and find the target
		 * node.
		 */
		mem_access_node = find_node_for_process_migration(
		                    cpu_access_node,
		                    proc_data);

		if (mem_access_node == -1 ||  mem_access_node == cpu_access_node)
			return;

		numa_reference[*curr_index].pid = proc_data.pid;
		numa_reference[*curr_index].target_node = mem_access_node;
		(*curr_index)++;

		if(verbose <= 3)
			continue;

		printf("Move process:TID=%d (PID:%d) highest cpu node : %d "
		       "and >%d memory access node: %d\n",
		       (pid_t)(proc_data.pid),
		       (pid_t)(proc_data.pid >> 32), cpu_access_node,
		       proc_mem_acc_threshold, mem_access_node);
	}
}
