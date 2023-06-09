/*
 * processtats_user.c - Automatic NUMA memory balancer Based on IBS sampler
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

struct in_mem_proc_runtime_data {
	volatile u64 pid;
	volatile u32 memory[MAX_NUMA_NODES];
	volatile u32 cpu[MAX_NUMA_NODES];
};

struct process_group_bucket {
	volatile int proc_pid;
	volatile u32 proc_thread_idx;
	volatile bool is_scattered_memory;
	struct in_mem_proc_runtime_data threads[MAX_PROCESS_STATS_IDX];
};

static struct process_group_bucket proc_runtime_data[MAX_PROCESS_STATS_IDX];
static int proc_group_idx;

#define PROC_MEM_ACC_THRESHOLD 70

/* Autotune specific control params for process stats. */
u64 sampling_interval_cnt = 50;
u64 sampling_iter;
bool proc_data_sampling_done = false;
bool is_begining_of_sampling = true;
bool fallback_to_memory_balance = true;
u32 curr_proc_data_map_idx;


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

void process_migrate_balance_processes(int map_fd)
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

		if (verbose >= 5)
			printf("TID %d (PID:%d)\n",
				(pid_t)key, (pid_t)(key >> 32));

		for (i = 0; i < max_nodes; i++) {
			if (verbose >= 5)
				printf("CPU%d %-5u ",
					i, stats.cpu[i]);

			if (stats.cpu[i] > max_cpu_ref) {
				max_cpu_ref = stats.cpu[i];
				max_cpu_ref_node = i;
			}
			total_cpu_ref += stats.cpu[i];
			numa_cpu_ref[i] += stats.cpu[i];

			ref_count = stats.memory[i];
			if (verbose >= 5)
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
		if (verbose >= 5)
			printf("\n");

		if ((max_cpu_ref_node != target_node) &&
		    total_ref &&
		    (((max_ref * 100)/ total_ref) > MAX_REMOTE_REF)) {

			numa_reference[process_cnt].target_node = target_node;
			numa_reference[process_cnt].curr_node = max_cpu_ref_node;
			numa_reference[process_cnt].pid = key;
			numa_reference[process_cnt].max_ref = max_ref;

			process_cnt++;
		}
	}

	if (process_cnt && do_migration)
		process_migrate_move_process(process_cnt, false);

	cpu_mem_access_summary(total_cpu_ref, numa_cpu_ref,
				total_mem_ref, numa_mem_ref);
}

void reset_proc_runtime_data(void)
{
	proc_group_idx = 0;
	memset(proc_runtime_data, 0,
	MAX_PROCESS_STATS_IDX * sizeof(struct process_group_bucket));
}

void update_process_run_data(int map_fd)
{
	u64 key = 0, next_key;
	struct process_stats stats;
	int i, j, found_group_idx, found_thread_idx;
	struct process_group_bucket *proc_data;
	struct in_mem_proc_runtime_data *thread_data;

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(map_fd, &next_key, &stats);
		key = next_key;
		bpf_map_delete_elem(map_fd, &next_key);

		found_group_idx = -1;
		found_thread_idx = -1;

		if (verbose > 5)
			printf("TID %d (PID:%d)\n", (pid_t)key,
				(pid_t)(key >> 32));

		/* Find the slot of pid if we already have */
		for (i=0; i< proc_group_idx; i++) {
			if (proc_runtime_data[i].proc_pid == (pid_t)(key >> 32)) {
				found_group_idx = i;
				/* Find if we have seen this thread already. */
				for (j=0; j < proc_runtime_data[i].proc_thread_idx; j++) {
					if(proc_runtime_data[i].threads[j].pid == key) {
						found_thread_idx = j;
						break;
					}
				}
				break;
			}
		}

		if (found_group_idx == -1) {
			if (proc_group_idx >= MAX_PROCESS_STATS_IDX) {
				/*TODO: unlikely block but handle this.*/
				assert(0);
			}
			found_group_idx = proc_group_idx;
			proc_group_idx++;
		}

		proc_data = &proc_runtime_data[found_group_idx];

		if (proc_data->proc_pid)
			assert(proc_data->proc_pid == (pid_t)(key >> 32));
		else
			proc_data->proc_pid = (pid_t)(key >> 32);

		if (found_thread_idx == -1) {
			if (proc_data->proc_thread_idx >= MAX_PROCESS_STATS_IDX)
				assert(0);

			found_thread_idx = proc_data->proc_thread_idx;
			proc_data->proc_thread_idx++;
		}

		thread_data = &(proc_data->threads[found_thread_idx]);

		if (thread_data->pid)
			assert(thread_data->pid == key);
		else
			thread_data->pid = key;

		for (i = 0; i < max_nodes; i++) {
			thread_data->cpu[i] += stats.cpu[i];
			thread_data->memory[i] += stats.memory[i];

			if (verbose <= 5)
				continue;

			printf("CPU%d %-5u , stat[%d].CPU%d %-5u\n",
				i, stats.cpu[i], found_thread_idx, i,
				thread_data->cpu[i]);

			printf("MEM%d %-5u , stat[%d].MEM%d %-5u\n",
				i, stats.memory[i], found_thread_idx, i,
				thread_data->memory[i]);
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
	                        PROC_MEM_ACC_THRESHOLD)/100;

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

bool is_scattered_proc_group(void)
{
	for (int i=0; i < proc_group_idx; i++) {
		if (proc_runtime_data[i].is_scattered_memory)
			return true;
	}

	return false;
}

void autotune_filter_data(u32 *curr_index)
{
	struct process_group_bucket *proc_data;
	struct in_mem_proc_runtime_data *thread_data;
	int prev_mem_access_node;
	int mem_access_node;
	int cpu_access_node;
	u64 highest_access_val;
	u64 total_cpu_ref = 0;
	u64 total_mem_ref = 0;
	u64 numa_cpu_ref[max_nodes];
	u64 numa_mem_ref[max_nodes];

	memset(numa_cpu_ref, 0, max_nodes * sizeof(u64));
	memset(numa_mem_ref, 0, max_nodes * sizeof(u64));

	memset(per_node_thread_cnt, 0, max_nodes * sizeof(int));

	/*
	 * Find if any of the single numa node has memory access more than
	 * PROC_MEM_ACC_THRESHOLD (set to 70%) and if that is remote,
	 * we suggest to move the process.
	 * Otherwise we better balance memory.
	 */
	for (int i=0; i < proc_group_idx; i++) {

		proc_data = &proc_runtime_data[i];

		for (int j=0; j< proc_data->proc_thread_idx; j++) {

			prev_mem_access_node = -1;
			mem_access_node = -1;
			cpu_access_node = -1;
			highest_access_val = 0;

			thread_data = &(proc_data->threads[j]);
			/* First find the highest compute node */
			for (int k = 0; k < max_nodes; k++) {
				if (thread_data->cpu[k] > highest_access_val) {
					highest_access_val = thread_data->cpu[k];
					cpu_access_node = k;
				}

				total_cpu_ref += thread_data->cpu[k];
				numa_cpu_ref[k] += thread_data->cpu[k];
				total_mem_ref  += thread_data->memory[k];
				numa_mem_ref[k] += thread_data->memory[k];
			}
			/*
			 * Consider the relative cost for each NUMA node to compute ,
			 * weight in respect to highest compute node and find the target
			 * node.
			 */
			mem_access_node = find_node_for_process_migration(
		                    cpu_access_node,
		                    *thread_data);

			if (mem_access_node == -1 ||
				mem_access_node == cpu_access_node)
				continue;

			if (prev_mem_access_node == -1) {
				/* First occurence */
				prev_mem_access_node = mem_access_node;
			} else if (prev_mem_access_node != mem_access_node){
				/* We are having more than one target node
				 * for threads of this process.
				 */
				proc_data->is_scattered_memory = true;
			}

			per_node_thread_cnt[mem_access_node]++;

			/* Continue adding the threads of process we are balancing.
			 * Later we will evaluate if we are really adopting to process
			 * migration scheme or falling back to memory balancing.
			 */

			numa_reference[*curr_index].pid = thread_data->pid;
			numa_reference[*curr_index].target_node = mem_access_node;
			numa_reference[*curr_index].curr_node = cpu_access_node;
			numa_reference[*curr_index].curr_to_target_distance =
					numa_table[cpu_access_node].distance[mem_access_node];

			(*curr_index)++;

			if(verbose <= 3)
				continue;

			printf("Move process:TID=%d (PID:%d) highest cpu node : %d "
				"and >%d memory access node: %d\n",
				(pid_t)(thread_data->pid),
				(pid_t)(thread_data->pid >> 32), cpu_access_node,
				PROC_MEM_ACC_THRESHOLD, mem_access_node);
		} /* threads loop */
	} /* process group loop */

	/* Display the cpu and memory access pattern after final iteration. */

	cpu_mem_access_summary(total_cpu_ref, numa_cpu_ref,
			total_mem_ref, numa_mem_ref);

}

void autotune_sampler_and_analyzer(int map_fd)
{
	/* Capture and update the process run data
	 * till the sampling_interval_cnt.
	 */
	if (sampling_interval_cnt &&
		((sampling_iter % sampling_interval_cnt)+1
		< sampling_interval_cnt)) {

		if (is_begining_of_sampling) {
			printf("\nAutotune sampling is in progress.....\n"
				"Sampling interval count: %llu\n", sampling_interval_cnt);
			is_begining_of_sampling = false;
		}
		if (verbose >= 3)
			printf("Capturing process run data :"
				"sampling_iter=%llu/%llu\n",
				(sampling_iter % sampling_interval_cnt),
				sampling_interval_cnt);

		update_process_run_data(map_fd);
	} else {
		printf("\nDone capturing data."
			"Analyzing and setting process tuning.\n");

		autotune_filter_data(&curr_proc_data_map_idx);
		proc_data_sampling_done = true;
		is_begining_of_sampling = true;
	}
}

bool autotune_tuner(void)
{
	bool tuning_done = false;

	if (!curr_proc_data_map_idx) {
		/* Nothing to do here to tune process */
		return tuning_done;
	}

	int i = 0;
	int mig_skipped = 0;

	assert(proc_data_sampling_done == true);

	if(is_scattered_proc_group()) {
		mig_skipped = curr_proc_data_map_idx;
	} else {
		process_migrate_move_process(curr_proc_data_map_idx, true);
		/*
		 * Scan, if had to skip all of it.
		 * This is good indication to move to
		 * memory balance.
		 */
		while(i < curr_proc_data_map_idx)
		{
			if(numa_reference[i].status != 0)
				mig_skipped++;
			i++;
		}
	}

	if (mig_skipped == curr_proc_data_map_idx) {
		/* We had to skip all of them.
		 * Depending on state of fallback_to_memory_balance,
		 * further decide to move to memory balance or not.
		 * For Ex. Previous iterations we moved some, and now
		 * we skip. So better to stick to process balancing.
		 */
		printf("\n** No further process tuning is done!! **\n");
	} else {
		if (fallback_to_memory_balance)
			fallback_to_memory_balance = false;
		tuning_done = true;
	}
	curr_proc_data_map_idx = 0;

	return tuning_done;
}
