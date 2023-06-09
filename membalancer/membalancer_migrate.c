/*
 * membalancer_migrate.c - Process migration functions
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
#include<stdio.h>
#include<stdlib.h>
#include<sched.h>
#include <errno.h>
#include <limits.h>
#include "memory_profiler_common.h"
#include "memory_profiler_arch.h"
#include "thread_pool.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_migrate.h"

#define NUMA_HOP_THRESHOLD 2
#define LOAD_AVG_RETRY_CNT 5

cpu_set_t node_cpumask[MAX_NUMA_NODES];

struct noderef_sample numa_reference[MAX_PROCESS_STATS_IDX];
int per_node_thread_cnt[MAX_NUMA_NODES];

static inline bool node_busy(int node)
{
	int load;
	short iter = LOAD_AVG_RETRY_CNT;

	/* The below iterative retry loop is a polling checkpoint to in-progress
	 * calculation of load average. The computation happens in different
	 * thread context.
	 * The likelihood of incomplete computation of load avg is less here,
	 * but is a plausible scenario. So,it is best effort before we give up!!
	 */
	do {
		load = get_node_loadavg(node);
	} while (load == INT_MAX && iter--);

	if (load < NODE_LOAD_AVG_THRESHOLD)
		return false;

	return true;
}

static inline bool acceptable_distance(int reference_node, int curr_node)
{
	if (reference_node == curr_node)
		return true;

	if ((numa_table[reference_node].distance[curr_node] /
		numa_table[reference_node].distance[reference_node])
		>= NUMA_HOP_THRESHOLD)
		return false;

	return true;
}

static inline int target_cpu_node_get(int curr_target)
{
	int count, *nodes;
	int i = 0;
	int hop = 1;
	int err;

	/* node_busy() check is the checkpoint for computing load avg.
	 * idle_cpu_cnt will be computed as part of load avg calculation.
	 * Need to keep the checks in that order.
	 */
	if (!node_busy(curr_target) && idle_cpu_cnt[curr_target])
		return curr_target;

	err = nodes_at_hop_or_tier(curr_target, hop, &count, &nodes);
	if (err)
		return err;

	for (i = 0; i < count; i++) {
		if (!node_busy(nodes[i]) && idle_cpu_cnt[nodes[i]] &&
			acceptable_distance(curr_target, nodes[i]))
			return nodes[i];
	}

	return -EINVAL;
}

static inline bool get_migrate_token(int target_node, int *target_cpu)
{
	/* This is based on idle cpu available for the node.
	 * The idle cpu capacity is already
	 * throttled by migration_throttle_limit.
	 */
	if (idle_cpu_cnt[target_node]) {
#ifdef CPU_LEVEL_MIG
		*target_cpu = get_next_idle_cpu(target_node);
#endif
		idle_cpu_cnt[target_node]--;
		return true;
	}

	return false;
}

static int data_cmp(const void *p1, const void *p2)
{
	const struct noderef_sample  *s1 = p1, *s2 = p2;

	return s2->max_ref - s1->max_ref;
}

static int data_cmp_distance(const void *p1, const void *p2)
{
	const struct noderef_sample  *s1 = p1, *s2 = p2;

	return s2->curr_to_target_distance - s1->curr_to_target_distance;
}


#ifdef CPU_LEVEL_MIG
static int inline membalancer_sched_setaffinity(pid_t pid,
					int target_node,
					int target_cpu,
					cpu_set_t *set)
{
	int err;

	CPU_SET(target_cpu, set);
	err = sched_setaffinity(pid, sizeof(cpu_set_t), set);
	CPU_CLR(target_cpu, set);

	if (verbose > 3)
		printf("Attempted migration to cpu = %d, status=%d\n",
		       target_cpu, err);

	return err;
}
#else
static int inline membalancer_sched_setaffinity(pid_t pid,
					int target_node,
					int target_cpu,
					cpu_set_t *set)
{
	int err;

	err = sched_setaffinity(pid, sizeof(cpu_set_t),
			&node_cpumask[target_node]);

	if (verbose > 3)
		printf("Attempted migration to cpus of node =%d, status=%d\n",
		       target_node, err);

	return err;
}
#endif

int process_migrate_move_process(u32 max_count, bool autotune)
{
	int target_node;
	int target_cpu;
	cpu_set_t set;
	int i;
	u64 pid;
	int err = 0;
	int batch_err = 0;
	u32 req_mig_count;
	u32 failed_migrate = 0;
	u32 skipped_migrate = 0;

	if (!max_count)
		return 0;

	CPU_ZERO(&set);

	if (verbose >= 3)
		printf("Requested migration = %u\n", max_count);

	req_mig_count = max_count;

	qsort(numa_reference, max_count, sizeof(struct noderef_sample),
		autotune ? data_cmp_distance : data_cmp);

	if (max_count > MAX_NUM_PROC_PER_ITER)
		max_count *= autotune ? AUTOTUNE_MIGRATION_THROTTLE :
			MIGRATION_THROTTLE;

	if(autotune) {
		if (max_count != req_mig_count) {
			/* Not be acting on last (req_mig_count - max_count) processes.
			 * Set the status, to indicate, we skipped them.
			 */
			for (i=max_count; i < req_mig_count; i++)
				numa_reference[i].status = -EAGAIN;
		}
	}

	if (verbose >= 3)
		printf("After throttling:"
			"Requested migration = %u\n", max_count);

	for (i = max_count - 1 ; i >= 0; i--) {
		pid = numa_reference[i].pid;
		target_node = numa_reference[i].target_node;
		numa_reference[i].status = 0;

		/* Check the load average of the node and migrate only if we find a
		 * non busy node, even if next best. Otherwise skip.
		 */
		target_node = target_cpu_node_get(target_node);

		if (target_node == -EINVAL) {
			if (verbose >= 3)
				printf("Skipped:TID %d (PID:%d) migration"
					"due to target node\n",
					(pid_t)pid, (pid_t)(pid >> 32));

			skipped_migrate++;
			numa_reference[i].status = -EAGAIN;
			continue;
		}

		if (target_node == numa_reference[i].curr_node) {
			/* Nothing we can do. The found next best
			 * node is where I am now
			 */
			if (verbose >= 5)
				printf("Skipped:TID %d (PID:%d) migration as"
					" same current and target node:"
					"target=%d and curr=%d\n",
					(pid_t)pid, (pid_t)(pid >> 32),
					target_node, numa_reference[i].curr_node);
			  skipped_migrate++;
			  numa_reference[i].status = -EAGAIN;
			  continue;
		}

		/*
		 * Good that we have found node with some room.
		 * Check if some cpus are really idle.
		 */
		if (!get_migrate_token(target_node, &target_cpu)) {
			skipped_migrate++;
			numa_reference[i].status = -EAGAIN;
			continue;
		}

		err = membalancer_sched_setaffinity((pid_t)pid,
				target_node,
				target_cpu,
				&set);

		if (err && (verbose > 3))
			printf("ERROR:TID %d (PID:%d) migration failed."
			       "target node %d err %d\n", (pid_t)pid, (pid_t)(pid >> 32),
			       target_node, errno);

		/*
		 * We will continue here for other pids, if any.
		 * Capturing the failed status for the batch,
		 * but not individually.
		 * .i.e the last error will be returned for the
		 * entire batch, indicating, not everything was clean.
		 * TODO: Handle errors individually.
		 */
		if (err) {
			/* Let it be the latest. */
			batch_err = err;
			numa_reference[i].status = -EAGAIN;
			failed_migrate++;
			continue;
		}

		if (verbose > 3) {
			printf("TID %d (PID %d) migrated,"
				"to target node %d \n",
				(pid_t)pid, (pid_t)(pid >> 32),
				target_node);
		}
	}

	if (verbose >= 3)
		printf("Total requested migration %u, skipped %u"
			" and failed %u\n",
			max_count, skipped_migrate, failed_migrate);

	return batch_err;;
}
