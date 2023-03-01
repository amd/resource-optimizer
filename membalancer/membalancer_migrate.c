/*
 * Copyright (c) 2023 Advanced Micro Devices, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#define _GNU_SOURCE
#include<stdio.h>
#include<stdlib.h>
#include<sched.h>
#include <errno.h>

#include "membalancer_common.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_migrate.h"

cpu_set_t node_cpumask[MAX_NUMA_NODES];

struct  ibs_noderef_sample numa_reference[MAX_PROCESS_STATS_IDX];

static inline bool node_busy(int node)
{
	if (get_node_loadavg(node) < node_load_avg_threshold)
		return false;
	return true;
}

static inline int target_cpu_node_get(int curr_target)
{
	int count, *nodes;
	int i = 0;
	int hop = 1;
	int err;

	if (!node_busy(curr_target))
		return curr_target;

	err = nodes_at_hop_or_tier(curr_target, hop, &count, &nodes);
	if (err)
		return err;

	for (i = 0; i < count; i++) {
		if (!node_busy(nodes[i]))
			return nodes[i];
	}
	return -EINVAL;
}

static inline bool get_migrate_token(int target_node)
{
	/* This is based on idle cpu available for the node.
	 * The idle cpu capacity is already
	 * throttled by migration_throttle_limit.
	 */
	if (idle_cpu_cnt[target_node]) {
		idle_cpu_cnt[target_node]--;
		return true;
	}
	return false;
}

static int data_cmp(const void *p1, const void *p2)
{
	const struct ibs_noderef_sample  *s1 = p1, *s2 = p2;

	return s1->max_ref - s2->max_ref;
}

int move_process(u32 max_count, bool sort)
{
	int target_node;
	int i;
	u64 pid;
	int err = 0;
	int batch_err = 0;
	u32 failed_migrate = 0;
	u32 skipped_migrate = 0;
	bool busy_node_map[MAX_NUMA_NODES] = { 0 };

	if (!max_count)
		return 0;

	if (sort)
		qsort(numa_reference, max_count,
				sizeof(struct ibs_noderef_sample), data_cmp);

	for (i = max_count - 1 ; i >= 0; i--) {
	    pid = numa_reference[i].pid;
	    target_node = numa_reference[i].target_node;
		/*
		 * Check the load average of the node and
		 * migrate only if we find a non busy node,
		 * even if next best.
		 * Otherwise skip.
		 */
		target_node = target_cpu_node_get(target_node);
		if (target_node == -EINVAL) {
			skipped_migrate++;
			continue;
		}
		/*
		 * Good that we have found node with some room.
		 * Check if some cpus are really idle.
		 */
		if (!get_migrate_token(target_node)) {
			skipped_migrate++;
			continue;
		}

	    err = sched_setaffinity((pid_t)pid, sizeof(cpu_set_t),
						&node_cpumask[target_node]);

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
