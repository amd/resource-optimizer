/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
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

#include "membalancer.h"
#include "membalancer_migrate.h"

cpu_set_t node_cpumask[MAX_NUMA_NODES];

struct  ibs_noderef_sample numa_reference[MAX_PROCESS_CNT];

static int data_cmp(const void *p1, const void *p2)
{
	const struct ibs_noderef_sample  *s1 = p1, *s2 = p2;

	return s1->max_ref - s2->max_ref;
}

int move_process(u32 max_count)
{
    size_t target_node;
    int i;
    pid_t pid;
    int err = 0;

    qsort(numa_reference, max_count, sizeof(struct ibs_noderef_sample), data_cmp);

    for (i = max_count - 1 ; i >= 0; i--) {
	    pid = numa_reference[i].pid;
	    target_node = numa_reference[i].target_node;
	    err = sched_setaffinity(pid, sizeof(cpu_set_t), &node_cpumask[target_node]);
	    if (err) {
		printf("Pid %d migration failed target node %zd error %d\n", pid, target_node, err);
	    }
	    else  {
		if (verbose > 3)
		    printf("Pid %d migrated to target node %zd \n", pid, target_node);
	    }
    }
    return 0;
}
