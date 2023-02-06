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
 * Help functions for collecting per-process samples
 */
#pragma once
static struct numa_range numa_ranges[MAX_NUMA_NODES];
static int max_num_ranges;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct numa_range);
	__uint(max_entries, MAX_NUMA_NODES);
} numa_address_range SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, struct process_stats);
	__uint(max_entries, 16384);
} process_stats_map SEC(".maps");

#define MAX_PROCESS_STATS_IDX 256
static struct process_stats process_stats_global[MAX_PROCESS_STATS_IDX];
static u64 process_stats_free[MAX_PROCESS_STATS_IDX];

static int memory_node_get(u64 address)
{
	int i;

	for (i = 0; i < MAX_NUMA_NODES; i++) {
		if ((address >= (numa_ranges[i].first_pfn * PAGE_SIZE)) &&
		    (address < (numa_ranges[i].last_pfn * PAGE_SIZE))) {
			return i;
		}
	}

	return -1;
}

static void load_numa_ranges(void)
{
	int key, i;
	struct numa_range *range;

	for (i = 0; i < MAX_NUMA_NODES; i++) {
		key = i;
		range = bpf_map_lookup_elem(&numa_address_range, &key);
		if (!range)
			break;

		numa_ranges[i].first_pfn = range->first_pfn;
		numa_ranges[i].last_pfn  = range->last_pfn;
		numa_ranges[i].node      = range->node;
		numa_ranges[i].tier      = range->tier;

		if (kern_verbose >= 5) {
			char msg[] = "PFN %lx-%lx node_tier %x";
			bpf_trace_printk(msg, sizeof(msg),
					(unsigned long)range->first_pfn,
					(unsigned long)range->last_pfn,
					range->node << 16 | range->tier);

		}
		bpf_map_delete_elem(&numa_address_range, &key);
	}

	max_num_ranges = i;
}

static inline struct process_stats * alloc_process_stats(unsigned int *idx)
{
	unsigned int i;

#if (__clang_major__ >= 14)
	for (i = 0; i < MAX_PROCESS_STATS_IDX; i++) {
		if (ATOMIC64_CMPXCHG(&process_stats_free[i], 0, 1) == 0) {
			*idx = i;
			return &process_stats_global[i];
		}
	}

	return NULL;
#else
	{
		unsigned int j;
		static volatile unsigned int next_value_idx;
		/*
		 * Workaround in the absence of ATOMIC64_CMPXCHG
		 * support by LLVM. Remove this code block entirely
		 * once compare-and-exchange works.
		 */
		i = ATOMIC_READ(&next_value_idx);
		ATOMIC_INC(&next_value_idx);
		j = i % MAX_PROCESS_STATS_IDX;
		*idx = j;

		return &process_stats_global[j];
	}
#endif
}

static inline void release_process_stats(int idx)
{
	int i;

	for (i = 0; i < MAX_PROCESS_STATS_IDX; i++) {
		if (i == idx) {
			ATOMIC64_SET(&process_stats_free[i], 0);
			break;
		}
	}
}

static void update_process_statistics(u64 tgid, u64 address, bool fetch)
{
	struct process_stats *stats, *statsp;
	int idx, mem_node, cpu_node = 0;
	pid_t pid = tgid >> 32;

	stats = NULL;
	idx   = -1;

	cpu_node = cpu_node_get(pid);
	if (cpu_node < 0)
		return;

	mem_node = memory_node_get(address);
	if (mem_node < 0)
		return;

	statsp = bpf_map_lookup_elem(&process_stats_map, &pid);
	if (!statsp) {
		stats = alloc_process_stats(&idx);
		if (!stats)
			return;

		bpf_map_update_elem(&process_stats_map, &pid, stats,
				    BPF_NOEXIST);
		statsp = stats;
	}

	inc_resource_usage(cpu_node, statsp->cpu);
	inc_resource_usage(mem_node, statsp->memory);

	if (idx >= 0)
		release_process_stats(idx);

	if (fetch)
		inc_ibs_fetch_samples();
	else
		inc_ibs_op_samples();
}
