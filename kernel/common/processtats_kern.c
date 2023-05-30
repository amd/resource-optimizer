/*
 * Copyright (c) 2023 Advanced Micro Devices, Inc. All Rights Reserved.
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
#include <linux/version.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <linux/perf_event.h>
#include <bpf/bpf_helpers.h>
#include <assert.h>
#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"
#include "memory_profiler_pvt.h"

static int max_num_ranges;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct numa_range);
	__uint(max_entries, MAX_NUMA_NODES);
} numa_address_range SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct process_stats);
	__uint(max_entries, 16384);
} process_stats_map SEC(".maps");

static int memory_node_get(u64 address)
{
	int left, right, key, mid, i;
	struct numa_range *range;
	u64 pfn = address >> PAGE_SHIFT;

	left = 0;
	right = max_num_ranges - 1;

	/*
	 * Fixed for loop is to avoid validation failure by eBPF verifier which
	 * likes only finite loops.
	 */
	for (i = 0; i < MAX_NUMA_NODES; i++) {
		if (left > right)
			break;

		/*
		 * To circumvent LLVM error "Unsupportied signed division.",
		 * a right shift is performed instead of dividing by 2.
		 */
		mid = (left + right) >> 1;
		if (mid < 0 || mid >= max_num_ranges)
			break;

		key = mid;
		range = bpf_map_lookup_elem(&numa_address_range, &key);
		if (!range)
			break;

		if ((pfn >= range->first_pfn) &&
			(pfn < range->last_pfn))
			return range->node;

		if (pfn < range->first_pfn)
			right = mid - 1;

		if (pfn > range->first_pfn)
			left = mid + 1;
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

	}

	max_num_ranges = i;
}

static void update_process_statistics(u64 tgid, u64 address, bool code)
{
	struct process_stats *statsp;
	int mem_node, cpu_node = 0;
	u64 curr_tgid = tgid;

	cpu_node = cpu_node_get();
	if (!VALID_NODE(cpu_node))
		return;

	mem_node = memory_node_get(address);
	if (VALID_NODE(mem_node) == 0)
		return;

	statsp = bpf_map_lookup_elem(&process_stats_map, &curr_tgid);
	if (!statsp) {
		statsp = alloc_process_stats();
		if (!statsp)
			return;

		bpf_map_update_elem(&process_stats_map, &curr_tgid, statsp,
					BPF_NOEXIST);
	}

	inc_resource_usage(cpu_node, statsp->cpu);
	inc_resource_usage(mem_node, statsp->memory);

	if (code)
		inc_code_samples(1);
	else
		inc_data_samples(1);
}

SEC("perf_event")
int processstats_data_sampler(struct bpf_perf_event_data *ctx)
{
	struct data_sample *data;
	int err;
	u64 tgid, key;

	init_function();

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	data = alloc_data_sample();
	if (!data)
		return -ENOMEM;

	memset(data, 0, sizeof(*data));
	data->tgid = tgid;

	err = data_sampler(ctx, data);
	if (err)
		return err;

#ifdef MEMB_USE_VA
	key = data->vaddr;
#else
	key = data->paddr;
#endif

	update_process_statistics(tgid, key, false);

	return 0;

}

SEC("perf_event")
int processstats_code_sampler(struct bpf_perf_event_data *ctx)
{
	struct code_sample *code;
	int err;
	u64 tgid, key;

	init_function();

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	code = alloc_code_sample();
	if (!code)
		return -ENOMEM;

	memset(code, 0, sizeof(*code));
	code->tgid = tgid;

	err = code_sampler(ctx, code);
	if (err)
		return err;

#ifdef MEMB_USE_VA
	key = code->vaddr;
#else
	key = code->paddr;
#endif

	update_process_statistics(tgid, key, true);
	return 0;
}
