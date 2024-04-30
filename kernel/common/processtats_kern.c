/*
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
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

#pragma once
#include "vmlinux.h"
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
