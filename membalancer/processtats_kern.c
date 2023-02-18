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
#include <generic_kern_amd.h>
#include <assert.h>
#include "membalancer.h"
#include "membalancer_pvt.h"

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
	__type(key, u64);
	__type(value, struct process_stats);
	__uint(max_entries, 16384);
} process_stats_map SEC(".maps");

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

static void update_process_statistics(u64 tgid, u64 address, bool fetch)
{
	struct process_stats *statsp;
	int mem_node, cpu_node = 0;
	u64 curr_tgid = tgid;
	//pid_t pid = (pid_t)tgid;

	cpu_node = cpu_node_get();
	if (!VALID_NODE(cpu_node))
		return;

	mem_node = memory_node_get(address);
	if (mem_node < 0)
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

	if (fetch)
		inc_ibs_fetch_samples();
	else
		inc_ibs_op_samples();
}

SEC("perf_event")
int processstats_data_sampler(struct bpf_perf_event_data *ctx)
{
	struct value_op *op_data;
	int err;
	u64 ip, tgid, key;

	op_data = alloc_value_op();
	if (!op_data)
		return -ENOMEM;

	memset(op_data, 0, sizeof(*op_data));
	err = ibs_op_event(ctx, op_data, &tgid, &ip);
	if (err)
		return err;

#ifdef MEMB_USE_VA
	key = op_data->op_regs[IBS_DC_LINADDR];
#else
	key = op_data->op_regs[IBS_DC_PHYSADDR];
#endif

	update_process_statistics(tgid, key, false);

	return 0;

}

SEC("perf_event")
int processstats_code_sampler(struct bpf_perf_event_data *ctx)
{
	struct value_fetch *fetch_data;
	int err;
	u64 ip, tgid, key;

	fetch_data = alloc_value_fetch();
	if (!fetch_data)
		return -ENOMEM;

	memset(fetch_data, 0, sizeof(*fetch_data));
	err = ibs_fetch_event(ctx, fetch_data, &tgid, &ip);
	if (err)
		return err;

#ifdef MEMB_USE_VA
	key = fetch_data->fetch_regs[IBS_FETCH_LINADDR];
#else
	key = fetch_data->fetch_regs[IBS_FETCH_PHYSADDR];
#endif

	update_process_statistics(tgid, key, true);
	return 0;
}
