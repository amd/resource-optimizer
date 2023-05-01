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
 * IBS sampler : Arm IBS fetch and op sampling, collect both kernel and
 * process samples.
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
#include "membalancer_common.h"
#include "membalancer_pvt.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct value_fetch);
	__uint(max_entries, MAX_IBS_SAMPLES);
} ibs_fetch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct value_op);
	__uint(max_entries, MAX_IBS_SAMPLES);
} ibs_op_map SEC(".maps");

static void inc_resource_usage(const int node,
			       volatile u32 counts[MAX_NUMA_NODES])
{
	if (!VALID_NODE(node))
		return;

	/*
	 * TODO: Handle atomicity issue.
	 * ATOMIC_INC which is the right primitive here which eBPF verifier
	 * does not accept. Workaround for now until its replacement comes.
	 */
	ATOMIC_SET(&counts[node], ATOMIC_READ(&counts[node]) + 1);
}

static void save_node_usage(volatile u32 counts[MAX_NUMA_NODES])
{
	int node;

	if (!per_numa_access_stats)
		return;

	node = cpu_node_get();
	if (!VALID_NODE(node))
		return;
	/*
	 * Cannot access dynamic array index. To avoid eBPF
	 * verifuer failure, a long indirect route needs to
	 * be taken.
	 */

	/*
	ATOMIC_INC(&counts[node]);
	*/
	inc_resource_usage(node, counts);

	return;
}

static void save_fetch_latency(u64 reg, struct value_fetch *valuep)
{
	u32 latency, idx;

	if (!latency_stats && !latency_stats_l3miss)
		return;

	if (latency_stats_l3miss && !IBS_FETCH_LLC_MISS(reg))
		return;

	idx = ATOMIC_READ(&valuep->count);
	if (idx >= MAX_LATENCY_IDX)
		return;

	latency = reg >> 32;
	latency &= (latency << 16) >> 16;

	ATOMIC_SET(&valuep->latency[idx], latency);
}

static void save_op_latency(u64 reg, struct value_op *valuep)
{
	u32 latency, idx;

	if (!latency_stats && !latency_stats_l3miss)
		return;

	if (latency_stats_l3miss && !IBS_OP_LLC_MISS(reg))
		return;

	idx = ATOMIC_READ(&valuep->count);
	if (idx >= MAX_LATENCY_IDX)
		return;

	latency = reg >> 32;
	latency &= (latency << 16) >> 16;

	ATOMIC_SET(&valuep->latency[idx], latency);
}

static int process_fetch_samples(u64 tgid, struct value_fetch *fetch_data,
				u64 ip, u32 page_size)
{
	u64 key;
	struct value_fetch *valuep;

#ifdef MEMB_USE_VA
	key = fetch_data->fetch_regs[IBS_FETCH_LINADDR];
#else
	key = fetch_data->fetch_regs[IBS_FETCH_PHYSADDR];
#endif
	if (page_size > 0)
		key &= ~(page_size - 1);

	valuep = bpf_map_lookup_elem(&ibs_fetch_map, &key);
	if (valuep) {

		save_fetch_latency(fetch_data->fetch_regs[IBS_FETCH_CTL],
				   valuep);

		save_node_usage(valuep->counts);
 		ATOMIC_INC(&valuep->count);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_ibs_fetch_samples(1);
		else if ((ATOMIC_READ(&valuep->count) % defer_cnt) == 0)
			inc_ibs_fetch_samples(defer_cnt);

		return 0;
	}


	fetch_data->tgid = tgid;
	fetch_data->ip   = ip;
	fetch_data->filler = 0;

	save_node_usage(fetch_data->counts);

	/* If its is akernel sample or user sample with process id
	* then record it.
	*/
	if ((IBS_KERN_SAMPLE(ip) || fetch_data->tgid)) {
		save_fetch_latency(fetch_data->fetch_regs[IBS_FETCH_CTL],
				    fetch_data);
		ATOMIC_SET(&fetch_data->count, 1);
		bpf_map_update_elem(&ibs_fetch_map, &key, fetch_data,
				   BPF_NOEXIST);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_ibs_fetch_samples(1);
	}

	return 0;
}

static int process_op_samples(u64 tgid, struct value_op *op_data,
			      u64 ip, u64 page_size)
{
	u64 key;
	struct value_op *valuep;

#ifdef MEMB_USE_VA
	key = op_data->op_regs[IBS_DC_LINADDR];
#else
	key = op_data->op_regs[IBS_DC_PHYSADDR];
#endif
	if (page_size > 0)
		key &= ~(page_size - 1);

	valuep = bpf_map_lookup_elem(&ibs_op_map, &key);
	if (valuep) {
		save_op_latency(op_data->op_regs[IBS_OP_DATA3], valuep);
		save_node_usage(valuep->counts);
		ATOMIC_INC(&valuep->count);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_ibs_op_samples(1);
		else if ((ATOMIC_READ(&valuep->count) % defer_cnt) == 0)
			inc_ibs_op_samples(defer_cnt);

		return 0;
	}


	op_data->tgid = tgid;
	op_data->ip = ip;
	op_data->filler = 0;

	save_node_usage(op_data->counts);

	/* If its is akernel sample or user sample with process id
	* then record it.
	*/
	if (op_data->op_regs[IBS_DC_PHYSADDR] != (u64)-1 &&
            (IBS_KERN_SAMPLE(ip) || op_data->tgid)) {
		save_op_latency(op_data->op_regs[IBS_OP_DATA3], op_data);
		ATOMIC_SET(&op_data->count, 1);
		bpf_map_update_elem(&ibs_op_map, &key, op_data, BPF_NOEXIST);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_ibs_op_samples(1);
	}

	return 0;
}

SEC("perf_event")
int memstats_data_sampler(struct bpf_perf_event_data *ctx)
{
	struct value_op *op_data;
	int err;
	u64 ip, tgid;

	init_function();

	op_data = alloc_value_op();
	if (!op_data)
		return -ENOMEM;

	memset(op_data, 0, sizeof(*op_data));
	err = ibs_op_event(ctx, op_data, &tgid, &ip);
	if (err)
		return err;

	return process_op_samples(tgid, op_data, ip, my_page_size);
}

SEC("perf_event")
int memstats_code_sampler(struct bpf_perf_event_data *ctx)
{
	struct value_fetch *fetch_data;
	int err;
	u64 ip, tgid;

	init_function();

	fetch_data = alloc_value_fetch();
	if (!fetch_data)
		return -ENOMEM;

	memset(fetch_data, 0, sizeof(*fetch_data));
	err = ibs_fetch_event(ctx, fetch_data, &tgid, &ip);
	if (err)
		return err;

	return process_fetch_samples(tgid, fetch_data, ip, my_page_size);
}
