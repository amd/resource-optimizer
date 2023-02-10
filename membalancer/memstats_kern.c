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
#include "membalancer.h"
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct value_latency);
	__uint(max_entries, MAX_IBS_SAMPLES);
} latency_map SEC(".maps");

#define INC_COUNTER(counts, node, i) \
	if (node == i)  {    \
		ATOMIC_INC(&counts[i]); \
		return;      \
	}

#define INC_COUNTERS(counts, node, base) \
	INC_COUNTER(counts, node, 0 + (base));\
	INC_COUNTER(counts, node, 1 + (base));\
	INC_COUNTER(counts, node, 2 + (base));\
	INC_COUNTER(counts, node, 3 + (base));\
	INC_COUNTER(counts, node, 4 + (base));\
	INC_COUNTER(counts, node, 5 + (base));\
	INC_COUNTER(counts, node, 6 + (base));\
	INC_COUNTER(counts, node, 7 + (base));

void inc_resource_usage(int node,
			volatile u32 counts[MAX_NUMA_NODES])
{

	_Static_assert(MAX_NUMA_NODES == 16, "MAX_NUMA_NODES != 16");

	if (!VALID_NODE(node))
		return; 

	if (node < MAX_NUMA_NODES / 2) {
		INC_COUNTERS(counts, node, 0);
	} else {
		INC_COUNTERS(counts, node, MAX_NUMA_NODES / 2);
	}
}

static void save_node_usage(pid_t pid,
		            volatile u32 counts[MAX_NUMA_NODES])
{
	int node;

	if (!per_numa_access_stats)
		return;

	node = cpu_node_get(pid);
	if (!VALID_NODE(node))
		return;
	/*
	ATOMIC_INC(&counts[*nodep]);
	*/
	inc_resource_usage(node, counts);

	return;
}

#define VALUE_LATENCY_IDX 64
static struct value_latency value_latency_global[VALUE_LATENCY_IDX];
static u64 value_latency_free[VALUE_LATENCY_IDX];
static inline struct value_latency * get_value_latency(unsigned int *idx)
{
	unsigned int i;

#if (__clang_major__ >= 14)
	for (i = 0; i < VALUE_LATENCY_IDX; i++) {
		if (ATOMIC64_CMPXCHG(&value_latency_free[i], 0, 1) == 0) {
			*idx = i;
			return &value_latency_global[i];
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
		j = i % VALUE_LATENCY_IDX;
		*idx = j;

		return &value_latency_global[j];
	}
#endif
}

static inline void put_value_latency(int idx)
{
	int i;

	for (i = 0; i < VALUE_LATENCY_IDX; i++) {
		if (i == idx) {
			ATOMIC64_SET(&value_latency_free[i], 0);
			break;
		}
	}
}

static inline void save_latency(u32 lat, u64 key, bool op, int idx)
{
	unsigned int i;
	struct value_latency *valuep;

	valuep = bpf_map_lookup_elem(&latency_map, &key);
	if (valuep) {
		idx = ATOMIC_READ(&valuep->idx);
		if (idx >= MAX_LATENCY_IDX)
			return;

		for (i = 0; i < MAX_LATENCY_IDX; i++) {
			if (i == idx) {
				ATOMIC_SET(&valuep->latency[i], lat);
				break;
			}
		}
		ATOMIC_INC(&valuep->idx);
	} else {
		valuep = get_value_latency(&i);
		if (!valuep) {
			char msg[] = "Cannot find value for key %p";

			bpf_trace_printk(msg, sizeof(msg), key);
			return;
		}

		ATOMIC_SET(&valuep->idx, 0);
		bpf_map_update_elem(&latency_map, &key, valuep, BPF_NOEXIST);
		put_value_latency(i);
	}
}

static void save_fetch_latency(u64 reg, u64 addr, int idx)
{
	u32 latency;

	if (!latency_stats && !latency_stats_l3miss)
		return;

	if (latency_stats_l3miss && !IBS_FETCH_LLC_MISS(reg))
		return;

	latency = reg >> 32;
	latency &= (latency << 16) >> 16;
	save_latency(latency, addr, false, idx);
}

static void save_op_latency(u64 reg, u64 addr, int idx)
{
	u32 latency;

	if (!latency_stats && !latency_stats_l3miss)
		return;

	if (latency_stats_l3miss && !IBS_OP_LLC_MISS(reg))
		return;

	latency = reg >> 32;
	latency &= (latency << 16) >> 16;

	save_latency(latency, addr, true, idx);
}

static int process_fetch_samples(u64 tgid, struct value_fetch *fetch_data,
				u64 ip, u32 page_size)
{
	u64 key;
	struct value_fetch *valuep;
	int i;

#ifdef MEMB_USE_VA
	key = fetch_data->fetch_regs[IBS_FETCH_LINADDR];
#else
	key = fetch_data->fetch_regs[IBS_FETCH_PHYSADDR];
#endif
	if (page_size > 0)
		key &= ~(page_size - 1);

	valuep = bpf_map_lookup_elem(&ibs_fetch_map, &key);
	if (valuep) {

		save_fetch_latency(fetch_data->fetch_regs[IBS_FETCH_CTL], key,
				  ATOMIC_READ(&valuep->count));
 		ATOMIC_INC(&valuep->count);

		save_node_usage(tgid >> 32,  valuep->counts);

		inc_ibs_fetch_samples();

		return 0;
	}

	save_fetch_latency(fetch_data->fetch_regs[IBS_FETCH_CTL], key, 0);

	ATOMIC_SET(&fetch_data->count, 1);
	fetch_data->tgid = tgid;
	fetch_data->filler = 0;

	for (i = 0; i < MAX_NUMA_NODES; i++)
		fetch_data->counts[i] = 0;

	save_node_usage(tgid >> 32, fetch_data->counts);

	/* If its is akernel sample or user sample with process id
	* then record it.
	*/
	if ((IBS_KERN_SAMPLE(ip) || fetch_data->tgid)) {
		bpf_map_update_elem(&ibs_fetch_map, &key, fetch_data,
				   BPF_NOEXIST);
		inc_ibs_fetch_samples();
	}

	return 0;
}

static int process_op_samples(u64 tgid, struct value_op *op_data,
			      u64 ip, u64 page_size)
{
	u64 key;
	struct value_fetch *valuep;
	int i;

#ifdef MEMB_USE_VA
	key = op_data->op_regs[IBS_DC_LINADDR];
#else
	key = op_data->op_regs[IBS_DC_PHYSADDR];
#endif
	if (page_size > 0)
		key &= ~(page_size - 1);

	valuep = bpf_map_lookup_elem(&ibs_op_map, &key);
	if (valuep) {
		save_op_latency(op_data->op_regs[IBS_OP_DATA3], key,
				ATOMIC_READ(&valuep->count));
		ATOMIC_INC(&valuep->count);
		save_node_usage(tgid >> 32, valuep->counts);
		inc_ibs_op_samples();

		return 0;
	}

	save_op_latency(op_data->op_regs[IBS_OP_DATA3], key, 0);

	ATOMIC_SET(&op_data->count, 1);
	op_data->tgid = tgid;
	op_data->ip = ip;
	op_data->filler = 0;

	for (i = 0; i < MAX_NUMA_NODES; i++)
		op_data->counts[i] = 0;

	save_node_usage(tgid >> 32, op_data->counts);

	/* If its is akernel sample or user sample with process id
	* then record it.
	*/
	if (op_data->op_regs[IBS_DC_PHYSADDR] != (u64)-1 &&
            (IBS_KERN_SAMPLE(ip) || op_data->tgid)) {
		bpf_map_update_elem(&ibs_op_map, &key, op_data, BPF_NOEXIST);
		inc_ibs_op_samples();
	}

	return 0;
}

SEC("perf_event")
int memstats_data_sampler(struct bpf_perf_event_data *ctx)
{
	struct value_op op_data;
	int err;
	u64 ip, tgid;

        err = ibs_op_event(ctx, &op_data, &tgid, &ip);
        if (err)
		return err;

	/*
	if (user_space_only && IBS_KERN_SAMPLE(ip))
		return 0;

	if (!IBS_OP_LINADDR_VALID(op_data.op_regs[IBS_OP_DATA3]))
		return 0;

	if (!IBS_OP_PHYSADDR_VALID(op_data.op_regs[IBS_OP_DATA3]))
		return 0;
	*/

	return process_op_samples(tgid, &op_data, ip, my_page_size);
}

SEC("perf_event")
int memstats_code_sampler(struct bpf_perf_event_data *ctx)
{
	struct value_fetch fetch_data;
	int err;
	u64 ip, tgid;

        err = ibs_fetch_event(ctx, &fetch_data, &tgid, &ip);
        if (err)
		return err;

	return process_fetch_samples(tgid, &fetch_data, ip, my_page_size);
}
