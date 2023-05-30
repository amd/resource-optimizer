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
 * code and data sampleris : Collect code and data samples, process them and
 * saved them into their respective maps
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
#include <assert.h>
#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"
#include "memory_profiler_pvt.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct code_sample);
	__uint(max_entries, MAX_SAMPLES);
} code_sample_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct data_sample);
	__uint(max_entries, MAX_SAMPLES);
} data_sample_map SEC(".maps");

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

static void save_code_latency(u32 lat, struct code_sample *code)
{
	u32 idx;

	if (lat == INVALID_LATENCY)
		return;

	idx = ATOMIC_READ(&code->count);
	if (idx >= MAX_LATENCY_IDX)
		return;

	ATOMIC_SET(&code->latency[idx], lat);
}

static void save_data_latency(u32 lat, struct data_sample *data)
{
	u32 idx;

	if (lat == INVALID_LATENCY)
		return;

	idx = ATOMIC_READ(&data->count);
	if (idx >= MAX_LATENCY_IDX)
		return;

	ATOMIC_SET(&data->latency[idx], lat);
}

static int process_code_samples(struct code_sample *code, u32 page_size)
{
	u64 key;
	struct code_sample *saved;

#ifdef MEMB_USE_VA
	key = code->vaddr;
#else
	key = code->paddr;
#endif
	if (page_size > 0)
		key &= ~(page_size - 1);

	saved = bpf_map_lookup_elem(&code_sample_map, &key);
	if (saved) {

		save_code_latency(code_latency(code->lat), code);

		save_node_usage(saved->counts);
 		ATOMIC_INC(&saved->count);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_code_samples(1);
		else if ((ATOMIC_READ(&saved->count) % defer_cnt) == 0)
			inc_code_samples(defer_cnt);

		return 0;
	}


	save_node_usage(code->counts);

	/* If its is akernel sample or user sample with process id
	* then record it.
	*/
	if ((KERN_SAMPLE(code->ip) || code->tgid)) {
		save_code_latency(code_latency(code->lat), code);
		ATOMIC_SET(&code->count, 1);
		bpf_map_update_elem(&code_sample_map, &key, code,
				   BPF_NOEXIST);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_code_samples(1);
	}

	return 0;
}

static int process_data_samples(struct data_sample *data, u64 page_size)
{
	u64 key;
	struct data_sample *saved;

#ifdef MEMB_USE_VA
	key = data->vaddr;
#else
	key = data->paddr;
#endif
	if (page_size > 0)
		key &= ~(page_size - 1);

	saved = bpf_map_lookup_elem(&data_sample_map, &key);
	if (saved) {
		save_data_latency(data_latency(data->lat), saved);
		save_node_usage(saved->counts);
		ATOMIC_INC(&saved->count);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_data_samples(1);
		else if ((ATOMIC_READ(&saved->count) % defer_cnt) == 0)
			inc_data_samples(defer_cnt);

		return 0;
	}


	save_node_usage(data->counts);

	/* If its is akernel sample or user sample with process id
	* then record it.
	*/
	if (data->paddr != (u64)-1 && (KERN_SAMPLE(data->ip) || data->tgid)) {
		save_data_latency(data_latency(data->lat), data);
		ATOMIC_SET(&data->count, 1);
		bpf_map_update_elem(&data_sample_map, &key, data, BPF_NOEXIST);

		/* Have dense samples before processing */
		if (!defer_cnt)
			inc_data_samples(1);
	}

	return 0;
}

SEC("perf_event")
int memstats_data_sampler(struct bpf_perf_event_data *ctx)
{
	struct data_sample *data;
	u64 tgid;
	int err;

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

	return process_data_samples(data, my_page_size);
}

SEC("perf_event")
int memstats_code_sampler(struct bpf_perf_event_data *ctx)
{
	struct code_sample *sample;
	u64 tgid;
	int err;

	init_function();

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	sample = alloc_code_sample();
	if (!sample)
		return -ENOMEM;

	memset(sample, 0, sizeof(*sample));
	sample->tgid = tgid;

	err = code_sampler(ctx, sample);
	if (err)
		return err;

	return process_code_samples(sample, my_page_size);
}
