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

#include <string.h>
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

	/* To comply with bpf validator */
	if (unlikely(code == NULL))
		return -EINVAL;

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

int memstats_data_sampler_function(struct bpf_perf_event_data *ctx,
				   bool filter)
{
	struct data_sample *data;
	u64 tgid;
	int err;

	init_function();
	if (filter)
		init_profiler();

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

	/* Ignore samples outside if filter is set */
	if (filter && !profiler_valid_addr(data->ip))
		return 0;

	return process_data_samples(data, my_page_size);
}

SEC("perf_event")
int memstats_data_sampler(struct bpf_perf_event_data *ctx)
{
	return memstats_data_sampler_function(ctx, false);
}

int memstats_code_sampler_function(struct bpf_perf_event_data *ctx,
				   bool filter)
{
	struct code_sample *sample;
	u64 tgid;
	int err;

	init_function();
	if (filter)
		init_profiler();

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

	/* Ignore samples outside if filter is set */
	if (filter && !profiler_valid_addr(sample->ip))
		return 0;

	return process_code_samples(sample, my_page_size);
}

SEC("perf_event")
int memstats_code_sampler(struct bpf_perf_event_data *ctx)
{
	return memstats_code_sampler_function(ctx, false);
}
