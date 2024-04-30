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

#ifndef _MEMORY_PROFILER__PVT_H_
#define _MEMORY_PROFILER__PVT_H_
unsigned long my_page_size;
struct value_latency * get_value_latency(void);
struct process_stats * alloc_process_stats(void);
struct data_sample * alloc_data_sample(void);
struct code_sample * alloc_code_sample(void);
static void init_function(void);
int amd_lbr_sampler(struct bpf_perf_event_data *ctx,
		    struct perf_branch_entry **firstentryout,
		    int *entries, u64 *tgidout);
int amd_lbr_sampler_entry(struct perf_branch_entry *src,
			  struct perf_branch_entry *dst);

int memstats_code_sampler_function(
		struct bpf_perf_event_data *ctx,
		bool filter);

int memstats_data_sampler_function(
		struct bpf_perf_event_data *ctx,
		bool filter);

static void init_profiler(void);
static bool profiler_valid_addr(u64 addr);
#endif
