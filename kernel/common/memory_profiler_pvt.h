/*
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Process samples from IBS or software sampler and analyze the instruction and
 * data (if available) samples.
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
