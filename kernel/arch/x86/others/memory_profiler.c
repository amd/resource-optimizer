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
 * Memory sampling : Using native CPU sampling of data and code.
 */

#include <memory_profiler_arch.h>

static u32 other_arch_code_latency(u64 reg)
{
	return INVALID_LATENCY;
}

static int other_arch_code_sampler(struct bpf_perf_event_data *ctx,
				   struct code_sample *code)
{
	return -EINVAL;
}

static u32 other_arch_data_latency(u64 reg)
{
	return INVALID_LATENCY;
}

static int other_arch_data_sampler(struct bpf_perf_event_data *ctx,
				   struct data_sample *sample)
{
	return -EINVAL;
}

u32 code_latency(u64 reg)
{
	return other_arch_code_latency(reg);
}

int code_sampler(struct bpf_perf_event_data *ctx, struct code_sample *sample)
{
	return other_arch_code_sampler(ctx, sample);
}

u32 data_latency(u64 reg)
{
	return other_arch_data_latency(reg);
}

int data_sampler(struct bpf_perf_event_data *ctx, struct data_sample *sample)
{
	return other_arch_data_sampler(ctx, sample);
}
