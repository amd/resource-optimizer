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

SEC("perf_event")
int profiler_data_sampler(struct bpf_perf_event_data *ctx)
{
	return memstats_data_sampler_function(ctx, true);
}

SEC("perf_event")
int profiler_code_sampler(struct bpf_perf_event_data *ctx)
{
	return memstats_code_sampler_function(ctx, true);
}
