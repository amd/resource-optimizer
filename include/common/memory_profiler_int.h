/*
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
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
 * Process samples from IBS or software sampler and analyze the instruction and
 * data (if available) samples.
 */

#ifndef _MEMORY_PROFILER_INT_H_
#define _MEMORY_PROFILER_INT_H_
#ifdef __KERNEL__
int code_sampler(struct bpf_perf_event_data *ctx, struct code_sample *sample);
int data_sampler(struct bpf_perf_event_data *ctx, struct data_sample *sample);
u32 code_latency(u64 register);
u32 data_latency(u64 register);
#endif
#endif
