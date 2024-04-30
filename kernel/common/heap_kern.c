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
 */
#pragma once
#include <assert.h>
#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"
#include "memory_profiler_pvt.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct process_stats);
	__uint(max_entries, MAX_CPU_CORES);
}  per_cpu_process_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct code_sample);
	__uint(max_entries, MAX_CPU_CORES);
}  per_cpu_code_sample SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct data_sample);
	__uint(max_entries, MAX_CPU_CORES);
}  per_cpu_data_sample SEC(".maps");

struct process_stats;
struct code_sample;
struct data_sample;

struct process_stats * alloc_process_stats(void)
{
	int key;

	key = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&per_cpu_process_stats, &key);
}

struct data_sample * alloc_data_sample(void)
{
	int key;

	key = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&per_cpu_data_sample, &key);
}

struct code_sample * alloc_code_sample(void)
{
	int key;

	key = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&per_cpu_code_sample, &key);
}
