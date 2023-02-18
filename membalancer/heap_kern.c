/*
 * Copyright (c) 2023 Advanced Micro Devices, Inc.
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
	__type(key, int);
	__type(value, struct value_latency);
	__uint(max_entries, MAX_CPU_CORES);
}  per_cpu_value_latency SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct process_stats);
	__uint(max_entries, MAX_CPU_CORES);
}  per_cpu_process_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct value_fetch);
	__uint(max_entries, MAX_CPU_CORES);
}  per_cpu_value_fetch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct value_op);
	__uint(max_entries, MAX_CPU_CORES);
}  per_cpu_value_op SEC(".maps");

struct value_latency;
struct process_stats;
struct value_fetch;
struct value_op;

struct value_latency * get_value_latency(void)
{
	int key;

	key = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&per_cpu_value_latency, &key);
}

struct process_stats * alloc_process_stats(void)
{
	int key;

	key = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&per_cpu_process_stats, &key);
}

struct value_op * alloc_value_op(void)
{
	int key;

	key = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&per_cpu_value_op, &key);
}

struct value_fetch * alloc_value_fetch(void)
{
	int key;

	key = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&per_cpu_value_fetch, &key);
}

