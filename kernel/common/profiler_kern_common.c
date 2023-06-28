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
 * LBR sampling : Architectural independent functions for branch records
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
#include "profiler_common.h"
#include "lbr_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct profiler_filter);
	__uint(max_entries, MAX_PROFILER_FILTERS);
} profiler_filter_map SEC(".maps");

static volatile int max_filters;

static void init_profiler(void)
{
	static volatile unsigned long once;
	int key, i;

	if (JUST_ONCE(&once, 0, 1) != 0)
		return;

	for (i = 0; i < MAX_PROFILER_FILTERS; i++) {
		key = i;
		if (!bpf_map_lookup_elem(&profiler_filter_map, &key))
			break;
	}

	ATOMIC_SET(&max_filters, i);
}

static bool profiler_valid_addr(u64 addr)
{
	int left, right, key, mid, i, max;
	struct profiler_filter *filter;

	/* If no filters, every address is valid */
	max = ATOMIC_READ(&max_filters);
	if (max < 1)
		return true;

	left  = 0;
	right = max - 1;

	for (i = 0; i < MAX_PROFILER_FILTERS; i++) {
		if (left > right)
			break;

		mid = (left + right) >> 1;
		if (mid < 0 || mid >= max)
			break;

		key = mid;
		filter = bpf_map_lookup_elem(&profiler_filter_map, &key);
		if (!filter)
			break;

		if ((addr >= filter->addr_begin) &&
		    (addr < filter->addr_end))
		    return true;

		if (addr < filter->addr_begin)
			right = mid - 1;

		else if (addr > filter->addr_begin)
			left = mid + 1;
	}

	return false;
}
