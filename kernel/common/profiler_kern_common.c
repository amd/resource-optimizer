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

#pragma once
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
