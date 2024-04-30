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
#include "vmlinux.h"
#include <assert.h>
#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"
#include "memory_profiler_pvt.h"
#include "profiler_common.h"
#include "lbr_common.h"

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct lbr_pbe_key);
        __type(value, struct lbr_pbe_val);
        __uint(max_entries, MAX_LBR_SAMPLES);
} lbr_pbe SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, u32);
        __type(value, struct lbr_pbe_flags);
        __uint(max_entries, MAX_LBR_SAMPLES);
} lbr_pbe_flags SEC(".maps");

static volatile u32 next_unique;

static void save_pbe_sample_flags(u32 unique, u64 flags)
{
	struct lbr_pbe_flags value, *valuep;
	struct lbr_pbe_flags_key key;

	key.unique = unique;
	key.filler = 0;
	key.flags  = flags;

	valuep = bpf_map_lookup_elem(&lbr_pbe_flags, &key);
	if (valuep) {
		ATOMIC_INC(&valuep->ref);
		return;
	}

	ATOMIC_SET(&value.ref, 1);

	bpf_map_update_elem(&lbr_pbe_flags, &key, &value, BPF_NOEXIST);
}

static void save_pbe_sample(struct perf_branch_entry *entry, u64 tgid)
{
	struct lbr_pbe_key key;
	struct lbr_pbe_val value, *valuep;
	u32 unique;
	u64 *flagsp;

	entry->reserved = 0;

	flagsp = (u64 *)&entry->to;
	flagsp++;

	key.tgid = tgid;
	key.from = entry->from;
	key.to   = entry->to;

	valuep = bpf_map_lookup_elem(&lbr_pbe, &key);

	if (valuep) {
		ATOMIC_INC(&valuep->ref);
		unique = valuep->unique;
	} else {
		unique = ATOMIC_INC_RETURN(&next_unique);
		value.unique = unique;
		ATOMIC_SET(&value.ref, 1);
		bpf_map_update_elem(&lbr_pbe, &key, &value, BPF_NOEXIST);
	}

	save_pbe_sample_flags(unique, *flagsp);
}

SEC("perf_event")
int lbr_sampler(struct bpf_perf_event_data *ctx)
{
	int i, err, entries = 0;
	struct perf_branch_entry *src = NULL, dst;
	u64 tgid;


	/* Global initialization */
	init_function();

	/* Local initialization */
	init_profiler();

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	err = lbr_sample(ctx, &src, &entries);
	if (err)
		return err;

	for (i = 0; i < MAX_LBR_ENTRIES; i++) {
		if (i < entries) {
			err = lbr_entry(src, &dst);
			if (err)
				break;
		} else {
			dst.from = dst.to = 0;
		}

		if (!dst.from && !dst.to)
			break;

		if (profiler_valid_addr(dst.from) ||
		    profiler_valid_addr(dst.to))
			save_pbe_sample(&dst, tgid);

		src++;
	}

	return err;
}
