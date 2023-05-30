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
#include "lbr_common.h"

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key,   struct lbr_pbe_key);
        __type(value, struct lbr_pbe_val);
        __uint(max_entries, MAX_LBR_SAMPLES);
} lbr_pbe SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key,   u32);
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

	init_function();

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

		save_pbe_sample(&dst, tgid);
		src++;
	}

	return err;
}
