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
 * LBR sampler : Using natie processor telemetry
 */

#include <memory_profiler_arch.h>

int other_arch_lbr_sample(struct bpf_perf_event_data *ctx,
			  struct perf_branch_entry **firstentryout,
			  int *entries)
{
	return -EINVAL;
}

int other_arch_sample_entry(struct perf_branch_entry *src,
			    struct perf_branch_entry *dst)
{
	return -EINVAL;
}

int lbr_sample(struct bpf_perf_event_data *ctx,
	       struct perf_branch_entry **firstentryout,
	       int *entries)
{
	return other_arch_lbr_sample(ctx, firstentryout, entries);
}

int lbr_entry(struct perf_branch_entry *src,
	      struct perf_branch_entry *dst)
{
	return other_arch_sample_entry(src, dst);
}
