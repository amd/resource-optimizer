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
 * LBR sampler : Using AMD LBR telemetry
 */

#include <memory_profiler_arch.h>

extern int LINUX_KERNEL_VERSION __kconfig;

static int amd_lbr_sample(struct bpf_perf_event_data *ctx,
		struct perf_branch_entry **firstentryout,
		int *entries)
{
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data data;
	char *datap = NULL;
	struct perf_branch_stack br;
	u64 tgid;

	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 1, 22))
		return -EINVAL;

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;

	if (bpf_core_read(&datap, sizeof(datap), &(kern_ctx->data)))
		return -EFAULT;

	if (bpf_core_read(&data, sizeof(data), datap))
		return -EFAULT;

	if ((data.sample_flags & PERF_SAMPLE_BRANCH_STACK) == 0)
		return -EINVAL;

	if (bpf_core_read(&br, sizeof(br), data.br_stack))
		return -EFAULT;

	if (entries)
		*entries = br.nr;

	if (firstentryout)
		*firstentryout = (void *)(data.br_stack + sizeof(br));

	return 0;
}

static int amd_lbr_sample_entry(struct perf_branch_entry *src,
				struct perf_branch_entry *dst)
{
	if (bpf_core_read(dst, sizeof(*dst), src))
		return -EFAULT;

	return 0;
}

int lbr_sample(struct bpf_perf_event_data *ctx,
	       struct perf_branch_entry **firstentryout, int *entries)
{
	return amd_lbr_sample(ctx, firstentryout, entries);
}

int lbr_entry(struct perf_branch_entry *src,
			  struct perf_branch_entry *dst)
{
	return amd_lbr_sample_entry(src, dst);
}
