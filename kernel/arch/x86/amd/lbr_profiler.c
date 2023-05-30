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
 * LBR sampler : Using AMD LBR telemetry
 */
#include <linux/version.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <linux/perf_event.h>
#include <bpf/bpf_helpers.h>
#include <memory_profiler_arch.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 22))
static int amd_lbr_sample(struct bpf_perf_event_data *ctx,
			  struct perf_branch_entry **firstentryout,
			  int *entries)
{
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data data;
	char *datap = NULL;
	struct perf_branch_stack br;
	u64 tgid;

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;
	if (bpf_probe_read(&datap, sizeof(datap), &(kern_ctx->data)))
		return -EFAULT;

	if (bpf_probe_read(&data, sizeof(data), datap))
		return -EFAULT;

	if ((data.sample_flags & PERF_SAMPLE_BRANCH_STACK) == 0)
		return -EINVAL;

	if (bpf_probe_read(&br, sizeof(br), data.br_stack))
		return -EFAULT;

	if (entries)
		*entries = br.nr;

	if (firstentryout)
		*firstentryout = (void *)(data.br_stack + sizeof(br));

	return 0;
}
#else
static int amd_lbr_sample(struct bpf_perf_event_data *ctx,
			  struct perf_branch_entry **firstentryout,
			  int *entries)
{
	return -EINVAL;
}
#endif

static int amd_lbr_sample_entry(struct perf_branch_entry *src,
				struct perf_branch_entry *dst)
{
	if (bpf_probe_read(dst, sizeof(*dst), src))
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
