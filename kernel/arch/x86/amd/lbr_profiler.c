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
