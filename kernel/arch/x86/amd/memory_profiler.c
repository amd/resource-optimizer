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
 *
 * IBS sampler : Arm IBS fetch and op sampling, collect both kernel and
 * process samples.
 */

#include <errno.h>
#include "memory_profiler_arch.h"

static u32 ibs_fetch_latency(u64 reg)
{
	u32 latency;

        if (!latency_stats && !latency_stats_l3miss)
                return INVALID_LATENCY;

        if (latency_stats_l3miss && !IBS_FETCH_LLC_MISS(reg))
                return INVALID_LATENCY;

	latency = reg >> 32;
	latency = (latency << 16) >> 16;

	return latency;
}

static int ibs_fetch_event(struct bpf_perf_event_data *ctx,
			   struct code_sample *code)
{
	u64 ip;
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data *data = NULL;
	struct perf_raw_record *raw = NULL;
	struct perf_ibs_fetch_data *ibs_data;
	struct perf_raw_frag frag;
	void *addr;
	u64 fetch_regs[IBSFETCH_REG_COUNT];

	/* To comply with bpf validator */
	if (unlikely(code == NULL))
		return -EINVAL;

	ip = PT_REGS_IP(&ctx->regs);
	if (user_space_only && IBS_KERN_SAMPLE(ip))
		return -EINVAL;

	/* Collect samples from IBS Fetch registers */
	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;

	if (bpf_core_read(&data, sizeof(data), &(kern_ctx->data)))
		return -EFAULT;

	if (bpf_core_read(&raw, sizeof(raw), &(data->raw)))
		return -EFAULT;

	if (bpf_core_read(&frag, sizeof(frag), &(raw->frag)))
		return -EFAULT;

	ibs_data = (struct perf_ibs_fetch_data *)frag.data;
	addr     = &ibs_data->data[0];

	/* To comply with bpf validator */
	if (unlikely(addr == NULL))
		return -EINVAL;

	if (bpf_core_read(fetch_regs, sizeof(fetch_regs), addr))
		return -EFAULT;

	if (!IBS_FETCH_PHYSADDR_VALID(fetch_regs[IBS_FETCH_CTL]))
		return -EINVAL;

	code->vaddr = fetch_regs[IBS_FETCH_LINADDR];
	code->paddr = fetch_regs[IBS_FETCH_PHYSADDR];
    	code->ip    = ip;
	code->lat   = fetch_regs[IBS_FETCH_CTL];

	return 0;
}

static u32 ibs_op_latency(u64 reg)
{
	u32 latency;

        if (!latency_stats && !latency_stats_l3miss)
                return INVALID_LATENCY;

        if (latency_stats_l3miss && !IBS_FETCH_LLC_MISS(reg))
                return INVALID_LATENCY;

	latency = reg >> 32;
	latency = (latency << 16) >> 16;

	return latency;
}

static int ibs_op_event(struct bpf_perf_event_data *ctx,
			struct data_sample *sample)
{
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data *data = NULL;
	struct perf_raw_record *raw = NULL;
	struct perf_ibs_fetch_data *ibs_data;
	struct perf_raw_frag frag;
	void *addr;
	u64 op_regs[IBSOP_REG_COUNT];
	u64 ip;

	ip = PT_REGS_IP(&ctx->regs);
	if (user_space_only && IBS_KERN_SAMPLE(ip))
		return -EINVAL;

	/* Collect samples from IBS OP registers */
	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;

	if (bpf_core_read(&data, sizeof(data), &(kern_ctx->data)))
		return -EFAULT;

	if (bpf_core_read(&raw, sizeof(raw), &(data->raw)))
		return -EFAULT;

	if (bpf_core_read(&frag, sizeof(frag), &(raw->frag)))
		return -EFAULT;

	/* ibs fetch data  below is not a mistake */
	ibs_data = (struct perf_ibs_fetch_data *)frag.data;
	addr     = &ibs_data->data[0];

	/* To comply with bpf validator */
	if (unlikely(addr == NULL))
		return -EINVAL;

	if (bpf_core_read(op_regs, sizeof(op_regs), addr))
		return -EFAULT;

	if (!IBS_OP_LINADDR_VALID(op_regs[IBS_OP_DATA3]))
		return -EINVAL;

	if (!IBS_OP_PHYSADDR_VALID(op_regs[IBS_OP_DATA3]))
		return -EINVAL;

	/* To comply with bpf validator */
	if (unlikely(sample == NULL))
		return -EINVAL;

	sample->vaddr = op_regs[IBS_DC_LINADDR];
	sample->paddr = op_regs[IBS_DC_PHYSADDR];
	sample->ip    = op_regs[IBS_OP_RIP];
	sample->lat   = op_regs[IBS_OP_DATA3];

	return 0;
}

u32 code_latency(u64 reg)
{
	return ibs_fetch_latency(reg);
}

int code_sampler(struct bpf_perf_event_data *ctx, struct code_sample *sample)
{
	return ibs_fetch_event(ctx, sample);
}

u32 data_latency(u64 reg)
{
	return ibs_op_latency(reg);
}

int data_sampler(struct bpf_perf_event_data *ctx, struct data_sample *sample)
{
	return ibs_op_event(ctx, sample);
}
