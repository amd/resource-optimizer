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
 * IBS sampler : Arm IBS fetch and op sampling, collect both kernel and
 * process samples.
 */
#include <linux/version.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <linux/perf_event.h>
#include <bpf/bpf_helpers.h>
#include <generic_kern_amd.h>

int ibs_fetch_event(struct bpf_perf_event_data *ctx,
		    struct value_fetch *fetch_data,
		    u64 *tgidout, u64 *ipout)

{
	u64 ip;
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data *data = NULL;
	struct perf_raw_record *raw = NULL;
	struct perf_ibs_fetch_data *ibs_data;
	struct perf_raw_frag frag;
	void *addr;
	u64 tgid;

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	ip = PT_REGS_IP(&ctx->regs);
	if (user_space_only && IBS_KERN_SAMPLE(ip))
		return -EINVAL;

	/* Collect samples from IBS Fetch registers */
	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;

	bpf_probe_read(&data, sizeof(data), &(kern_ctx->data));
	bpf_probe_read(&raw, sizeof(raw), &(data->raw));
	bpf_probe_read(&frag, sizeof(frag), &(raw->frag));

	ibs_data = (struct perf_ibs_fetch_data *)frag.data;
	addr     = &ibs_data->data[0];

	bpf_probe_read(&fetch_data->fetch_regs[0],
			sizeof(fetch_data->fetch_regs),
			addr);

	if (!IBS_FETCH_PHYSADDR_VALID(fetch_data->fetch_regs[IBS_FETCH_CTL]))
			return -EINVAL;

	*ipout = ip;
	*tgidout = tgid;

	return 0;
}

int ibs_op_event(struct bpf_perf_event_data *ctx,
		 struct value_op *op_data,
		 u64 *tgidout, u64 *ipout)
{
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data *data = NULL;
	struct perf_raw_record *raw = NULL;
	struct perf_ibs_fetch_data *ibs_data;
	struct perf_raw_frag frag;
	u64 ip;
	void *addr;
	u64 tgid;

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return -EINVAL;

	ip = PT_REGS_IP(&ctx->regs);
	if (user_space_only && IBS_KERN_SAMPLE(ip))
		return -EINVAL;

	/* Collect samples from IBS Fetch registers */
	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;

	bpf_probe_read(&data, sizeof(data), &(kern_ctx->data));
	bpf_probe_read(&raw, sizeof(raw), &(data->raw));
	bpf_probe_read(&frag, sizeof(frag), &(raw->frag));

	ibs_data = (struct perf_ibs_fetch_data *)frag.data;
	addr     = &ibs_data->data[0];
	
	bpf_probe_read(&op_data->op_regs[0], sizeof(op_data->op_regs),
			addr);

	if (!IBS_OP_LINADDR_VALID(op_data->op_regs[IBS_OP_DATA3]))
		return -EINVAL;

	if (!IBS_OP_PHYSADDR_VALID(op_data->op_regs[IBS_OP_DATA3]))
		return -EINVAL;

	*ipout = ip;
	*tgidout = tgid;

	return 0;
}
