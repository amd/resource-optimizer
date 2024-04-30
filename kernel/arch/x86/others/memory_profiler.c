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

static u32 other_arch_code_latency(u64 reg)
{
	return INVALID_LATENCY;
}

static int other_arch_code_sampler(struct bpf_perf_event_data *ctx,
				   struct code_sample *code)
{
	return -EINVAL;
}

static u32 other_arch_data_latency(u64 reg)
{
	return INVALID_LATENCY;
}

static int other_arch_data_sampler(struct bpf_perf_event_data *ctx,
				   struct data_sample *sample)
{
	return -EINVAL;
}

u32 code_latency(u64 reg)
{
	return other_arch_code_latency(reg);
}

int code_sampler(struct bpf_perf_event_data *ctx, struct code_sample *sample)
{
	return other_arch_code_sampler(ctx, sample);
}

u32 data_latency(u64 reg)
{
	return other_arch_data_latency(reg);
}

int data_sampler(struct bpf_perf_event_data *ctx, struct data_sample *sample)
{
	return other_arch_data_sampler(ctx, sample);
}
