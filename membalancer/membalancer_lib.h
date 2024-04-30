/*
 * membalancer_lib.h - Memory balancer library functions
 * and analyze the instruction and data (if available) samples.
 *
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

#ifndef MEMBALANCER_LIB_H
#define MEMBALANCER_LIB_H
int get_ibs_device_type(const char *dev);
void open_ibs_devices(void);
void close_ibs_devices(void);
int process_include_pids(struct bpf_object *obj, char *pid_string, bool ppid);
int parse_cpulist(const char *cpu_list, cpu_set_t *cpusetp, size_t set_size);
int perf_sampling_begin(int freq, struct bpf_program *prog,
			struct bpf_link *links[], cpu_set_t *cpusetp);
int ibs_fetch_sampling_begin(int freq, struct bpf_program *prog,
			     struct bpf_link *links[], cpu_set_t *cpusetp);
int lbr_sampling_begin(int freq, struct bpf_program *prog,
		       struct bpf_link *links[], cpu_set_t *cpusetp);
void ibs_sampling_end(struct bpf_link *links[]);
int ibs_op_sampling_begin(int freq, struct bpf_program *prog,
                          struct bpf_link *links[], cpu_set_t *cpusetp);
int fill_cpu_nodes(struct bpf_object *obj);
#endif
