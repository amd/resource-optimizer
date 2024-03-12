/*
 * profiler_pvt.h - Process profiler using IBS or LBR
 * and analyze the instruction and data (if available) samples.
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
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

#ifndef _PROFILER_PVT_H
#define _PROFILER_PVT_H
int iprofiler_function(const char *kernobj, int freq, int msecs,
		       char *include_pids, char *include_ppids,
		       cpu_set_t *cpusetp, char *filter_str);

int lbr_profiler_function(const char *kernobj, int freq, int msecs,
			  char *include_pids, char *include_ppids,
			  cpu_set_t *cpusetp, char *filter_str);

int init_and_load_bpf_programs(struct bpf_program **prog, int *map_fd,
			       struct bpf_object *obj, char **program_names,
			       char **map_fd_names);

void set_knob(int fd, int knob, int value);
extern int parse_additional_bpf_programs(struct bpf_object *bpfobj);
extern int launch_additional_bpf_programs(void);
int terminate_additional_bpf_programs(void);
void profiler_cleanup(int fetch_fd, int op_fd);
unsigned long peek_samples(int fd, unsigned long old, unsigned long *new);

struct profiler_filter;
int profiler_parse_filter(char *str, struct profiler_filter *filter,
			  const int max_entries);

int profiler_fill_filter(struct bpf_object *obj, struct profiler_filter *filter,
			 int max_entries);
extern char * ebpf_object_dir;
extern unsigned int cpu_nodes;
extern bool user_space_only;
extern float maximizer_mode;
extern unsigned int lbr_profiler;
#endif
