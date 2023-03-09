/*
 * membalancer_utils.h - Process samples from IBS or software sample
 * and analyze the instruction and data (if available) samples.
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (c) 2023 Advanced Micro Devices, Inc.
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

#ifndef MEMBALANCER_USER_H
#define MEMBALANCER_USER_H

#define _GNU_SOURCE
#include <sched.h>
#include<stdbool.h>
#include<sys/types.h>

enum tuning_mode {
	UNINITIALIZED = 0,
	MEMORY_MOVE = 2,
	PROCESS_MOVE = 4,
	AUTOTUNE = 8
};

enum tuning_profile {
	MEMORY,
	PROCESS
#if 0
	/* This is not rally a profile.
	 * Its a mix of above two primary profiles.
	 */
	AUTOTUNE
#endif
};

enum map_fd_elems {
	IBS_FETCH_MAP,
	IBS_OP_MAP,
	PROC_STAT_MAP,
	FETCH_COUNTER_MAP,
	OP_COUNTER_MAP,
	KNOBS,
	TOTAL_MAPS
};

enum bpf_programs {
	IBS_CODE_SAMPLER,
	IBS_DATA_SAMPLER,
	NON_IBS_CODE_SAMPLER,
	TOTAL_BPF_PROGRAMS
};

char * memory_profile_program_names[TOTAL_BPF_PROGRAMS] = {
	"memstats_code_sampler",
	"memstats_data_sampler",
	NULL,
};


char * process_profile_program_names[TOTAL_BPF_PROGRAMS] = {
	"processstats_code_sampler",
	"processstats_data_sampler",
	NULL,
};

#define ADDITIONAL_PROGRAMS 1

static struct bpf_program *additional_programs[ADDITIONAL_PROGRAMS];
static int addtional_program_count;
static struct bpf_link *additional_bpflinks[ADDITIONAL_PROGRAMS];
static char * additional_programs_name[ADDITIONAL_PROGRAMS] = {
    NULL,
};

/* Below NULL elements are kept to maintain the relative index,
 * keping TOTAL_MAPS fixed for any profile.
 */

static char *memory_map_fd_names[TOTAL_MAPS] = {
	"ibs_fetch_map",
	"ibs_op_map",
	NULL,
	"fetch_counter",
	"op_counter",
	"knobs",
};

static char *process_map_fd_names[TOTAL_MAPS] = {
 	NULL,
	NULL,
	"process_stats_map",
	"fetch_counter",
	"op_counter",
	"knobs"
};

#endif
