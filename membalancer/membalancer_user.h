/*
 * membalancer_user.h - Process samples from IBS or software sample
 * and analyze the instruction and data (if available) samples.
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (c) 2023 Advanced Micro Devices, Inc. All Rights Reserved.
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
	PROCESS,
#if 0
	/* This is not really a profile.
	 * Its a mix of above two primary profiles.
	 */
	AUTOTUNE
#endif
};

enum map_fd_elems {
	CODE_MAP,
	DATA_MAP,
	PROC_STAT_MAP,
	CODE_COUNTER_MAP,
	DATA_COUNTER_MAP,
	KNOBS,
	LBR_PBE,
	LBR_PBE_FLAGS,
	TOTAL_MAPS
};

enum bpf_programs {
	CODE_SAMPLER,
	DATA_SAMPLER,
	LBR_SAMPLER,
	NON_IBS_CODE_SAMPLER,
	TOTAL_BPF_PROGRAMS
};

static char * profiler_program_names[TOTAL_BPF_PROGRAMS] = {
	"profiler_code_sampler",
	"profiler_data_sampler",
	NULL,
	NULL,
};

static char * lbr_profiler_program_names[TOTAL_BPF_PROGRAMS] = {
	NULL,
	NULL,
	"lbr_sampler",
	NULL,
};

static char * memory_profile_program_names[TOTAL_BPF_PROGRAMS] = {
	"memstats_code_sampler",
	"memstats_data_sampler",
	NULL,
	NULL,
};


static char * process_profile_program_names[TOTAL_BPF_PROGRAMS] = {
	"processstats_code_sampler",
	"processstats_data_sampler",
	NULL,
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
	"code_sample_map",
	"data_sample_map",
	NULL,
	"code_samples_counter",
	"data_samples_counter",
	"knobs",
	NULL,
 	NULL,
};

static char *process_map_fd_names[TOTAL_MAPS] = {
 	NULL,
	NULL,
	"process_stats_map",
	"code_samples_counter",
	"data_samples_counter",
	"knobs",
 	NULL,
	NULL
};

static char *profiler_map_fd_names[TOTAL_MAPS] = {
	"code_sample_map",
	"data_sample_map",
	NULL,
	"code_samples_counter",
	"data_samples_counter",
	"knobs",
};

static char *lbr_profiler_map_fd_names[TOTAL_MAPS] = {
 	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	"lbr_pbe",
	"lbr_pbe_flags"
};

/* Autotune specific control params for sampling and analysis of process stats
 * and defined in processtats_user.c.
 */
extern u64 sampling_interval_cnt;
extern u64 sampling_iter;
extern bool proc_data_sampling_done;
extern bool is_begining_of_sampling;
extern bool fallback_to_memory_balance;
extern u32 curr_proc_data_map_idx;

/* End of Autotune specific control params.*/

#endif
