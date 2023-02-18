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

#ifndef MEMBALANCER_UTILS_H
#define MEMBALANCER_UTILS_H

#define _GNU_SOURCE
#include <sched.h>
#include<stdbool.h>
#include<sys/types.h>

#include "membalancer.h"

struct ibs_fetch_sample {
        unsigned long ip;
        unsigned int count;
        unsigned int counts[MAX_NUMA_NODES];
        unsigned long tgid;
        char  process[PROCESSNAMELEN];
        unsigned long fetch_regs[IBSFETCH_REG_COUNT];
};

struct ibs_op_sample {
        unsigned long key;
        unsigned int count;
        unsigned int counts[MAX_NUMA_NODES];
        unsigned long tgid;
        char          process[PROCESSNAMELEN];
        unsigned long op_regs[IBSOP_REG_COUNT];
};

extern cpu_set_t node_cpumask[MAX_NUMA_NODES];
extern struct ibs_fetch_sample fetch_samples[MAX_NUMA_NODES][MAX_IBS_SAMPLES];
extern unsigned long fetch_samples_max[MAX_NUMA_NODES];
extern unsigned long fetch_samples_cnt[MAX_NUMA_NODES];

extern struct ibs_op_sample op_samples[MAX_NUMA_NODES][MAX_IBS_SAMPLES];
extern unsigned long op_samples_max[MAX_NUMA_NODES];
extern unsigned long op_samples_cnt[MAX_NUMA_NODES];
extern bool tracer_physical_mode;

struct bst_node;
int bst_add_page(pid_t pid, int to_node, unsigned long addr,
	         bool upgrade, struct bst_node **root);

int tracer_init(const char *path);
void update_sample_statistics_tracer(unsigned long *samples,
				     bool fetch);
void process_ibs_op_samples_tracer(struct bst_node **rootpp,
                                   unsigned long total,
                                   bool user_space_only);

void process_ibs_fetch_samples_tracer(struct bst_node **rootpp,
                                    unsigned long total,
                                    bool user_space_only);
void report_tracer_statistics(void);
void set_base_page_size(unsigned long base_pagesz);

unsigned long get_physaddr(pid_t pid, unsigned long vaddr);

bool cpuvendor_supported(void);
struct bpf_object;
int fill_numa_address_range_map(struct bpf_object *obj);
void process_migrate_processes(int map_fd);
int numa_range_get(int idx, struct numa_range *range);
int init_heap(struct bpf_object *obj);

void update_process_run_data(int map_fd);
void analyze_and_set_autotune_params(unsigned *curr_index);

#define BRIGHT   "\x1b[1m"
#define MAGENTA  "\x1B[35m"
#define BLUE     "\x1B[34m"
#define BMAGENTA "\x1B[45m"
#define BBLUE     "\x1B[44m"
#define RED      "\x1B[31m"
#define BRED      "\x1B[41m"
#define GREEN    "\x1B[33m"
#define BGREEN    "\x1B[43m"
#define BCYAN   "\x1B[46m"
#define ULINE   "\x1B[4m"
#define CYAN     "\x1B[36m"
#define NORM     "\x1B[0m"
#define BLACK    "\x1B[30m"
#define BWHITE   "\x1B[47m"
#define WHITE   "\x1B[37m"

#endif
