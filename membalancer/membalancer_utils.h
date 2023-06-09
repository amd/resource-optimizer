/*
 * membalancer_utils.h - Process samples from IBS or software sample
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

#ifndef MEMBALANCER_UTILS_H
#define MEMBALANCER_UTILS_H

#define _GNU_SOURCE
#include <sched.h>
#include<stdbool.h>
#include<sys/types.h>

struct code_samples {
        unsigned long tgid;
        unsigned long ip;
        unsigned long vaddr;
        unsigned long paddr;
        unsigned int  count;
        unsigned int  filler;
        unsigned int  counts[MAX_NUMA_NODES];
        unsigned int  latency[MAX_LATENCY_IDX];
        char          process[PROCESSNAMELEN];
};

struct data_samples {
        unsigned long tgid;
        unsigned long ip;
        unsigned long vaddr;
        unsigned long paddr;
        unsigned int  count;
        unsigned int  filler;
        unsigned int  counts[MAX_NUMA_NODES];
        unsigned int  latency[MAX_LATENCY_IDX];
        char          process[PROCESSNAMELEN];
};

#define NODE_LOAD_AVG_THRESHOLD 70
#define CPU_IDLE_THRESHOLD 80
extern int idle_cpu_cnt[MAX_NUMA_NODES];
extern int nr_cpus;
extern cpu_set_t *cpusetp;
extern int verbose;

struct cpu_utilinfo {
	int cpu;
	long double idletime;
	long double totaltime;
};

enum {
		USER_FIELD,
		NICE_FIELD,
		SYSTEM_FIELD,
		IDLE_FIELD,
		IOWAIT_FIELD,
		IRQ_FIELD,
		SOFTIRQ_FIELD,
		STEAL_FIELD,
		GUEST_FIELD,
		GUEST_NICE,
		MAX_FIELDS,
};

void update_node_loadavg(void *);
int get_node_loadavg(int node);
void set_idle_cpu(int cpu, int node);
int get_next_idle_cpu(int node);

extern bool histogram_format;
extern int report_frequency;
extern bool do_migration;
extern bool l3miss;

extern cpu_set_t node_cpumask[MAX_NUMA_NODES];
extern struct code_samples code_samples[MAX_NUMA_NODES][MAX_SAMPLES];
extern unsigned long code_samples_max[MAX_NUMA_NODES];
extern unsigned long code_samples_cnt[MAX_NUMA_NODES];

extern struct data_samples data_samples[MAX_NUMA_NODES][MAX_SAMPLES];
extern unsigned long data_samples_max[MAX_NUMA_NODES];
extern unsigned long data_samples_cnt[MAX_NUMA_NODES];

extern bool tracer_physical_mode;
extern atomic64_t status_code_cnt, status_data_cnt;

struct bst_node;
int bst_add_page(pid_t pid, int to_node, unsigned long addr,
	         bool upgrade, struct bst_node **root);

int tracer_init(const char *path);
void update_sample_statistics_tracer(unsigned long *samples,
				     bool fetch);
void process_data_samples_tracer(struct bst_node **rootpp,
				 unsigned long total,
				 bool user_space_only);

void process_code_samples_tracer(struct bst_node **rootpp,
				 unsigned long total,
				 bool user_space_only);
void report_tracer_statistics(void);
void set_base_page_size(unsigned long base_pagesz);

unsigned long get_physaddr(pid_t pid, unsigned long vaddr);

bool cpuvendor_supported(void);
struct bpf_object;
int fill_numa_address_range_map(struct bpf_object *obj);
void process_migrate_balance_processes(int map_fd);
int numa_range_get(int idx, struct numa_range *range);
int init_heap(struct bpf_object *obj);

void update_process_run_data(int map_fd);
void reset_proc_runtime_data(void);
void autotune_filter_data(unsigned *curr_index);
void autotune_sampler_and_analyzer(int map_fd);
bool autotune_tuner(void);
bool is_scattered_proc_group();
void print_bar(int numa, bool text,
			bool process_context,
			bool cpu, double pct);
void print_text(u64 total_ref, u64 *numa_ref);
unsigned long seconds_elapsed(struct timeval *start,
			struct timeval *end);
unsigned long milliseconds_elapsed(struct timeval *start,
			struct timeval *end);
int freemem_threshold(void);

int init_generic_tier(void);
int nodes_at_hop_or_tier(int node, int hop_or_tier, int *countp, int **listpp);
bool is_tier_mode(void);
bool is_default_tier_mode(void);
void set_tier_mode(void);
int get_code_samples(int fd, __u64 *total_freq, bool defer);
void cleanup_code_samples(int fd);
int get_data_samples(int fd, __u64 *total_freq, bool defer);
void cleanup_data_samples(int fd);
unsigned long get_bytecount(char unit, unsigned int size);

extern int report_frequency;
extern int iprofiler;

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

extern unsigned int min_samples;
#define MIN_CLASSIC_SAMPLES 500 /* Tune if needed */
#define MIN_L3MISS_SAMPLES  500 /* Tune if needed */
#define MIN_SAMPLES min_samples
#define MIN_CODE_SAMPLES (MIN_SAMPLES / 4)
#define MIN_DATA_SAMPLES (MIN_SAMPLES / 2)

#endif
