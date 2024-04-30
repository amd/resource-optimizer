/*
 * membalancer_numa.h - Process samples from IBS or software sampler
 * and analyze the instruction and data (if available) samples.
 *
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc.  All Rights Reserved.
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

#ifndef MEMBALANCER_NUMA_H
#define MEMBALANCER_NUMA_H

struct numa_node_mem {
        unsigned long first_pfn;
        unsigned long last_pfn;
        int           node;
        int           level;
        int           upgrade_pct;
        int           downgrade_pct;
	int           tierno;
	int           freemem_pct;
	int           distance[MAX_NUMA_NODES];
};

struct mem_tier {
	int tierno;
	int nodes;
	int next_node;
	int upgrade_tier;
        int upgrade_pct;
        int upgrade_cap;
	int downgrade_tier;
        int downgrade_pct;
        int downgrade_cap;
	int unused;
	struct numa_node_mem *nodep[MAX_NUMA_NODES];
};

extern struct numa_node_mem numa_table[MAX_NUMA_NODES];

/*TODO: Using this structure only for per node cpu_cnt.
 * Remove if not really required.
 */
struct numa_node_cpu {
	int cpu_cnt;
	int cpu_list[MAX_CPU_CORES];
};

extern struct numa_node_cpu numa_node_cpu[MAX_NUMA_NODES];
extern int numa_cpu[MAX_CPU_CORES];

int get_current_node(unsigned long physaddr);
int fill_numa_table(void);
int init_tier( char *args);

void update_sample_statistics_numa(unsigned long *samples, bool fetch);
void update_sample_statistics_tier(unsigned long *samples, bool fetch);
void get_sample_statistics_numa(bool fetch, unsigned long **samples,
				int *count);
void get_sample_statistics_tier(bool fetch, unsigned long **samples,
				int *count);
void process_code_samples_numa(struct bst_node **rootpp,
			       unsigned long total,
			       bool balancer_mode,
			       bool user_space_only);
void process_data_samples_numa(struct bst_node **rootpp,
			       unsigned long total,
			       bool balancer_mode,
			       bool user_space_only);
void process_code_samples_tier(struct bst_node **rootpp,
			       unsigned long total,
			       bool balancer_mode,
			       bool user_space_only);
void process_data_samples_tier(struct bst_node **rootpp,
			       unsigned long total,
			       bool balancer_mode,
			       bool user_space_only);
int node_freemem_get(int node);
void update_per_node_freemem(void *arg);
extern int max_nodes;
#endif
