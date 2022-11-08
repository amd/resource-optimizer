/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Process samples from IBS or software sampler and analyze the instruction and
 * data (if available) samples.
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
	int           unused;
	int           distance[MAX_NUMA];
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
	struct numa_node_mem *nodep[MAX_NUMA];
};

int get_current_node(unsigned long physaddr);
int fill_numa_table(void);
int init_tier( char *args);

void update_sample_statistics_numa(unsigned long *samples, bool fetch);
void update_sample_statistics_tier(unsigned long *samples, bool fetch);
void get_sample_statistics_numa(bool fetch, unsigned long **samples,
				int *count);
void get_sample_statistics_tier(bool fetch, unsigned long **samples,
				int *count);

void process_ibs_fetch_samples_numa(struct bst_node **rootpp,
                                    unsigned long total,
                                    bool balancer_mode,
                                    bool user_space_only);
void process_ibs_op_samples_numa(struct bst_node **rootpp,
				 unsigned long total,
				 bool balancer_mode,
				 bool user_space_only);

void process_ibs_fetch_samples_tier(struct bst_node **rootpp,
                                    unsigned long total,
                                    bool balancer_mode,
                                    bool user_space_only);

void process_ibs_op_samples_tier(struct bst_node **rootpp,
                                 unsigned long total,
                                 bool balancer_mode,
                                 bool user_space_only);

extern int max_nodes;
extern int verbose;
extern bool tier_mode;
#endif
