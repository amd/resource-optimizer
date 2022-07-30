/*
 * Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright 2021 AMD, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <numa.h>
#include <numaif.h>
#include <stdbool.h>

typedef unsigned int __u32, u32;
typedef unsigned long__u64, u64;
#include "membalancer.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"

extern struct numa_node_mem numa_table[MAX_NUMA];
struct mem_tier mem_tier[MAX_NUMA];
int mem_tiers;
bool tier_mode = false;

#define PAGE_SIZE  4096 /*getpagesize()*/
#define PAGE_SHIFT 12

static unsigned long fetch_overall_samples[MAX_NUMA];
static unsigned long op_overall_samples[MAX_NUMA];

int numa_tier_get(unsigned long physaddr)
{
        int i;

        physaddr >>= PAGE_SHIFT;

        for (i = max_nodes - 1; i > -1; i--) {
                if ((physaddr >= numa_table[i].first_pfn) &&
                    (physaddr <= numa_table[i].last_pfn))
                        return numa_table[i].tierno;
        }

        return -1;
}


static char * next_tier(char **string)
{
	int i;
	char *mystr = *string;

	if (!mystr)
		return NULL;

	i = 0;

	while (mystr[i] != 0 && mystr[i] != '-')
		i++;

	if (mystr[i] == '-') {
		mystr[i] = 0;
		i++;
		*string = &mystr[i];
	} else {
		*string = 0;
	}

	return mystr;
}

static int get_tier_info(char *tier, struct mem_tier *mem_tier)
{
	int tierno, node, promote_pct, promote_to_tier, promote_cap;
	int demote_pct, demote_to_tier, demote_cap;
	int i, j, next_node, nodes;

	i  = 0;
	
	/* parse tier number */
	while (tier[i] != 0 && tier[i] != ':')
		i++;

	if (i == 0)
		return -1;

	tier[i] = 0;
	tierno = atoi(tier);

	if (verbose > 3)
		printf("Tier No %d,", tierno);

	mem_tier->tierno = tierno;

	/* parse nodes in the given tier */
	nodes  = 0;

	do {
		j = ++i;
		next_node = 0;
		while (tier[j] != 0 && tier[j] != ':' && tier[j] != ',')
			j++;

		if (tier[j] == ',')
			next_node++;
		tier[j] = 0;
		node = atoi(&tier[i]);

		if (verbose > 3)
			printf("node %d,", node);

		mem_tier->nodep[nodes] = &numa_table[node];
		mem_tier->nodep[nodes]->tierno = tierno;
		i = j;
		nodes++;
	} while (next_node);

	if (nodes == 0)
		return -1;

	mem_tier->nodes = nodes;
	mem_tier->next_node = 0;
	
	j = ++i;

	/* promote percentage */
	while (tier[j] != 0 && tier[j] != ':')
		j++;

	if (i == j) {
		promote_pct = 0;
	} else {
		tier[j] = 0;
		promote_pct = atoi(&tier[i]);
	}

	if (verbose > 3)
		printf("promote %d%%,", promote_pct);

	mem_tier->upgrade_pct  = promote_pct;

	/* promote to tier */
	i = ++j;
	while (tier[j] != 0 && tier[j] != ':')
		j++;

	if (i == j) {
		promote_to_tier = -1;
	} else {
		tier[j] = 0;
		promote_to_tier = atoi(&tier[i]);
	}

	if (verbose > 3)
		printf("promote_to_tier %d,", promote_to_tier);

	mem_tier->upgrade_tier  = promote_to_tier;

	/* promote cap */
	i = ++j;
	while (tier[j] != 0 && tier[j] != ':')
		j++;

	if (i == j) {
		promote_cap = 0;
	} else {
		tier[j] = 0;
		promote_cap = atoi(&tier[i]);
	}

	if (verbose > 3)
		printf("promote_cap %d%%,", promote_cap);

	mem_tier->upgrade_cap = promote_cap;

	/* demote percentage */
	i = ++j;
	while (tier[j] != 0 && tier[j] != ':')
		j++;

	if (i == j) {
		demote_pct = 0;
	} else {
		tier[j] = 0;
		demote_pct = atoi(&tier[i]);
	}

	if (verbose > 3)
		printf("demote %d%%,", demote_pct);

	mem_tier->downgrade_pct = demote_pct;

	/* demote to tier */
	i = ++j;
	while (tier[j] != 0 && tier[j] != ':')
		j++;

	if (i == j) {
		demote_to_tier = -1;
	} else {
		tier[j] = 0;
		demote_to_tier = atoi(&tier[i]);
	}

	if (verbose > 3)
		printf("demote_to_tier %d, ", demote_to_tier);

	mem_tier->downgrade_tier  = demote_to_tier;

	/* demote cap */
	i = ++j;
	while (tier[j] != 0 && tier[j] != ':')
		j++;

	if (i == j) {
		demote_cap = 0;
	} else {
		tier[j] = 0;
		demote_cap = atoi(&tier[i]);
	}

	if (verbose > 3)
		printf("demote_cap %d%%\n", demote_cap);

	mem_tier->downgrade_cap  = demote_cap;

	return 0;
}

static int process_numa_tier_args(char *numa_string,
				  struct mem_tier *mem_tier,
				  int max_numa)
{
	int i, error;
	char *tier;

	i = 0;

	while ((tier = next_tier(&numa_string))) {
		error = get_tier_info(tier, &mem_tier[i]);
		if (error)
			return error;
		i++;
	}

	mem_tiers = i;

	if (mem_tiers < 2)
		return -1;

	return 0;
}

static int calcuate_weight(int node, unsigned int *counts, int numa_count)
{
        int weight, i;

        weight = 0;
        for (i = 0; i < numa_count; i++)
                weight += numa_table[node].distance[i] * counts[i];

        return weight;
}

static int get_target_node_tier(int node, bool upgrade)
{
	int tier, next_tier, target_node, idx;
	struct numa_node_mem *nodep;

	tier = numa_table[node].tierno;

	if (upgrade) {
		assert(tier >= 1 && tier < mem_tiers);
		next_tier = tier - 1;
	} else {
		assert(tier >= 0 && tier < (mem_tiers - 1));
		next_tier = tier + 1;
	}

	idx = mem_tier[next_tier].next_node;
	assert(idx >= 0 && idx < max_nodes);
	nodep = mem_tier[next_tier].nodep[idx];
	
	target_node = nodep->node;

	if (mem_tier[next_tier].nodes > 1) {
		mem_tier[next_tier].next_node++; 
		mem_tier[next_tier].next_node %= mem_tier[next_tier].nodes;
	}

	/*
		printf("node %d tier %d next_tier %d target_node %d\n",
			node, tier, next_tier, target_node);
	*/

	return target_node;
}

int init_tier(char *args)
{
	int err;

	if (!args)
		return 0;

	err = process_numa_tier_args(args, mem_tier, max_nodes);
	if (err)
		return err;

	tier_mode = true;

	return 0;
}

void update_sample_statistics_tier(unsigned long *samples, bool fetch)
{
	int i, tier;

	if (fetch) {
		for (i = 0; i < mem_tiers; i++)
			fetch_overall_samples[i] = 0;

		for (i = 0; i < max_nodes; i++) {
			tier = numa_table[i].tierno;
			fetch_overall_samples[tier] += samples[i];
		}
	} else {
		for (i = 0; i < mem_tiers; i++)
			op_overall_samples[i] = 0;

		for (i = 0; i < max_nodes; i++) {
			tier = numa_table[i].tierno;
			op_overall_samples[tier] += samples[i];
		}
	}
}

void get_sample_statistics_tier(bool fetch, unsigned long **samples, int *count)
{
        *count   = mem_tiers;
        *samples = (fetch) ? fetch_overall_samples : op_overall_samples;
}

static unsigned long upgrade_fetch_sample(struct bst_node **rootpp,
					  bool balancer_mode,
					  unsigned long total,
					  bool user_space_only,
					  int node, int pct)
{
        int i, j, k, target_node, upgrade_pct;
        unsigned long count, pages = 0;

	k = (fetch_samples_cnt[node] * pct) / 100;

	for (i = fetch_samples_cnt[node] - 1; i > -1; i--) {
		if (!fetch_samples[node][i].count)
			continue;
		if (--k < 0) {
			fetch_samples[node][i].count = 0;
			break;
		}

    		count = 0;
                for (j = 0; j < max_nodes; j++)
			count += fetch_samples[node][i].counts[j];

		if (!user_space_only && IBS_KERN_SAMPLE(
						fetch_samples[node][i].ip)) {
			fetch_samples[node][i].count = 0;
			continue;
		}

		if (balancer_mode) {
			target_node = get_target_node_tier(node, true);
    		} else {
			target_node = node;
		}


		if (node != target_node) {
			pages++;
			bst_add_page(fetch_samples[node][i].tgid,
					target_node,
					fetch_samples[node][i].fetch_regs[
							IBS_FETCH_LINADDR],
					true,
					rootpp);
		}

		fetch_samples[node][i].count = 0;
	}

	return pages;
}

static unsigned long upgrade_op_sample(struct bst_node **rootpp,
					bool balancer_mode,
					unsigned long total,
					bool user_space_only,
					int node, int pct)
{
        int i, j, k, target_node, upgrade_pct;
        unsigned long count, pages = 0;

	k = (op_samples_cnt[node] * pct) / 100;

	for (i = op_samples_cnt[node] - 1; i > -1; i--) {
		if (!op_samples[node][i].count)
			continue;

		if (--k < 0) {
			op_samples[node][i].count = 0;
			continue;
		}

    		count = 0;
                for (j = 0; j < max_nodes; j++)
			count += op_samples[node][i].counts[j];

		if (!user_space_only && IBS_KERN_SAMPLE(
			op_samples[node][i].op_regs[IBS_OP_RIP])) {
			op_samples[node][i].count = 0;
			continue;
   		}

		if (balancer_mode) {
			target_node = get_target_node_tier(node, true);
    		} else {
			target_node = node;
		}

		if (node != target_node) {
			pages++;
			bst_add_page(op_samples[node][i].tgid,
					target_node,
					op_samples[node][i].op_regs[
							IBS_DC_LINADDR],
					true,
					rootpp);
		}

		op_samples[node][i].count = 0;
	}

	return pages;
}

static unsigned long upgrade_sample(struct bst_node **rootpp,
				    bool balancer_mode,
				    unsigned long total,
				    bool user_space_only, int node,
				    bool fetch)
{
	int tier;
	unsigned long pages;
	assert(node >= 0 && node < max_nodes);

	tier = numa_table[node].tierno;

	if (mem_tier[tier].upgrade_pct  == 0)
		return 0;

	if (fetch)
		pages = upgrade_fetch_sample(rootpp, balancer_mode, total,
					     user_space_only, node,
					     mem_tier[tier].upgrade_pct);
	else
		pages = upgrade_op_sample(rootpp, balancer_mode, total,
					  user_space_only, node,
					  mem_tier[tier].upgrade_pct);

	return pages;
}

static void downgrade_fetch_sample(struct bst_node **rootpp, bool balancer_mode,
				   unsigned long total, bool user_space_only,
				   int node, int pct, unsigned long *pagesp)
{
        int i, j, k, target_node, upgrade_pct;
        unsigned long count;

	k = (fetch_samples_cnt[node] * pct) / 100;

	for (i = 0; i < fetch_samples_cnt[node]; i++) {
		if (*pagesp == 0)
			return;
		if (!fetch_samples[node][i].count)
			continue;
		if (--k < 0) {
			fetch_samples[node][i].count = 0;
			break;
		}

    		count = 0;
                for (j = 0; j < max_nodes; j++)
			count += fetch_samples[node][i].counts[j];

		if (!user_space_only && IBS_KERN_SAMPLE(
						fetch_samples[node][i].ip)) {
			fetch_samples[node][i].count = 0;
			continue;
		}

		if (balancer_mode) {
			target_node = get_target_node_tier(node, false);
    		} else {
			target_node = node;
		}


		if (node != target_node) {
			--*pagesp;
			bst_add_page(fetch_samples[node][i].tgid,
					target_node,
					fetch_samples[node][i].fetch_regs[
							IBS_FETCH_LINADDR],
					false,
					rootpp);
		}

		fetch_samples[node][i].count = 0;
	}
}

static void downgrade_op_sample(struct bst_node **rootpp, bool balancer_mode,
				unsigned long total, bool user_space_only,
				int node, int pct, unsigned long *pagesp)
{
        int i, j, k, target_node, upgrade_pct;
        unsigned long count;


	k = (op_samples_cnt[node] * pct) / 100;

	for (i = 0; i < op_samples_cnt[node]; i++) {
		if (*pagesp == 0)
			return;
		if (!op_samples[node][i].count)
			continue;

		if (--k < 0) {
			op_samples[node][i].count = 0;
			continue;
		}

    		count = 0;
                for (j = 0; j < max_nodes; j++)
			count += op_samples[node][i].counts[j];

		if (!user_space_only && IBS_KERN_SAMPLE(
			op_samples[node][i].op_regs[IBS_OP_RIP])) {
			op_samples[node][i].count = 0;
			continue;
   		}

		if (balancer_mode) {
			target_node = get_target_node_tier(node, false);
    		} else {
			target_node = node;
		}

		if (node != target_node) {
			--*pagesp;
			bst_add_page(op_samples[node][i].tgid,
					target_node,
					op_samples[node][i].op_regs[
							IBS_DC_LINADDR],
					false,
					rootpp);
		}

		op_samples[node][i].count = 0;
	}
}

static void downgrade_sample(struct bst_node **rootpp, bool balancer_mode,
                           unsigned long total, bool user_space_only, int node,
			   bool fetch, unsigned long *pagesp)
{
	int tier;
	assert(node >= 0 && node < max_nodes);

	tier = numa_table[node].tierno;

	if (mem_tier[tier].downgrade_pct  == 0)
		return;

	if (fetch)
		downgrade_fetch_sample(rootpp, balancer_mode, total,
				       user_space_only, node,
				       mem_tier[tier].downgrade_pct,
				       pagesp);
	else
		downgrade_op_sample(rootpp, balancer_mode, total,
				    user_space_only, node,
				    mem_tier[tier].downgrade_pct,
				    pagesp);
}

static int upgrade_downgrade_ratio(void)
{
	int i, sum_down_pct, sum_up_pct;

	sum_down_pct = 0;
	sum_up_pct  = 0;

	for (i = 0; i < mem_tiers; i++) {
		sum_up_pct   += mem_tier[i].upgrade_pct;
		sum_down_pct += mem_tier[i].downgrade_pct;
	}

	if (sum_up_pct == 0)
		return 100;

	return sum_down_pct * 100 / sum_up_pct;

}

void process_ibs_fetch_samples_tier(struct bst_node **rootpp,
				    unsigned long total,
				    bool balancer_mode,
				    bool user_space_only)
{
	int node;
	unsigned long pages;

        if (!total)
                return;

	pages = 0;

        for (node = 0; node < max_nodes; node++)
		pages += upgrade_sample(rootpp, balancer_mode, total,
					user_space_only, node, true);


	pages *= upgrade_downgrade_ratio();
	pages /= 100;

        for (node = 0; node < max_nodes; node++)
		downgrade_sample(rootpp, balancer_mode, total, user_space_only,
				 node, true, &pages);
}

void process_ibs_op_samples_tier(struct bst_node **rootpp,
				 unsigned long total,
				 bool balancer_mode,
				 bool user_space_only)
{
	int node;
	unsigned long pages;

        if (!total)
                return;

	pages = 0;

        for (node = 0; node < max_nodes; node++)
		pages += upgrade_sample(rootpp, balancer_mode, total,
					user_space_only, node, false);

	pages *= upgrade_downgrade_ratio();
	pages /= 100;

        for (node = 0; node < max_nodes; node++)
		downgrade_sample(rootpp, balancer_mode, total, user_space_only,
				node, false, &pages);
}

