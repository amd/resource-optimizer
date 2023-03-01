/*
 * membalancer_tier.c - Automatic NUMA memory balancer Based on IBS sampler
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

#include "membalancer_common.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"

extern struct numa_node_mem numa_table[MAX_NUMA_NODES];
struct mem_tier mem_tier[MAX_NUMA_NODES];
int mem_tiers;

#define GENERIC_TIER_MIGRATION_PCT 1

struct node_list {
	int node;
	int distance;
};

struct generic_tier {
	int max_nodes;
	int node[MAX_NUMA_NODES];
};

struct generic_tier generic_tier[MAX_NUMA_NODES][MAX_NUMA_NODES];
static bool tier_mode = false;
static bool default_tier = false;

static unsigned long fetch_overall_samples[MAX_NUMA_NODES];
static unsigned long op_overall_samples[MAX_NUMA_NODES];


bool is_tier_mode(void)
{
	return tier_mode;
}

void set_tier_mode(void)
{
	tier_mode = true;
}

bool is_default_tier_mode(void)
{
	return default_tier;
}

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

static int hops_between_nodes(int node1, int node2)
{
	int i, j, count, *nodes, k;

	for (i = 0; i < max_nodes; i++) {

		if (nodes_at_hop_or_tier(node1, i, &count, &nodes))
			continue;

		if (count < 1)
			continue;

		for (j = 0; j < count; j++) {
			if (nodes[j] == node2)
				return i;
		}
	}

	return -1;
}

static int get_target_node_generic_tier_upgrade(
					int node,
					unsigned int *ref_counts,
					int nodes)
{
	int i, j, count, *list, minfree_pct, target_node;
	int total, hops, next_node;
	bool dominant_sample;

	total = 0;
	for (i = 0; i < nodes; i++)
		total += ref_counts[i];

	if (!total)
		return node;

	j = 0;
	count = ref_counts[0];
	for (i = 1; i < nodes; i++) {
		if (count > ref_counts[i]) {
			j = i;
			count =  ref_counts[i];
		}
	}

	if ((count * 100 / total) > 50)
		dominant_sample = true;
	else
		dominant_sample = false;

	target_node = j;
	hops = hops_between_nodes(target_node, node);
	if (hops <= 0)
		return node;

	/* Upgrade twice for dominant case, or else move to the above tier */
	if ((total > 2 * nodes) && dominant_sample && (hops >= 2))
		hops -= 2;
	else
		hops -= 1;

	minfree_pct = freemem_threshold();

	for (i = hops; i >= 0; i--) {
		if (nodes_at_hop_or_tier(target_node, i, &count, &list))
			continue;

		if (count == 0)
			continue;

		for (j = 0; j < count; j++) {
			next_node = list[j];

			if (node_freemem_get(next_node) >= minfree_pct)
				return next_node;
		}
	}

	return node;
}

static int get_target_node_generic_tier_downgrade(
						int node,
						unsigned int *refs,
						int nodes)
{
	int i, j, count, *list, minfree_pct, target_node, next_node;

	j = 0;
	count = refs[0];
	for (i = 1; i < nodes; i++) {
		if (!count && (refs[i] > 0)) {
			count = refs[i];
			j = i;
			continue;
		}

		if ((refs[i] > 0) && (refs[i] < count)) {
			count = refs[i];
			j = i;
			continue;
		}
	}

	if (!count)
		return node;

	target_node = j;

	minfree_pct = freemem_threshold();

	/*
	 * For downgrade try nodes with hop 1 or more from the target node.
	 */
	nodes = (nodes > 2) ? nodes : 2;
	for (i = 1; i < nodes; i++) {
		if (nodes_at_hop_or_tier(target_node, i, &count, &list))
			continue;

		if (count == 0)
			continue;

		for (j = 0; j < count; j++) {
			next_node = list[j];

			if (node_freemem_get(next_node) >= minfree_pct)
				return next_node;
		}
	}

	return node;
}

static int get_target_node_generic_tier(int node,
					bool upgrade,
					unsigned int *ref_counts,
					int nodes)
{

	if (upgrade) 
		return get_target_node_generic_tier_upgrade(node, ref_counts,
							    nodes);
	return get_target_node_generic_tier_downgrade(node, ref_counts,
						      nodes);
}

static int get_target_node_tier_int(int node, bool upgrade)
{
	int tier, next_tier, target_node, idx;
	struct numa_node_mem *nodep;
	int minfree_pct;

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

	minfree_pct = freemem_threshold();
	if (node_freemem_get(target_node) >= minfree_pct)
		return target_node;

	return node;
}

static int get_target_node_tier(int node,
				bool upgrade,
				unsigned int *ref_counts,
				int nodes)
{
	if (default_tier)
		return get_target_node_generic_tier(node, upgrade, ref_counts,
						    nodes);

	return get_target_node_tier_int(node, upgrade);
}

static int cmp_distance(const void *p1, const void *p2)
{
	const struct node_list  *n1 = p1, *n2 = p2;

	return n1->distance - n2->distance;
}

static void arrange_neighbours(int node,
			       struct node_list *list,
			       int nodes)
{
	int i;

	for (i = 0; i < nodes; i++) {
		list[i].node = i;
		list[i].distance = numa_table[node].distance[i];
	}

	qsort(list, nodes, sizeof(*list), cmp_distance);

}

static void init_generic_tier_elem(int node, int max_nodes)
{
	struct node_list node_list[MAX_NUMA_NODES];
	int i, j, distance, nodes;

	arrange_neighbours(node, node_list, max_nodes);

	distance = node_list[0].distance;
	j = 0;
	nodes = 0;

	for (i = 0; i < max_nodes; i++) {
		if (distance == node_list[i].distance) {
			generic_tier[node][j].node[nodes++] = node_list[i].node;
			generic_tier[node][j].max_nodes = nodes;
		} else {
			nodes = 0;
			generic_tier[node][++j].node[nodes++] =
							node_list[i].node;
			distance = node_list[i].distance;
			generic_tier[node][j].max_nodes = nodes;
		}
	}
}

int nodes_at_hop_or_tier(int node, int hop_or_tier, int *countp, int **listpp)
{
	int count;

	if (node > max_nodes)
		return -EINVAL;

	count = generic_tier[node][hop_or_tier].max_nodes;
	if (count <= 0)
		return -EINVAL;

	*countp = count;
	*listpp = generic_tier[node][hop_or_tier].node;

	return 0;
}

static int process_generic_tier(int max_numa)
{
	int i;

	if (!max_numa)
		return -EINVAL;

	for (i = 0; i < max_numa; i++)
		init_generic_tier_elem(i, max_numa);

	if (verbose <= 3)
		return 0;

	for (i = 0; i < max_numa; i++) {
		int j, count, *nodes, k;

		printf("\n");
		for (j = 0; j < max_numa; j++) {
			if (nodes_at_hop_or_tier(i, j, &count, &nodes))
				break;

			printf("For node %d, ", i);

			if (count > 1)
				printf("nodes at hop %d nodes: ", j);
			else
				printf("node at hop %d node: ", j);

			for (k = 0; k < count; k++)
				printf("%d, ", nodes[k]);

			printf("total nodes %d\n", count);
		}
	}

	return 0;
}

int init_generic_tier(void)
{
	return process_generic_tier(max_nodes);
}

int init_tier(char *args)
{
	int err;

	if (!args || args[0] == 0) {
		err = process_generic_tier(max_nodes);
		if (!err) {
			default_tier = true;
			mem_tiers = max_nodes;
		}
	} else {
		err = process_numa_tier_args(args, mem_tier, max_nodes);
	}

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
	int i, k, target_node, upgrade_pct;
	unsigned long count, pages = 0;

	k = (fetch_samples_cnt[node] * pct) / 100;

	for (i = fetch_samples_cnt[node] - 1; i > -1; i--) {
		float pct;

		if (!fetch_samples[node][i].count)
			continue;
		if (--k < 0) {
			fetch_samples[node][i].count = 0;
			break;
		}

		count = fetch_samples[node][i].count;
		pct  = (float)fetch_samples[node][i].count * 100;
		pct /= total;

		if ((!l3miss && (pct < MIN_PCT)) || count < MIN_CNT) {
			fetch_samples[node][i].count = 0;
			continue;
		}

		if (!user_space_only && IBS_KERN_SAMPLE(
						fetch_samples[node][i].ip)) {
			fetch_samples[node][i].count = 0;
			continue;
		}

		if (balancer_mode)
			target_node = get_target_node_tier(node, true,
						fetch_samples[node][i].counts,
						max_nodes);
    		else
			target_node = node;

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
	int i, k, target_node, upgrade_pct;
	unsigned long count, pages = 0;

	k = (op_samples_cnt[node] * pct) / 100;

	for (i = op_samples_cnt[node] - 1; i > -1; i--) {
		float pct;

		if (!op_samples[node][i].count)
			continue;

		if (--k < 0) {
			op_samples[node][i].count = 0;
			continue;
		}

		count = op_samples[node][i].count;
		pct  = (float)op_samples[node][i].count * 100;
		pct /= total;

		if ((!l3miss && (pct < MIN_PCT)) || count < MIN_CNT) {
			op_samples[node][i].count = 0;
			continue;
		}

		if (!user_space_only && IBS_KERN_SAMPLE(
			op_samples[node][i].op_regs[IBS_OP_RIP])) {
			op_samples[node][i].count = 0;
			continue;
   		}

		if (balancer_mode)
			target_node = get_target_node_tier(node, true,
						op_samples[node][i].counts,
						max_nodes);
    		else
			target_node = node;

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
	int tier, upgrade_pct;
	unsigned long pages;

	assert(node >= 0 && node < max_nodes);

	tier = numa_table[node].tierno;

	if (default_tier)
		upgrade_pct = GENERIC_TIER_MIGRATION_PCT;
	else
		upgrade_pct = mem_tier[tier].upgrade_pct;

	if (upgrade_pct == 0)
		return 0;

	if (fetch)
		pages = upgrade_fetch_sample(rootpp, balancer_mode, total,
					     user_space_only, node,
					     upgrade_pct);
	else
		pages = upgrade_op_sample(rootpp, balancer_mode, total,
					  user_space_only, node,
					  upgrade_pct);

	return pages;
}

static void downgrade_fetch_sample(struct bst_node **rootpp, bool balancer_mode,
				   unsigned long total, bool user_space_only,
				   int node, int pct, unsigned long *pagesp)
{
	int i, k, target_node, upgrade_pct;
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

		if (!user_space_only && IBS_KERN_SAMPLE(
						fetch_samples[node][i].ip)) {
			fetch_samples[node][i].count = 0;
			continue;
		}

		if (balancer_mode)
			target_node = get_target_node_tier(node, false,
						fetch_samples[node][i].counts,
						max_nodes);
    		else
			target_node = node;

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
	int i, k, target_node, upgrade_pct;
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

		if (!user_space_only && IBS_KERN_SAMPLE(
			op_samples[node][i].op_regs[IBS_OP_RIP])) {
			op_samples[node][i].count = 0;
			continue;
   		}

		if (balancer_mode)
			target_node = get_target_node_tier(node, false,
						op_samples[node][i].counts,
						max_nodes);
    		else
			target_node = node;

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
	int tier, downgrade_pct;
	assert(node >= 0 && node < max_nodes);

	tier = numa_table[node].tierno;

	if (default_tier)
		downgrade_pct = GENERIC_TIER_MIGRATION_PCT;
	else
		downgrade_pct = mem_tier[tier].downgrade_pct;
	

	if (downgrade_pct == 0)
		return;

	if (fetch)
		downgrade_fetch_sample(rootpp, balancer_mode, total,
				       user_space_only, node,
				       downgrade_pct,
				       pagesp);
	else
		downgrade_op_sample(rootpp, balancer_mode, total,
				    user_space_only, node,
				    downgrade_pct,
				    pagesp);
}

static int upgrade_downgrade_ratio(void)
{
	int i, sum_down_pct, sum_up_pct;

	sum_down_pct = 0;
	sum_up_pct  = 0;

	for (i = 0; i < mem_tiers; i++) {
		if (default_tier) {
			sum_up_pct   += GENERIC_TIER_MIGRATION_PCT;
			sum_down_pct += GENERIC_TIER_MIGRATION_PCT;

		} else {
			sum_up_pct   += mem_tier[i].upgrade_pct;
			sum_down_pct += mem_tier[i].downgrade_pct;
		}
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
