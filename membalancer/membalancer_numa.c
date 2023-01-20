/*
 * membalancer_numa.c -  Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
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

typedef unsigned int __u32, u32;
typedef unsigned long __u64, u64;
#include "membalancer.h"

#include "membalancer_utils.h"
#include "membalancer_numa.h"

int max_nodes;
struct numa_node_mem numa_table[MAX_NUMA_NODES];


#define PAGE_SIZE  4096 /*getpagesize()*/
#define PAGE_SHIFT 12
#define MIN_PCT 1.75

static unsigned long fetch_overall_samples[MAX_NUMA_NODES];
static unsigned long op_overall_samples[MAX_NUMA_NODES];

#define NUMA_NODE_INFO "/sys/devices/system/node"

static int init_numa_node(void **fpout)
{
        FILE *fp;
        char buffer[1024];
        int i;

        fp = popen("/usr/bin/cat /proc/zoneinfo|/usr/bin/grep start_pfn", "r");
        i = 0;
        while (fgets(buffer, sizeof(buffer) - 1, fp)) {
                if (i++ >= 1)
                        break;

        }

        *fpout = fp;

        return 0;
}

static void deinit_numa_node(void *handle)
{
        FILE *fp = handle;

        fclose(fp);
}

static int get_next_numa_distance(char **distance)
{
        int i, val;
        char *dist = *distance;

        i = 0;
        while (dist[i] != 0 && dist[i] != ' ')
                i++;

        if (dist[i] == ' ')
                *distance = &dist[++i];
        else
                *distance = NULL;

        val  = atoi(&dist[0]);

        return  val;
}


static int fill_numa_distances_for_node(int node)
{
        int fd, i, val;
        char path[1024];
        char buffer[1024];
        ssize_t bytes;
        char *bufferp;

        snprintf(path, sizeof(path), "%s/node%d/distance",
                NUMA_NODE_INFO, node);

        fd = open(path, O_RDONLY);
        if (fd < 0)
                return -1;

        bytes = read(fd,  buffer, sizeof(buffer));
        close(fd);

        bufferp = buffer;
        if (bytes <= 0)
                return -1;
        i = 0;
        while (bufferp) {
                val = get_next_numa_distance(&bufferp);
                numa_table[node].distance[i++] = val;
        }

        return 0;
}

static unsigned long numa_node_next(void *handle)
{
        FILE *fp;
        char buffer[1024];
        char *value;

        fp = handle;
        if (!fgets(buffer, 1024, fp))
                return (unsigned long)-1;

        value = strchr(buffer, ':');
        value++;

        while (*value != 0 && *value == ' ')
                value++;

        if (*value == 0)
                return (unsigned long)-1;

        return atol(value);
}

static int fill_numa_distances(void)
{
        int i, err;

        for (i = 0; i < max_nodes; i++) {
                err = fill_numa_distances_for_node(i);
                if (err)
                        return err;
        }

        return 0;
}


int fill_numa_table(void)
{
        void *handle;
        int err;
        int i, j, node = 0;
        unsigned long value, last_pfn;

        err = init_numa_node(&handle);
        if (err)
                return err;

        while ((value = numa_node_next(handle)) != -1) {
                numa_table[max_nodes].node = node++;
                numa_table[max_nodes].tierno = -1;
                numa_table[max_nodes].first_pfn = value;
                last_pfn  = value;
                last_pfn += (numa_node_size(max_nodes, NULL) / PAGE_SIZE);
                numa_table[max_nodes++].last_pfn = last_pfn;
                assert(last_pfn > numa_table[max_nodes].first_pfn);

        }

        /* FIXUP numa table */
        for (i = 0; i < max_nodes - 1; i++)
                numa_table[i].last_pfn = numa_table[i + 1].first_pfn - 1;

        deinit_numa_node(handle);
        fill_numa_distances();
        for (i = 0; i < max_nodes; i++) {
                printf("numa.%d ", i);
                for (j = 0; j < max_nodes; j++)
                        printf("%d ", numa_table[i].distance[j]);

                printf("\n");
        }

        if (verbose > 3) {
                for (i = 0; i < max_nodes; i++)
                        printf("NUMA %i 0x%lx-0x%lx 0x%lu\n", i,
                                numa_table[i].first_pfn * PAGE_SIZE,
                                numa_table[i].last_pfn * PAGE_SIZE,
                                PAGE_SIZE * (numa_table[i].last_pfn -
                                numa_table[i].first_pfn + 1));

        }

	return 0;
}

int get_current_node(unsigned long physaddr)
{
        int i;

        if (physaddr == (unsigned long)-1)
                return -1;

        physaddr >>= PAGE_SHIFT;

        for (i = max_nodes - 1; i > -1; i--) {
                if ((physaddr >= numa_table[i].first_pfn) &&
                    (physaddr <= numa_table[i].last_pfn))
                        return i;
        }

        return -1;
}

static int calcuate_weight(int node, unsigned int *counts, int numa_count)
{
        int weight, i;

        weight = 0;
        for (i = 0; i < numa_count; i++)
                weight += numa_table[node].distance[i] * counts[i];

        return weight;
}

int get_target_node_numa(int node, unsigned long count, unsigned int *counts,
			 int numa_count, unsigned long total_samples)
{
        int next_node;
        int i;
        int weight, weight_current, weight_min;
	unsigned long ccount = 0;

        next_node = 0;

        weight_current = calcuate_weight(node, counts, numa_count);
        weight_min = weight_current;
        for (i = 0; i < numa_count; i++) {
		ccount += counts[i];
                if (i == node)
                        continue;

                weight = calcuate_weight(i, counts, numa_count);
                if ((weight + (weight / 10)) < weight_min) {
                        weight_min = weight;
                        next_node = i;
                }
        }

        if ((weight_min + (weight_min / 10))<= weight_current)
                return next_node;

        return node;
}

void update_sample_statistics_numa(unsigned long *samples, bool fetch)
{
	int i;

	if (fetch) {
		for (i = 0; i < max_nodes; i++)
			fetch_overall_samples[i] = samples[i];
	} else {
		for (i = 0; i < max_nodes; i++)
			op_overall_samples[i] = samples[i];
	}
}

void get_sample_statistics_numa(bool fetch, unsigned long **samples, int *count)
{
 	*count   = max_nodes;
	*samples = (fetch) ? fetch_overall_samples : op_overall_samples;
}

void process_ibs_fetch_samples_numa(struct bst_node **rootpp,
				    unsigned long total,
				    bool balancer_mode,
				    bool user_space_only)
{
        int i, j, k, node, target_node;
        unsigned long count;
        bool hdr = true;

        if (!total)
                return;

        for (node = 0; node < max_nodes; node++) {
                k = (fetch_samples_cnt[node] * MIN_PCT) / 100;
                for (i = fetch_samples_cnt[node] - 1; i > -1; i--) {
                        float pct;

                        if (!fetch_samples[node][i].count)
                                continue;

                        if (--k < 0)  {
                                fetch_samples[node][i].count = 0;
                                continue;
                        }

                        count = 0;
                        for (j = 0; j < max_nodes; j++)
                                count += fetch_samples[node][i].counts[j];

                        pct  = (float)fetch_samples[node][i].count * 100;
                        pct /= total;

                        /*
                        if (pct < min_pct || count < MIN_CNT) {
                                fetch_samples[node][i].count = 0;
                                continue;
                        }
                        */


                        if (user_space_only &&
                                IBS_KERN_SAMPLE(
                                        fetch_samples[node][i].ip)) {

                                fetch_samples[node][i].count = 0;
                                continue;
                        }

                        if (balancer_mode) {
                                target_node = get_target_node_numa(node,
                                                fetch_samples[node][i].count,
                                                fetch_samples[node][i].counts,
                                                max_nodes, total);
                        } else {
                                target_node = node;
                        }


                        if (node != target_node) {
                                bst_add_page(fetch_samples[node][i].tgid,
                                        target_node,
                                        fetch_samples[node][i].fetch_regs[
                                                IBS_FETCH_LINADDR],
					true,
                                        rootpp);
                        }

                        fetch_samples[node][i].count = 0;

                }

        }
}

void process_ibs_op_samples_numa(struct bst_node **rootpp,
				 unsigned long total,
				 bool balancer_mode,
				 bool user_space_only)
{
        int i, j, k, node, target_node;
        unsigned long count;
        bool hdr = true;

        for (node = 0; node < max_nodes; node++) {
                k = (op_samples_cnt[node] * MIN_PCT) / 100;
                for (i = op_samples_cnt[node] - 1; i > -1; i--) {
                        float pct;

                        if (!op_samples[node][i].count)
                                continue;
                        if (--k < 0)  {
                                op_samples[node][i].count = 0;
                                continue;
                        }

                        count = 0;
                        for (j = 0; j < max_nodes; j++)
                                count += op_samples[node][i].counts[j];

                        pct  = (float)op_samples[node][i].count * 100;
                        pct /= total;
                        /*
                        if (pct < min_pct || count < MIN_CNT) {
                                op_samples[node][i].count = 0;
                                continue;
                        }
                        */

                        if (!user_space_only &&
                                IBS_KERN_SAMPLE(
                                op_samples[node][i].op_regs[IBS_OP_RIP])) {

                                op_samples[node][i].count = 0;
                                continue;
                        }

                        if (balancer_mode) {
                                target_node = get_target_node_numa(node,
                                                op_samples[node][i].count,
                                                op_samples[node][i].counts,
                                                max_nodes, total);
                        } else {
                                target_node = node;
                        }


                        if (node != target_node) {
                                bst_add_page(op_samples[node][i].tgid,
                                        target_node,
                                        op_samples[node][i].op_regs[
                                        IBS_DC_LINADDR],
					true,
                                        rootpp);
                        }

                        op_samples[node][i].count = 0;
                }
        }
}

int numa_range_get(int idx, struct numa_range *range)
{
	if (idx >= max_nodes)
		return -1;

	range->first_pfn = numa_table[idx].first_pfn;
	range->last_pfn  = numa_table[idx].last_pfn;
	range->node      = numa_table[idx].node;
	range->tier      = numa_table[idx].tierno;

	return 0;
}

