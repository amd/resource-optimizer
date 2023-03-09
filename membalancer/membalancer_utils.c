/*
 * membalancer_utils.c - place holder for helper routines.
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
#include<string.h>
#include<stdint.h>
#include<cpuid.h>
#include<stdbool.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <assert.h>
#include <errno.h>

#include "membalancer_utils.h"
#include "membalancer_numa.h"

#define VENDOR_ID_LEN 12  /* cpu vendor id length in bytes */
#define REG_COUNT 3   /* number of registers to read cpu vendor id */

enum {
	VENDOR_AMD,
    /*  VENDOR_INTEL, */
	MAX_VENDOR_ID,
};

typedef uint8_t cpu_vendor_t[VENDOR_ID_LEN];

/*
 * Currently supporting only with AMD CPUS
 * TODO add list of supported cpu vendors
 */
static const cpu_vendor_t cpu_vendor_id[MAX_VENDOR_ID] = { {"AuthenticAMD"},
						  /* {"GenuineIntel"} */ };

/* Function detects cpu vendor of host machine
 * and matches against supported cpu vendors
 */
bool cpuvendor_supported(void)
{
	uint32_t a = 0, id[REG_COUNT];
	int i;

	/*
	 * Reason for reordering id array
	 * example "AuthenticAMD" vendor in hex bytes 41757468  656e7469  63414d44
	 * whereas __cpuid reads register values of vendor id as
	 *  EAX: 10 EBX: 68747541 ECX: 444d4163 EDX: 69746e65
	 *  Assumption : Host machine is little endian
	 */
	__cpuid (0, a, id[0], id[2], id[1]);

	for (i = 0; i < MAX_VENDOR_ID; i++) {
		if (!memcmp(cpu_vendor_id[i], id, VENDOR_ID_LEN))
			return true;
	}
	return false;
}

void print_bar(int numa, bool text,
		bool process_context,
		bool cpu, double pct)
{
	char buffer[15];
	int i;
	char *title;

	if (is_tier_mode() && !is_default_tier_mode())
		title = "TIER";
	else
		title = "NUMA";

	if (text)
		printf("%s%s", BRIGHT, MAGENTA);
	else
		printf("%s%s", BRIGHT, BLUE);

	if (process_context)
		snprintf(buffer, sizeof(buffer), "%s%d(%s)",
				title, numa, cpu ? "CPU" : "MEMORY");
	else
		snprintf(buffer, sizeof(buffer), "%s%d(%s)",
				title, numa, text ? "CODE" : "DATA");

	printf("%-10s", buffer);
	printf("%s", NORM);

	i = pct * 60.0 / 100.0;

	if (pct >= 75.0)
		printf("%s", BRED);
	else if (pct >= 50.0)
		printf("%s", BMAGENTA);
	else if (pct >= 25.0)
		printf("%s", BBLUE);
	else if (pct >= 10.0)
		printf("%s", BGREEN);
	else
		printf("%s", BCYAN);

	do {
		if (text)
			printf("%c", 248);
		else
			printf("%c", 252);
	} while (--i > 0);

	printf("%s", NORM);
	if (text)
		printf("%s%s", BRIGHT, CYAN);
	else
		printf("%s%s", BRIGHT, CYAN);
	printf("%5.2lf%%", pct);
	printf("%s", NORM);
	printf("\n");
}

void print_text(u64 total_ref, u64 *numa_ref)
{
	double pct = 0.0;
	int i = 0;

	for (i = 0; i < MAX_NUMA_NODES; i++) {
		if (numa_ref[i] <= 0 || !total_ref)
			pct = 0.0;
		else
			pct = (((double)numa_ref[i]) * 100) / total_ref;
		if (pct >= 75.0)
			printf("%s", BRED);
		else if (pct >= 50.0)
			printf("%s", BMAGENTA);
		else if (pct >= 25.0)
			printf("%s", BBLUE);
		else if (pct >= 10.0)
			printf("%s", CYAN);
		else
			printf("%s", WHITE);

		printf("%-12.2lf", pct);
		printf("%s", NORM);
	}
}

unsigned long seconds_elapsed(struct timeval *start, struct timeval *end)
{
	unsigned long seconds;

	seconds = (end->tv_sec - start->tv_sec) * 1000UL * 1000;
	seconds += end->tv_usec - start->tv_usec;
	seconds /= 1000 * 1000;

	return seconds;
}

static double numa_node_loadavg[MAX_NUMA_NODES];
int idle_cpu_cnt[MAX_NUMA_NODES];

static int get_cpu_util(struct cpu_utilinfo *cpuutil)
{
	char str[100];
	const char d[2] = " ";
	char *token;
	int idx = 0, i = 0;
	long double totaltime, idletime;
	FILE *fp;

	fp = fopen("/proc/stat","r");
	if (!fp)
		return -errno;

	fgets(str, 100, fp);
	while (idx < nr_cpus && fgets(str, 100, fp) != NULL) {
		token = strtok(str,d);
		totaltime = 0;
		idletime = 0;
		while(token != NULL) {

			token = strtok(NULL,d);
			if(token != NULL){
				totaltime += atoi(token);
				if(i == IDLE_FIELD || i == IOWAIT_FIELD)
					idletime += atoi(token);

				assert(i < MAX_FIELDS);
				i++;
			}
		}
		i = 0;
		cpuutil[idx].idletime = idletime;
		cpuutil[idx].totaltime = totaltime;
		idx++;
	}
	fclose(fp);
	return 0;
}

/*
 * TODO make update_node_loadavg atomic for parallel
 * update and consumption.
 */
int update_node_loadavg(void)
{
	struct cpu_utilinfo snap1[MAX_CPU_CORES] = { 0 };
	struct cpu_utilinfo snap2[MAX_CPU_CORES] = { 0 };
	int node;
	int err;

	err = get_cpu_util(snap1);
	if (err)
		return err;
	sleep(1);
	err = get_cpu_util(snap2);
	if (err)
		return err;

	memset(idle_cpu_cnt, 0, MAX_NUMA_NODES * sizeof(int));
	memset(numa_node_loadavg, 0, MAX_NUMA_NODES * sizeof(double));

	for (int cpu = 0; cpu < MAX_CPU_CORES; cpu++ ) {
		if (numa_cpu[cpu] == -1)
			continue;

		node = numa_cpu[cpu];
		double total_delta = snap2[cpu].totaltime- snap1[cpu].totaltime;
		double idle_delta = snap2[cpu].idletime - snap1[cpu].idletime;
		double util  = 100.0 * (1.0 - idle_delta / total_delta);
		numa_node_loadavg[node] += util;

		if ((100 - util) > cpu_idle_threshold)
			idle_cpu_cnt[node]++;
	}

	for (int i = 0; i < max_nodes; i++) {
		if (!numa_node_cpu[i].cpu_cnt) {
			/* Node without CPU */
			numa_node_loadavg[i] = 100;
			idle_cpu_cnt[i] = 0;
			continue;
		}
		numa_node_loadavg[i] /= numa_node_cpu[i].cpu_cnt;
		/* Throttle the migration by throttling
		 * idle cpu capacity of each node.
		 */
		idle_cpu_cnt[i] /= migration_throttle_limit;
	}
	return 0;
}

int get_node_loadavg(int node)
{
	return numa_node_loadavg[node];
}
