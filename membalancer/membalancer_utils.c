/*
 * membalancer_utils.c - placeholder for helper routines.
 *
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
#define _GNU_SOURCE
#include<string.h>
#include<stdint.h>
#include<cpuid.h>
#include<stdbool.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<assert.h>
#include<errno.h>
#include<pthread.h>
#include<limits.h>
#include<stdatomic.h>
#include<time.h>
#include<signal.h>
#include <sched.h>
#include "memory_profiler_common.h"
#include "memory_profiler_arch.h"
#include "thread_pool.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"

#define VENDOR_ID_LEN 12  /* cpu vendor id length in bytes */
#define REG_COUNT 3   /* number of registers to read cpu vendor id */

#define KB 1024ul
#define MB (1024ul * KB)
#define GB (1024ul * MB)
#define TB (1024ul * GB)

enum {
	VENDOR_AMD,
    /*  VENDOR_INTEL, */
	MAX_VENDOR_ID,
};

cpu_set_t *cpusetp;

#ifdef CPU_LEVEL_MIG

#define num_dword 8

typedef int  dword_t;

#define BITS_PER_DWORD  (sizeof(dword_t) * CHAR_BIT)

struct free_cpu {
    int free_cpu_map[num_dword];
};

struct free_cpu per_node_free_cpu[MAX_NUMA_NODES];

#endif

extern int timer_clock;
static struct cpu_utilinfo snap1[MAX_CPU_CORES];
static struct cpu_utilinfo snap2[MAX_CPU_CORES];

static void cpu_loadavg(union sigval timer_data);

typedef struct sigevent sigevent_t;
typedef struct itimerspec itimerspec_t;
typedef struct event_data {
	sigevent_t		sev;
	timer_t			timer_id;
	itimerspec_t	its;
} event_data_t;

typedef uint8_t cpu_vendor_t[VENDOR_ID_LEN];
static atomic_int pending_cpuload_cal;
static atomic_int error_status; /* thread error status */
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

	if (fgets(str, 100, fp) == NULL)
		return -EINVAL;

	while (idx < nr_cpus) {

		if(!CPU_ISSET(idx, cpusetp)) {
			idx++;
			continue;
		}
		if (fgets(str, 100, fp) == NULL)
			break;

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

static int start_timer(void)
{
	int err;
	event_data_t *event_data = (event_data_t *)malloc(sizeof(event_data_t));
	memset(event_data, 0, sizeof(event_data_t));

	event_data->sev.sigev_notify = SIGEV_THREAD;
	event_data->sev.sigev_notify_function = &cpu_loadavg;
	event_data->sev.sigev_value.sival_ptr = event_data;

	event_data->its.it_value.tv_sec  = timer_clock;

	/* create timer */
	err = timer_create(CLOCK_REALTIME, &event_data->sev, &event_data->timer_id);
	if (err != 0) return err;

	/* start timer */
	err = timer_settime(event_data->timer_id, 0, &event_data->its, NULL);
	if (err != 0)
	{
		timer_delete(event_data->timer_id);
		free(event_data);
		return err;
	}

	return 0;
}

static void cpu_loadavg(union sigval timer_data)
{
	int err, cpu, i, node;
	event_data_t *event_data = (event_data_t *)timer_data.sival_ptr;
	timer_t timer_id = event_data->timer_id;

	memset(snap2, 0, MAX_CPU_CORES * sizeof(struct cpu_utilinfo));

	err = get_cpu_util(snap2);
	if (err) {
		atomic_store(&error_status, 1);
		return;
	}

	for (cpu = 0; cpu < MAX_CPU_CORES; cpu++ ) {
		if (numa_cpu[cpu] == -1)
			continue;

		node = numa_cpu[cpu];
		double total_delta = snap2[cpu].totaltime- snap1[cpu].totaltime;
		double idle_delta = snap2[cpu].idletime - snap1[cpu].idletime;
		double util  = 100.0 * (1.0 - idle_delta / total_delta);
		numa_node_loadavg[node] += util;

		if ((100 - util) > CPU_IDLE_THRESHOLD) {
			idle_cpu_cnt[node]++;
#ifdef CPU_LEVEL_MIG
			set_idle_cpu(cpu, node);
#endif
		}
	}

	for (i = 0; i < max_nodes; i++) {
		if (!numa_node_cpu[i].cpu_cnt) {
			/* Node without CPU */
			numa_node_loadavg[i] = 100;
			idle_cpu_cnt[i] = 0;
			continue;
		}
		numa_node_loadavg[i] /= numa_node_cpu[i].cpu_cnt;
	}
	atomic_store(&pending_cpuload_cal, 0);
	timer_delete(timer_id);
	free(event_data);

	return;
}

void update_node_loadavg(void *arg)
{
	int err;

	atomic_init(&pending_cpuload_cal, 1);
	atomic_init(&error_status, 0);
	memset(snap1, 0, MAX_CPU_CORES * sizeof(struct cpu_utilinfo));
	memset(idle_cpu_cnt, 0, MAX_NUMA_NODES * sizeof(int));
	memset(numa_node_loadavg, 0, MAX_NUMA_NODES * sizeof(double));
#ifdef CPU_LEVEL_MIG
	memset(per_node_free_cpu, 0, max_nodes * sizeof(struct free_cpu));
#endif
	err = get_cpu_util(snap1);
	if (err) {
		atomic_store(&error_status, 1);
		return;
	}

	err = start_timer();
	if (err)
		atomic_store(&error_status, 1);
}

int get_node_loadavg(int node)
{
	if(atomic_load(&pending_cpuload_cal) &&
			!atomic_load(&error_status)) {
		usleep(500 * 1000);
		if(atomic_load(&pending_cpuload_cal) ||
				atomic_load(&error_status))
			return INT_MAX;
	}

	return numa_node_loadavg[node];
}

#ifdef CPU_LEVEL_MIG

void set_idle_cpu(int cpu, int node) {
	int *dword_val;
	int *cpu_map;
	int dword_idx;

	cpu_map = per_node_free_cpu[node].free_cpu_map;
	dword_idx = cpu/BITS_PER_DWORD;
	dword_val = &cpu_map[dword_idx];
	*dword_val |= ( (unsigned)1 << (cpu & (BITS_PER_DWORD -1)));
}

int get_next_idle_cpu(int node)
{
	int *cpu_map;
	cpu_map = per_node_free_cpu[node].free_cpu_map;

	int *dword_val;
	int fetched_cpu = -EINVAL;

	for (int i = 0; i < num_dword; i++ ) {
		dword_val = &cpu_map[i];
		if (!*dword_val)
			continue;

		fetched_cpu = __builtin_ffs(*dword_val);
		fetched_cpu -= 1;
		fetched_cpu += i * BITS_PER_DWORD;
		break;
	}

	if (fetched_cpu == -EINVAL)
		return -EINVAL;

	assert((fetched_cpu >= 0) && (fetched_cpu < MAX_CPU_CORES));

	/* Mark it busy */
	*dword_val &= (*dword_val -1);

	return fetched_cpu;
}

#endif

unsigned long get_bytecount(char unit, unsigned int size)
{
	unsigned long scale = 0;

	switch (unit) {
	case 'K':
		scale = KB;
		break;
	case 'M':
		scale =  MB;
		break;
	case 'G':
		scale = GB;
		break;
	case 'T':
		scale = TB;
		break;
	default :
		break;
	}
	return scale * (unsigned long) size;
}

unsigned long milliseconds_elapsed(struct timeval *start,
		struct timeval *end)
{
    unsigned long milliseconds;

    milliseconds = (end->tv_sec - start->tv_sec) * 1000UL;
    milliseconds += (end->tv_usec - start->tv_usec) / 1000;

    return milliseconds;
}
