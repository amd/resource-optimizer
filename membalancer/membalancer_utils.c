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

#include "membalancer_utils.h"

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

	if (tier_mode)
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
