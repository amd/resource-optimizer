/*
 * membalancer_utils.c - place holder for helper routines.
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
#include<string.h>
#include<stdint.h>
#include<cpuid.h>
#include<stdbool.h>
#include<stdio.h>

typedef unsigned int __u32, u32;
typedef unsigned long __u64, u64;
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
bool cpuvendor_supported()
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
