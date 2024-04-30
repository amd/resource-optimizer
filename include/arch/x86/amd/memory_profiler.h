/*
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
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

#ifndef _MEMORY_PROFILER_AMD_
#define _MEMORY_PROFILER_AMD_

#include "resource_manager_types.h"

extern int verbose;

enum {
	IBS_FETCH_EVENT,
	IBS_OP_EVENT,
};

enum {
	IBS_FETCH_CTL,
	IBS_FETCH_LINADDR,
	IBS_FETCH_PHYSADDR,
	IBSFETCH_REG_COUNT,
};

struct perf_ibs_fetch_data {
	u32 size;
	union {
		u32	data[0];	/* data buffer starts here */
		u32	caps;
	};
	u64 regs[IBSFETCH_REG_COUNT];
};

enum {
        IBS_OP_CTL,
        IBS_OP_RIP,
        IBS_OP_DATA,
        IBS_OP_DATA2,
        IBS_OP_DATA3,
        IBS_DC_LINADDR,
        IBS_DC_PHYSADDR,
        IBSOP_REG_COUNT,
};

#define IBS_FETCH_RAW_SIZE 36
#define IBS_OP_RAW_SIZE 68

#define IBS_FETCH_VALID_PHYSADDR (1ULL << 52)
#define IBS_FETCH_PHYSADDR_VALID(reg) (reg & IBS_FETCH_VALID_PHYSADDR)
#define IBS_OP_PHYSADDR_VALID(reg) (reg & (1UL << 18))
#define IBS_OP_LINADDR_VALID(reg) (reg & (1UL << 17))
#define IBS_FETCH_LLC_MISS_VAL   (1UL << 51)
#define IBS_FETCH_LLC_MISS(reg)  (reg & IBS_FETCH_LLC_MISS_VAL)
#define IBS_OP_LLC_MISS(reg) (reg & (1UL << 7))

/*
 * The following 4 definitions are independent of AMD hardware. Unable to remove
 * them at this time because of they are used in AMD specific functions.
 *
 * TO DO : Refactor in future to avoid this strong coupling between machine
 * indepdendent and dependent codes.
 */
#define MAX_NUMA_NODES 64
#define KERN_PAGE_OFFSET 0xffff880000000000
#define IBS_KERN_SAMPLE(ip) (ip > KERN_PAGE_OFFSET)
#define MAX_LATENCY_IDX 128

#define MAX_LBR_ENTRIES_ZEN4 16
#define MAX_LBR_ENTRIES MAX_LBR_ENTRIES_ZEN4
#endif
