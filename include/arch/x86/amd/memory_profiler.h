/*
 * Copyright (c) 2023 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Process samples from IBS or software sampler and analyze the instruction and
 * data (if available) samples.
 */

#ifndef _MEMORY_PROFILER_AMD_
#define _MEMORY_PROFILER_AMD_
#include <linux/types.h>

typedef __u32 u32;
typedef __u64 u64;
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
