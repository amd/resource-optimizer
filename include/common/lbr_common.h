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

#ifndef _LBR_COMMON_H_
#define _LBR_COMMON_H_
#define MAX_LBR_SAMPLES (64 * 1024)
struct lbr_pbe_key {
	u64 tgid;
	u64 from;
	u64 to;
};

struct lbr_pbe_val {
	volatile u32 ref;
	u32 unique;
};

struct lbr_pbe_flags_key {
	u64 flags;
	u32 unique;
	u32 filler;
};

struct lbr_pbe_flags {
	volatile u32 ref;
};
#endif


