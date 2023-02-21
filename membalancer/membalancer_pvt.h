/*
 * Copyright (c) 2023 Advanced Micro Devices, Inc.
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

#ifndef _MEMBALANCER_PVT_H_
#define _MEMBALANCER_PVT_H_
unsigned long my_page_size;
int ibs_op_event(struct bpf_perf_event_data *ctx,
		 struct value_op *op_data,
		 u64 *tgid, u64 *ip);
int ibs_fetch_event(struct bpf_perf_event_data *ctx,
		    struct value_fetch *fetch_data,
		    u64 *tgid, u64 *ip);

struct value_latency * get_value_latency(void);
struct process_stats * alloc_process_stats(void);
struct value_op * alloc_value_op(void);
struct value_fetch * alloc_value_fetch(void);
static void init_function(void);

#endif
