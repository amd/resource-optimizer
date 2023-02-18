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
 */

#ifndef MIGRATE_PROCESS_H
#define MIGRATE_PROCESS_H

#define MAX_REMOTE_REF 50

struct ibs_noderef_sample {
    short target_node;
    unsigned long pid;
    unsigned long max_ref;
};

extern struct ibs_noderef_sample numa_reference[MAX_PROCESS_STATS_IDX];
int move_process(u32 max_count, bool sort);

#endif
