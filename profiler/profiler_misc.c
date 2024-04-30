/*
 * profiler_misc.c - helper functions for profiler
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
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
#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"
#include "profiler_common.h"

static int get_next_address(char **strinout, u64 *numberout)
{
	char *str;
	char *endp;
	int i = 0;
	char *next, c;

	if (!strinout || !*strinout)
		return -EINVAL;

	str = next = *strinout;

	if (*str == 0)
		return -EINVAL;

	if (str[i++] != '0')
		return -EINVAL;

	if (str[i++] != 'x')
		return -EINVAL;

	while((str[i] >= '0' && str[i] <= '9') ||
	      (str[i] >= 'a' && str[i] <= 'f'))
		i++;

	c = str[i];
	str[i] = 0;
	*numberout = (u64)strtoul(next, &endp, 16);
	str[i] = c;
	*strinout = &str[i];

	return 0;
}

int profiler_parse_filter(char *str, struct profiler_filter *filter,
			  const int max_entries)
{
	u64 from, to;
	int i, err;

	if (!str)
		return 0;

	i = 0;

	err = 0;

	/*
	 * The format of filter parameters are a pair of addresses in hex,
	 * separated by :. The given filter 0xaaabbcc-0xbbccdd:0xeeeee-0xfffff,
	 * for instance is two such pairs of addresses.
	 */
	while (*str != 0) {
		/* First a hexadecimal address where the filter should begin */
		err = get_next_address(&str, &from);
		if (err)
			break;

		/* Next should be the separator hyphen */
		if (*str++ != '-') {
			err = -EINVAL;
			break;
		}

		/* Then a hexadecimal address where the filter should end */
		err = get_next_address(&str, &to);
		if (err)
			break;

		if (from > to) {
			err = -EINVAL;
			break;
		}

		/*
		 * If there is a second, third, ... pair of addresses, then
		 * it should be separated with colon.
		 */
		if (*str == ':')
			str++;

		filter[i].addr_begin = from;
		filter[i].addr_end   = to;
		i++;
	}

	if (err)
		return err;

	return i;
}

int profiler_fill_filter(struct bpf_object *obj, struct profiler_filter *filter,
			  int max_entries)
{
	int fd, i;

	fd = bpf_object__find_map_fd_by_name(obj, "profiler_filter_map");
	if (fd < 0)
		return -errno;

	for (i = 0; i < max_entries; i++)
		bpf_map_update_elem(fd, &i, &filter[i], BPF_NOEXIST);

	return 0;
}
