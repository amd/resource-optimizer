/*
 * Rate limiter: simple token bucket algorithm
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdbool.h>
#include <assert.h>

#include "memory_profiler_common.h"
#include "membalancer_utils.h"
#include "rate_limiter.h"

#define RMIN(a,b) (((a)<(b))?(a):(b))

struct rate_limiter {
	unsigned long bucket_capacity;
	unsigned long current_capacity;
	unsigned int refresh_rate;
	struct timeval last_updated;
};

rate_limiter_t *
ratelimiter_create(unsigned long capacity,
		unsigned int refresh_rate)
{
	rate_limiter_t *rt =
		(rate_limiter_t *) malloc(sizeof(rate_limiter_t));
	if (rt == NULL)
		return NULL;
	if (verbose > 3)
		printf("Bucket capacity %lu , Refresh rate %u\n",
				capacity, refresh_rate);
	gettimeofday(&rt->last_updated, NULL);
	rt->bucket_capacity = capacity;
	rt->refresh_rate = refresh_rate;
	rt->current_capacity = capacity;
	return rt;
}

static
void refresh_bucket(rate_limiter_t *rt)
{
	struct timeval current_time;
	unsigned long tokens;

	gettimeofday(&current_time, NULL);
	tokens = milliseconds_elapsed(&rt->last_updated , &current_time) *
							(unsigned long)rt->refresh_rate;
	rt->current_capacity = RMIN((rt->current_capacity + tokens),
							rt->bucket_capacity);
	rt->last_updated = current_time;
}

bool ratelimiter_grant(rate_limiter_t *rt,
		unsigned int token_request)
{
	static int light_semaphore;
	bool result;

	if (atomic_cmxchg(&light_semaphore, 0, 1))
			return false;

	refresh_bucket(rt);
	if (rt->current_capacity > 0 &&
		token_request <= rt->current_capacity) {
		rt->current_capacity -= token_request;
		result = true;
	} else {
		result = false;
	}
	assert(atomic_cmxchg(&light_semaphore, 1, 0) == 1);
	return result;
}

void ratelimiter_destroy(rate_limiter_t *rt)
{
	if (rt)
		free(rt);
}
