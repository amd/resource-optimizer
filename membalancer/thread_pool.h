/*
 * thread_pool.h - thread management for membalancer tool
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

#ifndef THREADPOOL_H
#define THREADPOOL_H
#include "list.h"

typedef struct work
{
	void	(*func)(void *arg);
	void	*arg;
	struct clist_head list_member;
} work_t;

typedef struct thread
{
	pthread_t	pthread;
	int			id;
} thread_t;

typedef struct theadpool
{
	size_t				thread_count;
	thread_t			*pool;
	struct clist_head	head;
	pthread_mutex_t		work_mutex;
	pthread_cond_t		work_cond;
	pthread_cond_t		working_cond;
	volatile size_t		working_cnt;
	bool				stop;
} threadpool_t;

threadpool_t *
threadpool_create(int num_threads);
int threadpool_add_work(threadpool_t *tp,
		void (*function_p)(void *), void *arg_p);
void threadpool_destroy(threadpool_t *tp);
#endif
