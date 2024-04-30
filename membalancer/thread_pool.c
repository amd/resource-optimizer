/*
 *
 * thread_pool.c - thread management for membalancer tool
 *
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
#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>
#include<stdbool.h>
#include<assert.h>

#include "thread_pool.h"
#include "list.h"

static void threadpool_wait(threadpool_t *tp);
static void *run(void *arg);
static void workqueue_init(struct clist_head *head);
static void workqueue_destroy(struct clist_head *head);
static work_t * workqueue_pull(struct clist_head *head);

threadpool_t *
threadpool_create(int num_threads)
{
	int i;
	int err;
	threadpool_t *tp;

	tp = (threadpool_t *) malloc(sizeof(threadpool_t));
	if (tp == NULL) {
		printf("Failed to create threadpool \n");
		return NULL;
	}
	memset(tp, 0, sizeof(*tp));

	tp->pool = (thread_t *) malloc(num_threads * sizeof(thread_t));
	if(tp->pool == NULL) {
		printf("Failed to create threadpool \n");
		free(tp);
		return NULL;
	}

	tp->stop = false;
	tp->thread_count = num_threads;
	pthread_mutex_init(&tp->work_mutex, NULL);
	pthread_cond_init(&tp->work_cond, NULL);
	pthread_cond_init(&tp->working_cond, NULL);

	workqueue_init(&tp->head);

	for (i = 0; i < num_threads; i++) {
		tp->pool[i].id = i;
		err = pthread_create(&tp->pool[i].pthread, NULL, run, tp);
		if (err) {
			printf("Failed to create threads \n");
			threadpool_destroy(tp);
			return NULL;
		}
		assert(tp->pool[i].pthread);
		pthread_detach(tp->pool[i].pthread);
	}
	return tp;
}

static void *run(void *arg)
{
	void (*func)(void *);
	void *func_arg;
	work_t *work;

	threadpool_t *tp = (threadpool_t *) arg;

	while (true) {
		pthread_mutex_lock(&tp->work_mutex);
		while (list_empty(&tp->head) && !tp->stop)
			pthread_cond_wait(&tp->work_cond, &tp->work_mutex);

		if (tp->stop)
			break;

		assert(!list_empty(&tp->head));

		work = workqueue_pull(&tp->head);
		tp->working_cnt++;
		pthread_mutex_unlock(&tp->work_mutex);

		work->func(work->arg);
		free(work);

		pthread_mutex_lock(&tp->work_mutex);
		tp->working_cnt--;
		if (tp->stop && tp->working_cnt == 0
				&& list_empty(&tp->head)) {
			pthread_cond_signal(&tp->working_cond);
		}
		pthread_mutex_unlock(&tp->work_mutex);
	}

	pthread_cond_signal(&tp->working_cond);
	pthread_mutex_unlock(&tp->work_mutex);

	return NULL;
}

void threadpool_destroy(threadpool_t *tp)
{
	if(tp->pool == NULL) return;

	pthread_mutex_lock(&tp->work_mutex);

	workqueue_destroy(&tp->head);
	tp->stop = true;
	pthread_cond_broadcast(&tp->work_cond);

	pthread_mutex_unlock(&tp->work_mutex);
	threadpool_wait(tp);

	pthread_mutex_destroy(&tp->work_mutex);
	pthread_cond_destroy(&tp->work_cond);
	pthread_cond_destroy(&tp->working_cond);
	free(tp->pool);
	free(tp);
}

static void threadpool_wait(threadpool_t *tp)
{
	pthread_mutex_lock(&tp->work_mutex);
	while (true) {
		if (!tp->stop || tp->working_cnt != 0)
			pthread_cond_wait(&tp->working_cond, &tp->work_mutex);
		 else
			break;
	}
	pthread_mutex_unlock(&tp->work_mutex);
}

static void workqueue_init(struct clist_head *head)
{
	init_list_head(head);
}

static work_t * workqueue_pull(struct clist_head *head)
{
	work_t *work;

	struct clist_head *iter = head->next;
	work = list_entry(iter, work_t, list_member);
	list_remove(&work->list_member);
	return work;
}

static int workqueue_push(struct clist_head *head, work_t *work)
{
	if (work == NULL)
		return -EINVAL;

	init_list_head(&work->list_member);
	list_insert_at_tail(&work->list_member, head);
	return 0;
}

int threadpool_add_work(threadpool_t *tp,
		void (*function_p)(void *), void *arg_p)
{
	work_t *work;

	work = (work_t *)malloc(sizeof(work_t));
	if (work == NULL)
		return -ENOMEM;

	work->func = function_p;
	work->arg = arg_p;

	pthread_mutex_lock(&tp->work_mutex);
	workqueue_push(&tp->head, work);
	pthread_cond_signal(&tp->work_cond);
	pthread_mutex_unlock(&tp->work_mutex);

	return 0;
}

static void workqueue_destroy(struct clist_head *head)
{
	struct clist_head *iter = head->next;
	work_t *work;

	while(!list_empty(head)) {
		work = list_entry(iter, work_t, list_member);
		iter = iter->next;
		list_remove(&work->list_member);
		free(work);
	}
}
