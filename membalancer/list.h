/*
 * Linked list management
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

#ifndef LIST_H
#define LIST_H
#include<stddef.h>
#include <stdbool.h>
#define list_entry(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		        (type *)( (char *)__mptr - offsetof(type,member) );})

struct clist_head {
	struct clist_head *next, *prev;
};

static inline
void init_list_head(struct clist_head *head)
{
	head->next = head;
	head->prev = head;
}

static inline
bool list_empty(const struct clist_head *head)
{
	return head->next == head;
}

/* Inserts entry at list end */
static inline
void list_insert_at_tail(struct clist_head *new,
		struct clist_head *head)
{
	struct clist_head *tail= head->prev;

	head->prev = new;
	new->next = head;
	new->prev = tail;
	tail->next = new;
}

/* removes entry from list */
static inline
void list_remove(struct clist_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}
#endif
