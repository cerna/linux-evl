/*
 * Copyright (C) 2013 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef _STEELY_POSIX_PROCESS_H
#define _STEELY_POSIX_PROCESS_H

#include <linux/list.h>
#include <linux/bitmap.h>
#include <steely/ppd.h>

#define NR_PERSONALITIES  4
#if BITS_PER_LONG < NR_PERSONALITIES
#error "NR_PERSONALITIES overflows internal bitmap"
#endif

struct mm_struct;
struct xnthread_personality;
struct steely_timer;

struct steely_resources {
	struct list_head condq;
	struct list_head mutexq;
	struct list_head semq;
	struct list_head monitorq;
	struct list_head eventq;
	struct list_head schedq;
};

struct steely_process {
	struct mm_struct *mm;
	struct hlist_node hlink;
	struct steely_ppd sys_ppd;
	unsigned long permap;
	struct rb_root usems;
	struct list_head sigwaiters;
	struct steely_resources resources;
	DECLARE_BITMAP(timers_map, CONFIG_STEELY_NRTIMERS);
	struct steely_timer *timers[CONFIG_STEELY_NRTIMERS];
	void *priv[NR_PERSONALITIES];
	int ufeatures;
};

struct steely_resnode {
	struct steely_resources *scope;
	struct steely_process *owner;
	struct list_head next;
	xnhandle_t handle;
};

int steely_register_personality(struct xnthread_personality *personality);

int steely_unregister_personality(int xid);

struct xnthread_personality *steely_push_personality(int xid);

void steely_pop_personality(struct xnthread_personality *prev);

int steely_bind_core(int ufeatures);

int steely_bind_personality(unsigned int magic);

struct steely_process *steely_search_process(struct mm_struct *mm);

int steely_map_user(struct xnthread *thread, __u32 __user *u_winoff);

void *steely_get_context(int xid);

int steely_yield(ktime_t min, ktime_t max);

int steely_process_init(void);

extern struct list_head steely_thread_list;

extern struct steely_resources steely_global_resources;

static inline struct steely_process *steely_current_process(void)
{
	return dovetail_current_state()->process;
}

static inline struct steely_process *
steely_set_process(struct steely_process *process)
{
	struct dovetail_state *p = dovetail_current_state();
	struct steely_process *old;

	old = p->process;
	p->process = process;

	return old;
}

static inline struct steely_ppd *steely_ppd_get(int global)
{
	struct steely_process *process;

	if (global || (process = steely_current_process()) == NULL)
		return &steely_kernel_ppd;

	return &process->sys_ppd;
}

static inline struct steely_resources *steely_current_resources(int pshared)
{
	struct steely_process *process;

	if (pshared || (process = steely_current_process()) == NULL)
		return &steely_global_resources;

	return &process->resources;
}

static inline
void __steely_add_resource(struct steely_resnode *node, int pshared)
{
	node->owner = steely_current_process();
	node->scope = steely_current_resources(pshared);
}

#define steely_add_resource(__node, __type, __pshared)			\
	do {								\
		__steely_add_resource(__node, __pshared);		\
		list_add_tail(&(__node)->next,				\
			      &((__node)->scope)->__type ## q);		\
	} while (0)

static inline
void steely_del_resource(struct steely_resnode *node)
{
	list_del(&node->next);
}

extern struct xnthread_personality *steely_personalities[];

extern struct xnthread_personality steely_interface_personality;

#endif /* !_STEELY_POSIX_PROCESS_H */
