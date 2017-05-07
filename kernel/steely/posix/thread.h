/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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
#ifndef _STEELY_POSIX_THREAD_H
#define _STEELY_POSIX_THREAD_H

#include <stdarg.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/signal.h>
#include <steely/thread.h>
#include <uapi/steely/thread.h>
#include <uapi/steely/sched.h>
/* CAUTION: steely/steely.h reads this header. */
#include <steely/posix/syscall.h>
#include <steely/extension.h>

#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED  1

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

#define PTHREAD_INHERIT_SCHED  0
#define PTHREAD_EXPLICIT_SCHED 1

#define PTHREAD_MUTEX_NORMAL     0
#define PTHREAD_MUTEX_RECURSIVE  1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT    0

struct steely_thread;
struct steely_threadstat;

/*
 * pthread_mutexattr_t and pthread_condattr_t fit on 32 bits, for
 * compatibility with libc.
 */

/* The following definitions are copied from linuxthread pthreadtypes.h. */
struct _pthread_fastlock {
	long int __status;
	int __spinlock;
};

typedef struct {
	struct _pthread_fastlock __c_lock;
	long __c_waiting;
	char __padding[48 - sizeof (struct _pthread_fastlock)
		       - sizeof (long) - sizeof (long long)];
	long long __align;
} pthread_cond_t;

enum {
	PTHREAD_PRIO_NONE,
	PTHREAD_PRIO_INHERIT,
	PTHREAD_PRIO_PROTECT
};

typedef struct {
	int __m_reserved;
	int __m_count;
	long __m_owner;
	int __m_kind;
	struct _pthread_fastlock __m_lock;
} pthread_mutex_t;

int __steely_thread_create(unsigned long pth, int policy,
			   struct sched_param_ex __user *u_param,
			   int xid, __u32 __user *u_winoff);

int __steely_thread_setschedparam_ex(struct steely_thread *thread, int policy,
				     const struct sched_param_ex *param_ex);

int steely_thread_setschedparam_ex(unsigned long pth,
				   int policy,
				   const struct sched_param_ex *param_ex,
				   __u32 __user *u_winoff,
				   int __user *u_promoted);

int steely_thread_getschedparam_ex(unsigned long pth,
				   int *policy_r,
				   struct sched_param_ex *param_ex);

int __steely_thread_getschedparam_ex(struct steely_thread *thread,
				     int *policy_r,
				     struct sched_param_ex *param_ex);

struct steely_thread *steely_thread_find(pid_t pid);

struct steely_thread *steely_thread_find_local(pid_t pid);

struct steely_thread *steely_thread_lookup(unsigned long pth);

STEELY_SYSCALL_DECL(thread_create,
		    (unsigned long pth, int policy,
		     struct sched_param_ex __user *u_param,
		     int xid, __u32 __user *u_winoff));

struct steely_thread *
steely_thread_shadow(struct task_struct *p,
		     struct steely_local_hkey *lhkey,
		     __u32 __user *u_winoff);

STEELY_SYSCALL_DECL(thread_setmode,
		    (int clrmask, int setmask, int __user *u_mode_r));

STEELY_SYSCALL_DECL(thread_setname,
		    (unsigned long pth, const char __user *u_name));

STEELY_SYSCALL_DECL(thread_kill, (unsigned long pth, int sig));

STEELY_SYSCALL_DECL(thread_join, (unsigned long pth));

STEELY_SYSCALL_DECL(thread_getpid, (unsigned long pth));

STEELY_SYSCALL_DECL(thread_getstat,
		    (pid_t pid, struct steely_threadstat __user *u_stat));

STEELY_SYSCALL_DECL(thread_setschedparam_ex,
		    (unsigned long pth,
		     int policy,
		     const struct sched_param_ex __user *u_param,
		     __u32 __user *u_winoff,
		     int __user *u_promoted));

STEELY_SYSCALL_DECL(thread_getschedparam_ex,
		    (unsigned long pth,
		     int __user *u_policy,
		     struct sched_param_ex __user *u_param));

#endif /* !_STEELY_POSIX_THREAD_H */
