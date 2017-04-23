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
#ifndef _STEELY_POSIX_SEM_H
#define _STEELY_POSIX_SEM_H

#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <steely/thread.h>
#include <steely/registry.h>
#include <steely/posix/syscall.h>
#include <steely/posix/process.h>

struct steely_process;
struct filename;

struct steely_sem {
	unsigned int magic;
	struct xnsynch synchbase;
	struct steely_sem_state *state;
	int flags;
	unsigned int refs;
	struct filename *pathname;
	struct steely_resnode resnode;
};

/* Copied from Linuxthreads semaphore.h. */
struct _sem_fastlock
{
  long int __status;
  int __spinlock;
};

typedef struct
{
  struct _sem_fastlock __sem_lock;
  int __sem_value;
  long __sem_waiting;
} sem_t;

#include <uapi/steely/sem.h>

#define SEM_VALUE_MAX	(INT_MAX)
#define SEM_FAILED	NULL
#define SEM_NAMED	0x80000000

struct steely_sem_shadow __user *
__steely_sem_open(struct steely_sem_shadow __user *usm,
		  const char __user *u_name,
		  int oflags, mode_t mode, unsigned int value);

int __steely_sem_timedwait(struct steely_sem_shadow __user *u_sem,
			   const void __user *u_ts,
			   int (*fetch_timeout)(struct timespec *ts,
						const void __user *u_ts));

int __steely_sem_destroy(xnhandle_t handle);

void steely_nsem_reclaim(struct steely_process *process);

struct steely_sem *
__steely_sem_init(const char *name, struct steely_sem_shadow *sem,
		  int flags, unsigned value);

STEELY_SYSCALL_DECL(sem_init,
		    (struct steely_sem_shadow __user *u_sem,
		     int flags, unsigned value));

STEELY_SYSCALL_DECL(sem_post,
		    (struct steely_sem_shadow __user *u_sem));

STEELY_SYSCALL_DECL(sem_wait,
		    (struct steely_sem_shadow __user *u_sem));

STEELY_SYSCALL_DECL(sem_timedwait,
		    (struct steely_sem_shadow __user *u_sem,
		     struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(sem_trywait,
		    (struct steely_sem_shadow __user *u_sem));

STEELY_SYSCALL_DECL(sem_getvalue,
		    (struct steely_sem_shadow __user *u_sem,
		     int __user *u_sval));

STEELY_SYSCALL_DECL(sem_destroy,
		    (struct steely_sem_shadow __user *u_sem));

STEELY_SYSCALL_DECL(sem_open,
		    (struct steely_sem_shadow __user *__user *u_addrp,
		     const char __user *u_name,
		     int oflags, mode_t mode, unsigned int value));

STEELY_SYSCALL_DECL(sem_close,
		    (struct steely_sem_shadow __user *usm));

STEELY_SYSCALL_DECL(sem_unlink, (const char __user *u_name));

STEELY_SYSCALL_DECL(sem_broadcast_np,
		    (struct steely_sem_shadow __user *u_sem));

STEELY_SYSCALL_DECL(sem_inquire,
		    (struct steely_sem_shadow __user *u_sem,
		     struct steely_sem_info __user *u_info,
		     pid_t __user *u_waitlist,
		     size_t waitsz));

void steely_sem_reclaim(struct steely_resnode *node,
			spl_t s);

#endif /* !_STEELY_POSIX_SEM_H */
