/*
 * Copyright (C) 2009 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_POSIX_SCHED_H
#define _STEELY_POSIX_SCHED_H

#include <linux/list.h>
#include <steely/sched.h>
#include <steely/posix/syscall.h>

struct steely_resources;
struct steely_process;

struct steely_sched_group {
#ifdef CONFIG_STEELY_SCHED_QUOTA
	struct xnsched_quota_group quota;
#endif
	struct steely_resources *scope;
	int pshared;
	struct list_head next;
};

int __steely_sched_weightprio(int policy,
			      const struct sched_param_ex *param_ex);

int __steely_sched_setconfig_np(int cpu, int policy,
				void __user *u_config,
				size_t len,
				union sched_config *(*fetch_config)
				(int policy, const void __user *u_config,
				 size_t *len),
				int (*ack_config)(int policy,
						  const union sched_config *config,
						  void __user *u_config));

ssize_t __steely_sched_getconfig_np(int cpu, int policy,
				    void __user *u_config,
				    size_t len,
				    union sched_config *(*fetch_config)
				    (int policy, const void __user *u_config,
				     size_t *len),
				    ssize_t (*put_config)(int policy,
							  void __user *u_config, size_t u_len,
							  const union sched_config *config,
							  size_t len));
int steely_sched_setscheduler_ex(pid_t pid,
				 int policy,
				 const struct sched_param_ex *param_ex,
				 __u32 __user *u_winoff,
				 int __user *u_promoted);

int steely_sched_getscheduler_ex(pid_t pid,
				 int *policy_r,
				 struct sched_param_ex *param_ex);

struct xnsched_class *
steely_sched_policy_param(union xnsched_policy_param *param,
			  int u_policy, const struct sched_param_ex *param_ex,
			  ktime_t *tslice_r);

STEELY_SYSCALL_DECL(sched_yield, (void));

STEELY_SYSCALL_DECL(sched_weightprio,
		    (int policy, const struct sched_param_ex __user *u_param));

STEELY_SYSCALL_DECL(sched_minprio, (int policy));

STEELY_SYSCALL_DECL(sched_maxprio, (int policy));

STEELY_SYSCALL_DECL(sched_setconfig_np,
		    (int cpu,
		     int policy,
		     union sched_config __user *u_config,
		     size_t len));

STEELY_SYSCALL_DECL(sched_getconfig_np,
		    (int cpu, int policy,
		     union sched_config __user *u_config,
		     size_t len));

STEELY_SYSCALL_DECL(sched_setscheduler_ex,
		    (pid_t pid,
		     int policy,
		     const struct sched_param_ex __user *u_param,
		     __u32 __user *u_winoff,
		     int __user *u_promoted));

STEELY_SYSCALL_DECL(sched_getscheduler_ex,
		    (pid_t pid,
		     int __user *u_policy,
		     struct sched_param_ex __user *u_param));

void steely_sched_reclaim(struct steely_process *process);

#endif /* !_STEELY_POSIX_SCHED_H */
