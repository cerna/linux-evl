obj-$(CONFIG_STEELY) += steely.o rtdm/ posix/

steely-y :=	arith.o 	\
		bufd.o		\
		clock.o		\
		coreclk.o	\
		heap.o		\
		init.o		\
		intr.o		\
		lock.o		\
		registry.o	\
		sched-idle.o	\
		sched-rt.o	\
		sched.o		\
		select.o	\
		synch.o		\
		thread.o	\
		timer.o		\
		tree.o

steely-$(CONFIG_STEELY_SCHED_QUOTA) += sched-quota.o
steely-$(CONFIG_STEELY_SCHED_WEAK) += sched-weak.o
steely-$(CONFIG_STEELY_SCHED_SPORADIC) += sched-sporadic.o
steely-$(CONFIG_STEELY_SCHED_TP) += sched-tp.o
steely-$(CONFIG_STEELY_DEBUG) += debug.o
steely-$(CONFIG_STEELY_PIPE) += pipe.o
steely-$(CONFIG_STEELY_MAP) += map.o
steely-$(CONFIG_PROC_FS) += vfile.o procfs.o
