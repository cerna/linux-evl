obj-$(CONFIG_STEELY) += steely.o rtdm/ posix/

ccflags-y += -Ikernel

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
		syscall.o	\
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
steely-$(CONFIG_STEELY_ARCH_SYS3264) += compat.o syscall32.o
steely-$(CONFIG_PROC_FS) += vfile.o procfs.o

syscall_entries := $(srctree)/$(src)/gen-syscall-entries.sh

quiet_cmd_syscall_entries = GEN     $@
      cmd_syscall_entries = $(CONFIG_SHELL) '$(syscall_entries)' $^ > $@

$(obj)/syscall_entries.h: $(syscall_entries) $(wildcard $(srctree)/$(src)/*.c) $(wildcard $(srctree)/$(src)/posix/*.c)
	$(call if_changed,syscall_entries)

target += syscall_entries.h

$(obj)/syscall.o: $(obj)/syscall_entries.h
