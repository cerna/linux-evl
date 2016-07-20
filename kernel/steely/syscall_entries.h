/* Automatically generated file; DO NOT EDIT. */

#define __STEELY_CALL_ENTRIES \
	__STEELY_CALL_ENTRY(sigwait) \
	__STEELY_CALL_ENTRY(sigtimedwait) \
	__STEELY_CALL_ENTRY(sigwaitinfo) \
	__STEELY_CALL_ENTRY(sigpending) \
	__STEELY_CALL_ENTRY(kill) \
	__STEELY_CALL_ENTRY(sigqueue) \
	__STEELY_CALL_ENTRY(timerfd_create) \
	__STEELY_CALL_ENTRY(timerfd_settime) \
	__STEELY_CALL_ENTRY(timerfd_gettime) \
	__STEELY_CALL_ENTRY(monitor_init) \
	__STEELY_CALL_ENTRY(monitor_enter) \
	__STEELY_CALL_ENTRY(monitor_wait) \
	__STEELY_CALL_ENTRY(monitor_sync) \
	__STEELY_CALL_ENTRY(monitor_exit) \
	__STEELY_CALL_ENTRY(monitor_destroy) \
	__STEELY_CALL_ENTRY(cond_init) \
	__STEELY_CALL_ENTRY(cond_destroy) \
	__STEELY_CALL_ENTRY(cond_wait_prologue) \
	__STEELY_CALL_ENTRY(cond_wait_epilogue) \
	__STEELY_CALL_ENTRY(mq_notify) \
	__STEELY_CALL_ENTRY(mq_open) \
	__STEELY_CALL_ENTRY(mq_close) \
	__STEELY_CALL_ENTRY(mq_unlink) \
	__STEELY_CALL_ENTRY(mq_getattr) \
	__STEELY_CALL_ENTRY(mq_timedsend) \
	__STEELY_CALL_ENTRY(mq_timedreceive) \
	__STEELY_CALL_ENTRY(migrate) \
	__STEELY_CALL_ENTRY(trace) \
	__STEELY_CALL_ENTRY(archcall) \
	__STEELY_CALL_ENTRY(get_current) \
	__STEELY_CALL_ENTRY(backtrace) \
	__STEELY_CALL_ENTRY(serialdbg) \
	__STEELY_CALL_ENTRY(mayday) \
	__STEELY_CALL_ENTRY(bind) \
	__STEELY_CALL_ENTRY(extend) \
	__STEELY_CALL_ENTRY(thread_setschedparam_ex) \
	__STEELY_CALL_ENTRY(thread_getschedparam_ex) \
	__STEELY_CALL_ENTRY(thread_create) \
	__STEELY_CALL_ENTRY(thread_setmode) \
	__STEELY_CALL_ENTRY(thread_setname) \
	__STEELY_CALL_ENTRY(thread_kill) \
	__STEELY_CALL_ENTRY(thread_join) \
	__STEELY_CALL_ENTRY(thread_getpid) \
	__STEELY_CALL_ENTRY(thread_getstat) \
	__STEELY_CALL_ENTRY(sem_init) \
	__STEELY_CALL_ENTRY(sem_post) \
	__STEELY_CALL_ENTRY(sem_wait) \
	__STEELY_CALL_ENTRY(sem_timedwait) \
	__STEELY_CALL_ENTRY(sem_trywait) \
	__STEELY_CALL_ENTRY(sem_getvalue) \
	__STEELY_CALL_ENTRY(sem_destroy) \
	__STEELY_CALL_ENTRY(sem_broadcast_np) \
	__STEELY_CALL_ENTRY(sem_inquire) \
	__STEELY_CALL_ENTRY(sem_open) \
	__STEELY_CALL_ENTRY(sem_close) \
	__STEELY_CALL_ENTRY(sem_unlink) \
	__STEELY_CALL_ENTRY(clock_getres) \
	__STEELY_CALL_ENTRY(clock_gettime) \
	__STEELY_CALL_ENTRY(clock_settime) \
	__STEELY_CALL_ENTRY(clock_nanosleep) \
	__STEELY_CALL_ENTRY(mutex_check_init) \
	__STEELY_CALL_ENTRY(mutex_init) \
	__STEELY_CALL_ENTRY(mutex_destroy) \
	__STEELY_CALL_ENTRY(mutex_trylock) \
	__STEELY_CALL_ENTRY(mutex_lock) \
	__STEELY_CALL_ENTRY(mutex_timedlock) \
	__STEELY_CALL_ENTRY(mutex_unlock) \
	__STEELY_CALL_ENTRY(corectl) \
	__STEELY_CALL_ENTRY(timer_delete) \
	__STEELY_CALL_ENTRY(timer_create) \
	__STEELY_CALL_ENTRY(timer_settime) \
	__STEELY_CALL_ENTRY(timer_gettime) \
	__STEELY_CALL_ENTRY(timer_getoverrun) \
	__STEELY_CALL_ENTRY(sched_minprio) \
	__STEELY_CALL_ENTRY(sched_maxprio) \
	__STEELY_CALL_ENTRY(sched_yield) \
	__STEELY_CALL_ENTRY(sched_setconfig_np) \
	__STEELY_CALL_ENTRY(sched_getconfig_np) \
	__STEELY_CALL_ENTRY(sched_weightprio) \
	__STEELY_CALL_ENTRY(sched_setscheduler_ex) \
	__STEELY_CALL_ENTRY(sched_getscheduler_ex) \
	__STEELY_CALL_ENTRY(select) \
	__STEELY_CALL_ENTRY(open) \
	__STEELY_CALL_ENTRY(socket) \
	__STEELY_CALL_ENTRY(close) \
	__STEELY_CALL_ENTRY(fcntl) \
	__STEELY_CALL_ENTRY(ioctl) \
	__STEELY_CALL_ENTRY(read) \
	__STEELY_CALL_ENTRY(write) \
	__STEELY_CALL_ENTRY(recvmsg) \
	__STEELY_CALL_ENTRY(sendmsg) \
	__STEELY_CALL_ENTRY(mmap) \
	/* end */
#define __STEELY_CALL_MODES \
	__STEELY_MODE(sigwait, primary) \
	__STEELY_MODE(sigtimedwait, nonrestartable) \
	__STEELY_MODE(sigwaitinfo, nonrestartable) \
	__STEELY_MODE(sigpending, primary) \
	__STEELY_MODE(kill, conforming) \
	__STEELY_MODE(sigqueue, conforming) \
	__STEELY_MODE(timerfd_create, lostage) \
	__STEELY_MODE(timerfd_settime, primary) \
	__STEELY_MODE(timerfd_gettime, current) \
	__STEELY_MODE(monitor_init, current) \
	__STEELY_MODE(monitor_enter, primary) \
	__STEELY_MODE(monitor_wait, nonrestartable) \
	__STEELY_MODE(monitor_sync, nonrestartable) \
	__STEELY_MODE(monitor_exit, primary) \
	__STEELY_MODE(monitor_destroy, primary) \
	__STEELY_MODE(cond_init, current) \
	__STEELY_MODE(cond_destroy, current) \
	__STEELY_MODE(cond_wait_prologue, nonrestartable) \
	__STEELY_MODE(cond_wait_epilogue, primary) \
	__STEELY_MODE(mq_notify, primary) \
	__STEELY_MODE(mq_open, lostage) \
	__STEELY_MODE(mq_close, lostage) \
	__STEELY_MODE(mq_unlink, lostage) \
	__STEELY_MODE(mq_getattr, current) \
	__STEELY_MODE(mq_timedsend, primary) \
	__STEELY_MODE(mq_timedreceive, primary) \
	__STEELY_MODE(migrate, current) \
	__STEELY_MODE(trace, adaptive) \
	__STEELY_MODE(archcall, current) \
	__STEELY_MODE(get_current, current) \
	__STEELY_MODE(backtrace, lostage) \
	__STEELY_MODE(serialdbg, current) \
	__STEELY_MODE(mayday, current) \
	__STEELY_MODE(bind, lostage) \
	__STEELY_MODE(extend, lostage) \
	__STEELY_MODE(thread_setschedparam_ex, conforming) \
	__STEELY_MODE(thread_getschedparam_ex, current) \
	__STEELY_MODE(thread_create, init) \
	__STEELY_MODE(thread_setmode, primary) \
	__STEELY_MODE(thread_setname, current) \
	__STEELY_MODE(thread_kill, conforming) \
	__STEELY_MODE(thread_join, primary) \
	__STEELY_MODE(thread_getpid, current) \
	__STEELY_MODE(thread_getstat, current) \
	__STEELY_MODE(sem_init, current) \
	__STEELY_MODE(sem_post, current) \
	__STEELY_MODE(sem_wait, primary) \
	__STEELY_MODE(sem_timedwait, primary) \
	__STEELY_MODE(sem_trywait, primary) \
	__STEELY_MODE(sem_getvalue, current) \
	__STEELY_MODE(sem_destroy, current) \
	__STEELY_MODE(sem_broadcast_np, current) \
	__STEELY_MODE(sem_inquire, current) \
	__STEELY_MODE(sem_open, lostage) \
	__STEELY_MODE(sem_close, lostage) \
	__STEELY_MODE(sem_unlink, lostage) \
	__STEELY_MODE(clock_getres, current) \
	__STEELY_MODE(clock_gettime, current) \
	__STEELY_MODE(clock_settime, current) \
	__STEELY_MODE(clock_nanosleep, primary) \
	__STEELY_MODE(mutex_check_init, current) \
	__STEELY_MODE(mutex_init, current) \
	__STEELY_MODE(mutex_destroy, current) \
	__STEELY_MODE(mutex_trylock, primary) \
	__STEELY_MODE(mutex_lock, primary) \
	__STEELY_MODE(mutex_timedlock, primary) \
	__STEELY_MODE(mutex_unlock, nonrestartable) \
	__STEELY_MODE(corectl, probing) \
	__STEELY_MODE(timer_delete, current) \
	__STEELY_MODE(timer_create, current) \
	__STEELY_MODE(timer_settime, primary) \
	__STEELY_MODE(timer_gettime, current) \
	__STEELY_MODE(timer_getoverrun, current) \
	__STEELY_MODE(sched_minprio, current) \
	__STEELY_MODE(sched_maxprio, current) \
	__STEELY_MODE(sched_yield, primary) \
	__STEELY_MODE(sched_setconfig_np, conforming) \
	__STEELY_MODE(sched_getconfig_np, conforming) \
	__STEELY_MODE(sched_weightprio, current) \
	__STEELY_MODE(sched_setscheduler_ex, conforming) \
	__STEELY_MODE(sched_getscheduler_ex, current) \
	__STEELY_MODE(select, primary) \
	__STEELY_MODE(open, lostage) \
	__STEELY_MODE(socket, lostage) \
	__STEELY_MODE(close, lostage) \
	__STEELY_MODE(fcntl, current) \
	__STEELY_MODE(ioctl, handover) \
	__STEELY_MODE(read, handover) \
	__STEELY_MODE(write, handover) \
	__STEELY_MODE(recvmsg, handover) \
	__STEELY_MODE(sendmsg, handover) \
	__STEELY_MODE(mmap, lostage) \
	/* end */
