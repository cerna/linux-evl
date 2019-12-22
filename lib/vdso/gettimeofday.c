// SPDX-License-Identifier: GPL-2.0
/*
 * Generic userspace implementations of gettimeofday() and similar.
 */
#include <linux/compiler.h>
#include <linux/math64.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/hrtimer_defs.h>
#include <vdso/datapage.h>
#include <vdso/helpers.h>

/*
 * The generic vDSO implementation requires that gettimeofday.h
 * provides:
 * - __arch_get_vdso_data(): to get the vdso datapage.
 * - __arch_get_vdso_priv(): if CONFIG_GENERIC_CLOCKSOURCE_VDSO is enabled,
 *   to get the vdso private/per-process data page.
 * - __arch_get_hw_counter(): to get the hw counter based on the
 *   clock_mode.
 * - gettimeofday_fallback(): fallback for gettimeofday.
 * - clock_gettime_fallback(): fallback for clock_gettime.
 * - clock_getres_fallback(): fallback for clock_getres.
 */
#ifdef ENABLE_COMPAT_VDSO
#include <asm/vdso/compat_gettimeofday.h>
#else
#include <asm/vdso/gettimeofday.h>
#endif /* ENABLE_COMPAT_VDSO */

#ifdef CONFIG_GENERIC_CLOCKSOURCE_VDSO

#include <linux/fcntl.h>
#include <linux/io.h>
#include <linux/ioctl.h>
#include <uapi/linux/clocksource.h>

static notrace u64 readl_mmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return readl_relaxed(info->reg_lower);
}

static notrace u64 readl_mmio_down(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return ~(u64)readl_relaxed(info->reg_lower) & info->mask_lower;
}

static notrace u64 readw_mmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return readw_relaxed(info->reg_lower);
}

static notrace u64 readw_mmio_down(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return ~(u64)readl_relaxed(info->reg_lower) & info->mask_lower;
}

static notrace u64 readl_dmmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	void __iomem *reg_lower, *reg_upper;
	u32 upper, old_upper, lower;

	reg_lower = info->reg_lower;
	reg_upper = info->reg_upper;

	upper = readl_relaxed(reg_upper);
	do {
		old_upper = upper;
		lower = readl_relaxed(reg_lower);
		upper = readl_relaxed(reg_upper);
	} while (upper != old_upper);

	return (((u64)upper) << info->bits_lower) | lower;
}

static notrace u64 readw_dmmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	void __iomem *reg_lower, *reg_upper;
	u16 upper, old_upper, lower;

	reg_lower = info->reg_lower;
	reg_upper = info->reg_upper;

	upper = readw_relaxed(reg_upper);
	do {
		old_upper = upper;
		lower = readw_relaxed(reg_lower);
		upper = readw_relaxed(reg_upper);
	} while (upper != old_upper);

	return (((u64)upper) << info->bits_lower) | lower;
}

static notrace __cold vdso_read_cycles_t *get_mmio_read_cycles(unsigned int type)
{
	switch (type) {
	case CLKSRC_MMIO_L_UP:
		return &readl_mmio_up;
	case CLKSRC_MMIO_L_DOWN:
		return &readl_mmio_down;
	case CLKSRC_MMIO_W_UP:
		return &readw_mmio_up;
	case CLKSRC_MMIO_W_DOWN:
		return &readw_mmio_down;
	case CLKSRC_DMMIO_L_UP:
		return &readl_dmmio_up;
	case CLKSRC_DMMIO_W_UP:
		return &readw_dmmio_up;
	default:
		return NULL;
	}
}

static __always_inline u16 to_cs_type(u32 cs_type_seq)
{
	return cs_type_seq >> 16;
}

static __always_inline u16 to_seq(u32 cs_type_seq)
{
	return cs_type_seq;
}

static __always_inline u32 to_cs_type_seq(u16 type, u16 seq)
{
	return (u32)type << 16U | seq;
}

static notrace noinline __cold
void map_clocksource(const struct vdso_data *vd, struct vdso_priv *vp,
		     u32 seq, u32 new_cs_type_seq)
{
	vdso_read_cycles_t *read_cycles = NULL;
	u32 new_cs_seq, new_cs_type;
	struct clksrc_info *info;
	int fd, ret;

	new_cs_seq = to_seq(new_cs_type_seq);
	new_cs_type = to_cs_type(new_cs_type_seq);
	info = &vp->clksrc_info[new_cs_type];

	if (new_cs_type < CLOCKSOURCE_VDSO_MMIO)
		goto done;

	fd = clock_open_device(vd->cs_mmdev, O_RDONLY);
	if (fd < 0)
		goto fallback_to_syscall;

	if (vdso_read_retry(vd, seq)) {
		vdso_read_begin(vd);
		if (to_seq(vd->cs_type_seq) != new_cs_seq) {
			/*
			 * cs_mmdev no longer corresponds to
			 * vd->cs_type_seq.
			 */
			clock_close_device(fd);
			return;
		}
	}

	ret = clock_ioctl_device(fd, CLKSRC_USER_MMIO_MAP, (long)&info->mmio);
	clock_close_device(fd);
	if (ret < 0)
		goto fallback_to_syscall;

	read_cycles = get_mmio_read_cycles(info->mmio.type);
	if (read_cycles == NULL) /* Mmhf, misconfigured. */
		goto fallback_to_syscall;
done:
	info->read_cycles = read_cycles;
	smp_wmb();
	new_cs_type_seq = to_cs_type_seq(new_cs_type, new_cs_seq);
	WRITE_ONCE(vp->current_cs_type_seq, new_cs_type_seq);

	return;

fallback_to_syscall:
	new_cs_type = CLOCKSOURCE_VDSO_NONE;
	info = &vp->clksrc_info[new_cs_type];
	goto done;
}

static inline notrace
u64 get_hw_counter(const struct vdso_data *vd, u32 *r_seq)
{
	const struct clksrc_info *info;
	struct vdso_priv *vp;
	u32 seq, cs_type_seq;
	unsigned int cs;
	u64 cycles;

	vp = __arch_get_vdso_priv();

	for (;;) {
		seq = vdso_read_begin(vd);
		cs_type_seq = READ_ONCE(vp->current_cs_type_seq);
		if (likely(to_seq(cs_type_seq) == to_seq(vd->cs_type_seq)))
			break;

		map_clocksource(vd, vp, seq, vd->cs_type_seq);
	}

	switch (to_cs_type(cs_type_seq)) {
	case CLOCKSOURCE_VDSO_NONE:
		cycles = (u64)-1; /* Use fallback. */
		break;
	case CLOCKSOURCE_VDSO_ARCHITECTED:
		cycles = __arch_get_hw_counter(vd->clock_mode);
		break;
	default:
		cs = to_cs_type(READ_ONCE(cs_type_seq));
		info = &vp->clksrc_info[cs];
		cycles = info->read_cycles(info);
		break;
	}

	*r_seq = seq;

	return cycles;
}

#else

static inline notrace
u64 get_hw_counter(const struct vdso_data *vd, u32 *r_seq)
{
	*r_seq = vdso_read_begin(vd);

	return __arch_get_hw_counter(vd->clock_mode);
}

#endif /* CONFIG_GENERIC_CLOCKSOURCE_VDSO */

#ifndef vdso_calc_delta
/*
 * Default implementation which works for all sane clocksources. That
 * obviously excludes x86/TSC.
 */
static __always_inline
u64 vdso_calc_delta(u64 cycles, u64 last, u64 mask, u32 mult)
{
	return ((cycles - last) & mask) * mult;
}
#endif

static int do_hres(const struct vdso_data *vd, clockid_t clk,
		   struct __kernel_timespec *ts)
{
	const struct vdso_timestamp *vdso_ts = &vd->basetime[clk];
	u64 cycles, last, sec, ns;
	u32 seq;

	do {
		cycles = get_hw_counter(vd, &seq);
		ns = vdso_ts->nsec;
		last = vd->cycle_last;
		if (unlikely((s64)cycles < 0))
			return -1;

		ns += vdso_calc_delta(cycles, last, vd->mask, vd->mult);
		ns >>= vd->shift;
		sec = vdso_ts->sec;
	} while (unlikely(vdso_read_retry(vd, seq)));

	/*
	 * Do this outside the loop: a race inside the loop could result
	 * in __iter_div_u64_rem() being extremely slow.
	 */
	ts->tv_sec = sec + __iter_div_u64_rem(ns, NSEC_PER_SEC, &ns);
	ts->tv_nsec = ns;

	return 0;
}

static void do_coarse(const struct vdso_data *vd, clockid_t clk,
		      struct __kernel_timespec *ts)
{
	const struct vdso_timestamp *vdso_ts = &vd->basetime[clk];
	u32 seq;

	do {
		seq = vdso_read_begin(vd);
		ts->tv_sec = vdso_ts->sec;
		ts->tv_nsec = vdso_ts->nsec;
	} while (unlikely(vdso_read_retry(vd, seq)));
}

static __maybe_unused int
__cvdso_clock_gettime_common(clockid_t clock, struct __kernel_timespec *ts)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	u32 msk;

	/* Check for negative values or invalid clocks */
	if (unlikely((u32) clock >= MAX_CLOCKS))
		return -1;

	/*
	 * Convert the clockid to a bitmask and use it to check which
	 * clocks are handled in the VDSO directly.
	 */
	msk = 1U << clock;
	if (likely(msk & VDSO_HRES)) {
		return do_hres(&vd[CS_HRES_COARSE], clock, ts);
	} else if (msk & VDSO_COARSE) {
		do_coarse(&vd[CS_HRES_COARSE], clock, ts);
		return 0;
	} else if (msk & VDSO_RAW) {
		return do_hres(&vd[CS_RAW], clock, ts);
	}
	return -1;
}

static __maybe_unused int
__cvdso_clock_gettime(clockid_t clock, struct __kernel_timespec *ts)
{
	int ret = __cvdso_clock_gettime_common(clock, ts);

	if (unlikely(ret))
		return clock_gettime_fallback(clock, ts);
	return 0;
}

static __maybe_unused int
__cvdso_clock_gettime32(clockid_t clock, struct old_timespec32 *res)
{
	struct __kernel_timespec ts;
	int ret;

	ret = __cvdso_clock_gettime_common(clock, &ts);

#ifdef VDSO_HAS_32BIT_FALLBACK
	if (unlikely(ret))
		return clock_gettime32_fallback(clock, res);
#else
	if (unlikely(ret))
		ret = clock_gettime_fallback(clock, &ts);
#endif

	if (likely(!ret)) {
		res->tv_sec = ts.tv_sec;
		res->tv_nsec = ts.tv_nsec;
	}
	return ret;
}

static __maybe_unused int
__cvdso_gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz)
{
	const struct vdso_data *vd = __arch_get_vdso_data();

	if (likely(tv != NULL)) {
		struct __kernel_timespec ts;

		if (do_hres(&vd[CS_HRES_COARSE], CLOCK_REALTIME, &ts))
			return gettimeofday_fallback(tv, tz);

		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = (u32)ts.tv_nsec / NSEC_PER_USEC;
	}

	if (unlikely(tz != NULL)) {
		tz->tz_minuteswest = vd[CS_HRES_COARSE].tz_minuteswest;
		tz->tz_dsttime = vd[CS_HRES_COARSE].tz_dsttime;
	}

	return 0;
}

#ifdef VDSO_HAS_TIME
static __maybe_unused __kernel_old_time_t __cvdso_time(__kernel_old_time_t *time)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	__kernel_old_time_t t = READ_ONCE(vd[CS_HRES_COARSE].basetime[CLOCK_REALTIME].sec);

	if (time)
		*time = t;

	return t;
}
#endif /* VDSO_HAS_TIME */

#ifdef VDSO_HAS_CLOCK_GETRES
static __maybe_unused
int __cvdso_clock_getres_common(clockid_t clock, struct __kernel_timespec *res)
{
	const struct vdso_data *vd = __arch_get_vdso_data();
	u64 hrtimer_res;
	u32 msk;
	u64 ns;

	/* Check for negative values or invalid clocks */
	if (unlikely((u32) clock >= MAX_CLOCKS))
		return -1;

	hrtimer_res = READ_ONCE(vd[CS_HRES_COARSE].hrtimer_res);
	/*
	 * Convert the clockid to a bitmask and use it to check which
	 * clocks are handled in the VDSO directly.
	 */
	msk = 1U << clock;
	if (msk & VDSO_HRES) {
		/*
		 * Preserves the behaviour of posix_get_hrtimer_res().
		 */
		ns = hrtimer_res;
	} else if (msk & VDSO_COARSE) {
		/*
		 * Preserves the behaviour of posix_get_coarse_res().
		 */
		ns = LOW_RES_NSEC;
	} else if (msk & VDSO_RAW) {
		/*
		 * Preserves the behaviour of posix_get_hrtimer_res().
		 */
		ns = hrtimer_res;
	} else {
		return -1;
	}

	if (likely(res)) {
		res->tv_sec = 0;
		res->tv_nsec = ns;
	}
	return 0;
}

int __cvdso_clock_getres(clockid_t clock, struct __kernel_timespec *res)
{
	int ret = __cvdso_clock_getres_common(clock, res);

	if (unlikely(ret))
		return clock_getres_fallback(clock, res);
	return 0;
}

static __maybe_unused int
__cvdso_clock_getres_time32(clockid_t clock, struct old_timespec32 *res)
{
	struct __kernel_timespec ts;
	int ret;

	ret = __cvdso_clock_getres_common(clock, &ts);

#ifdef VDSO_HAS_32BIT_FALLBACK
	if (unlikely(ret))
		return clock_getres32_fallback(clock, res);
#else
	if (unlikely(ret))
		ret = clock_getres_fallback(clock, &ts);
#endif

	if (likely(!ret && res)) {
		res->tv_sec = ts.tv_sec;
		res->tv_nsec = ts.tv_nsec;
	}
	return ret;
}
#endif /* VDSO_HAS_CLOCK_GETRES */
