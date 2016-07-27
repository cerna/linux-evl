/* -*- linux-c -*-
 * kernel/printk/pipeline.c
 *
 * Copyright (C) 2016 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/seq_buf.h>
#include <linux/kallsyms.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/irq_pipeline.h>
#include "internal.h"

struct head_seq_buf {
	unsigned char buffer[4096];
	struct seq_buf seq;
};

/* Safe printing in head stage context */
static DEFINE_PER_CPU(struct head_seq_buf, head_print_seq);

static DEFINE_PER_CPU(printk_func_t, std_printk_func);

static unsigned int printk_sirq;

static void do_vprintk(const char *fmt, ...)
{
	printk_func_t do_printk_func = this_cpu_read(std_printk_func);
	va_list ap;

	va_start(ap, fmt);
	do_printk_func(fmt, ap);
	va_end(ap);
}

static irqreturn_t do_deferred_printk(int sirq, void *dev_id)
{
	struct head_seq_buf *s = this_cpu_ptr(&head_print_seq);
	int n, last_n = 0, len;
	unsigned long flags;

	len = seq_buf_used(&s->seq);
	for (n = 0; n < len; n++) {
		if (s->buffer[n] == '\n') {
			do_vprintk("%.*s", (n - last_n) + 1,
				   s->buffer + last_n);
			last_n = n + 1;
		}
	}
	if (last_n < len) /* Check for partial line. */
		do_vprintk("%.*s\n", (len - 1 - last_n) + 1,
			   s->buffer + last_n);

	/*
	 * If we managed to write out the entire seqbuf uncontended,
	 * reinit it. Otherwise, if we raced with the head stage
	 * writing more data to it, schedule a new sirq to flush it
	 * again.
	 */
	flags = hard_local_irq_save();

	if (len != seq_buf_used(&s->seq))
		irq_stage_post_event(&root_irq_stage, printk_sirq);
	else
		seq_buf_init(&s->seq, s->buffer, sizeof(s->buffer));

	hard_local_irq_restore(flags);

	return IRQ_HANDLED;
}

static struct irqaction printk_sync = {
	.handler = do_deferred_printk,
	.name = "Deferred printk interrupt",
};

static int head_safe_vprintk(const char *fmt, va_list args)
{
	printk_func_t do_printk_func;
	struct head_seq_buf *s;
	unsigned long flags;
	int oldlen, len;

	/*
	 * Defer printk output not to wreck the hard interrupt state,
	 * cause unacceptable latency over the head stage, or risk a
	 * deadlock by reentering the printk() code from the head
	 * stage, if:
	 *
	 * - we are not running over the root stage,
	 * - IRQs are hard disabled on entry (which covers the case
	 *   of running over the root stage holding a hard lock).
	 * - the delay buffer is not empty on entry, in which case
	 *   we keep buffering until the buffer is flushed out, so
	 *   that the original output sequence is preserved.
	 *
	 * We don't care about CPU migration, we have redirected
	 * printk on all CPUs, and we can't compete with NMIs anyway.
	 */
	flags = hard_local_irq_save();

	s = raw_cpu_ptr(&head_print_seq);
	oldlen = seq_buf_used(&s->seq);
	if (oldlen == 0 &&
	    __on_root_stage() && !raw_irqs_disabled_flags(flags)) {
		/* We may invoke the printk() core directly. */
		hard_local_irq_restore(flags);
		do_printk_func = raw_cpu_read(std_printk_func);
		return do_printk_func(fmt, args);
	}

	/*
	 * Ok, we have to defer the output.
	 * XXX: we currently don't report overflows.
	 */
	seq_buf_vprintf(&s->seq, fmt, args);
	len = seq_buf_used(&s->seq) - oldlen;
	if (oldlen == 0)
		/* Fast IRQ injection, all the preconditions are met. */
		irq_stage_post_event(&root_irq_stage, printk_sirq);

	hard_local_irq_restore(flags);

	return len;
}

static void enable_safe_printk(void *arg)
{
	printk_func_t old_printk_func = this_cpu_read(printk_func);

	this_cpu_write(std_printk_func, old_printk_func);
	this_cpu_write(printk_func, head_safe_vprintk);
}

void __init printk_pipeline_init(void)
{
	struct head_seq_buf *s;
	unsigned long flags;
	int cpu;
	
	printk_sirq = irq_create_direct_mapping(synthetic_irq_domain);
	setup_irq(printk_sirq, &printk_sync);

	for_each_possible_cpu(cpu) {
		s = &per_cpu(head_print_seq, cpu);
		seq_buf_init(&s->seq, s->buffer, sizeof(s->buffer));
	}

	flags = irq_pipeline_lock(enable_safe_printk, NULL);
	enable_safe_printk(NULL);
	irq_pipeline_unlock(flags);
}
