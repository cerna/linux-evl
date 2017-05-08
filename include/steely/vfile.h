/*
 * Copyright (C) 2010 Philippe Gerum <rpm@xenomai.org>
 *
 * Xenomai is free software; you can redistribute it and/or
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

#ifndef _STEELY_VFILE_H
#define _STEELY_VFILE_H

#ifdef CONFIG_STEELY_VFILE

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <steely/lock.h>

struct xnvfile_directory;
struct xnvfile_regular_iterator;
struct xnvfile_snapshot_iterator;
struct xnvfile_lock_ops;

struct xnvfile {
	struct proc_dir_entry *pde;
	struct file *file;
	struct xnvfile_lock_ops *lockops;
	int refcnt;
	void *private;
};

struct xnvfile_lock_ops {
	int (*get)(struct xnvfile *vfile);
	void (*put)(struct xnvfile *vfile);
};

struct xnvfile_hostlock_class {
	struct xnvfile_lock_ops ops;
	struct mutex mutex;
};

struct xnvfile_nklock_class {
	struct xnvfile_lock_ops ops;
	spl_t s;
};

struct xnvfile_input {
	const char __user *u_buf;
	size_t size;
	struct xnvfile *vfile;
};

struct xnvfile_regular_ops {
	int (*rewind)(struct xnvfile_regular_iterator *it);
	void *(*begin)(struct xnvfile_regular_iterator *it);
	void *(*next)(struct xnvfile_regular_iterator *it);
	void (*end)(struct xnvfile_regular_iterator *it);
	int (*show)(struct xnvfile_regular_iterator *it, void *data);
	ssize_t (*store)(struct xnvfile_input *input);
};

struct xnvfile_regular {
	struct xnvfile entry;
	size_t privsz;
	struct xnvfile_regular_ops *ops;
};

struct xnvfile_regular_template {
	size_t privsz;
	struct xnvfile_regular_ops *ops;
	struct xnvfile_lock_ops *lockops;
};

struct xnvfile_regular_iterator {
	/* Current record position while iterating. */
	loff_t pos;
	/* Backlink to the host sequential file supporting the vfile. */
	struct seq_file *seq;
	/* Backlink to the vfile being read. */
	struct xnvfile_regular *vfile;
	/*
	 * Start of private area. Use xnvfile_iterator_priv() to
	 * address it.
	 */
	char private[0];
};

struct xnvfile_snapshot_ops {
	int (*rewind)(struct xnvfile_snapshot_iterator *it);
	void *(*begin)(struct xnvfile_snapshot_iterator *it);
	void (*end)(struct xnvfile_snapshot_iterator *it, void *buf);
	int (*next)(struct xnvfile_snapshot_iterator *it, void *data);
	int (*show)(struct xnvfile_snapshot_iterator *it, void *data);
	ssize_t (*store)(struct xnvfile_input *input);
};

struct xnvfile_rev_tag {
	/* Current revision number. */
	int rev;
};

struct xnvfile_snapshot_template {
	size_t privsz;
	size_t datasz;
	struct xnvfile_rev_tag *tag;
	struct xnvfile_snapshot_ops *ops;
	struct xnvfile_lock_ops *lockops;
};

struct xnvfile_snapshot {
	struct xnvfile entry;
	size_t privsz;
	size_t datasz;
	struct xnvfile_rev_tag *tag;
	struct xnvfile_snapshot_ops *ops;
};

struct xnvfile_snapshot_iterator {
	/* Number of collected records. */
	int nrdata;
	/* Address of record buffer. */
	caddr_t databuf;
	/* Backlink to the host sequential file supporting the vfile. */
	struct seq_file *seq;
	/* Backlink to the vfile being read. */
	struct xnvfile_snapshot *vfile;
	/* Buffer release handler. */
	void (*endfn)(struct xnvfile_snapshot_iterator *it, void *buf);
	/*
	 * Start of private area. Use xnvfile_iterator_priv() to
	 * address it.
	 */
	char private[0];
};

struct xnvfile_directory {
	struct xnvfile entry;
};

struct xnvfile_link {
	struct xnvfile entry;
};

/* vfile.begin()=> */
#define VFILE_SEQ_EMPTY			((void *)-1)
/* =>vfile.show() */
#define VFILE_SEQ_START			SEQ_START_TOKEN
/* vfile.next/show()=> */
#define VFILE_SEQ_SKIP			2

#define xnvfile_printf(it, args...)	seq_printf((it)->seq, ##args)
#define xnvfile_write(it, data, len)	seq_write((it)->seq, (data),(len))
#define xnvfile_puts(it, s)		seq_puts((it)->seq, (s))
#define xnvfile_putc(it, c)		seq_putc((it)->seq, (c))

static inline void xnvfile_touch_tag(struct xnvfile_rev_tag *tag)
{
	tag->rev++;
}

static inline void xnvfile_touch(struct xnvfile_snapshot *vfile)
{
	xnvfile_touch_tag(vfile->tag);
}

#define xnvfile_noentry			\
	{				\
		.pde = NULL,		\
		.private = NULL,	\
		.file = NULL,		\
		.refcnt = 0,		\
	}

#define xnvfile_nodir	{ .entry = xnvfile_noentry }
#define xnvfile_nolink	{ .entry = xnvfile_noentry }
#define xnvfile_nofile	{ .entry = xnvfile_noentry }

#define xnvfile_priv(e)			((e)->entry.private)
#define xnvfile_nref(e)			((e)->entry.refcnt)
#define xnvfile_file(e)			((e)->entry.file)
#define xnvfile_iterator_priv(it)	((void *)(&(it)->private))

extern struct xnvfile_nklock_class xnvfile_nucleus_lock;

extern struct xnvfile_directory steely_vfroot;

int xnvfile_init_root(void);

void xnvfile_destroy_root(void);

int xnvfile_init_snapshot(const char *name,
			  struct xnvfile_snapshot *vfile,
			  struct xnvfile_directory *parent);

int xnvfile_init_regular(const char *name,
			 struct xnvfile_regular *vfile,
			 struct xnvfile_directory *parent);

int xnvfile_init_dir(const char *name,
		     struct xnvfile_directory *vdir,
		     struct xnvfile_directory *parent);

int xnvfile_init_link(const char *from,
		      const char *to,
		      struct xnvfile_link *vlink,
		      struct xnvfile_directory *parent);

void xnvfile_destroy(struct xnvfile *vfile);

ssize_t xnvfile_get_blob(struct xnvfile_input *input,
			 void *data, size_t size);

ssize_t xnvfile_get_string(struct xnvfile_input *input,
			   char *s, size_t maxlen);

ssize_t xnvfile_get_integer(struct xnvfile_input *input, long *valp);

int __vfile_hostlock_get(struct xnvfile *vfile);

void __vfile_hostlock_put(struct xnvfile *vfile);

static inline
void xnvfile_destroy_snapshot(struct xnvfile_snapshot *vfile)
{
	xnvfile_destroy(&vfile->entry);
}

static inline
void xnvfile_destroy_regular(struct xnvfile_regular *vfile)
{
	xnvfile_destroy(&vfile->entry);
}

static inline
void xnvfile_destroy_dir(struct xnvfile_directory *vdir)
{
	xnvfile_destroy(&vdir->entry);
}

static inline
void xnvfile_destroy_link(struct xnvfile_link *vlink)
{
	xnvfile_destroy(&vlink->entry);
}

#define DEFINE_VFILE_HOSTLOCK(name)					\
	struct xnvfile_hostlock_class name = {				\
		.ops = {						\
			.get = __vfile_hostlock_get,			\
			.put = __vfile_hostlock_put,			\
		},							\
		.mutex = __MUTEX_INITIALIZER(name.mutex),		\
	}

#else /* !CONFIG_STEELY_VFILE */

#define xnvfile_touch_tag(tag)	do { } while (0)

#define xnvfile_touch(vfile)	do { } while (0)

#endif /* !CONFIG_STEELY_VFILE */

#endif /* !_STEELY_VFILE_H */
