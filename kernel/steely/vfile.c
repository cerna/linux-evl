/*
 * Copyright (C) 2010 Philippe Gerum <rpm@xenomai.org>
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
#include <stdarg.h>
#include <linux/ctype.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <steely/lock.h>
#include <steely/assert.h>
#include <steely/vfile.h>

struct xnvfile_directory steely_vfroot;
EXPORT_SYMBOL_GPL(steely_vfroot);

static struct xnvfile_directory sysroot;

static void *vfile_snapshot_start(struct seq_file *seq, loff_t *offp)
{
	struct xnvfile_snapshot_iterator *it = seq->private;
	loff_t pos = *offp;

	if (pos > it->nrdata)
		return NULL;

	if (pos == 0)
		return SEQ_START_TOKEN;

	return it->databuf + (pos - 1) * it->vfile->datasz;
}

static void *vfile_snapshot_next(struct seq_file *seq, void *v, loff_t *offp)
{
	struct xnvfile_snapshot_iterator *it = seq->private;
	loff_t pos = *offp;

	if (pos >= it->nrdata)
		return NULL;

	++*offp;

	return it->databuf + pos * it->vfile->datasz;
}

static void vfile_snapshot_stop(struct seq_file *seq, void *v)
{
}

static int vfile_snapshot_show(struct seq_file *seq, void *v)
{
	struct xnvfile_snapshot_iterator *it = seq->private;
	void *data = v == SEQ_START_TOKEN ? NULL : v;
	int ret;

	ret = it->vfile->ops->show(it, data);

	return ret == VFILE_SEQ_SKIP ? SEQ_SKIP : ret;
}

static struct seq_operations vfile_snapshot_ops = {
	.start = vfile_snapshot_start,
	.next = vfile_snapshot_next,
	.stop = vfile_snapshot_stop,
	.show = vfile_snapshot_show
};

static void vfile_snapshot_free(struct xnvfile_snapshot_iterator *it, void *buf)
{
	kfree(buf);
}

static int vfile_snapshot_open(struct inode *inode, struct file *file)
{
	struct xnvfile_snapshot *vfile = PDE_DATA(inode);
	struct xnvfile_snapshot_ops *ops = vfile->ops;
	struct xnvfile_snapshot_iterator *it;
	int revtag, ret, nrdata;
	struct seq_file *seq;
	caddr_t data;

	if ((file->f_mode & FMODE_WRITE) != 0 && ops->store == NULL)
		return -EACCES;

	/*
	 * Make sure to create the seq_file backend only when reading
	 * from the v-file is possible.
	 */
	if ((file->f_mode & FMODE_READ) == 0) {
		file->private_data = NULL;
		return 0;
	}

	if ((file->f_flags & O_EXCL) != 0 && xnvfile_nref(vfile) > 0)
		return -EBUSY;

	it = kzalloc(sizeof(*it) + vfile->privsz, GFP_KERNEL);
	if (it == NULL)
		return -ENOMEM;

	it->vfile = vfile;
	xnvfile_file(vfile) = file;

	ret = vfile->entry.lockops->get(&vfile->entry);
	if (ret)
		goto fail;
redo:
	/*
	 * The ->rewind() method is optional; there may be cases where
	 * we don't have to take an atomic snapshot of the v-file
	 * contents before proceeding. In case ->rewind() detects a
	 * stale backend object, it can force us to bail out.
	 *
	 * If present, ->rewind() may return a strictly positive
	 * value, indicating how many records at most may be returned
	 * by ->next(). We use this hint to allocate the snapshot
	 * buffer, in case ->begin() is not provided. The size of this
	 * buffer would then be vfile->datasz * hint value.
	 *
	 * If ->begin() is given, we always expect the latter do the
	 * allocation for us regardless of the hint value. Otherwise,
	 * a NULL return from ->rewind() tells us that the vfile won't
	 * output any snapshot data via ->show().
	 */
	nrdata = 0;
	if (ops->rewind) {
		nrdata = ops->rewind(it);
		if (nrdata < 0) {
			ret = nrdata;
			vfile->entry.lockops->put(&vfile->entry);
			goto fail;
		}
	}
	revtag = vfile->tag->rev;

	vfile->entry.lockops->put(&vfile->entry);

	/* Release the data buffer, in case we had to restart. */
	if (it->databuf) {
		it->endfn(it, it->databuf);
		it->databuf = NULL;
	}

	/*
	 * Having no record to output is fine, in which case ->begin()
	 * shall return VFILE_SEQ_EMPTY if present. ->begin() may be
	 * absent, meaning that no allocation is even required to
	 * collect the records to output. NULL is kept for allocation
	 * errors in all other cases.
	 */
	if (ops->begin) {
		STEELY_BUG_ON(STEELY, ops->end == NULL);
		data = ops->begin(it);
		if (data == NULL) {
			kfree(it);
			return -ENOMEM;
		}
		if (data != VFILE_SEQ_EMPTY) {
			it->databuf = data;
			it->endfn = ops->end;
		}
	} else if (nrdata > 0 && vfile->datasz > 0) {
		/* We have a hint for auto-allocation. */
		data = kmalloc(vfile->datasz * nrdata, GFP_KERNEL);
		if (data == NULL) {
			kfree(it);
			return -ENOMEM;
		}
		it->databuf = data;
		it->endfn = vfile_snapshot_free;
	}

	ret = seq_open(file, &vfile_snapshot_ops);
	if (ret)
		goto fail;

	it->nrdata = 0;
	data = it->databuf;
	if (data == NULL)
		goto finish;

	/*
	 * Take a snapshot of the vfile contents, redo if the revision
	 * tag of the scanned data set changed concurrently.
	 */
	for (;;) {
		ret = vfile->entry.lockops->get(&vfile->entry);
		if (ret)
			break;
		if (vfile->tag->rev != revtag)
			goto redo;
		ret = ops->next(it, data);
		vfile->entry.lockops->put(&vfile->entry);
		if (ret <= 0)
			break;
		if (ret != VFILE_SEQ_SKIP) {
			data += vfile->datasz;
			it->nrdata++;
		}
	}

	if (ret < 0) {
		seq_release(inode, file);
	fail:
		if (it->databuf)
			it->endfn(it, it->databuf);
		kfree(it);
		return ret;
	}

finish:
	seq = file->private_data;
	it->seq = seq;
	seq->private = it;
	xnvfile_nref(vfile)++;

	return 0;
}

static int vfile_snapshot_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct xnvfile_snapshot_iterator *it;

	if (seq) {
		it = seq->private;
		if (it) {
			--xnvfile_nref(it->vfile);
			STEELY_BUG_ON(STEELY, it->vfile->entry.refcnt < 0);
			if (it->databuf)
				it->endfn(it, it->databuf);
			kfree(it);
		}

		return seq_release(inode, file);
	}

	return 0;
}

ssize_t vfile_snapshot_write(struct file *file, const char __user *buf,
			     size_t size, loff_t *ppos)
{
	struct xnvfile_snapshot *vfile =
		PDE_DATA(file->f_path.dentry->d_inode);
	struct xnvfile_input input;
	ssize_t ret;

	if (vfile->entry.lockops) {
		ret = vfile->entry.lockops->get(&vfile->entry);
		if (ret)
			return ret;
	}

	input.u_buf = buf;
	input.size = size;
	input.vfile = &vfile->entry;

	ret = vfile->ops->store(&input);

	if (vfile->entry.lockops)
		vfile->entry.lockops->put(&vfile->entry);

	return ret;
}

static struct file_operations vfile_snapshot_fops = {
	.open = vfile_snapshot_open,
	.read = seq_read,
	.write = vfile_snapshot_write,
	.llseek = seq_lseek,
	.release = vfile_snapshot_release,
};

int xnvfile_init_snapshot(const char *name,
			  struct xnvfile_snapshot *vfile,
			  struct xnvfile_directory *parent)
{
	struct proc_dir_entry *ppde, *pde;
	int mode;

	STEELY_BUG_ON(STEELY, vfile->tag == NULL);

	if (vfile->entry.lockops == NULL)
		/* Defaults to nucleus lock */
		vfile->entry.lockops = &xnvfile_nucleus_lock.ops;

	if (parent == NULL)
		parent = &sysroot;

	mode = vfile->ops->store ? 0644 : 0444;
	ppde = parent->entry.pde;
	pde = proc_create_data(name, mode, ppde, &vfile_snapshot_fops, vfile);
	if (pde == NULL)
		return -ENOMEM;

	vfile->entry.pde = pde;

	return 0;
}
EXPORT_SYMBOL_GPL(xnvfile_init_snapshot);

static void *vfile_regular_start(struct seq_file *seq, loff_t *offp)
{
	struct xnvfile_regular_iterator *it = seq->private;
	struct xnvfile_regular *vfile = it->vfile;
	int ret;

	it->pos = *offp;

	if (vfile->entry.lockops) {
		ret = vfile->entry.lockops->get(&vfile->entry);
		if (ret)
			return ERR_PTR(ret);
	}

	/*
	 * If we have no begin() op, then we allow a single call only
	 * to ->show(), by returning the start token once. Otherwise,
	 * we are done.
	 */
	if (vfile->ops->begin == NULL)
		return it->pos > 0 ? NULL : SEQ_START_TOKEN;

	return vfile->ops->begin(it);
}

static void *vfile_regular_next(struct seq_file *seq, void *v, loff_t *offp)
{
	struct xnvfile_regular_iterator *it = seq->private;
	struct xnvfile_regular *vfile = it->vfile;
	void *data;

	if (vfile->ops->next == NULL)
		return NULL;

	it->pos = *offp + 1;

	data = vfile->ops->next(it);
	if (data == NULL)
		return NULL;

	*offp = it->pos;

	return data;
}

static void vfile_regular_stop(struct seq_file *seq, void *v)
{
	struct xnvfile_regular_iterator *it = seq->private;
	struct xnvfile_regular *vfile = it->vfile;

	if (vfile->entry.lockops)
		vfile->entry.lockops->put(&vfile->entry);

	if (vfile->ops->end)
		vfile->ops->end(it);
}

static int vfile_regular_show(struct seq_file *seq, void *v)
{
	struct xnvfile_regular_iterator *it = seq->private;
	struct xnvfile_regular *vfile = it->vfile;
	void *data = v == SEQ_START_TOKEN ? NULL : v;
	int ret;

	ret = vfile->ops->show(it, data);

	return ret == VFILE_SEQ_SKIP ? SEQ_SKIP : ret;
}

static struct seq_operations vfile_regular_ops = {
	.start = vfile_regular_start,
	.next = vfile_regular_next,
	.stop = vfile_regular_stop,
	.show = vfile_regular_show
};

static int vfile_regular_open(struct inode *inode, struct file *file)
{
	struct xnvfile_regular *vfile = PDE_DATA(inode);
	struct xnvfile_regular_ops *ops = vfile->ops;
	struct xnvfile_regular_iterator *it;
	struct seq_file *seq;
	int ret;

	if ((file->f_flags & O_EXCL) != 0 && xnvfile_nref(vfile) > 0)
		return -EBUSY;

	if ((file->f_mode & FMODE_WRITE) != 0 && ops->store == NULL)
		return -EACCES;

	if ((file->f_mode & FMODE_READ) == 0) {
		file->private_data = NULL;
		return 0;
	}

	it = kzalloc(sizeof(*it) + vfile->privsz, GFP_KERNEL);
	if (it == NULL)
		return -ENOMEM;

	it->vfile = vfile;
	it->pos = -1;
	xnvfile_file(vfile) = file;

	if (ops->rewind) {
		ret = ops->rewind(it);
		if (ret) {
		fail:
			kfree(it);
			return ret;
		}
	}

	ret = seq_open(file, &vfile_regular_ops);
	if (ret)
		goto fail;

	seq = file->private_data;
	it->seq = seq;
	seq->private = it;
	xnvfile_nref(vfile)++;

	return 0;
}

static int vfile_regular_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct xnvfile_regular_iterator *it;

	if (seq) {
		it = seq->private;
		if (it) {
			--xnvfile_nref(it->vfile);
			STEELY_BUG_ON(STEELY, xnvfile_nref(it->vfile) < 0);
			kfree(it);
		}

		return seq_release(inode, file);
	}

	return 0;
}

ssize_t vfile_regular_write(struct file *file, const char __user *buf,
			    size_t size, loff_t *ppos)
{
	struct xnvfile_regular *vfile =
		PDE_DATA(file->f_path.dentry->d_inode);
	struct xnvfile_input input;
	ssize_t ret;

	if (vfile->entry.lockops) {
		ret = vfile->entry.lockops->get(&vfile->entry);
		if (ret)
			return ret;
	}

	input.u_buf = buf;
	input.size = size;
	input.vfile = &vfile->entry;

	ret = vfile->ops->store(&input);

	if (vfile->entry.lockops)
		vfile->entry.lockops->put(&vfile->entry);

	return ret;
}

static struct file_operations vfile_regular_fops = {
	.open = vfile_regular_open,
	.read = seq_read,
	.write = vfile_regular_write,
	.llseek = seq_lseek,
	.release = vfile_regular_release,
};

int xnvfile_init_regular(const char *name,
			 struct xnvfile_regular *vfile,
			 struct xnvfile_directory *parent)
{
	struct proc_dir_entry *ppde, *pde;
	int mode;

	if (parent == NULL)
		parent = &sysroot;

	mode = vfile->ops->store ? 0644 : 0444;
	ppde = parent->entry.pde;
	pde = proc_create_data(name, mode, ppde, &vfile_regular_fops, vfile);
	if (pde == NULL)
		return -ENOMEM;

	vfile->entry.pde = pde;

	return 0;
}
EXPORT_SYMBOL_GPL(xnvfile_init_regular);

int xnvfile_init_dir(const char *name,
		     struct xnvfile_directory *vdir,
		     struct xnvfile_directory *parent)
{
	struct proc_dir_entry *ppde, *pde;

	if (parent == NULL)
		parent = &sysroot;

	ppde = parent->entry.pde;
	pde = proc_mkdir(name, ppde);
	if (pde == NULL)
		return -ENOMEM;

	vdir->entry.pde = pde;
	vdir->entry.lockops = NULL;
	vdir->entry.private = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(xnvfile_init_dir);

int xnvfile_init_link(const char *from,
		      const char *to,
		      struct xnvfile_link *vlink,
		      struct xnvfile_directory *parent)
{
	struct proc_dir_entry *ppde, *pde;

	if (parent == NULL)
		parent = &sysroot;

	ppde = parent->entry.pde;
	pde = proc_symlink(from, ppde, to);
	if (pde == NULL)
		return -ENOMEM;

	vlink->entry.pde = pde;
	vlink->entry.lockops = NULL;
	vlink->entry.private = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(xnvfile_init_link);

void xnvfile_destroy(struct xnvfile *vfile)
{
	proc_remove(vfile->pde);
}
EXPORT_SYMBOL_GPL(xnvfile_destroy);

ssize_t xnvfile_get_blob(struct xnvfile_input *input,
			 void *data, size_t size)
{
	ssize_t nbytes = input->size;

	if (nbytes > size)
		nbytes = size;

	if (nbytes > 0 && copy_from_user(data, input->u_buf, nbytes))
		return -EFAULT;

	return nbytes;
}
EXPORT_SYMBOL_GPL(xnvfile_get_blob);

ssize_t xnvfile_get_string(struct xnvfile_input *input,
			   char *s, size_t maxlen)
{
	ssize_t nbytes, eol;

	if (maxlen < 1)
		return -EINVAL;

	nbytes = xnvfile_get_blob(input, s, maxlen - 1);
	if (nbytes < 0)
		return nbytes;

	eol = nbytes;
	if (eol > 0 && s[eol - 1] == '\n')
		eol--;

	s[eol] = '\0';

	return nbytes;
}
EXPORT_SYMBOL_GPL(xnvfile_get_string);

ssize_t xnvfile_get_integer(struct xnvfile_input *input, long *valp)
{
	char *end, buf[32];
	ssize_t nbytes;
	long val;

	nbytes = xnvfile_get_blob(input, buf, sizeof(buf) - 1);
	if (nbytes < 0)
		return nbytes;

	if (nbytes == 0)
		return -EINVAL;

	buf[nbytes] = '\0';
	val = simple_strtol(buf, &end, 0);

	if (*end != '\0' && !isspace(*end))
		return -EINVAL;

	*valp = val;

	return nbytes;
}
EXPORT_SYMBOL_GPL(xnvfile_get_integer);

int __vfile_hostlock_get(struct xnvfile *vfile)
{
	struct xnvfile_hostlock_class *lc;

	lc = container_of(vfile->lockops, struct xnvfile_hostlock_class, ops);
	mutex_lock(&lc->mutex);

	return 0;
}
EXPORT_SYMBOL_GPL(__vfile_hostlock_get);

void __vfile_hostlock_put(struct xnvfile *vfile)
{
	struct xnvfile_hostlock_class *lc;

	lc = container_of(vfile->lockops, struct xnvfile_hostlock_class, ops);
	mutex_unlock(&lc->mutex);
}
EXPORT_SYMBOL_GPL(__vfile_hostlock_put);

static int __vfile_nklock_get(struct xnvfile *vfile)
{
	struct xnvfile_nklock_class *lc;

	lc = container_of(vfile->lockops, struct xnvfile_nklock_class, ops);
	xnlock_get_irqsave(&nklock, lc->s);

	return 0;
}

static void __vfile_nklock_put(struct xnvfile *vfile)
{
	struct xnvfile_nklock_class *lc;

	lc = container_of(vfile->lockops, struct xnvfile_nklock_class, ops);
	xnlock_put_irqrestore(&nklock, lc->s);
}

struct xnvfile_nklock_class xnvfile_nucleus_lock = {
	.ops = {
		.get = __vfile_nklock_get,
		.put = __vfile_nklock_put,
	},
};

int __init xnvfile_init_root(void)
{
	struct xnvfile_directory *vdir = &steely_vfroot;
	struct proc_dir_entry *pde;

	pde = proc_mkdir("steely", NULL);
	if (pde == NULL)
		return -ENOMEM;

	vdir->entry.pde = pde;
	vdir->entry.lockops = NULL;
	vdir->entry.private = NULL;

	return 0;
}

void xnvfile_destroy_root(void)
{
	steely_vfroot.entry.pde = NULL;
	remove_proc_entry("steely", NULL);
}
