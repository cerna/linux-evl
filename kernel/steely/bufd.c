/*
 * Copyright (C) 2009 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <steely/heap.h>
#include <steely/sched.h>
#include <steely/bufd.h>
#include <steely/assert.h>
#include <asm/steely/syscall.h>

void xnbufd_map_kmem(struct xnbufd *bufd, void *ptr, size_t len)
{
	bufd->b_ptr = ptr;
	bufd->b_len = len;
	bufd->b_mm = NULL;
	bufd->b_off = 0;
	bufd->b_carry = NULL;
}
EXPORT_SYMBOL_GPL(xnbufd_map_kmem);

void xnbufd_map_umem(struct xnbufd *bufd, void __user *ptr, size_t len)
{
	bufd->b_ptr = ptr;
	bufd->b_len = len;
	bufd->b_mm = current->mm;
	bufd->b_off = 0;
	bufd->b_carry = NULL;
}
EXPORT_SYMBOL_GPL(xnbufd_map_umem);

ssize_t xnbufd_copy_to_kmem(void *to, struct xnbufd *bufd, size_t len)
{
	caddr_t from;

	thread_only();

	if (len == 0)
		goto out;

	from = bufd->b_ptr + bufd->b_off;

	/*
	 * If the descriptor covers a source buffer living in the
	 * kernel address space, we may read from it directly.
	 */
	if (bufd->b_mm == NULL) {
		memcpy(to, from, len);
		goto advance_offset;
	}

	/*
	 * We want to read data from user-space, check whether:
	 * 1) the source buffer lies in the current address space,
	 * 2) we may fault while reading from the buffer directly.
	 *
	 * If we can't reach the buffer, or the current context may
	 * not fault while reading data from it, copy_from_user() is
	 * not an option and we have a bug somewhere, since there is
	 * no way we could fetch the data to kernel space immediately.
	 *
	 * Note that we don't check for non-preemptible Linux context
	 * here, since the source buffer would live in kernel space in
	 * such a case.
	 */
	if (current->mm == bufd->b_mm) {
		preemptible_only();
		if (steely_copy_from_user(to, (void __user *)from, len))
			return -EFAULT;
		goto advance_offset;
	}

	STEELY_BUG(STEELY);

	return -EINVAL;

advance_offset:
	bufd->b_off += len;
out:
	return (ssize_t)bufd->b_off;
}
EXPORT_SYMBOL_GPL(xnbufd_copy_to_kmem);

ssize_t xnbufd_copy_from_kmem(struct xnbufd *bufd, void *from, size_t len)
{
	caddr_t to;

	thread_only();

	if (len == 0)
		goto out;

	to = bufd->b_ptr + bufd->b_off;

	/*
	 * If the descriptor covers a destination buffer living in the
	 * kernel address space, we may copy to it directly.
	 */
	if (bufd->b_mm == NULL)
		goto direct_copy;

	/*
	 * We want to pass data to user-space, check whether:
	 * 1) the destination buffer lies in the current address space,
	 * 2) we may fault while writing to the buffer directly.
	 *
	 * If we can't reach the buffer, or the current context may
	 * not fault while copying data to it, copy_to_user() is not
	 * an option and we have to convey the data from kernel memory
	 * through the carry over buffer.
	 *
	 * Note that we don't check for non-preemptible Linux context
	 * here: feeding a RT activity with data from a non-RT context
	 * is wrong in the first place, so never mind.
	 */
	if (current->mm == bufd->b_mm) {
		preemptible_only();
		if (steely_copy_to_user((void __user *)to, from, len))
			return -EFAULT;
		goto advance_offset;
	}

	/*
	 * We need a carry over buffer to convey the data to
	 * user-space. xnbufd_unmap_uwrite() should be called on the
	 * way back to user-space to update the destination buffer
	 * from the carry over area.
	 */
	if (bufd->b_carry == NULL) {
		/*
		 * Try to use the fast carry over area available
		 * directly from the descriptor for short messages, to
		 * save a dynamic allocation request.
		 */
		if (bufd->b_len <= sizeof(bufd->b_buf))
			bufd->b_carry = bufd->b_buf;
		else {
			bufd->b_carry = xnmalloc(bufd->b_len);
			if (bufd->b_carry == NULL)
				return -ENOMEM;
		}
		to = bufd->b_carry;
	} else
		to = bufd->b_carry + bufd->b_off;

direct_copy:
	memcpy(to, from, len);

advance_offset:
	bufd->b_off += len;
out:
	return (ssize_t)bufd->b_off;
}
EXPORT_SYMBOL_GPL(xnbufd_copy_from_kmem);

ssize_t xnbufd_unmap_uread(struct xnbufd *bufd)
{
	preemptible_only();

#if STEELY_DEBUG(STEELY)
	bufd->b_ptr = (caddr_t)-1;
#endif
	return bufd->b_off;
}
EXPORT_SYMBOL_GPL(xnbufd_unmap_uread);

ssize_t xnbufd_unmap_uwrite(struct xnbufd *bufd)
{
	ssize_t ret = 0;
	void __user *to;
	void *from;
	size_t len;

	preemptible_only();

	len = bufd->b_off;

	if (bufd->b_carry == NULL)
		/* Copy took place directly. Fine. */
		goto done;

	/*
	 * Something was written to the carry over area, copy the
	 * contents to user-space, then release the area if needed.
	 */
	to = (void __user *)bufd->b_ptr;
	from = bufd->b_carry;
	ret = steely_copy_to_user(to, from, len);

	if (bufd->b_len > sizeof(bufd->b_buf))
		xnfree(bufd->b_carry);
done:
#if STEELY_DEBUG(STEELY)
	bufd->b_ptr = (caddr_t)-1;
#endif
	return ret ?: (ssize_t)len;
}
EXPORT_SYMBOL_GPL(xnbufd_unmap_uwrite);

void xnbufd_invalidate(struct xnbufd *bufd)
{
#if STEELY_DEBUG(STEELY)
	bufd->b_ptr = (caddr_t)-1;
#endif
	if (bufd->b_carry) {
		if (bufd->b_len > sizeof(bufd->b_buf))
			xnfree(bufd->b_carry);
		bufd->b_carry = NULL;
	}
	bufd->b_off = 0;
}
EXPORT_SYMBOL_GPL(xnbufd_invalidate);

ssize_t xnbufd_unmap_kread(struct xnbufd *bufd)
{
#if STEELY_DEBUG(STEELY)
	bufd->b_ptr = (caddr_t)-1;
#endif
	return bufd->b_off;
}
EXPORT_SYMBOL_GPL(xnbufd_unmap_kread);

ssize_t xnbufd_unmap_kwrite(struct xnbufd *bufd)
{
#if STEELY_DEBUG(STEELY)
	bufd->b_ptr = (caddr_t)-1;
#endif
	return bufd->b_off;
}
EXPORT_SYMBOL_GPL(xnbufd_unmap_kwrite);
