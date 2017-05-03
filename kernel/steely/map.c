/*
 * Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
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
#include <linux/module.h>
#include <steely/heap.h>
#include <steely/map.h>
#include <asm/steely/machine.h>

struct xnmap *xnmap_create(int nkeys, int reserve, int offset)
{
	struct xnmap *map;
	int mapsize;

	if (nkeys <= 0 || (nkeys & (nkeys - 1)) != 0)
		return NULL;

	mapsize = sizeof(*map) + (nkeys - 1) * sizeof(map->objarray[0]);
	map = xnmalloc(mapsize);

	if (!map)
		return NULL;

	map->ukeys = 0;
	map->nkeys = nkeys;
	map->offset = offset;
	map->himask = (1 << ((reserve + BITS_PER_LONG - 1) / BITS_PER_LONG)) - 1;
	map->himap = ~0;
	memset(map->lomap, ~0, sizeof(map->lomap));
	memset(map->objarray, 0, sizeof(map->objarray[0]) * nkeys);

	return map;
}
EXPORT_SYMBOL_GPL(xnmap_create);

void xnmap_delete(struct xnmap *map)
{
	xnfree(map);
}
EXPORT_SYMBOL_GPL(xnmap_delete);

int xnmap_enter(struct xnmap *map, int key, void *objaddr)
{
	int hi, lo, ofkey = key - map->offset;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (ofkey >= 0 && ofkey < map->nkeys) {
		if (map->objarray[ofkey] != NULL) {
			key = -EEXIST;
			goto unlock_and_exit;
		}
	} else if (map->ukeys >= map->nkeys) {
		key = -ENOSPC;
		goto unlock_and_exit;
	}
	else {
		/* The himask implements a namespace reservation of
		   half of the bitmap space which cannot be used to
		   draw keys. */

		hi = ffnz(map->himap & ~map->himask);
		lo = ffnz(map->lomap[hi]);
		ofkey = hi * BITS_PER_LONG + lo;
		++map->ukeys;

		map->lomap[hi] &= ~(1UL << lo);
		if (map->lomap[hi] == 0)
			map->himap &= ~(1UL << hi);
	}

	map->objarray[ofkey] = objaddr;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return ofkey + map->offset;
}
EXPORT_SYMBOL_GPL(xnmap_enter);

int xnmap_remove(struct xnmap *map, int key)
{
	int ofkey = key - map->offset, hi, lo;
	spl_t s;

	if (ofkey < 0 || ofkey >= map->nkeys)
		return -ESRCH;

	hi = ofkey / BITS_PER_LONG;
	lo = ofkey % BITS_PER_LONG;
	xnlock_get_irqsave(&nklock, s);
	map->objarray[ofkey] = NULL;
	map->himap |= (1UL << hi);
	map->lomap[hi] |= (1UL << lo);
	--map->ukeys;
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}
EXPORT_SYMBOL_GPL(xnmap_remove);
