/*
 * Copyright (C) 2001-2013 Philippe Gerum <rpm@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */
#ifndef _STEELY_VERSION_H
#define _STEELY_VERSION_H

#ifndef __KERNEL__
#include <steely_config.h>
#include <boilerplate/compiler.h>
#endif

#define STEELY_VERSION(maj, min, rev)  (((maj)<<16)|((min)<<8)|(rev))

#define STEELY_VERSION_CODE	STEELY_VERSION(CONFIG_VERSION_MAJOR,	\
					     CONFIG_VERSION_MINOR,	\
					     CONFIG_REVISION_LEVEL)

#define STEELY_VERSION_STRING	CONFIG_VERSION_STRING

#define STEELY_VERSION_NAME	CONFIG_VERSION_NAME

#endif /* _STEELY_VERSION_H */
