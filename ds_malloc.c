/* ds_malloc.c */
/*
 * Copyright (c) 2022 Stephen D Adams <s.d.adams.software@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This is a fallback implementation of the dynamic stack that simply delegates
 * to malloc(3), free(3), and realloc(3).
 */

#include <stdlib.h>

#include "ds.h"

MUXFS int
muxfs_dsinit(void)
{
	return 0;
}

MUXFS int
muxfs_dsfinal(void)
{
	return 0;
}

MUXFS int
muxfs_dspush(void **p_out, size_t s)
{
	void *p;

	p = malloc(s);
	if (p == NULL)
		exit(-1);

	*p_out = p;
	return 0;
}

MUXFS int
muxfs_dspop(void *p)
{
	free(p);
	return 0;
}

MUXFS int
muxfs_dsgrow(void **p_inout, size_t s)
{
	void *p;

	p = realloc(*p_inout, s);
	if (p == NULL)
		exit(-1);

	*p_inout = p;
	return 0;
}
