/* chk.h */
/*
 * Copyright (c) 2022 Stephen D. Adams <stephen@sdadams.org>
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

#ifndef _CHK_H_
#define _CHK_H_

#include <md5.h>
#include <sha1.h>
#include <stdint.h>
#include <unistd.h>
#include <zlib.h>

#include "muxfs.h"

struct muxfs_chk;

struct muxfs_chk_alg {
	enum muxfs_chk_alg_type type;
	size_t chk_size;
	void (*chk_init)(struct muxfs_chk *, struct muxfs_chk_alg *);
	void (*chk_update)(struct muxfs_chk *, const uint8_t *, size_t);
	void (*chk_final)(uint8_t *, struct muxfs_chk *);
	const char *name;
};

struct muxfs_chk_p {
	struct muxfs_chk_alg *alg;
	union {
		uLong ulong;
		MD5_CTX md5_ctx;
		SHA1_CTX sha1_ctx;
	} impl;
	uint32_t u32;
};

#endif /* _CHK_H_ */
