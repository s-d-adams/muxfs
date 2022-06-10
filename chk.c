/* chk.c */
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

#include <stdlib.h>
#include <string.h>

#include "chk.h"

static void
muxfs_crc32_init (struct muxfs_chk *_chk, struct muxfs_chk_alg *alg)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	chk->alg = alg;
	chk->impl.ulong = crc32_z(0L, NULL, 0);
}

static void
muxfs_crc32_update(struct muxfs_chk *_chk, const uint8_t *data, size_t size)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	chk->impl.ulong = crc32_z(chk->impl.ulong, data, size);
}

static void
muxfs_crc32_final(uint8_t *buf_out, struct muxfs_chk *_chk)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	chk->u32 = htole32(chk->impl.ulong);
	memcpy(buf_out, (uint8_t *)&chk->u32, chk->alg->chk_size);
}

static void
muxfs_md5_init (struct muxfs_chk *_chk, struct muxfs_chk_alg *alg)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	chk->alg = alg;
	MD5Init(&chk->impl.md5_ctx);
}

static void
muxfs_md5_update(struct muxfs_chk *_chk, const uint8_t *data, size_t size)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	MD5Update(&chk->impl.md5_ctx, data, size);
}

static void
muxfs_md5_final(uint8_t *buf_out, struct muxfs_chk *_chk)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	MD5Final(buf_out, &chk->impl.md5_ctx);
}

static void
muxfs_sha1_init (struct muxfs_chk *_chk, struct muxfs_chk_alg *alg)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	chk->alg = alg;
	SHA1Init(&chk->impl.sha1_ctx);
}

static void
muxfs_sha1_update(struct muxfs_chk *_chk, const uint8_t *data, size_t size)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	SHA1Update(&chk->impl.sha1_ctx, data, size);
}

static void
muxfs_sha1_final(uint8_t *buf_out, struct muxfs_chk *_chk)
{
	struct muxfs_chk_p *chk = (struct muxfs_chk_p *)_chk;
	SHA1Final(buf_out, &chk->impl.sha1_ctx);
}

MUXFS struct muxfs_chk_alg
muxfs_chk_alg_tab[] = {
	{ CAT_CRC32,  4, muxfs_crc32_init, muxfs_crc32_update,
	  muxfs_crc32_final, "crc32" },
	{ CAT_MD5  , 16, muxfs_md5_init  , muxfs_md5_update  ,
	  muxfs_md5_final  , "md5"   },
	{ CAT_SHA1 , 20, muxfs_sha1_init , muxfs_sha1_update ,
	  muxfs_sha1_final , "sha1"  },
	{ CAT_NONE ,  0, NULL            , NULL              ,
	  NULL             , "none"  }
};

MUXFS int
muxfs_chk_str_to_type(enum muxfs_chk_alg_type *type, const char *name,
                       size_t name_len)
{
	size_t i;
	struct muxfs_chk_alg *tab;

	tab = muxfs_chk_alg_tab;

	for (i = 0; tab[i].type != CAT_NONE; ++i) {
		if (strncmp(tab[i].name, name, name_len) == 0) {
			*type = tab[i].type;
			return 0;
		}
	}

	return 1;
}

MUXFS const char *
muxfs_chk_type_to_str(enum muxfs_chk_alg_type type)
{
	if (type >= CAT_NONE)
		exit(-1); /* Programming error. */
	return muxfs_chk_alg_tab[type].name;
}

MUXFS size_t
muxfs_chk_size(enum muxfs_chk_alg_type type)
{
	if (type >= CAT_NONE)
		exit(-1); /* Programming error. */
	return muxfs_chk_alg_tab[type].chk_size;
}

MUXFS void
muxfs_chk_init(struct muxfs_chk *chk, enum muxfs_chk_alg_type type)
{
	struct muxfs_chk_alg *alg;

	if (type >= CAT_NONE)
		exit(-1); /* Programming error. */
	alg = &muxfs_chk_alg_tab[type];
	alg->chk_init(chk, alg);
}

MUXFS void
muxfs_chk_update(struct muxfs_chk *_chk, const uint8_t *data, size_t size)
{
	struct muxfs_chk_p *chk;

	chk = (struct muxfs_chk_p *)_chk;
	chk->alg->chk_update(_chk, data, size);
}

MUXFS void
muxfs_chk_final(uint8_t *buf_out, struct muxfs_chk *_chk)
{
	struct muxfs_chk_p *chk;

	chk = (struct muxfs_chk_p *)_chk;
	chk->alg->chk_final(buf_out, _chk);
}
