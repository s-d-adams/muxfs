/* gen.c */
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
 * The purpose of gen.c is to generate gen.h which contains opaque types that
 * may be stack allocated, and are generated from concrete types defined using
 * external dependencies.  The opaque types may be used without including the
 * headers for the external dependencies allowing to keep namespaces clean
 * without losing runtime performance.  This has two advantages: 1. Namespace
 * collisions are less likely, and 2. Compile time is reduced for incremental
 * builds.  The program, gen, is built from gen.c then used by the Makefile
 * like a compiler.
 */

#include <stdio.h>

#include "chk.h"

int
main(int argc, char *argv[])
{
	printf("/*\n * Automatically generated, do not edit manually.\n");
	printf(" * Read gen.c for more information.\n */\n");
	printf("\n#ifndef _GEN_H_\n#define _GEN_H_\n\n");
	printf("struct muxfs_chk { uint8_t priv[%lu]; };\n",
	    sizeof(struct muxfs_chk_p));
	printf("\n#endif /* _GEN_H_ */\n");
	return 0;
}
