/* mount_muxfs_unity.c */
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
 * So long as all symbols at file scope are uniquely named and the total size
 * of the codebase fits within the system memory the whole-program-from-clean
 * build time can be reduced using a "unity build" whereby all modules are
 * concatenated into a single module.  Unity builds also give the compiler more
 * information with which to optimize the program.  Run "make unity" to conduct
 * a unity build of mount_muxfs.
 */

#include "chk.c"
#include "conf.c"
#include "desc.c"
#include "dev.c"
#if MUXFS_DS == 1
#include "ds.c"
#else
#include "ds_malloc.c"
#endif
#include "ops.c"
#include "state.c"
#include "util.c"
#include "version.c"
#include "mount_muxfs.c"
