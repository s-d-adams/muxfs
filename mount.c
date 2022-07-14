/* mount.c */
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

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ds.h"
#include "muxfs.h"
#include "ops.h"

static void
muxfs_mount_usage(void)
{
	fprintf(stderr, "usage: muxfs mount [-f] mount_point directory ...\n");
}

MUXFS int
muxfs_mount_main(int argc, char *argv[])
{
	int n;
	char *fuse_argv[8];

	if (muxfs_parse_args(argc, argv, 0)) {
		muxfs_mount_usage();
		exit(1);
	}

	if (muxfs_init(0))
		exit(-1);

	switch (muxfs_dev_seq_check()) {
	case 0:
		break; /* Match. */
	case 1:
		exit(-1); /* Error. */
	case 2:
		exit(1); /* Mismatch. */
	default:
		exit(-1); /* Programming error. */
	}

	n = 0;
	fuse_argv[n++] = argv[0];
	if (muxfs_cmdline.f)
		fuse_argv[n++] = "-f";
	fuse_argv[n++] = "-ouse_ino";
	fuse_argv[n++] = "-oallow_other";
	fuse_argv[n++] = muxfs_cmdline.mp_path;

	return fuse_main(n, fuse_argv, &muxfs_fuse_ops, NULL);
}
