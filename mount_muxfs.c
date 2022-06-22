/* mount_muxfs.c */
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

#include <fuse.h>
#include <stdio.h>
#include <string.h>

#include "ds.h"
#include "mount_muxfs.h"
#include "ops.h"

struct muxfs_args muxfs_cmdline;

static int
muxfs_parse_args(int argc, char **argv)
{
	int i;
	size_t len;
	struct muxfs_args *args = &muxfs_cmdline;

	i = argc - 1;
	if (argv[i][0] == '-')
		return 1;
	len = strlen(argv[i]);
	if (len >= PATH_MAX)
		return 1;
	strcpy(args->mp_path, argv[i]);

	args->dev_count = 0;
	for (i = 1; i < argc - 1; ++i) {
		if (argv[i][0] == '-')
			continue;
		len = strlen(argv[i]);
		if (len >= PATH_MAX)
			return 1;
		strcpy(args->dev_paths[args->dev_count++], argv[i]);
	} 
	return 0;
}

static void
muxfs_usage(void)
{
	fprintf(stderr, "Invalid arguments.\n");
}

int
main(int argc, char **argv)
{
	int n;
	char *fuse_argv[8];

	if (muxfs_state_syslog_init())
		return -1;
	if (muxfs_dsinit())
		return -1;

	n = 0;
	fuse_argv[n++] = argv[0];
	/*fuse_argv[n++] = "-f";*/
	/*fuse_argv[n++] = "-odebug";*/
	fuse_argv[n++] = "-ouse_ino";
	fuse_argv[n++] = "-oallow_other";
	fuse_argv[n++] = argv[argc - 1];

	if (muxfs_parse_args(argc, argv)) {
		muxfs_usage();
		return -1;
	}

	return fuse_main(n, fuse_argv, &muxfs_fuse_ops, NULL);
}
