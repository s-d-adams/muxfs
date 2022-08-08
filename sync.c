/* sync.c */
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

#include <stdio.h>
#include <stdlib.h>

#include "muxfs.h"

static void
muxfs_sync_usage(void)
{
	dprintf(2, "usage: muxfs sync destination source ...\n");
}

MUXFS int
muxfs_sync_main(int argc, char *argv[])
{
	int empty, exists;
	struct muxfs_dev *ddev, *sdev;
	const char *ddev_path;
	enum muxfs_chk_alg_type alg;
	size_t chksz, metasz;
	time_t seq_zero_time;
	const uint8_t *array_uuid;

	static const dind ddev_index = 0, sdev_index = 1;

	if (muxfs_parse_args(argc, argv, 1)) {
		muxfs_sync_usage();
		exit(1);
	}

	if (muxfs_init(1))
		exit(-1);

	if (muxfs_dev_count() < 2) {
		dprintf(2, "Error: There are less than 2 directories in the "
		    "array.\n");
		exit(1);
	}
	if (muxfs_dev_get(&ddev, ddev_index, 1))
		exit(-1);
	if (muxfs_dev_get(&sdev, sdev_index, 0))
		exit(-1);

	ddev_path = ddev->root_path;
	alg = sdev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);
	if (muxfs_meta_size_raw(&metasz, alg))
		exit(-1);
	seq_zero_time = sdev->conf.seq_zero_time;
	array_uuid = sdev->conf.array_uuid;

	if (muxfs_dir_is_empty(&empty, ddev_path))
		exit(-1);
	if (empty) {
		if (muxfs_dev_format(ddev_path, alg, chksz, metasz,
		    seq_zero_time, array_uuid))
			exit(-1);
	}

	if (muxfs_dev_mount(ddev_index, 1))
		exit(-1);

	if (muxfs_state_restore_only_set(ddev_index))
		exit(-1);
	if (muxfs_state_restore_push_back(ddev_index, "."))
		exit(-1);
	muxfs_restore_now();

	if (muxfs_dev_get(&ddev, ddev_index, 0))
		exit(-1);
	if (muxfs_dev_get(&sdev, sdev_index, 0))
		exit(-1);
	ddev->state.seq = sdev->state.seq;
	if (muxfs_dev_state_write_fd(ddev->state_fd, &ddev->state))
		exit(-1);

	if (muxfs_existsat(&exists, ddev->root_fd, ".muxfs/rename.tmp"))
		exit(-1);
	if (exists) {
		if (muxfs_removeat(ddev->root_fd, ".muxfs/rename.tmp"))
			exit(-1);
	}

	if (muxfs_final())
		exit(-1);

	return 0;
}
