/* fsck_muxfs.c */
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

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ds.h"
#include "muxfs.h"

enum muxfs_fsck_mode {
	MUXFS_FSCK_AUDIT,
	MUXFS_FSCK_RESTORE,
};

/*
 * 'path' is required to be null-terminated and pointing to a buffer of
 * capacity PATH_MAX, 'len' is provided so that 'path' may be mutated, then
 * returned to its original state.
 */
static int
muxfs_fsck_impl(enum muxfs_fsck_mode mode, dind dev_index, char *path,
    size_t len)
{
	int			 rc;
	struct muxfs_dev	*dev;
	struct stat		 st;
	struct muxfs_dir	 dir;
	struct dirent		*dirent;
	size_t			 i, sublen, dnamelen;
	const char		*dname;
	const char		*epath; /* Effective path. */

	epath = (len > 0) ? path : ".";

	if (muxfs_dev_get(&dev, dev_index))
		return 1;

	if (fstatat(dev->root_fd, epath, &st, AT_SYMLINK_NOFOLLOW))
		return 1;
	if (S_ISDIR(st.st_mode)) {
		rc = 1;
		if (muxfs_pushdir(&dir, dev->root_fd, epath))
			goto dirout;
		for (i = 0; i < dir.ent_count; ++i) {
			dirent = dir.ent_array[i];
			dname = dirent->d_name;
			dnamelen = dirent->d_namlen;
			if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
				continue;
			if ((dnamelen == 2) && (strncmp("..", dname, 2) == 0))
				continue;
			if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6)
			    == 0))
				continue;
			sublen = dnamelen;
			if (len > 0)
				sublen += len + 1;
			if (sublen >= PATH_MAX)
				goto dirout2;
			if (len > 0)
				strcat(path, "/");
			strcat(path, dname);
			if (muxfs_fsck_impl(mode, dev_index, path, sublen))
				goto dirout2;
			path[len] = '\0';
		}
		if (muxfs_readback(dev_index, epath, 0, NULL)) {
			printf("%s/%s\n", dev->root_path, epath);
			if ((mode == MUXFS_FSCK_RESTORE) &&
			    muxfs_state_restore_push_back(dev_index, epath))
				exit(-1);
		}
		rc = 0;
dirout2:
		if (muxfs_popdir(&dir))
			exit(-1);
dirout:
		return rc;
	}
	if (!(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)))
		return 1;
	if (muxfs_readback(dev_index, epath, 0, NULL)) {
		printf("%s/%s\n", dev->root_path, epath);
		if ((mode == MUXFS_FSCK_RESTORE) &&
		    muxfs_state_restore_push_back(dev_index, epath))
			exit(-1);
	}
	return 0;
}

static int
muxfs_fsck(enum muxfs_fsck_mode mode, dind dev_index)
{
	char path[PATH_MAX];

	memset(path, 0, PATH_MAX);
	if (muxfs_fsck_impl(mode, dev_index, path, 0))
		return 1;
	if (mode == MUXFS_FSCK_RESTORE)
		muxfs_restore_now();
	return 0;
}

int
main(int argc, char *argv[])
{
	uint64_t next_eno, max_next_eno;
	dind i, j, mnts;
	struct muxfs_args *args;
	dind dev_index, dev_count;
	enum muxfs_fsck_mode fsck_mode;

	if (muxfs_state_syslog_init())
		return -1;
	if (muxfs_dsinit())
		return -1;

	args = &muxfs_cmdline;
	if (muxfs_parse_args(argc, argv, 1)) {
		muxfs_fsck_usage();
		return -1;
	}
	fsck_mode = args->a ? MUXFS_FSCK_AUDIT : MUXFS_FSCK_RESTORE;

	muxfs_dev_module_init();
	if (muxfs_state_restore_queue_init())
		exit(-1);

	mnts = 0;
	max_next_eno = 0;
	for (i = 0; i < args->dev_count; ++i) {
		if (muxfs_dev_append(&j, args->dev_paths[i]))
			exit(-1);
		if (muxfs_dev_mount(j))
			continue;
		if (muxfs_assign_peek_next_eno(&next_eno, mnts))
			exit(-1);
		++mnts;
		if (next_eno > max_next_eno)
			max_next_eno = next_eno;
	}
	if (mnts == 0)
		exit(-1);

	if (muxfs_state_eno_next_init(max_next_eno))
		exit(-1);

	if ((dev_count = muxfs_dev_count()) == 0)
		exit(-1);
	for (dev_index = 0; dev_index < dev_count; ++dev_index) {
		if (muxfs_fsck(fsck_mode, dev_index))
			exit(-1);
	}

	dev_count = muxfs_dev_count();
	for (i = dev_count; i > 0; --i) {
		j = i - 1;
		if (muxfs_dev_is_mounted(j)) {
			if (muxfs_dev_unmount(j))
				exit(-1);
		}
	}
	muxfs_state_restore_queue_final();
	if (muxfs_state_syslog_final())
		exit(-1);
	if (muxfs_dsfinal())
		exit(-1);

	return 0;
}
