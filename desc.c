/* desc.c */
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
#include <sys/syslimits.h>

#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ds.h"
#include "muxfs.h"
#include "gen.h"

MUXFS int
muxfs_desc_chk_file_content(struct muxfs_desc *desc, dind dev_index, int fd)
{
	struct muxfs_dev *dev;
	struct muxfs_chk chk;
	uint8_t readbuf[MUXFS_BLOCK_SIZE];
	ssize_t readsz;
	enum muxfs_chk_alg_type alg;

	if (muxfs_dev_get(&dev, dev_index))
		return 1;

	alg = dev->conf.chk_alg_type;
	
	muxfs_chk_init(&chk, alg);

	if (lseek(fd, 0, SEEK_SET) != 0)
		return 1;
	while ((readsz = read(fd, readbuf, MUXFS_BLOCK_SIZE)) > 0) {
		if (readsz == -1)
			return 1;
		muxfs_chk_update(&chk, readbuf, readsz);
	}

	muxfs_chk_final(desc->content_checksum, &chk);

	return 0;
}

MUXFS int
muxfs_desc_chk_dir_content(struct muxfs_desc *desc, dind dev_index, int fd)
{
	int rc;
	struct muxfs_dir dir;

	if (muxfs_pushdir(&dir, fd, "."))
		exit(-1);
	rc = muxfs_dir_content_chk(desc->content_checksum, dev_index, &dir);
	if (muxfs_popdir(&dir))
		exit(-1);
	return rc;
}

MUXFS int
muxfs_desc_chk_symlink_content(struct muxfs_desc *desc, dind dev_index,
    const char *path)
{
	struct muxfs_dev *dev;
	int fd;
	enum muxfs_chk_alg_type alg;
	ssize_t lnksz;
	char lnkbuf[PATH_MAX];

	if (muxfs_dev_get(&dev, dev_index))
		return 1;
	fd = dev->root_fd;
	alg = dev->conf.chk_alg_type;

	memset(lnkbuf, 0, PATH_MAX);
	if ((lnksz = readlinkat(fd, path, lnkbuf, PATH_MAX - 1)) == -1)
		return 1;

	muxfs_desc_chk_provided_content(desc, (uint8_t *)lnkbuf, lnksz, alg);
	return 0;
}

MUXFS void
muxfs_desc_chk_provided_content(struct muxfs_desc *desc, const uint8_t *content,
    size_t contentsz, enum muxfs_chk_alg_type alg_type)
{
	struct muxfs_chk chk;

	muxfs_chk_init(&chk, alg_type);
	muxfs_chk_update(&chk, content, contentsz);
	muxfs_chk_final(desc->content_checksum, &chk);
}

/*
 * It is assumed that 'desc' has been initialized via
 * muxfs_desc_init_from_stat().
 */
MUXFS int
muxfs_desc_chk_node_content(struct muxfs_desc *desc, dind dev_index,
    const char *path)
{
	struct muxfs_dev *dev;
	int fd, rc;

	if (muxfs_dev_get(&dev, dev_index))
		return 1;

	switch (desc->type) {
	case MUXFS_DT_REG:
		if ((fd = openat(dev->root_fd, path, O_RDONLY|O_NOFOLLOW))
		    == -1)
			return 1;
		rc = muxfs_desc_chk_file_content(desc, dev_index, fd);
		close(fd);
		break;
	case MUXFS_DT_DIR:
		if ((fd = openat(dev->root_fd, path, O_RDONLY|O_NOFOLLOW))
		    == -1)
			return 1;
		rc = muxfs_desc_chk_dir_content(desc, dev_index, fd);
		close(fd);
		break;
	case MUXFS_DT_LNK:
		rc = muxfs_desc_chk_symlink_content(desc, dev_index, path);
		break;
	default:
		return 1;
	}
	
	return rc;
}

MUXFS void
muxfs_desc_chk_meta(uint8_t *sum_out, const struct muxfs_desc *desc,
    enum muxfs_chk_alg_type alg_type)
{
	struct muxfs_chk chk;
	ssize_t chksz;
	uint64_t u64h, u64le;

	chksz = muxfs_chk_size(alg_type);
	
	muxfs_chk_init(&chk, alg_type);

	u64h = desc->eno;
	u64le = htole64(u64h);
	muxfs_chk_update(&chk, (uint8_t *)&u64le, sizeof(uint64_t));
	u64h = desc->type;
	u64le = htole64(u64h);
	muxfs_chk_update(&chk, (uint8_t *)&u64le, sizeof(uint64_t));
	u64h = desc->owner;
	u64le = htole64(u64h);
	muxfs_chk_update(&chk, (uint8_t *)&u64le, sizeof(uint64_t));
	u64h = desc->group;
	u64le = htole64(u64h);
	muxfs_chk_update(&chk, (uint8_t *)&u64le, sizeof(uint64_t));
	u64h = desc->perms;
	u64le = htole64(u64h);
	muxfs_chk_update(&chk, (uint8_t *)&u64le, sizeof(uint64_t));

	muxfs_chk_update(&chk, desc->content_checksum, chksz);
	muxfs_chk_final(sum_out, &chk);
}

MUXFS int
muxfs_desc_init_from_stat(struct muxfs_desc *desc_out, struct stat *st,
    uint64_t eno)
{
	muxfs_desc_type desc_type;

	if (muxfs_desc_type_from_mode(&desc_type, st->st_mode))
		return 1;

	*desc_out = (struct muxfs_desc) {
		.eno = eno,
		.type = desc_type,
		.owner = st->st_uid,
		.group = st->st_gid,
		.perms = st->st_mode
	};
	return 0;
}

MUXFS int
muxfs_desc_type_from_mode(muxfs_desc_type *dt_out, mode_t mode)
{
	if (S_ISREG(mode))
		*dt_out = MUXFS_DT_REG;
	else if (S_ISDIR(mode))
		*dt_out = MUXFS_DT_DIR;
	else if (S_ISLNK(mode))
		*dt_out = MUXFS_DT_LNK;
	else
		return 1;
	return 0;
}
