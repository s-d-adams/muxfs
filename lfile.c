/* lfile.c */
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

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gen.h"
#include "muxfs.h"

MUXFS void
muxfs_range_compute(struct muxfs_range *range_inout, size_t chksz)
{
	struct muxfs_range r;

	r.byte_begin = range_inout->byte_begin;
	r.byte_end = range_inout->byte_end;

	r.blk_begin = muxfs_align_down(r.byte_begin, MUXFS_BLOCK_SIZE);
	r.blk_end = muxfs_align_up(r.byte_end, MUXFS_BLOCK_SIZE);
	r.blk_index_begin = r.blk_begin / MUXFS_BLOCK_SIZE;
	r.blk_index_end = r.blk_end / MUXFS_BLOCK_SIZE;
	r.lfilesz = chksz * (r.blk_index_end - r.blk_index_begin);
	r.lfileoff = chksz * r.blk_index_begin;

	*range_inout = r;
}

MUXFS int
muxfs_lfile_abs_range(uint64_t *index_out, uint64_t *count_out,
    uint64_t file_blk_count, uint64_t level)
{
	uint64_t n, l, i;

	if (file_blk_count == 0)
		return 1;

	i = 0;
	n = file_blk_count;
	for (l = 0; l < level; ++l) {
		if ((n == 1) && ((level - 1) > l))
			return 1;
		i += n;
		n = (n / 2) + (n % 2);
	}

	if (index_out)
		*index_out = i;
	if (count_out)
		*count_out = n;
	return 0;
}

MUXFS uint64_t
muxfs_lfile_root_level(uint64_t file_blk_count)
{
	uint64_t n, l;

	if (file_blk_count == 0)
		return 1;

	n = file_blk_count;
	l = 0;
	while (n != 1) {
		n = (n / 2) + (n % 2);
		++l;
	}
	return l;
}

MUXFS uint64_t
muxfs_lfile_root_abs_index(uint64_t file_blk_count)
{
	uint64_t level, index;

	level = muxfs_lfile_root_level(file_blk_count);

	if (muxfs_lfile_abs_range(&index, NULL, file_blk_count, level))
		exit(-1); /* Programming error. */

	return index;
}

MUXFS int
muxfs_lfile_open(int *fd_out, int lfile_fd, ino_t ino, int flags)
{
	int rc;
	char path_buf[PATH_MAX];
	size_t path_len;
	int fd;

	rc = 1;

	path_len = snprintf(NULL, 0, "%llu", ino);
	if (path_len < 0)
		goto out;
	if (path_len >= (PATH_MAX - 1))
		goto out;
	memset(path_buf, 0, PATH_MAX);
	snprintf(path_buf, PATH_MAX - 1, "%llu", ino);

	if ((fd = openat(lfile_fd, path_buf, flags)) == -1)
		goto out;

	*fd_out = fd;
	rc = 0;
out:
	return rc;
}

MUXFS int
muxfs_lfile_create(int lfile_fd, size_t chksz, ino_t ino, size_t filesz)
{
	int rc;
	uint64_t blk_count;
	size_t lfilesz;
	int path_len;
	char path_buf[PATH_MAX];
	int fd;

	rc = 1;

	blk_count = (filesz / MUXFS_BLOCK_SIZE) +
	    ((filesz % MUXFS_BLOCK_SIZE) ? 1 : 0);

	lfilesz = chksz * (muxfs_lfile_root_abs_index(blk_count) + 1);

	path_len = snprintf(NULL, 0, "%llu", ino);
	if (path_len < 0)
		goto out;
	if (path_len >= (PATH_MAX - 1))
		goto out;
	memset(path_buf, 0, PATH_MAX);
	snprintf(path_buf, PATH_MAX - 1, "%llu", ino);
	if ((fd = openat(lfile_fd, path_buf, O_RDWR|O_CREAT|O_EXCL, 0700))
	    == -1)
		goto out;
	if (ftruncate(fd, lfilesz))
		goto out2;

	rc = 0;
out2:
	if (close(fd))
		exit(-1);
out:
	return rc;
}

static int
muxfs_lfile_grow(int lfile_fd, size_t chksz, ino_t ino, size_t old_filesz,
    size_t new_filesz)
{
	int rc;
	uint64_t old_blk_count, new_blk_count;
	size_t new_lfilesz;
	uint64_t old_root_level, l, old_index, new_index, old_count, new_count;
	int fd;
	uint8_t *lfile;

	rc = 1;

	old_blk_count = (old_filesz / MUXFS_BLOCK_SIZE) +
	    ((old_filesz % MUXFS_BLOCK_SIZE) ? 1 : 0);
	new_blk_count = (new_filesz / MUXFS_BLOCK_SIZE) +
	    ((new_filesz % MUXFS_BLOCK_SIZE) ? 1 : 0);

	new_lfilesz = chksz * (muxfs_lfile_root_abs_index(new_blk_count) + 1);
	old_root_level = muxfs_lfile_root_level(old_blk_count);

	if (muxfs_lfile_open(&fd, lfile_fd, ino, O_RDWR))
		goto out;
	if (ftruncate(fd, new_lfilesz))
		goto out2;
	if ((lfile = mmap(NULL, new_lfilesz, PROT_READ|PROT_WRITE, MAP_SHARED,
	    fd, 0)) == MAP_FAILED)
		goto out2;

	for (l = old_root_level; l > 0; --l) {
		if (muxfs_lfile_abs_range(&old_index, &old_count, old_blk_count,
		    l))
			exit(-1); /* Programming error. */
		if (muxfs_lfile_abs_range(&new_index, &new_count, new_blk_count,
		    l))
			exit(-1); /* Programming error. */
		memmove(&lfile[new_index * chksz], &lfile[old_index * chksz],
		    old_count * chksz);
	}

	rc = 0;
/*out3:*/
	if (munmap(lfile, new_lfilesz))
		exit(-1);
out2:
	if (close(fd))
		exit(-1);
out:
	return rc;
}

static int
muxfs_lfile_shrink(int lfile_fd, size_t chksz, ino_t ino, size_t old_filesz,
    size_t new_filesz)
{
	int rc;
	uint64_t old_blk_count, new_blk_count;
	size_t old_lfilesz, new_lfilesz;
	uint64_t new_root_level, l, old_index, new_index, old_count, new_count;
	int fd;
	uint8_t *lfile;

	rc = 1;
	lfile = MAP_FAILED;

	old_blk_count = (old_filesz / MUXFS_BLOCK_SIZE) +
	    ((old_filesz % MUXFS_BLOCK_SIZE) ? 1 : 0);
	new_blk_count = (new_filesz / MUXFS_BLOCK_SIZE) +
	    ((new_filesz % MUXFS_BLOCK_SIZE) ? 1 : 0);

	old_lfilesz = chksz * (muxfs_lfile_root_abs_index(old_blk_count) + 1);
	new_lfilesz = chksz * (muxfs_lfile_root_abs_index(new_blk_count) + 1);
	new_root_level = muxfs_lfile_root_level(new_blk_count);

	if (muxfs_lfile_open(&fd, lfile_fd, ino, O_RDWR))
		goto out;
	if ((lfile = mmap(NULL, old_lfilesz, PROT_READ|PROT_WRITE, MAP_SHARED,
	    fd, 0)) == MAP_FAILED)
		goto out2;

	for (l = 1; l <= new_root_level; ++l) {
		if (muxfs_lfile_abs_range(&old_index, &old_count, old_blk_count,
		    l))
			exit(-1); /* Programming error. */
		if (muxfs_lfile_abs_range(&new_index, &new_count, new_blk_count,
		    l))
			exit(-1); /* Programming error. */
		memmove(&lfile[new_index * chksz], &lfile[old_index * chksz],
		    new_count * chksz);
	}

	if (munmap(lfile, new_lfilesz))
		exit(-1);
	lfile = MAP_FAILED;

	if (ftruncate(fd, new_lfilesz))
		goto out2;

	rc = 0;
/*out3:*/
	if (lfile != MAP_FAILED) {
		if (munmap(lfile, new_lfilesz))
			exit(-1);
	}
out2:
	if (close(fd))
		exit(-1);
out:
	return rc;
}

MUXFS int
muxfs_lfile_resize(int lfile_fd, size_t chksz, ino_t ino, size_t old_filesz,
    size_t new_filesz)
{
	if (new_filesz == old_filesz)
		return 0;
	else if (new_filesz > old_filesz) {
		return muxfs_lfile_grow(lfile_fd, chksz, ino, old_filesz,
		    new_filesz);
	} else {
		return muxfs_lfile_shrink(lfile_fd, chksz, ino, old_filesz,
		    new_filesz);
	}
	exit(-1); /* Unreachable. */
}

MUXFS int
muxfs_lfile_delete(int lfile_fd, ino_t ino)
{
	int rc;
	char path_buf[PATH_MAX];
	size_t path_len;

	rc = 1;

	path_len = snprintf(NULL, 0, "%llu", ino);
	if (path_len < 0)
		goto out;
	if (path_len >= (PATH_MAX - 1))
		goto out;
	memset(path_buf, 0, PATH_MAX);
	snprintf(path_buf, PATH_MAX - 1, "%llu", ino);

	if (unlinkat(lfile_fd, path_buf, 0))
		goto out;

	rc = 0;
out:
	return rc;
}

MUXFS int
muxfs_lfile_exists(int *exists_out, int lfile_fd, ino_t ino)
{
	char path_buf[PATH_MAX];
	size_t path_len;

	path_len = snprintf(NULL, 0, "%llu", ino);
	if (path_len < 0)
		return 1;
	if (path_len >= (PATH_MAX - 1))
		return 1;
	memset(path_buf, 0, PATH_MAX);
	snprintf(path_buf, PATH_MAX - 1, "%llu", ino);

	return muxfs_existsat(exists_out, lfile_fd, path_buf);
}

MUXFS int
muxfs_lfile_ancestors_recompute(uint8_t *root_sum, int lfile_fd,
    enum muxfs_chk_alg_type alg, ino_t ino, size_t filesz, uint64_t ibegin,
    uint64_t iend)
{
	int rc, fd;
	size_t chksz, lfilesz;
	uint64_t blk_count, root_level, l, li, ln, pli, pln, pi, i;
	uint8_t *lfile;
	struct muxfs_chk chk;

	rc = 1;
	fd = -1;
	lfile = MAP_FAILED;
	lfilesz = 0;

	chksz = muxfs_chk_size(alg);

	if (iend < 1)
		exit(-1); /* Programming error. */

	blk_count = (filesz / MUXFS_BLOCK_SIZE) +
	    ((filesz % MUXFS_BLOCK_SIZE) ? 1 : 0);
	lfilesz = chksz * (muxfs_lfile_root_abs_index(blk_count) + 1);
	root_level = muxfs_lfile_root_level(blk_count);

	if (muxfs_lfile_open(&fd, lfile_fd, ino, O_RDWR))
		goto out;
	if ((lfile = mmap(NULL, lfilesz, PROT_READ|PROT_WRITE, MAP_SHARED, fd,
	    0)) == MAP_FAILED)
		goto out;

	for (l = 0; l < root_level; ++l) {
		/* Align ibegin. */
		if (ibegin % 2)
			--ibegin;

		if (muxfs_lfile_abs_range(&li, &ln, blk_count, l))
			exit(-1); /* Programming error. */
		if (muxfs_lfile_abs_range(&pli, &pln, blk_count, l + 1))
			exit(-1); /* Programming error. */
		if (ibegin >= ln)
			exit(-1); /* Programming error. */
		if (iend > ln)
			exit(-1); /* Programming error. */
		
		for (i = ibegin; i < iend; i += 2) {
			muxfs_chk_init(&chk, alg);
			muxfs_chk_update(&chk, &lfile[chksz * (li + i)], chksz);
			if (i + 1 < iend) {
				muxfs_chk_update(&chk, &lfile[chksz * (li + i +
				    1)], chksz);
			}
			pi = i / 2;
			muxfs_chk_final(&lfile[chksz * (pli + pi)], &chk);
		}

		ibegin /= 2;
		iend = ((iend + 1) / 2);
	}

	if (root_sum != NULL) {
		memcpy(root_sum, &lfile[chksz *
		    muxfs_lfile_root_abs_index(blk_count)], chksz);
	}
	rc = 0;
out:
	if (lfile != MAP_FAILED) {
		if (lfilesz == 0)
			exit(-1); /* Programming error. */
		if (munmap(lfile, lfilesz))
			exit(-1);
	} else if (lfilesz != 0)
		exit(-1); /* Programming error. */
	if (fd != -1) {
		if (close(fd))
			exit(-1);
	}
	return rc;
}

MUXFS int
muxfs_lfile_readback(uint8_t *root_sum, dind dev_index, const char *path,
    size_t begin, size_t end, const uint8_t *expected)
{
	int rc;
	struct muxfs_dev *dev;
	enum muxfs_chk_alg_type alg;
	size_t chksz;
	struct stat st;
	ino_t ino;
	int fd, lfd;
	size_t filesz, lfilesz;
	uint8_t *lfile;
	uint64_t blk_count, root_level, l, li, ln, pli, pln, pi, i, ibegin,
	    iend;
	uint8_t buf[MUXFS_BLOCK_SIZE], sum[MUXFS_CHKSZ_MAX];
	size_t i_offset, rdsz;
	struct muxfs_chk chk;

	rc = 1;
	fd = -1;
	lfd = -1;
	lfile = MAP_FAILED;
	lfilesz = 0;

	if (muxfs_dev_get(&dev, dev_index))
		goto out;
	alg = dev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);

	if (fstatat(dev->root_fd, path, &st, AT_SYMLINK_NOFOLLOW))
		goto out;
	ino = st.st_ino;
	filesz = st.st_size;
	if (begin >= filesz)
		goto out;
	if (end > filesz)
		goto out;

	blk_count = (filesz / MUXFS_BLOCK_SIZE) +
	    ((filesz % MUXFS_BLOCK_SIZE) ? 1 : 0);
	lfilesz = chksz * (muxfs_lfile_root_abs_index(blk_count) + 1);
	root_level = muxfs_lfile_root_level(blk_count);
	ibegin = muxfs_align_down(begin, MUXFS_BLOCK_SIZE) / MUXFS_BLOCK_SIZE;
	iend = muxfs_align_up(end, MUXFS_BLOCK_SIZE) / MUXFS_BLOCK_SIZE;

	if ((ibegin + 1) > iend)
		exit(-1); /* Programming error. */
	if ((ibegin % 2) != 0)
		--ibegin;

	if ((fd = openat(dev->root_fd, path, O_RDONLY)) == -1)
		goto out;
	if (muxfs_lfile_open(&lfd, dev->lfile_fd, ino, O_RDONLY))
		goto out;
	if ((lfile = mmap(NULL, lfilesz, PROT_READ, MAP_SHARED, lfd, 0))
	    == MAP_FAILED)
		goto out;

	for (i = ibegin; i < iend; ++i) {
		i_offset = i * MUXFS_BLOCK_SIZE;
		rdsz = MUXFS_BLOCK_SIZE;
		if (i_offset + rdsz > filesz) {
			if ((i + 1) != iend)
				exit(-1); /* Programming error. */
			rdsz = filesz - i_offset;
		}
		if (pread(fd, buf, rdsz, i_offset) != rdsz)
			goto out;
		muxfs_chk_init(&chk, alg);
		muxfs_chk_update(&chk, buf, rdsz);
		muxfs_chk_final(sum, &chk);
		if (bcmp(sum, &lfile[chksz * i], chksz) != 0)
			goto out;
	}
	for (l = 0; l < root_level; ++l) {
		/* Align ibegin. */
		if (ibegin % 2)
			--ibegin;

		if (muxfs_lfile_abs_range(&li, &ln, blk_count, l))
			exit(-1); /* Programming error. */
		if (muxfs_lfile_abs_range(&pli, &pln, blk_count, l + 1))
			exit(-1); /* Programming error. */
		if (ibegin >= ln)
			exit(-1); /* Programming error. */
		if (iend > ln)
			exit(-1); /* Programming error. */
		
		for (i = ibegin; i < iend; i += 2) {
			muxfs_chk_init(&chk, alg);
			muxfs_chk_update(&chk, &lfile[chksz * (li + i)], chksz);
			if (i + 1 < iend) {
				muxfs_chk_update(&chk, &lfile[chksz * (li + i +
				    1)], chksz);
			}
			pi = i / 2;
			muxfs_chk_final(sum, &chk);
			if (bcmp(sum, &lfile[chksz * (pli + pi)], chksz) != 0)
				goto out;
		}

		ibegin /= 2;
		iend = ((iend + 1) / 2);
	}

	if ((expected != NULL) && (bcmp(expected, &lfile[chksz * pli], chksz)
	    != 0))
		goto out;
		
	if (root_sum != NULL)
		memcpy(root_sum, &lfile[chksz * pli], chksz);
	rc = 0;
out:
	if (lfile != MAP_FAILED) {
		if (lfilesz == 0)
			exit(-1); /* Programming error. */
		if (munmap(lfile, lfilesz))
			exit(-1);
	} else if (lfilesz != 0)
		exit(-1); /* Programming error. */
	if (lfd != -1) {
		if (close(lfd))
			exit(-1);
	}
	if (fd != -1) {
		if (close(fd))
			exit(-1);
	}
	return rc;
}
