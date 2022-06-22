/* util.c */
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
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "ds.h"
#include "muxfs.h"
#include "gen.h"

static int muxfs_restore_file(dind, dind, const char *, int, struct stat *,
    struct muxfs_meta *);
static int muxfs_restore_symlink(dind, dind, const char *, struct stat *,
    struct muxfs_meta *);

/*
 * This enum classifies the difference of a directory's content with respect to
 * the influence of a single specified file.
 */
enum muxfs_dir_patch_type {
	MUXFS_SUBSTITUTE, /* The content of the file is different. */
	MUXFS_PLUS, /* The filename is not listed in the base directory. */
	MUXFS_MINUS, /* The filename is not listed in the patched directory. */
};
struct muxfs_dir_patch {
	enum muxfs_dir_patch_type type;
	const char *fname;
	const uint8_t *sum;
};
static int
muxfs_dir_patch_sums(uint8_t *as_is_out, uint8_t *with_patch_out,
    enum muxfs_chk_alg_type alg, dind dev_index, int dirfd,
    struct muxfs_dir *dir, struct muxfs_dir_patch *patch)
{
	int rc;
	size_t chksz;
	struct stat subst;
	struct dirent *dirent;
	size_t i, dnamelen, fnamelen, entind1, entind2;
	const char *dname;
	int match;
	ino_t subino;
	struct muxfs_meta submeta;
	struct muxfs_chk as_is_content_chk, with_patch_content_chk;
	int patched;

	rc = 1;

	chksz = muxfs_chk_size(alg);
	fnamelen = strlen(patch->fname);

	muxfs_chk_init(&as_is_content_chk, alg);
	muxfs_chk_init(&with_patch_content_chk, alg);

	entind1 = 0;
	for (i = 0; i < dir->ent_count; ++i) {
		dirent = dir->ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
			continue;
		if ((dnamelen == 2) && (strncmp("..", dname, 2) == 0))
			continue;
		if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6)
		    == 0))
			continue;
		if (strcmp(dname, patch->fname) >= 0)
			break;
		++entind1;
	}

	patched = 0;
	entind2 = 0;
	for (i = 0; i < dir->ent_count; ++i) {
		dirent = dir->ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
			continue;
		if ((dnamelen == 2) && (strncmp("..", dname, 2) == 0))
			continue;
		if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6) == 0))
			continue;
		if (fstatat(dirfd, dname, &subst, AT_SYMLINK_NOFOLLOW))
			goto out;
		subino = subst.st_ino;
		if (muxfs_meta_read(&submeta, dev_index, subino))
			goto out;
		muxfs_chk_update(&as_is_content_chk, (uint8_t *)dname,
		    dnamelen);
		muxfs_chk_update(&as_is_content_chk, &submeta.checksums[0],
		    chksz);
		if (entind2 == entind1) {
			patched = 1;
			match = ((dnamelen == fnamelen) &&
			    (strncmp(patch->fname, dname, fnamelen) == 0));
			if (patch->type == MUXFS_MINUS) {
				if (!match)
					goto out;
				++entind2;
				continue;
			}
			muxfs_chk_update(&with_patch_content_chk,
			    (uint8_t *)patch->fname, fnamelen);
			muxfs_chk_update(&with_patch_content_chk, patch->sum,
			    chksz);
			switch (patch->type) {
			case MUXFS_SUBSTITUTE:
				if (!match)
					goto out;
				++entind2;
				continue;
				break;
			case MUXFS_PLUS:
				if (match)
					goto out;
				break;
			default:
				exit(-1); /* Programming error. */
			}
		}
		muxfs_chk_update(&with_patch_content_chk, (uint8_t *)dname,
		    dnamelen);
		muxfs_chk_update(&with_patch_content_chk, &submeta.checksums[0],
		    chksz);
		++entind2;
	}
	if (!patched) {
		if (patch->type != MUXFS_PLUS)
			goto out;
		muxfs_chk_update(&with_patch_content_chk,
		    (uint8_t *)patch->fname, fnamelen);
		muxfs_chk_update(&with_patch_content_chk, patch->sum, chksz);
	}
	muxfs_chk_final(as_is_out, &as_is_content_chk);
	muxfs_chk_final(with_patch_out, &with_patch_content_chk);

	rc = 0;
out:
	return rc;
}

MUXFS int
muxfs_dir_meta_recompute(struct muxfs_cud *pcud_out, dind dev_index,
    const struct muxfs_cud *ccud_in)
{
	int			 rc;
	struct muxfs_dev	*dev;
	int			 root_fd, dirfd;
	struct stat		 st;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;
	ino_t			 ino;
	struct muxfs_dir	 dir;
	struct muxfs_desc	 pre_desc, post_desc;
	uint64_t		 eno;
	struct muxfs_meta	 db_pre_meta, pre_meta, post_meta;
	struct muxfs_dir_patch	 patch;

	rc = 1;

	if (muxfs_dev_get(&dev, dev_index))
		goto out;
	root_fd = dev->root_fd;
	alg = dev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);

	if (muxfs_pushdir(&dir, root_fd, ccud_in->path))
		goto out;

	if ((dirfd = openat(root_fd, ccud_in->path, O_RDONLY|O_NOFOLLOW)) == -1)
		goto out2;
	if (fstat(dirfd, &st))
		goto out3;
	if (!S_ISDIR(st.st_mode))
		goto out3;
	ino = st.st_ino;
	if (muxfs_meta_read(&db_pre_meta, dev_index, ino))
		goto out3;
	eno = db_pre_meta.header.eno;
	if (muxfs_desc_init_from_stat(&pre_desc, &st, eno))
		goto out3;
	if (muxfs_desc_init_from_stat(&post_desc, &st, eno))
		goto out3;

	/*
	 * If this seems backwards it is because we are differencing the
	 * directory after having applied the operation.
	 */
	switch (ccud_in->type) {
	case MUXFS_CUD_CREATE:
		patch.type = MUXFS_MINUS;
		break;
	case MUXFS_CUD_UPDATE:
		patch.type = MUXFS_SUBSTITUTE;
		break;
	case MUXFS_CUD_DELETE:
		patch.type = MUXFS_PLUS;
		break;
	default:
		exit(-1); /* Programming error. */
	}
	patch.fname = ccud_in->fname;
	patch.sum = &ccud_in->pre_meta.checksums[0];

	if (muxfs_dir_patch_sums(post_desc.content_checksum,
	    pre_desc.content_checksum, alg, dev_index, dirfd, &dir,
	    &patch))
		goto out3;

	pre_meta.header = post_meta.header = (struct muxfs_meta_header) {
		.flags = MF_ASSIGNED,
		.eno = eno,
	};
	muxfs_desc_chk_meta(&pre_meta.checksums[0], &pre_desc, alg);
	muxfs_desc_chk_meta(&post_meta.checksums[0], &post_desc, alg);
	memcpy(&pre_meta.checksums[chksz], pre_desc.content_checksum, chksz);
	memcpy(&post_meta.checksums[chksz], post_desc.content_checksum, chksz);

	if (bcmp(&pre_meta.checksums[0], &db_pre_meta.checksums[0], chksz) != 0)
		goto out3;
	if (bcmp(&pre_meta.checksums[chksz], &db_pre_meta.checksums[chksz],
	    chksz) != 0)
		goto out3;

	if (muxfs_meta_write(&post_meta, dev_index, ino))
		goto out3;

	if (fsync(dev->meta_fd))
		exit(-1);

	if (muxfs_readback(dev_index, ccud_in->path, &post_meta))
		goto out3;

	pcud_out->type = MUXFS_CUD_UPDATE;
	pcud_out->pre_meta = pre_meta;
	rc = 0;
out3:
	if (close(dirfd))
		exit(-1);
out2:
	if (muxfs_popdir(&dir))
		exit(-1);
out:
	return rc;
}

/*
 * Returns 1 if 'path' points to the root directory, otherwise returns 0.
 * Assumes that 'path' has been through muxfs_path_sanitize().
 */
static int
muxfs_path_is_root(const char *path)
{
	return strcmp(".", path) == 0;
}

/*
 * Reads the content and metadata at 'path' in dev 'i', and computes its meta
 * checksum.  If the computed checksum does not match that in the meta.db file
 * then 1 is returned.  If 'expected' is not NULL and the computed checksum
 * does not match that in 'expected' then 1 is returned.  Otherwise 0 is
 * returned.
 */
MUXFS int
muxfs_readback(dind i, const char *path, struct muxfs_meta *expected)
{
	struct muxfs_dev	*dev;
	int			 root_fd;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;
	struct stat		 st;
	ino_t			 ino;
	struct muxfs_meta	 meta;
	uint64_t		 eno;
	struct muxfs_desc	 desc;
	uint8_t			 meta_chk_buf[MUXFS_CHKSZ_MAX];

	if (muxfs_dev_get(&dev, i))
		goto fail;
	root_fd = dev->root_fd;
	alg = dev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);
	if (fstatat(root_fd, path, &st, AT_SYMLINK_NOFOLLOW))
		goto fail;
	ino = st.st_ino;
	if (muxfs_meta_read(&meta, i, ino))
		goto fail;
	eno = meta.header.eno;
	if (muxfs_desc_init_from_stat(&desc, &st, eno))
		goto fail;
	if (muxfs_desc_chk_node_content(&desc, i, path))
		goto fail;
	muxfs_desc_chk_meta(meta_chk_buf, &desc, alg);
	if (bcmp(meta_chk_buf, &meta.checksums[0], chksz) != 0)
		goto fail;
	if ((expected != NULL) &&
	    (bcmp(meta_chk_buf, &expected->checksums[0], chksz) != 0))
		goto fail;
	return 0;
fail:
	return 1;
}

MUXFS int
muxfs_parent_readback(dind i, const char *path)
{
	char	 ppath[PATH_MAX];
	size_t	 path_len;

	if (muxfs_path_is_root(path))
		return 1;

	path_len = strlen(path);
	memcpy(ppath, path, path_len);
	ppath[path_len] = '\0';

	if (muxfs_path_pop(NULL, ppath, NULL)) {
		memset(ppath, 0, PATH_MAX);
		strcpy(ppath, ".");
	}

	return muxfs_readback(i, ppath, NULL);
}

static void
muxfs_path_trailing_seps_strip(char *path, size_t path_len)
{
	char *sep;

	sep = strrchr(path, '/');
	if (sep == NULL)
		return;
	while ((sep - path) == path_len) {
		*sep = '\0';
		--path_len;
		if (path_len == 0)
			return;
		sep = strrchr(path, '/');
		if (sep == NULL)
			return;
	}
}

/*
 * Replaces '/' in path with '\0' in order to split the path into directory and
 * filename components.  If fname_out is not NULL then *fname_out is set to
 * point to the start of the filename component after the replaced '/'.
 * Returns 1 if there was not a preceeding path component, otherwise returns 0.
 */
MUXFS int
muxfs_path_pop(const char **fname_out, char *path, size_t *path_len_inout)
{
	char	*sep, *fname;
	size_t	 path_len;

	if (path_len_inout != NULL)
		path_len = *path_len_inout;
	else
		path_len = strlen(path);

	muxfs_path_trailing_seps_strip(path, path_len);
	path_len = strlen(path);
	if (path_len == 0)
		return 1;

	sep = strrchr(path, '/');
	if (sep == NULL)
		return 1;
	fname = sep + 1;
	*sep = '\0';
	path_len = strlen(path);
	if (path_len == 0)
		return 1;
	muxfs_path_trailing_seps_strip(path, path_len);
	path_len = strlen(path);
	if (path_len == 0)
		return 1;

	if (path_len_inout != NULL)
		*path_len_inout = path_len;
	if (fname_out != NULL)
		*fname_out = fname;
	return 0;
}

/* Returns 1 if the final path component of 'path' is ".muxfs", 0 otherwise. */
static int
muxfs_path_is_dot_muxfs(const char *_path)
{
	char		 path[PATH_MAX];
	const char	*fname;
	size_t		 path_len;

	path_len = strlen(_path);
	memcpy(path, _path, path_len);
	path[path_len] = '\0';
	if (muxfs_path_pop(&fname, path, &path_len))
		fname = path;
	if ((strlen(fname) == 6) && (strncmp(fname, ".muxfs", 6) == 0))
		return 1;
	return 0;
}

MUXFS int
muxfs_path_sanitize(const char **path_inout)
{
	const char *path;

	for (path = *path_inout; path[0] == '/'; ++path);
	if (path[0] == '\0')
		path = ".";

	if (muxfs_path_is_dot_muxfs(path))
		return 1;

	*path_inout = path;
	return 0;
}

MUXFS int
muxfs_ancestors_meta_recompute(dind dev_index, struct muxfs_cud *cud)
{
	char			 path[PATH_MAX];
	const char		*fname;
	size_t			 path_len;
	struct muxfs_cud	 pcud, ccud;

	/* There are no ancestors of the root path. */
	if (muxfs_path_is_root(cud->path))
		return 0;

	ccud = *cud;
	
	assert(strlen(cud->path) < PATH_MAX);

	path_len = strlen(cud->path);
	memcpy(path, cud->path, path_len);
	path[path_len] = '\0';

	while (!muxfs_path_pop(&fname, path, &path_len)) {
		ccud.path = path;
		ccud.fname = fname;
	
		if (muxfs_dir_meta_recompute(&pcud, dev_index, &ccud))
			return 1;

		ccud = pcud;
	}
	if (path_len == 0)
		exit(-1); /* Programming error. */

	/* Account for the special case of the root directory. */
	ccud.path = ".";
	ccud.fname = path;
	if (muxfs_dir_meta_recompute(&pcud, dev_index, &ccud))
		return 1;

	return 0;
}

static int
muxfs_existsat(int *exists_out, int fd, const char *path)
{
	struct stat st;

	if (fstatat(fd, path, &st, AT_SYMLINK_NOFOLLOW)) {
		if (errno != ENOENT)
			return 1;

		*exists_out = 0;
		return 0;
	}

	*exists_out = 1;
	return 0;
}

static int
muxfs_alphasort(const void *v1, const void *v2)
{
	const struct dirent **d1, **d2;
	d1 = (const struct dirent **)v1;
	d2 = (const struct dirent **)v2;
	return alphasort(d1, d2);
}

/* 
 * After use muxfs_popdir() must be called on 'dir_out' and must be done
 * in-order with respect to all other muxfs_dspop() and muxfs_popdir() calls.
 * Read ds.h for more information.
 */
MUXFS int
muxfs_pushdir(struct muxfs_dir *dir_out, int fd, const char *path)
{
	struct stat	  st;
	size_t		  blksz;
	uint8_t		 *dirbuf;
	int		  dirfd;
	struct dirent	 *dirent;
	ssize_t		  rdsz, i, rdend;
	struct dirent	**ent_array;
	size_t		  ent_count, j;

	if (fstatat(fd, path, &st, AT_SYMLINK_NOFOLLOW))
		return 1;
	if (!S_ISDIR(st.st_mode))
		return 1;

	blksz = st.st_blksize;
	if (muxfs_dspush((void **)&dirbuf, blksz))
		exit(-1);

	if ((dirfd = openat(fd, path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW)) == -1)
		goto fail;

	rdend = 0;
	ent_count = 0;
	while ((rdsz = getdents(dirfd, &dirbuf[rdend], blksz)) > 0) {
		for (i = 0; i < rdsz; i += dirent->d_reclen) {
			dirent = (struct dirent *)&dirbuf[i];
			++ent_count;
		}
		rdend += i;
		if (muxfs_dsgrow((void **)&dirbuf, blksz))
			exit(-1);
	}
	if (rdsz == -1)
		goto fail2;
	if (close(dirfd))
		exit(-1);

	if (muxfs_dspush((void **)&ent_array,
	    ent_count * sizeof(struct dirent *)))
		exit(-1);

	for (i = 0, j = 0; i < rdend; i += dirent->d_reclen, ++j)
		ent_array[j] = (struct dirent *)&dirbuf[i];

	qsort(ent_array, ent_count, sizeof(struct dirent *), muxfs_alphasort);

	*dir_out = (struct muxfs_dir) {
		.base = dirbuf,
		.ent_array = ent_array,
		.ent_count = ent_count,
	};
	return 0;
fail2:
	if (close(dirfd))
		exit(-1);
fail:
	if (muxfs_dspop(dirbuf))
		exit(-1);
	return 1;
}

MUXFS int
muxfs_popdir(struct muxfs_dir *dir)
{
	if (muxfs_dspop(dir->ent_array))
		exit(-1);
	if (muxfs_dspop(dir->base))
		exit(-1);
	return 0;
}

/*
 * 'path' is required to be null-terminated and pointing to a buffer of
 * capacity PATH_MAX, 'len' is provided so that 'path' may be mutated, then
 * returned to its original state.
 */
static int
muxfs_removeat_impl(int fd, char *path, size_t len)
{
	int			 rc;
	struct stat		 st;
	struct muxfs_dir	 dir;
	struct dirent		*dirent;
	size_t			 i, sublen, dnamelen;
	const char		*dname;

	if (fstatat(fd, path, &st, AT_SYMLINK_NOFOLLOW))
		return 1;
	if (S_ISDIR(st.st_mode)) {
		rc = 1;
		if (muxfs_pushdir(&dir, fd, path))
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
				goto dirout2;
			sublen = len + 1 + dnamelen;
			if (sublen >= PATH_MAX)
				goto dirout2;
			strcat(path, "/");
			strcat(path, dname);
			if (muxfs_removeat_impl(fd, path, sublen))
				goto dirout2;
			path[len] = '\0';
		}
		if (unlinkat(fd, path, AT_REMOVEDIR))
			goto dirout2;
		rc = 0;
dirout2:
		if (muxfs_popdir(&dir))
			exit(-1);
dirout:
		return rc;
	}
	if (!(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)))
		return 1;
	if (unlinkat(fd, path, 0))
		return 1;
	return 0;
}

static int
muxfs_removeat(int fd, const char *_path)
{
	char	 path[PATH_MAX];
	size_t	 len;

	len = strlen(_path);
	memset(path, 0, PATH_MAX);
	memcpy(path, _path, len);

	return muxfs_removeat_impl(fd, path, len);
}

static int
muxfs_restore_dir(dind ddev_index, dind sdev_index, const char *path,
    int sfd, struct stat *sst, struct muxfs_meta *expected)
{
	int			 rc;
	struct muxfs_dev	*sdev,
				*ddev;
	struct stat		 dst;
	char			 pathbuf[PATH_MAX];
	size_t			 pathlen,
				 dnamelen;
	const char		*dname;
	struct muxfs_dir	 dir;
	struct dirent		*dirent;
	size_t			 i;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;
	struct			 muxfs_chk chk;
	uint8_t			 sum[MUXFS_CHKSZ_MAX];
	struct stat		 subst;
	ino_t			 subino;
	struct muxfs_meta	 submeta;
	int			 subfd;
	int			 dfd;
	ino_t			 dino;
	struct muxfs_assign	 assign;

	int exists;

	rc = 1;

	if (muxfs_dev_get(&ddev, ddev_index))
		goto out;
	if (muxfs_dev_get(&sdev, sdev_index))
		goto out;
	alg = sdev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);
	pathlen = strlen(path);

	if (fstatat(ddev->root_fd, path, &dst, AT_SYMLINK_NOFOLLOW))
		goto out;
	if (!S_ISDIR(dst.st_mode)) {
		if (!(S_ISREG(dst.st_mode) || S_ISLNK(dst.st_mode)))
			goto out;
		if (unlinkat(ddev->root_fd, path, 0))
			goto out;
	}

	if (muxfs_existsat(&exists, ddev->root_fd, path))
		goto out;
	if (!exists) {
		if (mkdirat(ddev->root_fd, path, sst->st_mode))
			goto out;
		if (fchownat(ddev->root_fd, path, sst->st_uid, sst->st_gid,
		    AT_SYMLINK_NOFOLLOW))
			goto out;
	}

	if (muxfs_pushdir(&dir, sdev->root_fd, path))
		goto out;

	muxfs_chk_init(&chk, alg);
	for (i = 0; i < dir.ent_count; ++i) {
		dirent = dir.ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
			continue;
		if ((dnamelen == 2) && (strncmp("..", dname, 2) == 0))
			continue;
		if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6) == 0))
			continue;
		if (pathlen + 1 + dnamelen >= PATH_MAX)
			goto out2;
		if (fstatat(sfd, dname, &subst, AT_SYMLINK_NOFOLLOW))
			goto out2;
		subino = subst.st_ino;
		if (muxfs_meta_read(&submeta, sdev_index, subino))
			goto out2;
		muxfs_chk_update(&chk, (uint8_t *)dname, dnamelen);
		muxfs_chk_update(&chk, &submeta.checksums[0], chksz);
	}
	muxfs_chk_final(sum, &chk);
	if (bcmp(sum, &expected->checksums[chksz], chksz) != 0) {
		if (muxfs_state_restore_push_back(sdev_index, path))
			exit(-1);
		goto out2;
	}

	for (i = 0; i < dir.ent_count; ++i) {
		dirent = dir.ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
			continue;
		if ((dnamelen == 2) && (strncmp("..", dname, 1) == 0))
			continue;
		if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6) == 0))
			continue;
		if (pathlen + 1 + dnamelen >= PATH_MAX)
			goto out2;
		memset(pathbuf, 0 , PATH_MAX);
		strcpy(pathbuf, path);
		strcat(pathbuf, "/");
		strcat(pathbuf, dname);
		if (fstatat(sfd, dname, &subst, AT_SYMLINK_NOFOLLOW))
			goto out2;
		subino = subst.st_ino;
		if (muxfs_meta_read(&submeta, sdev_index, subino))
			goto out2;
		if ((subfd = openat(sdev->root_fd, pathbuf,
		    O_RDONLY|O_NOFOLLOW))
		    == -1)
			goto out2;
		if (S_ISDIR(subst.st_mode)) {
			if (muxfs_restore_dir(ddev_index, sdev_index, pathbuf,
			    subfd, &subst, &submeta))
				goto subout;
		} else if (S_ISREG(subst.st_mode)) {
			if (muxfs_restore_file(ddev_index, sdev_index, pathbuf,
			    subfd, &subst, &submeta))
				goto subout;
		} else if (S_ISLNK(subst.st_mode)) {
			if (muxfs_restore_symlink(ddev_index, sdev_index,
			    pathbuf, &subst, &submeta))
				goto subout;
		} else {
			if (muxfs_state_restore_push_back(sdev_index, pathbuf))
				exit(-1);
			goto subout;
		}
		if (muxfs_readback(ddev_index, pathbuf, &submeta))
			goto subout;
		
		if (close(subfd))
			exit(-1);
		continue;
subout:
		if (close(subfd))
			exit(-1);
		goto out2;
	}

	if (muxfs_popdir(&dir))
		exit(-1);
	if (muxfs_pushdir(&dir, ddev->root_fd, path))
		goto out;

	for (i = 0; i < dir.ent_count; ++i) {
		dirent = dir.ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
			continue;
		if ((dnamelen == 2) && (strncmp("..", dname, 1) == 0))
			continue;
		if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6) == 0))
			continue;
		if (muxfs_existsat(&exists, sfd, dname))
			goto out2;
		if (!exists) {
			memset(pathbuf, 0 , PATH_MAX);
			if (pathlen + 1 + dnamelen >= PATH_MAX)
				goto out2;
			strcpy(pathbuf, path);
			strcat(pathbuf, "/");
			strcat(pathbuf, dname);
			muxfs_removeat(ddev->root_fd, pathbuf);
		}
	}

	if ((dfd = openat(ddev->root_fd, path, O_RDONLY)) == -1)
		goto out2;
	if (fstat(dfd, &dst))
		goto out3;
	dino = dst.st_ino;
	assign = (struct muxfs_assign) {
		.flags = AF_ASSIGNED,
		.ino = dino
	};
	if (muxfs_meta_write(expected, ddev_index, dino))
		goto out3;
	if (muxfs_assign_write(&assign, ddev_index, expected->header.eno))
		goto out3;
	if (fsync(dfd))
		exit(-1);
	if (fsync(ddev->meta_fd))
		exit(-1);
	if (fsync(ddev->assign_fd))
		exit(-1);

	rc = 0;
out3:
	if (close(dfd))
		exit(-1);
out2:
	if (muxfs_popdir(&dir))
		exit(-1);
out:
	return rc;
}

static int
muxfs_restore_file(dind ddev_index, dind sdev_index, const char *path,
    int sfd, struct stat *sst, struct muxfs_meta *expected)
{
	int			 rc;
	struct muxfs_dev	*sdev,
				*ddev;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;
	uint64_t		 eno;
	uint8_t			*content_buf;
	size_t			 content_sz;
	struct muxfs_chk	 chk;
	uint8_t			 sum[MUXFS_CHKSZ_MAX];
	int			 dfd;
	struct stat		 dst;
	ino_t			 dino;
	struct muxfs_assign	 assign;

	rc = 1;

	if (muxfs_dev_get(&ddev, ddev_index))
		goto out;
	if (muxfs_dev_get(&sdev, sdev_index))
		goto out;
	alg = sdev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);
	eno = expected->header.eno;
	content_sz = sst->st_size;

	if (muxfs_dspush((void **)&content_buf, content_sz))
		exit(-1);

	if (pread(sfd, content_buf, content_sz, 0) != content_sz)
		goto out2;
	muxfs_chk_init(&chk, alg);
	muxfs_chk_update(&chk, content_buf, content_sz);
	muxfs_chk_final(sum, &chk);
	if (bcmp(sum, &expected->checksums[chksz], chksz) != 0) {
		if (muxfs_state_restore_push_back(sdev_index, path))
			exit(-1);
		goto out2;
	}

	if ((dfd = openat(ddev->root_fd, path, O_RDWR|O_CREAT|O_TRUNC,
	    sst->st_mode)) == -1)
		goto out2;

	if (pwrite(dfd, content_buf, content_sz, 0) != content_sz)
		goto out3;
	if (fchown(dfd, sst->st_uid, sst->st_gid))
		goto out3;
	if (fstat(dfd, &dst))
		goto out3;
	dino = dst.st_ino;

	assign = (struct muxfs_assign) {
		.flags = AF_ASSIGNED,
		.ino = dino
	};
	if (muxfs_meta_write(expected, ddev_index, dino))
		goto out3;
	if (muxfs_assign_write(&assign, ddev_index, eno))
		goto out3;

	if (fsync(dfd))
		exit(-1);
	if (fsync(ddev->meta_fd))
		exit(-1);
	if (fsync(ddev->assign_fd))
		exit(-1);

	rc = 0;
out3:
	if (close(dfd))
		exit(-1);
out2:
	if (muxfs_dspop(content_buf))
		exit(-1);
out:
	return rc;
}

static int
muxfs_restore_symlink(dind ddev_index, dind sdev_index, const char *path,
    struct stat *sst, struct muxfs_meta *expected)
{
	int			 rc;
	struct muxfs_dev	*sdev,
				*ddev;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;
	uint64_t		 eno;
	char			 content_buf[PATH_MAX];
	size_t			 content_sz;
	struct muxfs_chk	 chk;
	uint8_t			 sum[MUXFS_CHKSZ_MAX];
	struct stat		 dst;
	ino_t			 dino;
	struct muxfs_assign	 assign;
	int			 exists;

	rc = 1;

	if (muxfs_dev_get(&ddev, ddev_index))
		goto out;
	if (muxfs_dev_get(&sdev, sdev_index))
		goto out;
	alg = sdev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);
	eno = expected->header.eno;

	memset(content_buf, 0, PATH_MAX);
	if ((content_sz = readlinkat(sdev->root_fd, path, content_buf,
	    PATH_MAX - 1)) == -1)
		goto out;
	if (content_sz >= PATH_MAX)
		goto out;
	muxfs_chk_init(&chk, alg);
	muxfs_chk_update(&chk, (uint8_t *)content_buf, content_sz);
	muxfs_chk_final(sum, &chk);
	if (bcmp(sum, &expected->checksums[chksz], chksz) != 0) {
		if (muxfs_state_restore_push_back(sdev_index, path))
			exit(-1);
		goto out;
	}

	if (muxfs_existsat(&exists, ddev->root_fd, path))
		goto out;
	if (exists) {
		if (muxfs_removeat(ddev->root_fd, path))
			goto out;
	}
	if (symlinkat(content_buf, ddev->root_fd, path))
		goto out;

	if (fchmodat(ddev->root_fd, path, sst->st_mode, AT_SYMLINK_NOFOLLOW))
		goto out;
	if (fchownat(ddev->root_fd, path, sst->st_uid, sst->st_gid,
	    AT_SYMLINK_NOFOLLOW))
		goto out;
	if (fstatat(ddev->root_fd, path, &dst, AT_SYMLINK_NOFOLLOW))
		goto out;
	dino = dst.st_ino;

	assign = (struct muxfs_assign) {
		.flags = AF_ASSIGNED,
		.ino = dino
	};
	if (muxfs_meta_write(expected, ddev_index, dino))
		goto out;
	if (muxfs_assign_write(&assign, ddev_index, eno))
		goto out;

	if (fsync(ddev->meta_fd))
		exit(-1);
	if (fsync(ddev->assign_fd))
		exit(-1);

	rc = 0;
out:
	return rc;
}

static int
muxfs_restore_possible_inner(int *is_delete_out, dind ddev_index,
    dind sdev_index, const char *path, struct muxfs_dev *ddev,
    struct muxfs_dev *sdev, enum muxfs_chk_alg_type alg, size_t chksz,
    const char *ppath, struct muxfs_dir_patch *patch, int expect_substitute)
{
	int			 rc, err, is_delete, exists;
	struct muxfs_meta	 smeta, spmeta, dpmeta;
	struct muxfs_dir	 ddir;
	int			 dpfd;
	struct stat		 sst, spst, dst, dpst;
	ino_t			 sino, spino, dpino;
	uint8_t			 as_is_sum[MUXFS_CHKSZ_MAX];
	uint8_t			 with_patch_sum[MUXFS_CHKSZ_MAX];
	uint8_t			 as_is_meta_sum[MUXFS_CHKSZ_MAX];
	uint64_t		 dpeno;
	struct muxfs_desc	 dpdesc;

	rc = 1;

	if (muxfs_existsat(&exists, ddev->root_fd, ppath))
		goto out;
	if (!exists) {
		if (muxfs_state_restore_push_back(ddev_index, ppath))
			exit(-1);
		rc = 2;
		goto out;
	}
	if (muxfs_existsat(&exists, sdev->root_fd, ppath))
		goto out;
	if (!exists) {
		if (muxfs_state_restore_push_back(sdev_index, ppath))
			exit(-1);
		rc = 3;
		goto out;
	}
	if (muxfs_readback(sdev_index, ppath, NULL)) {
		if (muxfs_state_restore_push_back(sdev_index, ppath))
			exit(-1);
		rc = 3;
		goto out;
	}
	exists = 1;
	if (fstatat(sdev->root_fd, path, &sst, AT_SYMLINK_NOFOLLOW)) {
		err = errno;
		if (err == ENOENT)
			exists = 0;
		else
			goto out;
	}
	if (exists) {
		if (!expect_substitute) {
			if (muxfs_readback(sdev_index, path, NULL)) {
				if (muxfs_state_restore_push_back(sdev_index,
				    path))
					exit(-1);
				rc = 3;
				goto out;
			}
		}
		sino = sst.st_ino;
		if (muxfs_meta_read(&smeta, sdev_index, sino))
			goto out;
		patch->sum = &smeta.checksums[0];
		patch->type = MUXFS_SUBSTITUTE;
	} else {
		if (expect_substitute)
			goto out;
		patch->type = MUXFS_MINUS;
	}
	is_delete = !exists;

	exists = 1;
	if (fstatat(ddev->root_fd, path, &dst, AT_SYMLINK_NOFOLLOW)) {
		err = errno;
		if (err == ENOENT)
			exists = 0;
		else
			goto out;
	}
	if (exists) {
		/* Do nothing. */
	} else if (patch->type == MUXFS_MINUS) {
		/*
		 * It is likely that the restore has already been done,
		 * and that the metadata checksum will be tested below to
		 * confirm this, so there is nothing to do here.
		 */
	} else {
		if (patch->type != MUXFS_SUBSTITUTE)
			exit(-1); /* Programming error. */
		if (expect_substitute)
			goto out;
		patch->type = MUXFS_PLUS;
	}

	exists = 1;
	if (fstatat(sdev->root_fd, ppath, &spst, AT_SYMLINK_NOFOLLOW))
		goto out;
	spino = spst.st_ino;
	if (muxfs_meta_read(&spmeta, sdev_index, spino))
		goto out;

	if (muxfs_pushdir(&ddir, ddev->root_fd, ppath))
		goto out;
	if ((dpfd = openat(ddev->root_fd, ppath, O_RDONLY|O_NOFOLLOW)) == -1)
		goto out2;

	if (muxfs_dir_patch_sums(as_is_sum, with_patch_sum, alg, ddev_index,
	    dpfd, &ddir, patch))
		goto out3;
	if (bcmp(with_patch_sum, &spmeta.checksums[chksz], chksz) != 0) {
		if (muxfs_state_restore_push_back(ddev_index, ppath))
			exit(-1);
		rc = 2;
		goto out3;
	}
	/*
	 * The unnecessary restore check will remain disabled until readback
	 * depth is implemented.
	 */
	if (0 && bcmp(with_patch_sum, as_is_sum, chksz) == 0) {
		if (fstatat(ddev->root_fd, ppath, &dpst, AT_SYMLINK_NOFOLLOW))
			goto out3;
		dpino = dpst.st_ino;
		if (muxfs_meta_read(&dpmeta, ddev_index, dpino))
			goto out3;
		dpeno = dpmeta.header.eno;
		if (muxfs_desc_init_from_stat(&dpdesc, &dpst, dpeno))
			goto out3;
		memcpy(dpdesc.content_checksum, as_is_sum, chksz);
		muxfs_desc_chk_meta(as_is_meta_sum, &dpdesc, alg);
		if (bcmp(as_is_meta_sum, &spmeta.checksums[0], chksz) == 0) {
			rc = 4;
			goto out3;
		}
	}

	if (is_delete_out != NULL)
		*is_delete_out = is_delete;
	rc = 0;
out3:
	if (close(dpfd))
		exit(-1);
out2:
	if (muxfs_popdir(&ddir))
		exit(-1);
out:
	return rc;
}

/*
 * This function performs preliminary checks on both sdev and ddev, ensuring
 * that either that the restore can be performed, or if not that the
 * restoration needed has been queued.  It also informs whether or not the
 * restore would be a delete operation.
 * Returns: 0 on success, 1 on hard failure, 2 on ddev restore delegated, 3 on
 * sdev corrupted and ddev restore queued, 4 on restore unnecessary (already
 * done).
 */
static int
muxfs_restore_possible(int *is_delete_out, dind ddev_index, dind sdev_index,
    const char *_path)
{
	int			 is_first, is_last, is_unnecessary, subrc,
				 is_delete;
	char			 path[PATH_MAX], ppathbuf[PATH_MAX];
	const char		*ppath, *fname;
	size_t			 ppathlen;
	struct muxfs_dev	*ddev, *sdev;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;
	struct muxfs_dir_patch	 patch;

	memset(path, 0, PATH_MAX);
	strcpy(path, _path);

	if (muxfs_dev_get(&ddev, ddev_index))
		return 1;
	if (muxfs_dev_get(&sdev, sdev_index))
		return 1;
	alg = ddev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);

	if (muxfs_path_is_root(path)) {
		if (muxfs_readback(sdev_index, path, NULL)) {
			if (muxfs_state_restore_push_back(sdev_index, path))
				exit(-1);
			return 3;
		}
		*is_delete_out = 0;
		return 0;
	}

	memset(ppathbuf, 0, PATH_MAX);
	strcpy(ppathbuf, path);
	ppath = ppathbuf;
	ppathlen = strlen(ppath);
	is_first = 1;
	is_last = 0;
	is_unnecessary = 1;
	for (;;) {
		if (muxfs_path_pop(&fname, ppathbuf, &ppathlen)) {
			patch.fname = ppathbuf;
			ppath = ".";
			ppathlen = strlen(ppath);
			is_last = 1;
		}

		subrc = muxfs_restore_possible_inner((is_first ? &is_delete :
		    NULL), ddev_index, sdev_index, path, ddev, sdev, alg, chksz,		    ppath, &patch, !is_first);

		switch (subrc) {
		case 0:
			is_unnecessary = 0;
			break;
		case 1:
		case 2:
		case 3:
			return subrc;
		case 4:
			break;
		default:
			exit(-1); /* Programming error. */
		}
		if (is_last)
			break;
		memset(path, 0, PATH_MAX);
		strcpy(path, ppath);
		is_first = 0;
	}
	*is_delete_out = is_delete;
	return is_unnecessary ? 4 : 0;
}

static int
muxfs_restore_delete(dind ddev_index, dind sdev_index, const char *path)
{
	int			 rc;
	struct muxfs_dev	*ddev;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;
	int			 dpfd;
	char			 ppath[PATH_MAX];
	struct muxfs_dev	*sdev;
	struct stat		 spst;
	ino_t			 spino;
	struct muxfs_meta	 spmeta, dpmeta;
	struct stat		 dpst;
	ino_t			 dpino;
	int			 exists;

	rc = 1;

	if (muxfs_path_is_root(path))
		goto out;

	if (muxfs_dev_get(&ddev, ddev_index))
		goto out;
	alg = ddev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);

	if (muxfs_removeat(ddev->root_fd, path))
		goto out;

	memset(ppath, 0, PATH_MAX);
	strcpy(ppath, path);
	if (muxfs_path_pop(NULL, ppath, NULL)) {
		memset(ppath, 0, PATH_MAX);
		strcpy(ppath, ".");
	}

	if (muxfs_dev_get(&sdev, sdev_index))
		goto out;
	if (fstatat(sdev->root_fd, ppath, &spst, AT_SYMLINK_NOFOLLOW))
		goto out;
	spino = spst.st_ino;
	if (muxfs_meta_read(&spmeta, sdev_index, spino))
		goto out;

	if ((dpfd = openat(ddev->root_fd, ppath, O_RDONLY|O_NOFOLLOW)) == -1)
		goto out;
	if (fstat(dpfd, &dpst))
		goto out2;
	dpino = dpst.st_ino;
	if (muxfs_meta_read(&dpmeta, ddev_index, dpino))
		goto out2;

	if (dpmeta.header.eno != spmeta.header.eno)
		goto out2;
	memcpy(&dpmeta.checksums[0], &spmeta.checksums[0], 2 * chksz);
	if (muxfs_meta_write(&dpmeta, ddev_index, dpino))
		goto out2;

	if (fsync(dpfd))
		exit(-1);
	if (fsync(ddev->meta_fd))
		exit(-1);

	if (muxfs_existsat(&exists, ddev->root_fd, path))
		goto out2;
	if (exists)
		goto out2;

	if (muxfs_readback(ddev_index, ppath, &spmeta))
		goto out2;

	rc = 0;
out2:
	if (close(dpfd))
		exit(-1);
out:
	return rc;
}

static int
muxfs_dir_meta_restore(dind ddev_index, dind sdev_index, const char *path)
{
	struct muxfs_dev	*ddev, *sdev;
	struct stat		 dst, sst;
	ino_t			 dino, sino;
	struct muxfs_meta	 meta;

	if (muxfs_dev_get(&ddev, ddev_index))
		return 1;
	if (muxfs_dev_get(&sdev, sdev_index))
		return 1;
	if (fstatat(ddev->root_fd, path, &dst, AT_SYMLINK_NOFOLLOW))
		return 1;
	if (fstatat(sdev->root_fd, path, &sst, AT_SYMLINK_NOFOLLOW))
		return 1;
	dino = dst.st_ino;
	sino = sst.st_ino;
	if (muxfs_meta_read(&meta, sdev_index, sino))
		return 1;
	if (muxfs_meta_write(&meta, ddev_index, dino))
		return 1;
	if (fsync(ddev->meta_fd))
		exit(-1);
	if (muxfs_readback(ddev_index, path, NULL))
		return 1;
	return 0;
}

static int
muxfs_ancestors_meta_restore(dind ddev_index, dind sdev_index,
    const char *_path)
{
	char		 path[PATH_MAX];
	const char	*fname;
	size_t		 path_len;

	/* There are no ancestors of the root path. */
	if (muxfs_path_is_root(_path))
		return 0;

	assert(strlen(_path) < PATH_MAX);

	path_len = strlen(_path);
	memcpy(path, _path, path_len);
	path[path_len] = '\0';

	while (!muxfs_path_pop(&fname, path, &path_len)) {
		if (muxfs_dir_meta_restore(ddev_index, sdev_index, path))
			return 1;
	}
	if (path_len == 0)
		exit(-1); /* Programming error. */

	/* Account for the special case of the root directory. */
	if (muxfs_dir_meta_restore(ddev_index, sdev_index, "."))
		return 1;

	return 0;
}

static int
muxfs_restore_impl(dind ddev_index, const char *path)
{
	struct muxfs_dev	*ddev, *sdev;
	int			 is_delete;
	dind			 si, dev_count;
	int			 sfd;
	struct stat		 sst;
	ino_t			 sino;
	struct muxfs_meta	 smeta;

	if ((dev_count = muxfs_dev_count()) == 0)
		return 1;
	if (muxfs_dev_get(&ddev, ddev_index))
		return 1;

	for (si = 0; si < dev_count; ++si) {
		if (si == ddev_index)
			continue;
		if (muxfs_dev_get(&sdev, si))
			continue;

		switch (muxfs_restore_possible(&is_delete, ddev_index, si,
		    path)) {
		case 0:
			break; /* Restore is possible. */
		case 1:
			return 1; /* Hard failure. */
		case 2:
			return 2; /* Delegated. */
		case 3:
			goto fail; /* sdev is corrupted. */
		case 4:
			return 4; /* Unnecessary. */
		default:
			exit(-1); /* Programming error. */
		}

		if (is_delete) {
			if (muxfs_restore_delete(ddev_index, si, path))
				goto fail;
			if (muxfs_ancestors_meta_restore(ddev_index, si, path))
				goto fail;
			return 0;
		}

		if (fstatat(sdev->root_fd, path, &sst, AT_SYMLINK_NOFOLLOW))
			goto fail2;
		sino = sst.st_ino;
		if (muxfs_meta_read(&smeta, si, sino))
			goto fail2;

		if (S_ISLNK(sst.st_mode)) {
			if (muxfs_restore_symlink(ddev_index, si, path, &sst,
			    &smeta))
				goto fail2;
		} else {
			if ((sfd = openat(sdev->root_fd, path,
			    O_RDONLY|O_NOFOLLOW)) == -1)
				goto fail;
			if (S_ISDIR(sst.st_mode)) {
				if (muxfs_restore_dir(ddev_index, si, path, sfd,
				    &sst, &smeta))
					goto fail2;
			} else if (S_ISREG(sst.st_mode)) {
				if (muxfs_restore_file(ddev_index, si, path,
				    sfd, &sst, &smeta))
					goto fail2;
			} else {
				if (close(sfd))
					exit(-1);
				if (muxfs_state_restore_push_back(si, path))
					exit(-1);
				goto fail2;
			}
			if (close(sfd))
				exit(-1);
		}
		if (muxfs_ancestors_meta_restore(ddev_index, si, path))
			goto fail2;
		if (muxfs_readback(ddev_index, path, &smeta))
			goto fail2;
		
		return 0;
fail2:
		if (close(sfd))
			exit(-1);
fail:
		continue;
	}
	return 1;
}

MUXFS void
muxfs_restore_now(void)
{
	dind ddev_index;
	char path[PATH_MAX];

	memset(path, 0, PATH_MAX);
	while (!muxfs_state_restore_pop_front(&ddev_index, path)) {
		muxfs_working_push(ddev_index);
		switch (muxfs_restore_impl(ddev_index, path)) {
		case 0:
			muxfs_info("Restored: %lu:/%s\n",
			    ddev_index, path);
			break;
		case 1:
			muxfs_alert("Restoration Failure: %lu:/%s\n",
			    ddev_index, path);
			goto fail;
		case 2:
			debug("Restore deferred: %lu:/%s\n", ddev_index, path);
			goto next;
		case 4:
			debug("Restore unnecessary: %lu:/%s\n", ddev_index,
			    path);
			goto next;
		default:
			exit(-1); /* Programming error. */
		}
		goto next;
fail:
		muxfs_degraded_set(ddev_index);
next:
		muxfs_working_pop(ddev_index);
		memset(path, 0, PATH_MAX);
	}
}

MUXFS int
muxfs_parent_gid(gid_t *parent_gid_out, const char *path)
{
	char			 pbuf[PATH_MAX], *ppath;
	size_t			 ppathlen;
	struct muxfs_dev	*dev;
	dind			 dev_count, i;
	struct stat		 st;

	ppathlen = strlen(path);
	if (ppathlen >= PATH_MAX)
		return 1;
	ppath = pbuf;
	memset(ppath, 0, PATH_MAX);
	strcpy(ppath, path);
	if (muxfs_path_pop(NULL, ppath, &ppathlen)) {
		ppath = ".";
		ppathlen = 1;
	}

	if ((dev_count = muxfs_dev_count()) == 0)
		return 1;
	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		if (fstatat(dev->root_fd, ppath, &st, AT_SYMLINK_NOFOLLOW))
			continue;
		*parent_gid_out = st.st_gid;
		return 0;
	}
	return 1;
}

MUXFS int
muxfs_dir_content_chk(uint8_t *sum_out, dind dev_index, struct muxfs_dir *dir)
{
	int			 rc;
	struct dirent		*dirent;
	size_t			 i;
	struct muxfs_dev	*dev;
	struct muxfs_chk	 chk;
	size_t			 chksz;
	enum muxfs_chk_alg_type	 alg;
	const char		*dname;
	size_t			 dnamelen;
	struct muxfs_meta	 meta;
	ino_t			 ino;

	rc = 1;

	if (muxfs_dev_get(&dev, dev_index))
		goto out;
	alg = dev->conf.chk_alg_type;
	chksz = muxfs_chk_size(alg);
	
	muxfs_chk_init(&chk, alg);
	for (i = 0; i < dir->ent_count; ++i) {
		dirent = dir->ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
			continue;
		if ((dnamelen == 2) && (strncmp("..", dname, 2) == 0))
			continue;
		if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6)
		    == 0))
			continue;
		ino = dirent->d_fileno;
		if (muxfs_meta_read(&meta, dev_index, ino))
			goto out;
		muxfs_chk_update(&chk, (uint8_t *)dname, dnamelen);
		muxfs_chk_update(&chk, &meta.checksums[0], chksz);
	}
	muxfs_chk_final(sum_out, &chk);

	rc = 0;
out:
	return rc;
}
