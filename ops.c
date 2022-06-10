/* ops.c */
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

#include <sys/syslimits.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ds.h"
#include "mount_muxfs.h"
#include "muxfs.h"
#include "gen.h"

static int
muxfs_statfs(const char *path, struct statvfs *stvfs)
{
	dind dev_count, i;
	struct muxfs_dev *dev;
	int fd;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;
	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		if ((fd = openat(dev->root_fd, path, O_RDONLY)) == -1)
			continue;
		if (fstatvfs(fd, stvfs)) {
			if (close(fd))
				exit(-1);
			return -errno;
		}
		if (close(fd))
			exit(-1);
		return 0;
	}
	return -EIO;
}

static void *
muxfs_init(struct fuse_conn_info *fci)
{
	uint64_t next_eno, max_next_eno;
	dind i, j, mnts;
	struct muxfs_args *args;

	args = &muxfs_cmdline;

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

	return NULL;
}

static void
muxfs_destroy(void *data)
{
	dind i, j, dev_count;

	dev_count = muxfs_dev_count();
	for (i = dev_count; i > 0; --i) {
		j = i - 1;
		if (muxfs_dev_is_mounted(j)) {
			if (muxfs_dev_unmount(j))
				exit(-1);
		}
	}
	muxfs_state_restore_queue_final();

	if (muxfs_dsfinal())
		exit(-1);
}

static int
muxfs_fsync(const char *path, int datasync, struct fuse_file_info *ffi)
{
	/*
	 * A call to fsync(2) is made as part of the create, update, and delete
	 * operations.
	 */
	return 0;
}

static int
muxfs_open(const char *path, struct fuse_file_info *ffi)
{
	return 0;
}

static int
muxfs_opendir(const char *path, struct fuse_file_info *ffi)
{
	return 0;
}

static int
muxfs_flush(const char *path, struct fuse_file_info *ffi)
{
	return 0;
}

static int
muxfs_release(const char *path, struct fuse_file_info *ffi)
{
	return 0;
}

static int
muxfs_releasedir(const char *path, struct fuse_file_info *ffi)
{
	return 0;
}

static int
muxfs_lock(const char *path, struct fuse_file_info *ffi, int op,
    struct flock *flk)
{
	return -EOPNOTSUPP;
}

enum muxfs_op_create_type {
	MUXFS_CT_MKNOD,
	MUXFS_CT_MKDIR,
	MUXFS_CT_SYMLINK
};
struct muxfs_op_create_args {
	enum muxfs_op_create_type	 type;
	const char			*path;
	mode_t				 mode;
	dev_t				 sys_dev;
	const char			*link_content;
};

static int
muxfs_op_create(struct muxfs_op_create_args *args)
{
	struct fuse_context *fuse_ctx;

	dind dev_count, i;
	struct muxfs_dev *dev;
	int fd;
	enum muxfs_chk_alg_type alg;
	size_t chksz;

	gid_t parent_gid;

	int				 rc, subrc, subfd;
	int				 has_write;
	uint64_t			 eno;
	struct muxfs_desc		 desc;
	struct muxfs_chk		 content_chk;
	struct stat			 st;
	ino_t				 ino;
	struct muxfs_meta_buffer	 meta_buf;
	struct muxfs_assign		 assign;

	struct muxfs_cud		 cud;

	fuse_ctx = fuse_get_context();

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;

	has_write = 0;
	if (muxfs_state_eno_next_acquire(&eno))
		return -EIO;

	if (muxfs_parent_gid(&parent_gid, args->path))
		return -EIO;

	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		muxfs_working_push(i);

		fd = dev->root_fd;
		alg = dev->conf.chk_alg_type;
		chksz = muxfs_chk_size(alg);

		desc = (struct muxfs_desc) {
			.eno = eno,
			.owner = fuse_ctx->uid,
			.group = parent_gid,
			.perms = args->mode
		};
		if (muxfs_desc_type_from_mode(&desc.type, args->mode)) {
			rc = -EOPNOTSUPP;
			goto early;
		}
		muxfs_chk_init(&content_chk, alg);
		muxfs_chk_final(desc.content_checksum, &content_chk);
	
		memcpy(&meta_buf.checksums[chksz],
		    desc.content_checksum, chksz);
		muxfs_desc_chk_meta(&meta_buf.checksums[0], &desc, alg);
		meta_buf.header.eno = eno;
		meta_buf.header.flags = MF_ASSIGNED;

		switch (args->type) {
		case MUXFS_CT_MKNOD:
			if (S_ISREG(args->mode)) {
				subfd = openat(fd, args->path,
				    O_RDWR|O_CREAT|O_EXCL, args->mode);
				if (subfd != -1) {
					if (close(subfd))
						exit(-1);
					subrc = 0;
				} else
					subrc = -1;
			} else {
				rc = -EOPNOTSUPP;
				goto early;
			}
			break;
		case MUXFS_CT_MKDIR:
			subrc = mkdirat(fd, args->path, args->mode);
			break;
		case MUXFS_CT_SYMLINK:
			subrc = symlinkat(args->link_content, fd, args->path);
			break;
		default:
			exit(-1); /* Programming error. */
		}
		if (subrc) {
			if (!has_write) {
				rc = -errno;
				goto early;
			}
			goto fail;
		}

		if ((subfd = openat(fd, args->path, O_RDONLY|O_NOFOLLOW)) == -1)
			goto fail;
		if (fchown(subfd, fuse_ctx->uid, -1))
			goto fail;
		if (fsync(subfd))
			exit(-1);

		if (fstat(subfd, &st)) {
			if (close(subfd))
				exit(-1);
			goto fail;
		}
		if (close(subfd))
			exit(-1);
		ino = st.st_ino;
		assign = (struct muxfs_assign) {
			.flags = AF_ASSIGNED,
			.ino = ino
		};
	
		if (muxfs_meta_write(&meta_buf, i, ino))
			goto fail;
		if (muxfs_assign_write(&assign, i, eno))
			goto fail;
	
		if (fsync(dev->meta_fd))
			exit(-1);
		if (fsync(dev->assign_fd))
			exit(-1);
	
		if (muxfs_readback(i, args->path, &meta_buf))
			goto fail;

		cud.type = MUXFS_CUD_CREATE;
		cud.path = args->path;
		if (muxfs_ancestors_meta_recompute(i, &cud))
			goto fail;
	
		has_write = 1;
		muxfs_working_pop(i);
		continue;
fail:
		muxfs_degraded_set(i);
		muxfs_working_pop(i);
		continue;
early:
		muxfs_working_pop(i);
		return rc;
	}
	return has_write ? 0 : -EIO;
}

static int
muxfs_mknod(const char *path, mode_t mode, dev_t sys_dev)
{
	struct muxfs_op_create_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_CT_MKNOD;
	args.path = path;
	args.mode = mode;
	args.sys_dev = sys_dev;

	return muxfs_op_create(&args);
}

static int
muxfs_mkdir(const char *path, mode_t mode)
{
	struct muxfs_op_create_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_CT_MKDIR;
	args.path = path;
	args.mode = mode;

	return muxfs_op_create(&args);
}

static int
muxfs_symlink(const char *link_content, const char *path)
{
	struct muxfs_op_create_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_CT_SYMLINK;
	args.path = path;
	args.link_content = link_content;
	args.mode = S_IFLNK | 0755;

	return muxfs_op_create(&args);
}

enum muxfs_op_delete_type {
	MUXFS_DT_UNLINK,
	MUXFS_DT_RMDIR
};

static int
muxfs_op_delete(const char *path, enum muxfs_op_delete_type type)
{
	dind			 dev_count;
	dind			 i;
	struct muxfs_dev	*dev;
	int			 fd;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;

	uint64_t return_eno;

	int				 rc, subrc;
	int				 has_write;
	struct stat			 prewr_st;
	ino_t				 prewr_ino;
	struct muxfs_meta_buffer	 prewr_meta_buf;
	uint64_t			 prewr_eno;
	struct muxfs_desc		 prewr_desc;
	uint8_t				 prewr_meta_chk_buf[MUXFS_CHKSZ_MAX];
	struct muxfs_meta_buffer	 wr_meta_buf;
	struct muxfs_assign		 wr_assign;
	char				 postwr_ppath[PATH_MAX];
	int				 postwr_pfd;
	struct stat			 postwr_st;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;

	has_write = 0;
	return_eno = UINT64_MAX;

	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		muxfs_working_push(i);

		fd = dev->root_fd;
		alg = dev->conf.chk_alg_type;
		chksz = muxfs_chk_size(alg);

		if (fstatat(fd, path, &prewr_st, AT_SYMLINK_NOFOLLOW)) {
			if (has_write)
				goto fail;
			rc = -errno;
			goto early;
		}
		prewr_ino = prewr_st.st_ino;
		if (muxfs_meta_read(&prewr_meta_buf, i, prewr_ino))
			goto fail;
		prewr_eno = prewr_meta_buf.header.eno;
		if (muxfs_desc_init_from_stat(&prewr_desc, &prewr_st,
		    prewr_eno))
			goto fail;
		if (muxfs_desc_chk_node_content(&prewr_desc, i, path))
			goto fail;
		muxfs_desc_chk_meta(prewr_meta_chk_buf, &prewr_desc, alg);
		if (bcmp(prewr_meta_chk_buf, &prewr_meta_buf.checksums[0],
		    chksz) != 0)
			goto fail;

		switch (type) {
		case MUXFS_DT_UNLINK:
			subrc = unlinkat(fd, path, 0);
			break;
		case MUXFS_DT_RMDIR:
			subrc = unlinkat(fd, path, AT_REMOVEDIR);
			break;
		default:
			exit(-1); /* Programming error. */
		}
		if (subrc) {
			if (has_write)
				goto fail;
			rc = -errno;
			goto early;
		}

		memset(postwr_ppath, 0, PATH_MAX);
		strcpy(postwr_ppath, path);
		if (muxfs_path_pop(NULL, postwr_ppath, NULL)) {
			memset(postwr_ppath, 0, PATH_MAX);
			strcpy(postwr_ppath, ".");
		}
		if ((postwr_pfd = openat(dev->root_fd, postwr_ppath,
		    O_RDONLY|O_NOFOLLOW)) == -1)
			goto fail;
		if (fsync(postwr_pfd))
			exit(-1);
		if (close(postwr_pfd))
			exit(-1);

		if (fstatat(fd, path, &postwr_st, AT_SYMLINK_NOFOLLOW) != -1)
			goto fail;
		if (errno != ENOENT)
			goto fail;

		memset(&wr_meta_buf, 0, sizeof(wr_meta_buf));
		memset(&wr_assign  , 0, sizeof(wr_assign  ));
		if (muxfs_meta_write(&wr_meta_buf, i, prewr_ino))
			goto fail;
		if (muxfs_assign_write(&wr_assign, i, prewr_eno))
			goto fail;

		if (!has_write) {
			has_write = 1;
			return_eno = prewr_eno;
		}

		muxfs_working_pop(i);
		continue;
fail:
		muxfs_degraded_set(i);
		muxfs_working_pop(i);
		continue;
early:
		muxfs_working_pop(i);
		return rc;
	}

	if (has_write) {
		if (muxfs_state_eno_next_return(return_eno))
			exit(-1);
		return 0;
	}
	return -EIO;
}

static int
muxfs_unlink(const char *path)
{
	if (muxfs_path_sanitize(&path))
		return -EIO;

	return muxfs_op_delete(path, MUXFS_DT_UNLINK);
}

static int
muxfs_rmdir(const char *path)
{
	if (muxfs_path_sanitize(&path))
		return -EIO;

	return muxfs_op_delete(path, MUXFS_DT_RMDIR);
}

enum muxfs_op_read_type {
	MUXFS_RT_GETATTR,
	MUXFS_RT_READ,
	MUXFS_RT_READLINK,
	MUXFS_RT_READDIR
};

struct muxfs_op_read_args {
	enum muxfs_op_read_type  type;
	const char		*path;
	struct stat		*st_out;
	char			*buf;
	size_t			 bufsz;
	off_t			 offset;
	struct fuse_file_info	*ffi;
	char			*buf_out;
	size_t			 size;
	struct statvfs		*stvfs;
	void			*fill_data;
	fuse_fill_dir_t		 fill;
};

static int
muxfs_getattr_inner(struct stat *st_out, struct stat *st, uint64_t eno)
{
	size_t sz;

	st->st_ino = eno;
	sz = st->st_size;
	st->st_blocks = (sz / MUXFS_BLOCK_SIZE) +
	    ((sz % MUXFS_BLOCK_SIZE) ? 1 : 0);
	st->st_blksize = MUXFS_BLOCK_SIZE;
	*st_out = *st;

	return 0;
}

static int
muxfs_read_inner(int root_fd, struct muxfs_op_read_args *args, struct stat *st,
    enum muxfs_chk_alg_type alg, size_t chksz,
    struct muxfs_meta_buffer *meta_buf, ssize_t *rdsz_out)
{
	int fd, rc;
	size_t fsz;
	uint8_t *buf;
	struct muxfs_chk content_chk;
	uint8_t content_sum[MUXFS_CHKSZ_MAX];
	ssize_t rdsz;

	rc = MUXFS_EINT;

	fsz = st->st_size;
	if (args->offset >= fsz) {
		*rdsz_out = 0;
		return 0;
	}

	if ((fd = openat(root_fd, args->path, O_RDONLY)) == -1)
		return MUXFS_EFS;

	if (muxfs_dspush((void **)&buf, fsz))
		exit(-1);

	if (read(fd, buf, fsz) != fsz) {
		rc = MUXFS_EFS;
		goto fail;
	}
	muxfs_chk_init(&content_chk, alg);
	muxfs_chk_update(&content_chk, buf, fsz);
	muxfs_chk_final(content_sum, &content_chk);
	if (bcmp(content_sum, &meta_buf->checksums[chksz], chksz) != 0) {
		rc = MUXFS_ECHK;
		goto fail;
	}
	rdsz = fsz - args->offset;
	if (rdsz > args->size)
		rdsz = args->size;
	memcpy(args->buf_out, &buf[args->offset], rdsz);

	if (muxfs_dspop(buf))
		exit(-1);

	*rdsz_out = rdsz;
	return 0;
fail:
	if (muxfs_dspop(buf))
		exit(-1);
	return rc;
}

static int
muxfs_readlink_inner(int root_fd, struct muxfs_op_read_args *args,
    enum muxfs_chk_alg_type alg, size_t chksz, struct muxfs_desc *desc,
    struct muxfs_meta_buffer *meta_buf, ssize_t *rdsz_out)
{
	struct muxfs_desc lnk_desc;
	ssize_t lnksz, rdsz;
	char lnkbuf[PATH_MAX];
	uint8_t lnk_meta_sum[MUXFS_CHKSZ_MAX];

	memset(lnkbuf, 0, PATH_MAX);
	if ((lnksz = readlinkat(root_fd, args->path, lnkbuf, PATH_MAX - 1))
	    == -1)
	{
		return MUXFS_EFS;
	}
	if (lnksz >= PATH_MAX)
		return MUXFS_EFS;

	muxfs_desc_chk_provided_content(&lnk_desc,
	    (uint8_t *)lnkbuf, lnksz, alg);
	muxfs_desc_chk_meta(lnk_meta_sum, desc, alg);
	if (bcmp(lnk_meta_sum, &meta_buf->checksums[0], chksz) != 0)
		return MUXFS_ECHK;

	rdsz = (lnksz < args->size) ? lnksz : args->size;
	memcpy(args->buf_out, lnkbuf, rdsz);

	*rdsz_out = rdsz;
	return 0;
}

static int
muxfs_readdir_inner(dind dev_index, int root_fd,
    struct muxfs_op_read_args *args, enum muxfs_chk_alg_type alg, size_t chksz,
    struct stat *st, struct muxfs_desc *desc,
    struct muxfs_meta_buffer *meta_buf)
{
	int rc, fd;
	uint8_t content_sum[MUXFS_CHKSZ_MAX];
	struct muxfs_dir dir;
	struct dirent *dirent;
	int i;
	const char *dname;
	size_t dnamelen;

	rc = MUXFS_EINT;

	if ((fd = openat(root_fd, args->path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW))
	    == -1) {
		rc = MUXFS_EFS;
		goto out;
	}
	if (muxfs_pushdir(&dir, root_fd, args->path))
		exit(-1);

	if (muxfs_dir_content_chk(content_sum, dev_index, &dir)) {
		rc = MUXFS_ECHK;
		goto out2;
	}
	if (bcmp(content_sum, &meta_buf->checksums[chksz], chksz) != 0) {
		rc = MUXFS_ECHK;
		goto out2;
	}
	for (i = 0; i < dir.ent_count; ++i) {
		dirent = dir.ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 6) && (strncmp(".muxfs", dname, 6) == 0))
			continue;
		args->fill(args->fill_data, dname, NULL, 0);
	}

	rc = 0;
out2:
	if (muxfs_popdir(&dir))
		exit(-1);
	if (close(fd))
		exit(-1);
out:
	return rc;
}

static int
muxfs_op_read(struct muxfs_op_read_args *args)
{
	dind dev_count, i;
	struct muxfs_dev *dev;
	int fd;
	enum muxfs_chk_alg_type alg;
	size_t chksz;

	int err, rc, subrc;
	struct stat st;
	ino_t ino;
	struct muxfs_meta_buffer meta_buf;
	uint64_t eno;
	struct muxfs_desc desc;

	uint8_t chk_buf[MUXFS_CHKSZ_MAX];
	ssize_t rdsz;

	if ((dev_count = muxfs_dev_count()) == 0) \
		return -EIO;

	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		fd = dev->root_fd;
		alg = dev->conf.chk_alg_type;
		chksz = muxfs_chk_size(alg);
		rdsz = -1;

		if (fstatat(fd, args->path, &st, AT_SYMLINK_NOFOLLOW)) {
			err = errno;
			if ((err == ENOENT) && (muxfs_parent_readback(i,
			    args->path)))
				goto fail;
			rc = -err;
			goto early;
		}
		ino = st.st_ino;
		if (muxfs_meta_read(&meta_buf, i, ino))
			goto fail;
		eno = meta_buf.header.eno;
		if (muxfs_desc_init_from_stat(&desc, &st, eno)) {
			rc = -EOPNOTSUPP;
			goto early;
		}
		memcpy(desc.content_checksum, &meta_buf.checksums[chksz],
		    chksz);
		muxfs_desc_chk_meta(chk_buf, &desc, alg);
		if (bcmp(chk_buf, &meta_buf.checksums[0], chksz) != 0)
			goto fail;

		switch (args->type) {
		case MUXFS_RT_GETATTR:
			subrc = muxfs_getattr_inner(args->st_out, &st, eno);
			break;
		case MUXFS_RT_READ:
			subrc = muxfs_read_inner(fd, args, &st, alg, chksz,
			    &meta_buf, &rdsz);
			break;
		case MUXFS_RT_READLINK:
			subrc = muxfs_readlink_inner(fd, args, alg, chksz,
			    &desc, &meta_buf, &rdsz);
			break;
		case MUXFS_RT_READDIR:
			subrc = muxfs_readdir_inner(i, fd, args, alg, chksz,
			    &st, &desc, &meta_buf);
			break;
		default:
			exit(-1); /* Programming error. */
		}
		switch (subrc) {
		case 0:
			break;
		case MUXFS_EINT:
			exit(-1); /* Unrecoverable runtime error. */
		case MUXFS_EFS:
			rc = -errno;
			goto early;
		case MUXFS_ECHK:
			goto fail;
		default:
			exit(-1); /* Programming error. */
		}

		muxfs_restore_now();
		if (rdsz > -1)
			return rdsz;
		return 0;
fail:
		if (muxfs_state_restore_push_back(i, args->path))
			exit(-1);
		continue;
early:
		muxfs_restore_now();
		return rc;
	}
	return -EIO;
}

static int
muxfs_getattr(const char *path, struct stat *st_out)
{
	struct muxfs_op_read_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_RT_GETATTR;
	args.path = path;
	args.st_out = st_out;

	return muxfs_op_read(&args);
}

static int
muxfs_read(const char *path, char *buf_out, size_t size, off_t offset,
    struct fuse_file_info *ffi)
{
	struct muxfs_op_read_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type    = MUXFS_RT_READ;
	args.path    = path;
	args.buf_out = buf_out;
	args.size    = size;
	args.offset  = offset;
	args.ffi     = ffi;

	return muxfs_op_read(&args);
}

static int
muxfs_readlink(const char *path, char *buf_out, size_t size)
{
	struct muxfs_op_read_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_RT_GETATTR;
	args.path = path;
	args.buf_out = buf_out;
	args.size = size;

	return muxfs_op_read(&args);
}

static int
muxfs_readdir(const char *path, void *fill_data, fuse_fill_dir_t fill,
    off_t offset, struct fuse_file_info *ffi)
{
	struct muxfs_op_read_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_RT_READDIR;
	args.path      = path     ;
	args.fill_data = fill_data;
	args.fill      = fill     ;
	args.offset    = offset   ;
	args.ffi       = ffi      ;

	return muxfs_op_read(&args);
}

enum muxfs_op_update_type {
	MUXFS_UT_CHMOD,
	MUXFS_UT_CHOWN,
	MUXFS_UT_UTIMENS,
	MUXFS_UT_TRUNCATE,
	MUXFS_UT_WRITE
};

struct muxfs_op_update_args {
	enum muxfs_op_update_type	 type;
	const char			*path;
	mode_t				 mode;
	uid_t				 uid;
	gid_t				 gid;
	const struct timespec		*ts;
	off_t				 offset;
	const char			*buf;
	size_t				 bufsz;
	struct fuse_file_info		*ffi;
};

static int
muxfs_truncate_inner(int root_fd, struct muxfs_op_update_args *args,
    enum muxfs_chk_alg_type alg, size_t chksz, struct stat *st,
    struct muxfs_meta_buffer *prewr_meta_buf,
    struct muxfs_meta_buffer *wr_meta_buf, struct muxfs_desc *wr_desc)
{
	int rc;
	int fd;
	uint8_t *content_buf;
	size_t content_sz, largest_sz;

	struct muxfs_chk	prewr_content_chk;
	uint8_t			prewr_content_sum[MUXFS_CHKSZ_MAX];
	struct muxfs_chk	wr_content_chk;

	largest_sz = content_sz = st->st_size;
	if (args->offset > largest_sz)
		largest_sz = args->offset;

	if (muxfs_dspush((void **)&content_buf, largest_sz))
		exit(-1);
	memset(content_buf, 0, largest_sz);
	fd = openat(root_fd, args->path, O_RDWR|O_NOFOLLOW);
	if (fd == -1) {
		rc = MUXFS_EFS;
		goto out2;
	}
	if (read(fd, content_buf, content_sz) != content_sz) {
		rc = MUXFS_EFS;
		goto out;
	}
	muxfs_chk_init(&prewr_content_chk, alg);
	muxfs_chk_update(&prewr_content_chk, content_buf, content_sz);
	muxfs_chk_final(prewr_content_sum, &prewr_content_chk);
	if (bcmp(prewr_content_sum, &prewr_meta_buf->checksums[chksz], chksz)
	    != 0) {
		rc = MUXFS_ECHK;
		goto out;
	}

	if (ftruncate(fd, args->offset)) {
		rc = MUXFS_EFS;
		goto out;
	}

	muxfs_chk_init(&wr_content_chk, alg);
	muxfs_chk_update(&wr_content_chk, content_buf, args->offset);
	muxfs_chk_final(wr_desc->content_checksum, &wr_content_chk);
	memcpy(&wr_meta_buf->checksums[chksz], wr_desc->content_checksum,
	    chksz);
	
	rc = 0;
out:
	if (close(fd))
		exit(-1);
out2:
	if (muxfs_dspop(content_buf))
		exit(-1);
	return rc;
}

static int
muxfs_write_inner(int root_fd, struct muxfs_op_update_args *args,
    enum muxfs_chk_alg_type alg, size_t chksz, struct stat *st,
    struct muxfs_meta_buffer *prewr_meta_buf,
    struct muxfs_meta_buffer *wr_meta_buf, struct muxfs_desc *wr_desc)
{
	int rc;
	int fd;
	uint8_t *content_buf;
	size_t prewr_sz, wrsz, largest_sz;

	struct muxfs_chk	prewr_content_chk;
	uint8_t			prewr_content_sum[MUXFS_CHKSZ_MAX];
	struct muxfs_chk	wr_content_chk;

	largest_sz = prewr_sz = st->st_size;
	wrsz = (args->offset + args->bufsz);
	if (wrsz > largest_sz)
		largest_sz = wrsz;

	if (muxfs_dspush((void **)&content_buf, largest_sz))
		exit(-1);
	fd = openat(root_fd, args->path, O_RDWR|O_NOFOLLOW);
	if (fd == -1) {
		rc = MUXFS_EFS;
		goto out2;
	}
	if (read(fd, content_buf, prewr_sz) != prewr_sz) {
		rc = MUXFS_EFS;
		goto out;
	}
	muxfs_chk_init(&prewr_content_chk, alg);
	muxfs_chk_update(&prewr_content_chk, content_buf, prewr_sz);
	muxfs_chk_final(prewr_content_sum, &prewr_content_chk);
	if (bcmp(prewr_content_sum, &prewr_meta_buf->checksums[chksz], chksz)
	    != 0) {
		rc = MUXFS_ECHK;
		goto out;
	}

	memcpy(content_buf + args->offset, args->buf, args->bufsz);
	if (pwrite(fd, args->buf, args->bufsz, args->offset) != args->bufsz) {
		rc = MUXFS_EFS;
		goto out;
	}

	muxfs_chk_init(&wr_content_chk, alg);
	muxfs_chk_update(&wr_content_chk, content_buf, largest_sz);
	muxfs_chk_final(wr_desc->content_checksum, &wr_content_chk);
	memcpy(&wr_meta_buf->checksums[chksz], wr_desc->content_checksum,
	    chksz);
	
	rc = 0;
out:
	if (close(fd))
		exit(-1);
out2:
	if (muxfs_dspop(content_buf))
		exit(-1);
	return rc;
}

static int
muxfs_op_update(struct muxfs_op_update_args *args)
{
	dind			 dev_count;
	dind			 i;
	struct muxfs_dev	*dev;
	int			 fd;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;

	int				 rc, subrc, subfd;
	int				 has_write;
	struct stat			 prewr_st;
	ino_t				 prewr_ino;
	struct muxfs_meta_buffer	 prewr_meta_buf;
	uint64_t			 prewr_eno;
	struct muxfs_desc		 prewr_desc;
	uint8_t				 prewr_meta_chk_buf[MUXFS_CHKSZ_MAX];
	struct muxfs_desc		 wr_desc;
	struct muxfs_meta_buffer	 wr_meta_buf;

	struct muxfs_cud		 cud;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;

	has_write = 0;

	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		muxfs_working_push(i);

		fd = dev->root_fd;
		alg = dev->conf.chk_alg_type;
		chksz = muxfs_chk_size(alg);

		if (fstatat(fd, args->path, &prewr_st, AT_SYMLINK_NOFOLLOW))
			goto fail;
		prewr_ino = prewr_st.st_ino;
		if (muxfs_meta_read(&prewr_meta_buf, i, prewr_ino))
			goto fail;
		prewr_eno = prewr_meta_buf.header.eno;
		if (muxfs_desc_init_from_stat(&prewr_desc, &prewr_st,
		    prewr_eno))
			goto fail;
		memcpy(prewr_desc.content_checksum,
		    &prewr_meta_buf.checksums[chksz], chksz);
		muxfs_desc_chk_meta(prewr_meta_chk_buf, &prewr_desc, alg);
		if (bcmp(prewr_meta_chk_buf, &prewr_meta_buf.checksums[0],
		    chksz) != 0)
			goto fail;

		wr_desc     = prewr_desc;
		wr_meta_buf = prewr_meta_buf;

		switch (args->type) {
		case MUXFS_UT_CHMOD:
			subrc = fchmodat(fd, args->path, args->mode,
			    AT_SYMLINK_NOFOLLOW);
			if (subrc)
				subrc = MUXFS_EFS;
			wr_desc.perms = (prewr_desc.perms & S_IFMT) |
			    ((~S_IFMT) & args->mode);
			break;
		case MUXFS_UT_CHOWN:
			subrc = fchownat(fd, args->path, args->uid, args->gid,
			    AT_SYMLINK_NOFOLLOW);
			if (subrc)
				subrc = MUXFS_EFS;
			if (args->uid != -1)
				wr_desc.owner = args->uid;
			if (args->gid != -1)
				wr_desc.group = args->gid;
			break;
		case MUXFS_UT_UTIMENS:
			subrc = utimensat(fd, args->path, args->ts,
			    AT_SYMLINK_NOFOLLOW);
			if (subrc)
				subrc = MUXFS_EFS;
			break;
		case MUXFS_UT_TRUNCATE:
			subrc = muxfs_truncate_inner(fd, args, alg, chksz,
			    &prewr_st, &prewr_meta_buf, &wr_meta_buf, &wr_desc);
			break;
		case MUXFS_UT_WRITE:
			subrc = muxfs_write_inner(fd, args, alg, chksz,
			    &prewr_st, &prewr_meta_buf, &wr_meta_buf, &wr_desc);
			break;
		default:
			exit(-1); /* Programming error. */
		}
		switch (subrc) {
		case 0:
			break;
		case MUXFS_EINT:
			exit(-1); /* Unrecoverable runtime error. */
			break;
		case MUXFS_EFS:
			if (has_write)
				goto fail;
			rc = -errno;
			goto early;
			break;
		case MUXFS_ECHK:
			goto fail;
			break;
		default:
			exit(-1); /* Programming error. */
		}
		muxfs_desc_chk_meta(&wr_meta_buf.checksums[0], &wr_desc, alg);
		if (muxfs_meta_write(&wr_meta_buf, i, prewr_ino))
			goto fail;

		if ((subfd = openat(fd, args->path, O_RDONLY|O_NOFOLLOW)) == -1)
			goto fail;
		if (fsync(subfd))
			exit(-1);
		if (close(subfd))
			exit(-1);
		if (fsync(dev->meta_fd))
			exit(-1);
	
		if (muxfs_readback(i, args->path, &wr_meta_buf))
			goto fail;

		cud.type = MUXFS_CUD_UPDATE;
		cud.path = args->path;
		cud.pre_mbuf = prewr_meta_buf;
		if (muxfs_ancestors_meta_recompute(i, &cud))
			goto fail;

		has_write = 1;
		muxfs_working_pop(i);
		continue;
fail:
		muxfs_degraded_set(i);
		muxfs_working_pop(i);
		continue;
early:
		muxfs_working_pop(i);
		return rc;
	}
	if (has_write) {
		if (args->type == MUXFS_UT_WRITE)
			return args->bufsz;
		return 0;
	}
	return -EIO;
}

static int
muxfs_rename(const char *from, const char *to)
{
	dind			 dev_count;
	dind			 i;
	struct muxfs_dev	*dev;
	int			 fd;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;

	int				 rc;
	int				 has_write;
	struct stat			 prewr_st;
	ino_t				 prewr_ino;
	struct muxfs_meta_buffer	 prewr_meta_buf;
	uint64_t			 prewr_eno;
	struct muxfs_desc		 prewr_desc;
	uint8_t				 prewr_meta_chk_buf[MUXFS_CHKSZ_MAX];
	struct stat			 postwr_st;

	struct muxfs_cud		 cud;

	if (muxfs_path_sanitize(&from))
		return -EIO;
	if (muxfs_path_sanitize(&to))
		return -EIO;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;

	has_write = 0;

	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		muxfs_working_push(i);

		fd = dev->root_fd;
		alg = dev->conf.chk_alg_type;
		chksz = muxfs_chk_size(alg);

		if (fstatat(fd, from, &prewr_st, AT_SYMLINK_NOFOLLOW))
			goto fail;
		prewr_ino = prewr_st.st_ino;
		if (muxfs_meta_read(&prewr_meta_buf, i, prewr_ino))
			goto fail;
		prewr_eno = prewr_meta_buf.header.eno;
		if (muxfs_desc_init_from_stat(&prewr_desc, &prewr_st,
		    prewr_eno))
			goto fail;
		memcpy(prewr_desc.content_checksum,
		    &prewr_meta_buf.checksums[chksz], chksz);
		muxfs_desc_chk_meta(prewr_meta_chk_buf, &prewr_desc, alg);
		if (bcmp(prewr_meta_chk_buf, &prewr_meta_buf.checksums[0],
		    chksz) != 0)
			goto fail;

		/*
		 * The renameing process juggles the file to achieve 3 separate
		 * objectives.
		 *
		 * The first rename tests if the requested operation is
		 * possible.
		 */
		if (renameat(fd, from, fd, to)) {
			if (has_write)
				goto fail;
			rc = -errno;
			goto early;
		}

		/*
		 * The second rename moves the file out of the tree so that the
		 * meta entries for the ancestors of 'from' can be recomputed
		 * without colliding with 'to', its ancestors, and their
		 * meta entries.
		 */
		if (renameat(fd, to, fd, ".muxfs/rename.tmp"))
			goto fail;
		if (fstatat(fd, from, &postwr_st, AT_SYMLINK_NOFOLLOW) != -1)
			goto fail;
		if (errno != ENOENT)
			goto fail;
		cud.type = MUXFS_CUD_DELETE;
		cud.path = from;
		cud.pre_mbuf = prewr_meta_buf;
		if (muxfs_ancestors_meta_recompute(i, &cud))
			goto fail;

		/*
		 * The third rename moves the file back to its destination; at
		 * this point the ancestors of 'to' can be recomputed.
		 */
		if (renameat(fd, ".muxfs/rename.tmp", fd, to))
			goto fail;
		if (muxfs_readback(i, to, &prewr_meta_buf))
			goto fail;
		cud.type = MUXFS_CUD_CREATE;
		cud.path = to;
		cud.pre_mbuf = prewr_meta_buf;
		if (muxfs_ancestors_meta_recompute(i, &cud))
			goto fail;

		has_write = 1;
		muxfs_working_pop(i);
		continue;
fail:
		muxfs_degraded_set(i);
		muxfs_working_pop(i);
		continue;
early:
		muxfs_working_pop(i);
		return rc;
	}
	return has_write ? 0 : -EIO;
}

static int
muxfs_link(const char *from, const char *to)
{
	return -EOPNOTSUPP;
}

static int
muxfs_chmod(const char *path, mode_t mode)
{
	struct muxfs_op_update_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_UT_CHMOD;
	args.path = path;
	args.mode = mode;

	return muxfs_op_update(&args);
}

static int
muxfs_chown(const char *path, uid_t uid, gid_t gid)
{
	struct muxfs_op_update_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_UT_CHOWN;
	args.path = path;
	args.uid  = uid;
	args.gid  = gid;

	return muxfs_op_update(&args);
}

static int
muxfs_utimens(const char *path, const struct timespec *ts)
{
	struct muxfs_op_update_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_UT_UTIMENS;
	args.path = path;
	args.ts = ts;

	return muxfs_op_update(&args);
}

static int
muxfs_truncate(const char *path, off_t offset)
{
	struct muxfs_op_update_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_UT_TRUNCATE;
	args.path = path;
	args.offset = offset;

	return muxfs_op_update(&args);
}

static int
muxfs_write(const char *path, const char *buf, size_t bufsz, off_t offset,
    struct fuse_file_info *ffi)
{
	struct muxfs_op_update_args args;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	args.type = MUXFS_UT_WRITE;
	args.path = path;
	args.buf = buf;
	args.bufsz = bufsz;
	args.offset = offset;
	args.ffi = ffi;

	return muxfs_op_update(&args);
}

const struct fuse_operations
muxfs_fuse_ops = {
	/* Pass-through */
	.statfs      = muxfs_statfs     ,
	/* Stateful */
	.init        = muxfs_init       ,
	.destroy     = muxfs_destroy    ,
	/* No-ops */
	.fsync       = muxfs_fsync      ,
	.open        = muxfs_open       ,
	.opendir     = muxfs_opendir    ,
	.flush       = muxfs_flush      ,
	.release     = muxfs_release    ,
	.releasedir  = muxfs_releasedir ,
	/* Create */
	.mknod       = muxfs_mknod      ,
	.mkdir       = muxfs_mkdir      ,
	.symlink     = muxfs_symlink    ,
	/* Read */
	.getattr     = muxfs_getattr    ,
	.read        = muxfs_read       ,
	.readlink    = muxfs_readlink   ,
	.readdir     = muxfs_readdir    ,
	/* Update */
	.rename      = muxfs_rename     ,
	.chmod       = muxfs_chmod      ,
	.chown       = muxfs_chown      ,
	.utimens     = muxfs_utimens    ,
	.truncate    = muxfs_truncate   ,
	.write       = muxfs_write      ,
	/* Delete */
	.unlink      = muxfs_unlink     ,
	.rmdir       = muxfs_rmdir      ,
	/* Explicitly not supported */
	.link        = muxfs_link       ,
	.lock        = muxfs_lock       ,

	/* Unsupported on OpenBSD: */
	/*.getdir      = muxfs_getdir     ,*/
	/*.setxattr    = muxfs_setxattr   ,*/
	/*.getxattr    = muxfs_getxattr   ,*/
	/*.listxattr   = muxfs_listxattr  ,*/
	/*.removexattr = muxfs_removexattr,*/
	/*.fsyncdir    = muxfs_fsyncdir   ,*/
	/*.access      = muxfs_access     ,*/
	/*.create      = muxfs_create     ,*/

	/*
	 * There do not appear to be implementations for these in libfuse on
	 * OpenBSD:
	 */
	/*.fgetattr    = muxfs_fgetattr   ,*/
	/*.ftruncate   = muxfs_ftruncate  ,*/
	/*.bmap        = muxfs_bmap       ,*/ 

	/* Unnecessary due to utimens: */
	/*.utime       = muxfs_utime      ,*/
};
