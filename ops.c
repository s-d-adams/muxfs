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

#include <sys/mman.h>
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
#include "muxfs.h"
#include "gen.h"

static void
muxfs_eids_set(void)
{
	struct fuse_context *fuse_ctx;

	fuse_ctx = fuse_get_context();
	if (setegid(fuse_ctx->gid))
		exit(-1);
	if (seteuid(fuse_ctx->uid))
		exit(-1);
}

static void
muxfs_eids_reset(void)
{
	if (seteuid(getuid()))
		exit(-1);
	if (setegid(getgid()))
		exit(-1);
}

static int
muxfs_statfs(const char *path, struct statvfs *stvfs)
{
	dind dev_count, i;
	struct muxfs_dev *dev;
	int fd, err, subrc;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;
	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		muxfs_eids_set();
		fd = openat(dev->root_fd, path, O_RDONLY);
		err = errno;
		muxfs_eids_reset();
		if (fd == -1)
			continue;
		muxfs_eids_set();
		subrc = fstatvfs(fd, stvfs);
		err = errno;
		muxfs_eids_reset();
		if (subrc) {
			if (close(fd))
				exit(-1);
			return -err;
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
	if (muxfs_state_syslog_final())
		exit(-1);
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
	dind dev_count, i;
	struct muxfs_dev *dev;
	int fd, err;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;
	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		muxfs_eids_set();
		fd = openat(dev->root_fd, path, ffi->flags);
		err = errno;
		muxfs_eids_reset();
		if (fd == -1)
			return -err;
		if (close(fd))
			exit(-1);
		return 0;
	}
	return -EIO;
}

static int
muxfs_opendir(const char *path, struct fuse_file_info *ffi)
{
	dind dev_count, i;
	struct muxfs_dev *dev;
	int fd, err;

	if (muxfs_path_sanitize(&path))
		return -EIO;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;
	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		muxfs_eids_set();
		fd = openat(dev->root_fd, path, ffi->flags|O_DIRECTORY);
		err = errno;
		muxfs_eids_reset();
		if (fd == -1)
			return -err;
		if (close(fd))
			exit(-1);
		return 0;
	}
	return -EIO;
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

	int			 rc, err, subrc, subfd;
	int			 has_write;
	uint64_t		 eno;
	struct muxfs_desc	 desc;
	struct muxfs_chk	 content_chk;
	struct stat		 st;
	ino_t			 ino;
	struct muxfs_meta	 meta;
	struct muxfs_assign	 assign;

	struct muxfs_cud	 cud;

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
			.mode = args->mode,
			.size = 0,
		};
		if (muxfs_desc_type_from_mode(&desc.type, args->mode)) {
			rc = -EOPNOTSUPP;
			goto early;
		}
		muxfs_chk_init(&content_chk, alg);
		if (args->type == MUXFS_CT_SYMLINK) {
			muxfs_chk_update(&content_chk,
			    (uint8_t *)args->link_content,
			    strlen(args->link_content));
		}
		muxfs_chk_final(desc.content_checksum, &content_chk);
	
		memcpy(&meta.checksums[chksz], desc.content_checksum, chksz);
		muxfs_desc_chk_meta(&meta.checksums[0], &desc, alg);
		meta.header.eno = eno;
		meta.header.flags = MF_ASSIGNED;

		switch (args->type) {
		case MUXFS_CT_MKNOD:
			if (S_ISREG(args->mode)) {
				muxfs_eids_set();
				subfd = openat(fd, args->path,
				    O_RDWR|O_CREAT|O_EXCL, args->mode);
				err = errno;
				muxfs_eids_reset();
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
			muxfs_eids_set();
			subrc = mkdirat(fd, args->path, args->mode);
			err = errno;
			muxfs_eids_reset();
			break;
		case MUXFS_CT_SYMLINK:
			muxfs_eids_set();
			subrc = symlinkat(args->link_content, fd, args->path);
			err = errno;
			muxfs_eids_reset();
			break;
		default:
			exit(-1); /* Programming error. */
		}
		if (subrc) {
			if (!has_write) {
				rc = -err;
				goto early;
			}
			goto fail;
		}

		if (args->type != MUXFS_CT_SYMLINK) {
			if ((subfd = openat(fd, args->path,
			    O_RDONLY|O_NOFOLLOW)) == -1)
				goto fail;
			if (fsync(subfd))
				exit(-1);
			if (close(subfd))
				exit(-1);
		}

		if (fstatat(fd, args->path, &st, AT_SYMLINK_NOFOLLOW))
			goto fail;
		ino = st.st_ino;
		assign = (struct muxfs_assign) {
			.flags = AF_ASSIGNED,
			.ino = ino
		};
	
		if (muxfs_meta_write(&meta, i, ino))
			goto fail;
		if (muxfs_assign_write(&assign, i, eno))
			goto fail;
	
		if (fsync(dev->meta_fd))
			exit(-1);
		if (fsync(dev->assign_fd))
			exit(-1);
	
		if (muxfs_readback(i, args->path, 0, &meta))
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

	int			 rc, err, subrc;
	int			 has_write;
	struct stat		 prewr_st;
	ino_t			 prewr_ino;
	struct muxfs_meta	 prewr_meta;
	uint64_t		 prewr_eno;
	struct muxfs_desc	 prewr_desc;
	uint8_t			 prewr_meta_chk_buf[MUXFS_CHKSZ_MAX];
	struct muxfs_meta	 wr_meta;
	struct muxfs_assign	 wr_assign;
	char			 postwr_ppath[PATH_MAX];
	int			 postwr_pfd;
	struct stat		 postwr_st;

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

		muxfs_eids_set();
		subrc = fstatat(fd, path, &prewr_st, AT_SYMLINK_NOFOLLOW);
		err = errno;
		muxfs_eids_reset();
		if (subrc) {
			if (has_write)
				goto fail;
			rc = -err;
			goto early;
		}
		prewr_ino = prewr_st.st_ino;
		if (muxfs_meta_read(&prewr_meta, i, prewr_ino))
			goto fail;
		prewr_eno = prewr_meta.header.eno;
		if (muxfs_desc_init_from_stat(&prewr_desc, &prewr_st,
		    prewr_eno))
			goto fail;
		if (muxfs_desc_chk_node_content(&prewr_desc, i, path))
			goto fail;
		muxfs_desc_chk_meta(prewr_meta_chk_buf, &prewr_desc, alg);
		if (bcmp(prewr_meta_chk_buf, &prewr_meta.checksums[0],
		    chksz) != 0)
			goto fail;

		switch (type) {
		case MUXFS_DT_UNLINK:
			muxfs_eids_set();
			subrc = unlinkat(fd, path, 0);
			err = errno;
			muxfs_eids_reset();
			if (prewr_st.st_size > MUXFS_BLOCK_SIZE) {
				if (muxfs_lfile_delete(dev->lfile_fd,
				    prewr_ino))
					goto fail;
			}
			break;
		case MUXFS_DT_RMDIR:
			muxfs_eids_set();
			subrc = unlinkat(fd, path, AT_REMOVEDIR);
			err = errno;
			muxfs_eids_reset();
			break;
		default:
			exit(-1); /* Programming error. */
		}
		if (subrc) {
			if (has_write)
				goto fail;
			rc = -err;
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

		memset(&wr_meta, 0, sizeof(wr_meta));
		memset(&wr_assign  , 0, sizeof(wr_assign  ));
		if (muxfs_meta_write(&wr_meta, i, prewr_ino))
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
muxfs_getattr_inner(struct stat *st_out, struct stat *st, uint64_t eno,
    int *err)
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
    enum muxfs_chk_alg_type alg, size_t chksz, struct muxfs_meta *meta,
    ssize_t *rdsz_out, int *err, int lfile_fd)
{
	int fd, rc;
	size_t fsz;
	uint8_t buf[MUXFS_BLOCK_SIZE];
	struct muxfs_chk content_chk;
	uint8_t content_sum[MUXFS_CHKSZ_MAX];
	ssize_t rdsz;
	struct muxfs_range r;
	size_t i_offset, out_offset, out_size, buf_offset;
	uint64_t i;
	int lfd;
	uint8_t *lfile;

	rc = MUXFS_EINT;

	muxfs_eids_set();
	fd = openat(root_fd, args->path, O_RDONLY);
	*err = errno;
	muxfs_eids_reset();
	if (fd == -1) {
		rc = MUXFS_EFS;
		goto out;
	}

	fsz = st->st_size;
	if (args->offset >= fsz) {
		*rdsz_out = 0;
		rc = 0;
		goto out2;
	}

	if (fsz <= MUXFS_BLOCK_SIZE) {
		if (read(fd, buf, fsz) != fsz) {
			rc = MUXFS_EFS;
			goto out2;
		}
		muxfs_chk_init(&content_chk, alg);
		muxfs_chk_update(&content_chk, buf, fsz);
		muxfs_chk_final(content_sum, &content_chk);
		if (bcmp(content_sum, &meta->checksums[chksz], chksz) != 0) {
			rc = MUXFS_ECHK;
			goto out2;
		}
		rdsz = fsz - args->offset;
		if (rdsz > args->size)
			rdsz = args->size;
		memcpy(args->buf_out, &buf[args->offset], rdsz);
	
		*rdsz_out = rdsz;
		rc = 0;
		goto out2;
	}

	r.byte_begin = args->offset;
	r.byte_end = args->offset + args->size;
	if (r.byte_end > fsz)
		r.byte_end = fsz;
	muxfs_range_compute(&r, chksz);
	out_offset = 0;

	if (muxfs_lfile_open(&lfd, lfile_fd, st->st_ino, O_RDONLY))
		goto out2;
	if ((lfile = mmap(NULL, r.lfilesz, PROT_READ, MAP_SHARED, lfd,
	    r.lfileoff)) == MAP_FAILED)
		goto out3;

	for (i = r.blk_index_begin; i < r.blk_index_end; ++i) {
		i_offset = i * MUXFS_BLOCK_SIZE;
		rdsz = MUXFS_BLOCK_SIZE;
		if (i_offset + rdsz > fsz)
			rdsz = fsz - i_offset;
		if (pread(fd, buf, rdsz, i_offset) != rdsz) {
			rc = MUXFS_EFS;
			goto out4;
		}
		muxfs_chk_init(&content_chk, alg);
		muxfs_chk_update(&content_chk, buf, rdsz);
		muxfs_chk_final(content_sum, &content_chk);
		if (bcmp(content_sum, &lfile[chksz * (i - r.blk_index_begin)],
		    chksz) != 0) {
			rc = MUXFS_ECHK;
			goto out4;
		}
		buf_offset = 0;
		out_size = rdsz;
		if (i_offset < r.byte_begin) {
			buf_offset = (r.byte_begin - i_offset);
			out_size -= buf_offset;
		}
		memcpy(&args->buf_out[out_offset], &buf[buf_offset], out_size);
		out_offset += out_size;
	}

	*rdsz_out = out_offset;
	rc = 0;
out4:
	if (r.lfilesz == 0)
		exit(-1); /* Programming error. */
	if (munmap(lfile, r.lfilesz))
		exit(-1);
out3:
	if (close(lfd))
		exit(-1);
out2:
	if (close(fd))
		exit(-1);
out:
	return rc;
}

static int
muxfs_readlink_inner(int root_fd, struct muxfs_op_read_args *args,
    enum muxfs_chk_alg_type alg, size_t chksz, const struct muxfs_desc *desc,
    const struct muxfs_meta *meta, int *err)
{
	struct muxfs_desc lnk_desc;
	ssize_t lnksz, rdsz;
	char lnkbuf[PATH_MAX];
	uint8_t lnk_meta_sum[MUXFS_CHKSZ_MAX];

	memset(lnkbuf, 0, PATH_MAX);
	muxfs_eids_set();
	lnksz = readlinkat(root_fd, args->path, lnkbuf, PATH_MAX - 1);
	*err = errno;
	muxfs_eids_reset();
	if (lnksz == -1)
		return MUXFS_EFS;
	if (lnksz >= PATH_MAX)
		return MUXFS_EFS;

	lnk_desc = *desc;
	memset(lnk_desc.content_checksum, 0, MUXFS_CHKSZ_MAX);
	muxfs_desc_chk_provided_content(&lnk_desc, (uint8_t *)lnkbuf, lnksz,
	    alg);
	muxfs_desc_chk_meta(lnk_meta_sum, &lnk_desc, alg);
	if (bcmp(lnk_meta_sum, &meta->checksums[0], chksz) != 0)
		return MUXFS_ECHK;

	rdsz = (lnksz < (args->size - 1)) ? lnksz : (args->size - 1);
	memcpy(args->buf_out, lnkbuf, rdsz);
	args->buf_out[rdsz] = '\0';

	return 0;
}

static int
muxfs_readdir_inner(dind dev_index, int root_fd,
    struct muxfs_op_read_args *args, enum muxfs_chk_alg_type alg, size_t chksz,
    struct stat *st, struct muxfs_desc *desc, struct muxfs_meta *meta, int *err)
{
	int rc, fd;
	uint8_t content_sum[MUXFS_CHKSZ_MAX];
	struct muxfs_dir dir;
	struct dirent *dirent;
	int i;
	const char *dname;
	size_t dnamelen;

	rc = MUXFS_EINT;

	muxfs_eids_set();
	fd = openat(root_fd, args->path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
	*err = errno;
	muxfs_eids_reset();
	if (fd == -1) {
		rc = MUXFS_EFS;
		goto out;
	}
	if (close(fd))
		exit(-1);

	if (muxfs_pushdir(&dir, root_fd, args->path))
		exit(-1);

	if (muxfs_dir_content_chk(content_sum, dev_index, &dir)) {
		rc = MUXFS_ECHK;
		goto out2;
	}
	if (bcmp(content_sum, &meta->checksums[chksz], chksz) != 0) {
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
	struct muxfs_meta meta;
	uint64_t eno;
	struct muxfs_desc desc;

	uint8_t chk_buf[MUXFS_CHKSZ_MAX];
	ssize_t rdsz;

	if ((dev_count = muxfs_dev_count()) == 0)
		return -EIO;

	for (i = 0; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i))
			continue;
		fd = dev->root_fd;
		alg = dev->conf.chk_alg_type;
		chksz = muxfs_chk_size(alg);
		rdsz = -1;

		muxfs_eids_set();
		subrc = fstatat(fd, args->path, &st, AT_SYMLINK_NOFOLLOW);
		err = errno;
		muxfs_eids_reset();
		if (subrc) {
			if ((err == ENOENT) && muxfs_parent_readback(i,
			    args->path))
				goto fail;
			rc = -err;
			goto early;
		}
		ino = st.st_ino;
		if (muxfs_meta_read(&meta, i, ino))
			goto fail;
		eno = meta.header.eno;
		if (muxfs_desc_init_from_stat(&desc, &st, eno)) {
			rc = -EOPNOTSUPP;
			goto early;
		}
		memcpy(desc.content_checksum, &meta.checksums[chksz], chksz);
		muxfs_desc_chk_meta(chk_buf, &desc, alg);
		if (bcmp(chk_buf, &meta.checksums[0], chksz) != 0)
			goto fail;

		switch (args->type) {
		case MUXFS_RT_GETATTR:
			subrc = muxfs_getattr_inner(args->st_out, &st, eno,
			    &err);
			break;
		case MUXFS_RT_READ:
			subrc = muxfs_read_inner(fd, args, &st, alg, chksz,
			    &meta, &rdsz, &err, dev->lfile_fd);
			break;
		case MUXFS_RT_READLINK:
			subrc = muxfs_readlink_inner(fd, args, alg, chksz,
			    &desc, &meta, &err);
			break;
		case MUXFS_RT_READDIR:
			subrc = muxfs_readdir_inner(i, fd, args, alg, chksz,
			    &st, &desc, &meta, &err);
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
			rc = -err;
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

	args.type = MUXFS_RT_READLINK;
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
    struct muxfs_meta *prewr_meta, struct muxfs_meta *wr_meta,
    struct muxfs_desc *wr_desc, int *err, int lfile_fd)
{
	int rc;
	int fd;
	uint8_t content_buf[MUXFS_BLOCK_SIZE];
	size_t prewr_sz, smaller_sz, larger_sz;

	struct muxfs_chk	prewr_content_chk;
	uint8_t			prewr_content_sum[MUXFS_CHKSZ_MAX];
	struct muxfs_chk	wr_content_chk;

	struct muxfs_range r;
	size_t rdsz, i_offset, off, beginsz, padsz;
	uint64_t i;
	int lfd;
	uint8_t *lfile;
	int szcase;

	const size_t blksz = MUXFS_BLOCK_SIZE;

	rc = MUXFS_EINT;
	fd = -1;
	lfd = -1;
	lfile = MAP_FAILED;
	r.lfilesz = 0;

	muxfs_eids_set();
	fd = openat(root_fd, args->path, O_RDWR|O_NOFOLLOW);
	*err = errno;
	muxfs_eids_reset();
	if (fd == -1) {
		rc = MUXFS_EFS;
		goto out;
	}

	larger_sz = smaller_sz = prewr_sz = st->st_size;
	if (args->offset > larger_sz)
		larger_sz = args->offset;
	if (args->offset < smaller_sz)
		smaller_sz = args->offset;

	if (args->offset == prewr_sz) {
		rc = 0;
		goto out;
	}

	if (prewr_sz <= blksz) {
		memset(content_buf, 0, blksz);
		if (pread(fd, content_buf, prewr_sz, 0) != prewr_sz) {
			rc = MUXFS_EFS;
			goto out;
		}
		muxfs_chk_init(&prewr_content_chk, alg);
		muxfs_chk_update(&prewr_content_chk, content_buf, prewr_sz);
		muxfs_chk_final(prewr_content_sum, &prewr_content_chk);
		if (bcmp(prewr_content_sum, &prewr_meta->checksums[chksz],
		    chksz) != 0) {
			rc = MUXFS_ECHK;
			goto out;
		}
	} else {
		if (args->offset <= prewr_sz) {
			r.byte_begin = args->offset;
			r.byte_end = prewr_sz;
		} else {
			r.byte_begin = r.byte_end = prewr_sz;
			if (r.byte_begin > 1)
				--r.byte_begin;
		}
		muxfs_range_compute(&r, chksz);

		if (muxfs_lfile_open(&lfd, lfile_fd, st->st_ino, O_RDONLY))
			goto out;
		if ((lfile = mmap(NULL, r.lfilesz, PROT_READ, MAP_SHARED, lfd,
		    r.lfileoff)) == MAP_FAILED)
			goto out;
	
		for (i = r.blk_index_begin; i < r.blk_index_end; ++i) {
			i_offset = i * blksz;
			rdsz = blksz;
			if (i_offset + rdsz > prewr_sz)
				rdsz = prewr_sz - i_offset;
			if (pread(fd, content_buf, rdsz, i_offset) != rdsz) {
				rc = MUXFS_EFS;
				goto out;
			}
			muxfs_chk_init(&prewr_content_chk, alg);
			muxfs_chk_update(&prewr_content_chk, content_buf, rdsz);
			muxfs_chk_final(prewr_content_sum, &prewr_content_chk);
			if (bcmp(prewr_content_sum, &lfile[chksz * (i -
			    r.blk_index_begin)], chksz) != 0) {
				rc = MUXFS_ECHK;
				goto out;
			}
		}

		if (munmap(lfile, r.lfilesz))
			exit(-1);
		lfile = MAP_FAILED;
		r.lfilesz = 0;
		if (close(lfd))
			exit(-1);
		lfd = -1;
	}

	szcase = (prewr_sz > blksz) ? 1 : 0;
	szcase += (args->offset > blksz) ? 2 : 0;
	switch (szcase) {
	case 1:
		if (muxfs_lfile_delete(lfile_fd, st->st_ino))
			goto out;
		memset(content_buf, 0, blksz);
		if (pread(fd, content_buf, args->offset, 0) != args->offset) {
			rc = MUXFS_EFS;
			goto out;
		}
		/* FALLTHROUGH */
	case 0:
		muxfs_chk_init(&wr_content_chk, alg);
		muxfs_chk_update(&wr_content_chk, content_buf, args->offset);
		muxfs_chk_final(wr_desc->content_checksum, &wr_content_chk);
		memcpy(&wr_meta->checksums[chksz], wr_desc->content_checksum,
		    chksz);
		break;
	case 2:
		if (muxfs_lfile_create(lfile_fd, chksz, st->st_ino,
		    args->offset))
			goto out;
		r.byte_begin = 0;
		r.byte_end = args->offset;
		muxfs_range_compute(&r, chksz);

		if (muxfs_lfile_open(&lfd, lfile_fd, st->st_ino, O_WRONLY))
			goto out;
		if ((lfile = mmap(NULL, r.lfilesz, PROT_WRITE, MAP_SHARED, lfd,
		    r.lfileoff)) == MAP_FAILED)
			goto out;
	
		for (i = r.blk_index_begin; i < r.blk_index_end; ++i) {
			i_offset = i * blksz;
			rdsz = blksz;
			if (i_offset + rdsz > args->offset)
				rdsz = args->offset - i_offset;
			if (pread(fd, content_buf, rdsz, i_offset) != rdsz) {
				rc = MUXFS_EFS;
				goto out;
			}
			muxfs_chk_init(&wr_content_chk, alg);
			muxfs_chk_update(&wr_content_chk, content_buf, rdsz);
			muxfs_chk_final(&lfile[chksz * i], &wr_content_chk);
		}

		if (munmap(lfile, r.lfilesz))
			exit(-1);
		lfile = MAP_FAILED;
		r.lfilesz = 0;
		if (close(lfd))
			exit(-1);
		lfd = -1;

		if (muxfs_lfile_ancestors_recompute(wr_desc->content_checksum,
		    lfile_fd, alg, st->st_ino, args->offset, r.blk_index_begin,
		    r.blk_index_end))
			goto out;
		break;
	case 3:
		if (muxfs_lfile_resize(lfile_fd, chksz, st->st_ino,
		    prewr_sz, args->offset))
			goto out;
		if (args->offset < prewr_sz) {
			r.byte_begin = r.byte_end = args->offset;
			if (r.byte_begin > 0)
				--r.byte_begin;
			muxfs_range_compute(&r, chksz);

			if (muxfs_lfile_open(&lfd, lfile_fd, st->st_ino,
			    O_WRONLY))
				goto out;
			if ((lfile = mmap(NULL, r.lfilesz, PROT_WRITE,
			    MAP_SHARED, lfd, r.lfileoff)) == MAP_FAILED)
				goto out;

			rdsz = args->offset - r.blk_begin;
			if (pread(fd, content_buf, rdsz, r.blk_begin)
			    != rdsz) {
				rc = MUXFS_EFS;
				goto out;
			}

			muxfs_chk_init(&wr_content_chk, alg);
			muxfs_chk_update(&wr_content_chk, content_buf, rdsz);
			muxfs_chk_final(&lfile[0], &wr_content_chk);

			if (munmap(lfile, r.lfilesz))
				exit(-1);
			lfile = MAP_FAILED;
			r.lfilesz = 0;
			if (close(lfd))
				exit(-1);
			lfd = -1;

			if (muxfs_lfile_ancestors_recompute(wr_desc
			    ->content_checksum, lfile_fd, alg, st->st_ino,
			    args->offset, r.blk_index_begin, r.blk_index_end))
				goto out;
			break;
		}
		r.byte_begin = prewr_sz;
		r.byte_end = args->offset;
		muxfs_range_compute(&r, chksz);

		if (muxfs_lfile_open(&lfd, lfile_fd, st->st_ino, O_WRONLY))
			goto out;
		if ((lfile = mmap(NULL, r.lfilesz, PROT_WRITE, MAP_SHARED, lfd,
		    r.lfileoff)) == MAP_FAILED)
			goto out;

		for (i = r.blk_index_begin; i < r.blk_index_end; ++i) {
			i_offset = i * blksz;
			off = 0;
			if (i_offset < prewr_sz) {
				beginsz = prewr_sz - i_offset;
				if (beginsz > blksz)
					beginsz = blksz;
				if (pread(fd, content_buf, beginsz, i_offset)
				    != beginsz) {
					rc = MUXFS_EFS;
					goto out;
				}
				off += beginsz;
			}
			if (off < blksz) {
				padsz = args->offset - (i_offset + off);
				if (off + padsz > blksz)
					padsz = blksz - off;
				memset(&content_buf[off], 0, padsz);
				off += padsz;
			}
			muxfs_chk_init(&wr_content_chk, alg);
			muxfs_chk_update(&wr_content_chk, content_buf, off);
			muxfs_chk_final(&lfile[chksz * (i -
			    r.blk_index_begin)], &wr_content_chk);
		}

		if (munmap(lfile, r.lfilesz))
			exit(-1);
		lfile = MAP_FAILED;
		r.lfilesz = 0;
		if (close(lfd))
			exit(-1);
		lfd = -1;

		if (muxfs_lfile_ancestors_recompute(wr_desc->content_checksum,
		    lfile_fd, alg, st->st_ino, args->offset, r.blk_index_begin,
		    r.blk_index_end))
			goto out;
		break;
	default:
		exit(-1); /* Unreachable. */
	}

	if (ftruncate(fd, args->offset)) {
		rc = MUXFS_EFS;
		goto out;
	}

	wr_desc->size = args->offset;

	rc = 0;
out:
	if (fd != -1) {
		if (close(fd))
			exit(-1);
	}
	return rc;
}

static int
muxfs_write_inner(int root_fd, struct muxfs_op_update_args *args,
    enum muxfs_chk_alg_type alg, size_t chksz, struct stat *st,
    struct muxfs_meta *prewr_meta, struct muxfs_meta *wr_meta,
    struct muxfs_desc *wr_desc, int *err, int lfile_fd)
{
	int rc;
	int fd;
	uint8_t content_buf[MUXFS_BLOCK_SIZE];
	size_t prewr_sz, wrub, largest_sz;

	struct muxfs_chk	prewr_content_chk;
	uint8_t			prewr_content_sum[MUXFS_CHKSZ_MAX];
	struct muxfs_chk	wr_content_chk;

	struct muxfs_range r;
	size_t rdsz, i_offset, wroff, off, beginsz, padsz, wrsz, endsz;
	uint64_t i;
	int lfd;
	uint8_t *lfile;

	const size_t blksz = MUXFS_BLOCK_SIZE;

	rc = MUXFS_EINT;
	fd = -1;
	lfd = -1;
	lfile = MAP_FAILED;
	r.lfilesz = 0;

	muxfs_eids_set();
	fd = openat(root_fd, args->path, O_RDWR|O_NOFOLLOW);
	*err = errno;
	muxfs_eids_reset();
	if (fd == -1) {
		rc = MUXFS_EFS;
		goto out;
	}

	largest_sz = prewr_sz = st->st_size;
	wrub = (args->offset + args->bufsz);
	if (wrub > largest_sz)
		largest_sz = wrub;

	if (prewr_sz <= blksz) {
		/*
		 * This memset is necessary since 'content_buf' is used at the
		 * write stage and the write may begin beyond the end of the
		 * current file size, in which case the file content will be
		 * padded with zeroes and this must be accounted for when
		 * computing the checksum.
		 */
		memset(content_buf, 0, blksz);

		if (read(fd, content_buf, prewr_sz) != prewr_sz) {
			rc = MUXFS_EFS;
			goto out;
		}
		muxfs_chk_init(&prewr_content_chk, alg);
		muxfs_chk_update(&prewr_content_chk, content_buf, prewr_sz);
		muxfs_chk_final(prewr_content_sum, &prewr_content_chk);
		if (bcmp(prewr_content_sum, &prewr_meta->checksums[chksz],
		    chksz) != 0) {
			rc = MUXFS_ECHK;
			goto out;
		}
	} else if (args->offset < prewr_sz) {
		r.byte_begin = args->offset;
		r.byte_end = args->offset + args->bufsz;
		if (r.byte_end > prewr_sz)
			r.byte_end = prewr_sz;
		muxfs_range_compute(&r, chksz);
	
		if (muxfs_lfile_open(&lfd, lfile_fd, st->st_ino, O_RDONLY))
			goto out;
		if ((lfile = mmap(NULL, r.lfilesz, PROT_READ, MAP_SHARED, lfd,
		    r.lfileoff)) == MAP_FAILED)
			goto out;
	
		for (i = r.blk_index_begin; i < r.blk_index_end; ++i) {
			i_offset = i * blksz;
			rdsz = blksz;
			if (i_offset + rdsz > prewr_sz)
				rdsz = prewr_sz - i_offset;
			if (pread(fd, content_buf, rdsz, i_offset) != rdsz) {
				rc = MUXFS_EFS;
				goto out;
			}
			muxfs_chk_init(&prewr_content_chk, alg);
			muxfs_chk_update(&prewr_content_chk, content_buf, rdsz);
			muxfs_chk_final(prewr_content_sum, &prewr_content_chk);
			if (bcmp(prewr_content_sum, &lfile[chksz * (i -
			    r.blk_index_begin)], chksz) != 0) {
				rc = MUXFS_ECHK;
				goto out;
			}
		}

		if (munmap(lfile, r.lfilesz))
			exit(-1);
		lfile = MAP_FAILED;
		r.lfilesz = 0;
		if (close(lfd))
			exit(-1);
		lfd = -1;
	}

	if ((prewr_sz <= blksz) && (wrub > blksz)) {
		if (muxfs_lfile_create(lfile_fd, chksz, st->st_ino, wrub))
			goto out;
	}

	if (largest_sz <= blksz) {
		memcpy(&content_buf[args->offset], args->buf, args->bufsz);
		if (pwrite(fd, args->buf, args->bufsz, args->offset) !=
		    args->bufsz) {
			rc = MUXFS_EFS;
			goto out;
		}

		muxfs_chk_init(&wr_content_chk, alg);
		muxfs_chk_update(&wr_content_chk, content_buf, largest_sz);
		muxfs_chk_final(wr_desc->content_checksum, &wr_content_chk);
		memcpy(&wr_meta->checksums[chksz], wr_desc->content_checksum,
		    chksz);
	} else {
		if ((prewr_sz > blksz) && (wrub > prewr_sz)) {
			if (muxfs_lfile_resize(lfile_fd, chksz, st->st_ino,
			    prewr_sz, wrub))
				goto out;
		}

		r.byte_begin = args->offset;
		if (prewr_sz < r.byte_begin)
			r.byte_begin = prewr_sz;
		r.byte_end = args->offset + args->bufsz;
		muxfs_range_compute(&r, chksz);

		if (muxfs_lfile_open(&lfd, lfile_fd, st->st_ino, O_WRONLY))
			goto out;
		if ((lfile = mmap(NULL, r.lfilesz, PROT_WRITE, MAP_SHARED, lfd,
		    r.lfileoff)) == MAP_FAILED)
			goto out;
	
		wroff = 0;

		for (i = r.blk_index_begin; i < r.blk_index_end; ++i) {
			i_offset = i * blksz;
			off = 0;
			if (i_offset < args->offset) {
				if (i_offset < prewr_sz) {
					beginsz = prewr_sz - i_offset;
					if (beginsz > blksz)
						beginsz = blksz;
					if (pread(fd, content_buf, beginsz,
					    i_offset) != beginsz) {
						rc = MUXFS_EFS;
						goto out;
					}
					off += beginsz;
				}
				if ((off < blksz) && (prewr_sz <
				    args->offset)) {
					padsz = args->offset - (i_offset + off);
					if (off + padsz > blksz)
						padsz = blksz - off;
					memset(&content_buf[off], 0, padsz);
					off += padsz;
				}
			}
			if (off < blksz) {
				wrsz = wrub - (i_offset + off);
				if (off + wrsz > blksz)
					wrsz = blksz - off;
				memcpy(&content_buf[off], &args->buf[wroff],
				    wrsz);
				wroff += wrsz;
				off += wrsz;
			}
			if (off < blksz) {
				endsz = largest_sz - (i_offset + off);
				if (off + endsz > blksz)
					endsz = blksz - off;
				if (pread(fd, &content_buf[off], endsz,
				    i_offset + off) != endsz) {
					rc = MUXFS_EFS;
					goto out;
				}
				off += endsz;
			}

			if (pwrite(fd, content_buf, off, i_offset) != off) {
				rc = MUXFS_EFS;
				goto out;
			}

			muxfs_chk_init(&wr_content_chk, alg);
			muxfs_chk_update(&wr_content_chk, content_buf, off);
			muxfs_chk_final(&lfile[chksz * (i -
			    r.blk_index_begin)], &wr_content_chk);
		}

		if (munmap(lfile, r.lfilesz))
			exit(-1);
		lfile = MAP_FAILED;
		r.lfilesz = 0;
		if (fsync(lfd))
			exit(-1);
		if (close(lfd))
			exit(-1);
		lfd = -1;

		if (muxfs_lfile_ancestors_recompute(wr_desc->content_checksum,
		    lfile_fd, alg, st->st_ino, largest_sz, r.blk_index_begin,
		    r.blk_index_end))
			goto out;
		memcpy(&wr_meta->checksums[chksz], wr_desc->content_checksum,
		    chksz);
	}

	wr_desc->size = largest_sz;

	rc = 0;
out:
	if (lfile != MAP_FAILED) {
		if (r.lfilesz == 0)
			exit(-1); /* Programming error. */
		if (munmap(lfile, r.lfilesz))
			exit(-1);
	} else if (r.lfilesz != 0)
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

static int
muxfs_op_update(struct muxfs_op_update_args *args)
{
	dind			 dev_count;
	dind			 i;
	struct muxfs_dev	*dev;
	int			 fd;
	enum muxfs_chk_alg_type	 alg;
	size_t			 chksz;

	int			 rc, err, subrc, subfd;
	int			 has_write;
	struct stat		 prewr_st;
	ino_t			 prewr_ino;
	struct muxfs_meta	 prewr_meta;
	uint64_t		 prewr_eno;
	struct muxfs_desc	 prewr_desc;
	uint8_t			 prewr_meta_chk_buf[MUXFS_CHKSZ_MAX];
	struct muxfs_desc	 wr_desc;
	struct muxfs_meta	 wr_meta;

	size_t			 mod_begin, mod_end, mod_size;

	struct muxfs_cud	 cud;

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

		muxfs_eids_set();
		subrc = fstatat(fd, args->path, &prewr_st, AT_SYMLINK_NOFOLLOW);
		err = errno;
		muxfs_eids_reset();
		if (subrc) {
			if (has_write)
				goto fail;
			rc = -err;
			goto early;
		}
		prewr_ino = prewr_st.st_ino;
		if (muxfs_meta_read(&prewr_meta, i, prewr_ino))
			goto fail;
		prewr_eno = prewr_meta.header.eno;
		if (muxfs_desc_init_from_stat(&prewr_desc, &prewr_st,
		    prewr_eno))
			goto fail;
		memcpy(prewr_desc.content_checksum,
		    &prewr_meta.checksums[chksz], chksz);
		muxfs_desc_chk_meta(prewr_meta_chk_buf, &prewr_desc, alg);
		if (bcmp(prewr_meta_chk_buf, &prewr_meta.checksums[0],
		    chksz) != 0)
			goto fail;

		wr_desc = prewr_desc;
		wr_meta = prewr_meta;

		switch (args->type) {
		case MUXFS_UT_CHMOD:
			muxfs_eids_set();
			subrc = fchmodat(fd, args->path, args->mode,
			    AT_SYMLINK_NOFOLLOW);
			err = errno;
			muxfs_eids_reset();
			if (subrc)
				subrc = MUXFS_EFS;
			wr_desc.mode = (prewr_desc.mode & S_IFMT) |
			    ((~S_IFMT) & args->mode);
			break;
		case MUXFS_UT_CHOWN:
			muxfs_eids_set();
			subrc = fchownat(fd, args->path, args->uid, args->gid,
			    AT_SYMLINK_NOFOLLOW);
			err = errno;
			muxfs_eids_reset();
			if (subrc)
				subrc = MUXFS_EFS;
			if (args->uid != -1)
				wr_desc.owner = args->uid;
			if (args->gid != -1)
				wr_desc.group = args->gid;
			break;
		case MUXFS_UT_UTIMENS:
			muxfs_eids_set();
			subrc = utimensat(fd, args->path, args->ts,
			    AT_SYMLINK_NOFOLLOW);
			err = errno;
			muxfs_eids_reset();
			if (subrc)
				subrc = MUXFS_EFS;
			break;
		case MUXFS_UT_TRUNCATE:
			subrc = muxfs_truncate_inner(fd, args, alg, chksz,
			    &prewr_st, &prewr_meta, &wr_meta, &wr_desc,
			    &err, dev->lfile_fd);
			break;
		case MUXFS_UT_WRITE:
			subrc = muxfs_write_inner(fd, args, alg, chksz,
			    &prewr_st, &prewr_meta, &wr_meta, &wr_desc, &err,
			    dev->lfile_fd);
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
			if (has_write)
				goto fail;
			rc = -err;
			goto early;
		case MUXFS_ECHK:
			goto fail;
		default:
			exit(-1); /* Programming error. */
		}
		muxfs_desc_chk_meta(&wr_meta.checksums[0], &wr_desc, alg);
		if (muxfs_meta_write(&wr_meta, i, prewr_ino))
			goto fail;

		if ((subfd = openat(fd, args->path, O_RDONLY|O_NOFOLLOW)) == -1)
			goto fail;
		if (fsync(subfd))
			exit(-1);
		if (close(subfd))
			exit(-1);
		if (fsync(dev->meta_fd))
			exit(-1);

		switch (args->type) {
		case MUXFS_UT_TRUNCATE:
			mod_end = args->offset;
			if (args->offset <= prewr_st.st_size) {
				mod_begin = args->offset;
				if (mod_begin > 1)
					--mod_begin;
			} else
				mod_begin = prewr_st.st_size;
			mod_size = mod_end;
			if (mod_size > MUXFS_BLOCK_SIZE) {
				if (muxfs_lfile_readback(NULL, i, args->path,
				    mod_begin, mod_end,
				    &wr_meta.checksums[chksz]))
					goto fail;
				if (muxfs_readback(i, args->path, 1, &wr_meta))
					goto fail;
			} else {
				if (muxfs_readback(i, args->path, 0, &wr_meta))
					goto fail;
			}
			break;
		case MUXFS_UT_WRITE:
			mod_begin = args->offset;
			if (mod_begin > prewr_st.st_size)
				mod_begin = prewr_st.st_size;
			mod_end = args->offset + args->bufsz;
			mod_size = mod_end;
			if (mod_size < prewr_st.st_size)
				mod_size = prewr_st.st_size;
			if (mod_size > MUXFS_BLOCK_SIZE) {
				if (muxfs_lfile_readback(NULL, i, args->path,
				    mod_begin, mod_end,
				    &wr_meta.checksums[chksz]))
					goto fail;
				if (muxfs_readback(i, args->path, 1, &wr_meta))
					goto fail;
			} else {
				if (muxfs_readback(i, args->path, 0, &wr_meta))
					goto fail;
			}
			break;
		default:
			if (muxfs_readback(i, args->path, 1, &wr_meta))
				goto fail;
		}

		cud.type = MUXFS_CUD_UPDATE;
		cud.path = args->path;
		cud.pre_meta = prewr_meta;
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

	int			 rc, err, subrc;
	int			 has_write;
	struct stat		 prewr_st;
	ino_t			 prewr_ino;
	struct muxfs_meta	 prewr_meta;
	uint64_t		 prewr_eno;
	struct muxfs_desc	 prewr_desc;
	uint8_t			 prewr_meta_chk_buf[MUXFS_CHKSZ_MAX];
	struct stat		 postwr_st;

	struct muxfs_cud	 cud;

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

		muxfs_eids_set();
		subrc = fstatat(fd, from, &prewr_st, AT_SYMLINK_NOFOLLOW);
		err = errno;
		muxfs_eids_reset();
		if (subrc) {
			if (has_write)
				goto fail;
			rc = -err;
			goto early;
		}
		prewr_ino = prewr_st.st_ino;
		if (muxfs_meta_read(&prewr_meta, i, prewr_ino))
			goto fail;
		prewr_eno = prewr_meta.header.eno;
		if (muxfs_desc_init_from_stat(&prewr_desc, &prewr_st,
		    prewr_eno))
			goto fail;
		memcpy(prewr_desc.content_checksum,
		    &prewr_meta.checksums[chksz], chksz);
		muxfs_desc_chk_meta(prewr_meta_chk_buf, &prewr_desc, alg);
		if (bcmp(prewr_meta_chk_buf, &prewr_meta.checksums[0],
		    chksz) != 0)
			goto fail;

		/*
		 * The renameing process juggles the file to achieve 3 separate
		 * objectives.
		 *
		 * The first rename tests if the requested operation is
		 * possible.
		 */
		muxfs_eids_set();
		subrc = renameat(fd, from, fd, to);
		err = errno;
		muxfs_eids_reset();
		if (subrc) {
			if (has_write)
				goto fail;
			rc = -err;
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
		cud.pre_meta = prewr_meta;
		if (muxfs_ancestors_meta_recompute(i, &cud))
			goto fail;

		/*
		 * The third rename moves the file back to its destination; at
		 * this point the ancestors of 'to' can be recomputed.
		 */
		if (renameat(fd, ".muxfs/rename.tmp", fd, to))
			goto fail;
		if (muxfs_readback(i, to, 0, &prewr_meta))
			goto fail;
		cud.type = MUXFS_CUD_CREATE;
		cud.path = to;
		cud.pre_meta = prewr_meta;
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
	.flush       = muxfs_flush      ,
	.release     = muxfs_release    ,
	.releasedir  = muxfs_releasedir ,
	/* Create */
	.mknod       = muxfs_mknod      ,
	.mkdir       = muxfs_mkdir      ,
	.symlink     = muxfs_symlink    ,
	/* Read */
	.open        = muxfs_open       ,
	.opendir     = muxfs_opendir    ,
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
