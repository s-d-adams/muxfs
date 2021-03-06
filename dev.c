/* dev.c */
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

#include <sys/stat.h>
#include <sys/syslimits.h>
#include <endian.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "muxfs.h"

#define MUXFS_PATH_DIR ".muxfs"
#define MUXFS_PATH_CONF		MUXFS_PATH_DIR"/muxfs.conf"
#define MUXFS_PATH_STATE_DB	MUXFS_PATH_DIR"/state.db"
#define MUXFS_PATH_META_DB	MUXFS_PATH_DIR"/meta.db"
#define MUXFS_PATH_ASSIGN_DB	MUXFS_PATH_DIR"/assign.db"
#define MUXFS_PATH_LFILE	MUXFS_PATH_DIR"/lfile"

/*
 * We store the roots here instead of struct muxfs_dev so files that include
 * muxfs.h don't have to include sys/syslimits.h for PATH_MAX.
 */
static char	muxfs_dev_roots[MUXFS_DEV_COUNT_MAX][PATH_MAX];
static struct	muxfs_dev muxfs_dev_array[MUXFS_DEV_COUNT_MAX];
static dind	muxfs_dev_array_count;
static dind	muxfs_dev_array_mounted_count;
static dind	muxfs_dev_array_degraded_count;

static int
muxfs_dev_state_read(struct muxfs_dev_state *state, int fd)
{
	ssize_t s;
	struct stat st;
	struct muxfs_dev_state disk_state;

	if (fstat(fd, &st))
		return 1;
	if (st.st_size != sizeof(*state))
		return 1;
	if ((s = pread(fd, &disk_state, sizeof(disk_state), 0)) == -1)
		return 1;
	if (s != sizeof(disk_state))
		return 1;

	*state = (struct muxfs_dev_state) {
		.seq       = letoh64(disk_state.seq      ),
		.mounted   = letoh64(disk_state.mounted  ),
		.working   = letoh64(disk_state.working  ),
		.restoring = letoh64(disk_state.restoring),
		.degraded  = letoh64(disk_state.degraded ),
	};

	return 0;
}

static int
muxfs_dev_state_is_clean(struct muxfs_dev_state *state)
{
	return !(state->mounted || state->restoring || state->working ||
	    state->degraded);
}

MUXFS int
muxfs_dev_state_write_fd(int fd, struct muxfs_dev_state *state)
{
	struct muxfs_dev_state disk_state;

	const size_t sz = sizeof(disk_state);

	disk_state = (struct muxfs_dev_state) {
		.seq       = htole64(state->seq      ),
		.mounted   = htole64(state->mounted  ),
		.working   = htole64(state->working  ),
		.restoring = htole64(state->restoring),
		.degraded  = htole64(state->degraded ),
	};

	return pwrite(fd, &disk_state, sz, 0) != sz;
}

static int
muxfs_dev_state_mount(struct muxfs_dev_state *state, int fd)
{
	state->mounted = 1;
	if (muxfs_dev_state_write_fd(fd, state))
		return 1;
	return 0;
}
static int
muxfs_dev_state_unmount(struct muxfs_dev_state *state, int fd)
{
	state->mounted = 0;
	if (muxfs_dev_state_write_fd(fd, state))
		return 1;
	return 0;
}

MUXFS dind
muxfs_dev_count(void)
{
	return muxfs_dev_array_count;
}

MUXFS int
muxfs_dev_get(struct muxfs_dev **dev_out, size_t dev_index, int force)
{
	struct muxfs_dev *dev;

	if (dev_index >= muxfs_dev_array_count)
		return 1;

	dev = &muxfs_dev_array[dev_index];
	if (!force) {
		if (!dev->mounted_now)
			return 1;
		if (dev->state.degraded)
			return 1;
	}

	*dev_out = dev;
	return 0;
}

static void
muxfs_dev_init(dind dev_index)
{
	struct muxfs_dev *dev;

	memset(&muxfs_dev_roots[dev_index], 0, PATH_MAX);

	dev = &muxfs_dev_array[dev_index];
	memset(dev, 0, sizeof(*dev));
	dev->  root_fd =
	dev-> state_fd =
	dev->  meta_fd =
	dev->assign_fd =
	dev-> lfile_fd = -1;
}

MUXFS void
muxfs_dev_module_init(void)
{
	dind i;
	
	memset(&muxfs_dev_roots, 0, MUXFS_DEV_COUNT_MAX * (PATH_MAX));
	for (i = 0; i < MUXFS_DEV_COUNT_MAX; ++i)
		muxfs_dev_init(i);
}

MUXFS int
muxfs_dev_is_mounted(dind dev_index)
{
	return muxfs_dev_array[dev_index].mounted_now;
}

MUXFS int
muxfs_dev_append(dind *dev_index_out, const char *path)
{
	struct muxfs_dev *dev;
	dind i;
	size_t len;

	if (muxfs_dev_array_count == MUXFS_DEV_COUNT_MAX)
		return 1;

	i = muxfs_dev_array_count;
	dev = &muxfs_dev_array[i];

	len = strlen(path);
	if (len >= PATH_MAX)
		return 1;

	strcpy(muxfs_dev_roots[i], path);
	dev->root_path = muxfs_dev_roots[i];
	dev->attached_now = 1;
	if (dev_index_out != NULL)
		*dev_index_out = i;
	++muxfs_dev_array_count;

	return 0;
}

MUXFS int
muxfs_dev_mount(dind dev_index, int force)
{
	int rc, root_fd, conf_fd, state_fd, meta_fd, assign_fd, lfile_fd;
	struct muxfs_dev *dev, *first;
	dind i, dev_count;

	  root_fd =
	  conf_fd =
	 state_fd =
	  meta_fd =
	assign_fd =
	 lfile_fd = -1;

	dev = &muxfs_dev_array[dev_index];
	if (!dev->attached_now)
		return 1;
	if (dev->mounted_now)
		return 1;

	if ((root_fd = open(dev->root_path, O_RDONLY|O_DIRECTORY))
	    == -1)
		goto fail;

	if ((conf_fd = openat(root_fd, MUXFS_PATH_CONF, O_RDONLY|O_NOFOLLOW))
	    == -1)
		goto fail;
	if (muxfs_conf_parse(&dev->conf, conf_fd))
		goto fail;
	rc = close(conf_fd);
	conf_fd = -1;
	if (rc)
		goto fail;

	if (muxfs_dev_array_mounted_count > 0) {
		dev_count = muxfs_dev_count();
		for (i = 0; i < dev_count; ++i) {
			if (i == dev_index)
				continue;
			if (!muxfs_dev_get(&first, i, 0))
				break;
		}
		if (bcmp(dev->conf.array_uuid, first->conf.array_uuid,
		    MUXFS_UUID_SIZE) != 0)
			goto fail;
	}

	if ((state_fd = openat(root_fd, MUXFS_PATH_STATE_DB,
	    O_RDWR|O_NOFOLLOW)) == -1)
		goto fail;
	if (muxfs_dev_state_read(&dev->state, state_fd))
		goto fail;
	if (!force && !muxfs_dev_state_is_clean(&dev->state))
		goto fail;

	if ((meta_fd = openat(root_fd, MUXFS_PATH_META_DB, O_RDWR|O_NOFOLLOW))
	    == -1)
		goto fail;

	if ((assign_fd = openat(root_fd, MUXFS_PATH_ASSIGN_DB,
	     O_RDWR|O_NOFOLLOW)) == -1)
		goto fail;

	if (muxfs_dev_state_mount(&dev->state, state_fd))
		goto fail;

	if ((lfile_fd = openat(root_fd, MUXFS_PATH_LFILE, O_RDONLY|O_DIRECTORY))
	    == -1)
		goto fail;

	dev->  root_fd =   root_fd;
	dev-> state_fd =  state_fd;
	dev->  meta_fd =   meta_fd;
	dev->assign_fd = assign_fd;
	dev-> lfile_fd =  lfile_fd;
	dev->mounted_now = 1;
	++muxfs_dev_array_mounted_count;

	return 0;
fail:
	if (lfile_fd != -1)
		close(lfile_fd);
	if (assign_fd != -1)
		close(assign_fd);
	if (meta_fd != -1)
		close(meta_fd);
	if (state_fd != -1)
		close(state_fd);
	if (conf_fd != -1)
		close(conf_fd);
	if (root_fd != -1)
		close(root_fd);
	return 1;
}

MUXFS int
muxfs_dev_unmount(size_t index)
{
	struct muxfs_dev *dev;

	if (muxfs_dev_get(&dev, index, 0))
		return 1;

	if (dev->state.working)
		return 1; /* Device busy. */
	if (dev->state.restoring)
		return 1; /* Device busy. */

	if (dev->meta_fd!= -1) {
		if (close(dev->meta_fd))
			exit(-1);
	}
	if (dev->root_fd != -1) {
		if (close(dev->root_fd))
			exit(-1);
	}
	if (muxfs_dev_state_unmount(&dev->state, dev->state_fd))
		exit(-1);
	if (dev->state_fd!= -1) {
		if (close(dev->state_fd))
			exit(-1);
	}

	--muxfs_dev_array_mounted_count;
	return 0;
}

MUXFS int
muxfs_working_push(size_t index)
{
	struct muxfs_dev *dev;

	if (muxfs_dev_get(&dev, index, 0))
		return 1;
	if (dev->state.working == UINT64_MAX)
		return 1;

	dev->state.working++;
	if (muxfs_dev_state_write_fd(dev->state_fd, &dev->state))
		return 1;

	return 0;
}

MUXFS int
muxfs_working_pop(size_t index, time_t now)
{
	struct muxfs_dev *dev;
	int conf_fd;

	if (muxfs_dev_get(&dev, index, 0))
		return 1;

	if (dev->state.working == 0)
		exit(-1);

	if (dev->state.seq == UINT64_MAX) {
		dev->state.seq = 0;
		dev->conf.seq_zero_time = now;
		if ((conf_fd = openat(dev->root_fd, MUXFS_PATH_CONF,
		    O_RDWR)) == -1)
			return 1;
		if (muxfs_conf_write(&dev->conf, conf_fd)) {
			if (close(conf_fd))
				exit(-1);
		}
		if (close(conf_fd))
			exit(-1);
	} else
		dev->state.seq++;

	dev->state.working--;
	if (muxfs_dev_state_write_fd(dev->state_fd, &dev->state))
		return 1;

	return 0;
}

MUXFS int
muxfs_restoring_push(size_t index)
{
	struct muxfs_dev *dev;

	if (muxfs_dev_get(&dev, index, 0))
		return 1;
	if (dev->state.restoring == UINT64_MAX)
		return 1;

	dev->state.restoring++;
	if (muxfs_dev_state_write_fd(dev->state_fd, &dev->state))
		return 1;

	return 0;
}

MUXFS int
muxfs_restoring_pop(size_t index)
{
	struct muxfs_dev *dev;

	if (muxfs_dev_get(&dev, index, 0))
		return 1;

	if (dev->state.restoring == 0)
		exit(-1);

	dev->state.restoring--;
	if (muxfs_dev_state_write_fd(dev->state_fd, &dev->state))
		return 1;

	return 0;
}

static int
muxfs_degraded_set_val(size_t dev_index, uint64_t val)
{
	struct muxfs_dev *dev;
	uint64_t *deg;

	if (muxfs_dev_get(&dev, dev_index, 0))
		return 1;

	deg = &dev->state.degraded;
	if (*deg != val) {
		*deg = val;
		val ? ++muxfs_dev_array_degraded_count
		    : --muxfs_dev_array_degraded_count;
		if (muxfs_dev_state_write_fd(dev->state_fd, &dev->state))
			return 1;
	}

	return 0;
}

MUXFS int
muxfs_degraded_set(size_t dev_index)
{
	muxfs_alert("Degraded: %llu", dev_index);
	return muxfs_degraded_set_val(dev_index, 1);
}

MUXFS int
muxfs_degraded_clear(size_t dev_index)
{
	return muxfs_degraded_set_val(dev_index, 0);
}

MUXFS int
muxfs_meta_size_raw(size_t *size_out, enum muxfs_chk_alg_type alg)
{
	size_t chk_size, base_size;

	const size_t a = MUXFS_MEM_ALIGN;

	chk_size = muxfs_chk_size(alg);
	base_size = sizeof(struct muxfs_meta_header) + (2 * chk_size);

	*size_out = a * ((base_size / a) + ((base_size % a) ? 1 : 0));
	return 0;
}

MUXFS int
muxfs_meta_size(size_t *size_out, dind dev_index)
{
	struct muxfs_dev *dev;

	if (muxfs_dev_get(&dev, dev_index, 0))
		return 1;

	return muxfs_meta_size_raw(size_out, dev->conf.chk_alg_type);
}

MUXFS int
muxfs_meta_read(struct muxfs_meta *meta, dind dev_index, uint64_t ino)
{
	struct muxfs_dev *dev;
	size_t msz;
	ssize_t rdsz;
	struct muxfs_meta disk_meta;

	if (muxfs_dev_get(&dev, dev_index, 0))
		return 1;

	if (muxfs_meta_size(&msz, dev_index))
		return 1;

	rdsz = pread(dev->meta_fd, &disk_meta, msz, ino * msz);
	if (rdsz == -1)
		return 1;

	memcpy(meta, &disk_meta, msz);
	meta->header.flags = letoh64(disk_meta.header.flags);
	meta->header.eno = letoh64(disk_meta.header.eno);

	return (size_t)rdsz != msz;
}

MUXFS int
muxfs_meta_write_fd(int fd, const struct muxfs_meta *meta, uint64_t ino,
    size_t msz)
{
	struct muxfs_meta disk_meta;
	ssize_t wrsz;

	memcpy(&disk_meta, meta, msz);
	disk_meta.header.flags = htole64(meta->header.flags);
	disk_meta.header.eno = htole64(meta->header.eno);

	wrsz = pwrite(fd, &disk_meta, msz, ino * msz);
	if (wrsz == -1)
		return 1;

	return (size_t)wrsz != msz;
}

MUXFS int
muxfs_meta_write(const struct muxfs_meta *meta, dind dev_index, uint64_t ino)
{
	struct muxfs_dev *dev;
	size_t msz;

	if (muxfs_dev_get(&dev, dev_index, 0))
		return 1;

	if (muxfs_meta_size(&msz, dev_index))
		return 1;

	return muxfs_meta_write_fd(dev->meta_fd, meta, ino, msz);
}

MUXFS int
muxfs_assign_peek_next_eno(uint64_t *eno_out, dind dev_index)
{
	struct muxfs_dev *dev;
	struct stat st;

	const size_t asz = sizeof(struct muxfs_assign);

	if (muxfs_dev_get(&dev, dev_index, 0))
		return 1;

	if (fstat(dev->assign_fd, &st))
		return 1;
	if ((st.st_size % asz) != 0)
		return 1;

	*eno_out = st.st_size / asz;
	return 0;
}

MUXFS int
muxfs_assign_read(struct muxfs_assign *assign, dind dev_index, uint64_t eno)
{
	struct muxfs_dev *dev;
	ssize_t rdsz;
	struct muxfs_assign disk_assign;

	const size_t asz = sizeof(struct muxfs_assign);

	if (muxfs_dev_get(&dev, dev_index, 0))
		return 1;

	rdsz = pread(dev->assign_fd, &disk_assign, asz, eno * asz);
	if (rdsz == -1)
		return 1;

	assign->flags = letoh64(disk_assign.flags);
	assign->ino = letoh64(disk_assign.ino);

	return (size_t)rdsz != asz;
}

MUXFS int
muxfs_assign_write_fd(int fd, const struct muxfs_assign *assign, uint64_t eno)
{
	ssize_t wrsz;
	struct muxfs_assign disk_assign;

	const size_t asz = sizeof(struct muxfs_assign);

	disk_assign.flags = htole64(assign->flags);
	disk_assign.ino = htole64(assign->ino);

	wrsz = pwrite(fd, &disk_assign, asz, eno * asz);
	if (wrsz == -1)
		return 1;

	return (size_t)wrsz != asz;
}

MUXFS int
muxfs_assign_write(const struct muxfs_assign *assign, dind dev_index,
    uint64_t eno)
{
	struct muxfs_dev *dev;

	if (muxfs_dev_get(&dev, dev_index, 0))
		return 1;

	return muxfs_assign_write_fd(dev->assign_fd, assign, eno);
}

/*
 * Returns 2 if there is any sequence number mismatch, 1 on error, 0 otherwise.
 * Prints a message to stderr on mismatch.
 */
MUXFS int
muxfs_dev_seq_check(void)
{
	dind i, dev_count;
	uint64_t seq;
	time_t seq_zero_time;
	struct muxfs_dev *dev;
	char tbuf1[26], tbuf2[26];

	if ((dev_count = muxfs_dev_count()) == 0)
		return 0;
	if (muxfs_dev_get(&dev, 0, 0))
		return 1;
	seq_zero_time = dev->conf.seq_zero_time;
	seq = dev->state.seq;
	for (i = 1; i < dev_count; ++i) {
		if (muxfs_dev_get(&dev, i, 0))
			return 1;
		if ((dev->conf.seq_zero_time != seq_zero_time) ||
		    (dev->state.seq != seq)) {
			memset(tbuf1, 0, 26);
			memset(tbuf2, 0, 26);
			if (ctime_r(&seq_zero_time, tbuf1) == NULL)
				return 1;
			if (ctime_r(&dev->conf.seq_zero_time, tbuf2) == NULL)
				return 1;
			dprintf(2, "Error: Sequence number mismatch.\n");
			dprintf(2, "Index 0:\n");
			dprintf(2, "\tWas zero at: %s\n", tbuf1);
			dprintf(2, "\tCurrent value: %llu\n", seq);
			dprintf(2, "Index %lu:\n", i);
			dprintf(2, "\tWas zero at: %s\n", tbuf2);
			dprintf(2, "\tCurrent value: %llu\n", dev->state.seq);
			return 2;
		}
	}

	return 0;
}
