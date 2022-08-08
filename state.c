/* state.c */
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

#include <sys/types.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "ds.h"
#include "muxfs.h"

struct muxfs_restore_item {
	size_t dev_index;
	size_t path_len;
	char path[];
};

struct muxfs_state {
	struct muxfs_restore_item *restore_queue, *front, *back;
	size_t restore_queue_size;
	uint64_t next_eno;
	struct syslog_data log;
	int is_restore_only;
	dind restore_only_dind;
	struct muxfs_wrbuf wr;
};

static struct muxfs_state muxfs_global_state;

static size_t
muxfs_restore_item_next_offset(const char *path)
{
	size_t risz, path_len;

	const size_t szsz = sizeof(size_t);

	path_len = strlen(path);
	risz = sizeof(struct muxfs_restore_item) + path_len + 1;
	return szsz * ((risz / szsz) + ((risz % szsz) ? 1 : 0));
}

MUXFS int
muxfs_state_restore_push_back(dind dev_index, const char *path)
{
	struct muxfs_restore_item **q, *curr, *next;
	size_t *qsz, next_offset;

	muxfs_warn("Corrupted: %lu:/%s\n", dev_index, path);

	if (muxfs_global_state.is_restore_only &&
	    (dev_index != muxfs_global_state.restore_only_dind))
		return 0;

	q = &muxfs_global_state.restore_queue;
	qsz = &muxfs_global_state.restore_queue_size;
	curr = muxfs_global_state.back;
	next_offset = muxfs_restore_item_next_offset(path);
	next = (struct muxfs_restore_item *)(((uint8_t *)curr) + next_offset);

	while (next - *q < *qsz) {
		*qsz *= 2;
		if ((*q = realloc(*q, *qsz)) == NULL)
			exit(-1);
	}

	curr->dev_index = dev_index;
	curr->path_len = strlen(path);
	memcpy(curr->path, path, curr->path_len);
	curr->path[curr->path_len] = '\0';

	muxfs_global_state.back = next;

	return 0;
}

MUXFS int
muxfs_state_restore_next_path_len(size_t *path_len_out)
{
	struct muxfs_restore_item *curr;

	if (muxfs_global_state.front == muxfs_global_state.back)
		return 1;

	curr = muxfs_global_state.front;
	*path_len_out = curr->path_len;
	return 0;
}

MUXFS int
muxfs_state_restore_pop_front(size_t *dev_index_out, char *path_out)
{
	struct muxfs_restore_item *curr, *next;
	size_t next_offset, used, offset, halfq;
	uint8_t **u8front, **u8back, **u8queue;

	if (muxfs_global_state.front == muxfs_global_state.back)
		return 1;

	curr = muxfs_global_state.front;
	next_offset = muxfs_restore_item_next_offset(curr->path);
	next = (struct muxfs_restore_item *)(((uint8_t *)curr) + next_offset);

	*dev_index_out = curr->dev_index;
	memcpy(path_out, curr->path, curr->path_len);
	path_out[curr->path_len] = '\0';

	muxfs_global_state.front = next;

	/* Reuse the allocated memory rather than allocating more. */
	u8front = (uint8_t **)&muxfs_global_state.front;
	u8back = (uint8_t **)&muxfs_global_state.back;
	u8queue = (uint8_t **)&muxfs_global_state.restore_queue;
	used = (*u8back) - (*u8front);
	offset = (*u8front) - (*u8queue);
	halfq = muxfs_global_state.restore_queue_size / 2;
	if (used == 0)
		(*u8front) = (*u8back) = (*u8queue);
	else if ((used < halfq) && (offset > halfq)) {
		memmove(*u8queue, *u8front, used);
		(*u8front) = *u8queue;
		(*u8back) -= offset;
	}

	return 0;
}

MUXFS int
muxfs_state_restore_queue_init(void)
{
	struct muxfs_state *state;

	state = &muxfs_global_state;

	if ((state->restore_queue = malloc(sysconf(_SC_PAGESIZE))) == NULL)
		exit(-1);

	state->front = state->back = state->restore_queue;

	state->is_restore_only = 0;
	state->restore_only_dind = 0;

	return 0;
}

MUXFS void
muxfs_state_restore_queue_final(void)
{
	free(muxfs_global_state.restore_queue);
}

MUXFS int
muxfs_state_eno_next_init(uint64_t eno)
{
	muxfs_global_state.next_eno = eno;
	return 0;
}

MUXFS int
muxfs_state_eno_next_acquire(uint64_t *eno_out)
{
	uint64_t *ne;

	ne = &muxfs_global_state.next_eno;

	/* Using the largest possible value for an eno as the invalid value. */
	if (*ne == UINT64_MAX)
		return 1;

	*eno_out = (*ne)++;
	return 0;
}

MUXFS int
muxfs_state_eno_next_return(uint64_t eno)
{
	uint64_t *ne;

	/* Using the largest possible value for an eno as the invalid value. */
	if (eno == UINT64_MAX)
		exit(-1);

	ne = &muxfs_global_state.next_eno;
	if (*ne == 0)
		return 1;
	if (eno == (*ne) - 1)
		--(*ne);
	return 0;
}

MUXFS int
muxfs_state_syslog_init(void)
{
	muxfs_global_state.log = (struct syslog_data)SYSLOG_DATA_INIT;
	openlog_r("muxfs", LOG_PID|LOG_NDELAY, LOG_USER,
	    &muxfs_global_state.log);
	return 0;
}

MUXFS int
muxfs_state_syslog_final(void)
{
	closelog_r(&muxfs_global_state.log);
	return 0;
}

MUXFS void
muxfs_debug(const char *msg, ...)
{
	va_list va_args;

	va_start(va_args, msg);
	vsyslog_r(LOG_DEBUG, &muxfs_global_state.log, msg, va_args);
	va_end(va_args);
}

MUXFS void
muxfs_info(const char *msg, ...)
{
	va_list va_args;

	va_start(va_args, msg);
	vsyslog_r(LOG_INFO, &muxfs_global_state.log, msg, va_args);
	va_end(va_args);
}

MUXFS void
muxfs_warn(const char *msg, ...)
{
	va_list va_args;

	va_start(va_args, msg);
	vsyslog_r(LOG_WARNING, &muxfs_global_state.log, msg, va_args);
	va_end(va_args);
}

MUXFS void
muxfs_alert(const char *msg, ...)
{
	va_list va_args;

	va_start(va_args, msg);
	vsyslog_r(LOG_ALERT, &muxfs_global_state.log, msg, va_args);
	va_end(va_args);
}

/* Assumes that muxfs_dsinit() has already been called. */
MUXFS int
muxfs_init(int skip_first_mount)
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
		if (skip_first_mount && (i == 0))
			continue;
		if (muxfs_dev_mount(j, 0)) {
			dprintf(2, "Error: Unable to mount %s.\n",
			    args->dev_paths[i]);
			exit(1);
		}
		if (muxfs_assign_peek_next_eno(&next_eno, j))
			exit(-1);
		++mnts;
		if (next_eno > max_next_eno)
			max_next_eno = next_eno;
	}
	if (mnts == 0)
		exit(-1);

	if (muxfs_state_eno_next_init(max_next_eno))
		exit(-1);

	if (muxfs_state_wrbuf_reset())
		exit(-1);

	return 0;
}

MUXFS int
muxfs_final(void)
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

	return 0;
}

MUXFS int
muxfs_state_restore_only_set(dind dev_index)
{
	muxfs_global_state.restore_only_dind = dev_index;
	muxfs_global_state.is_restore_only = 1;
	return 0;
}

MUXFS int
muxfs_state_wrbuf_is_set(void)
{
	return muxfs_global_state.wr.path[0] != '\0';
}

MUXFS int
muxfs_state_wrbuf_reset(void)
{
	memset(&muxfs_global_state.wr, 0, sizeof(muxfs_global_state.wr));
	return 0;
}

MUXFS int
muxfs_state_wrbuf_set(const char *path, uid_t user, gid_t group, size_t sz,
    size_t off, const uint8_t *buf)
{
	struct muxfs_wrbuf *wrbuf;

	wrbuf = &muxfs_global_state.wr;

	if (muxfs_state_wrbuf_is_set())
		return 1;
	if (path == NULL)
		return 1;
	if (path[0] == '\0')
		return 1;
	if (strlen(path) >= PATH_MAX)
		return 1;
	if (sz > MUXFS_WRBUF_SIZE)
		return 1;
	if (buf == NULL)
		return 1;

	*wrbuf = (struct muxfs_wrbuf) {
		.wc = {
			.user = user,
			.group = group,
		},
		.sz = sz,
		.off = off,
	};
	strcpy(wrbuf->path, path);
	memcpy(wrbuf->buf, buf, sz);

	return 0;
}

MUXFS int
muxfs_state_wrbuf_append(size_t *wrsz_out, const char *path, uid_t user,
    gid_t group, size_t sz, size_t off, const uint8_t *buf)
{
	struct muxfs_wrbuf *wrbuf;

	wrbuf = &muxfs_global_state.wr;

	if (!muxfs_state_wrbuf_is_set())
		return 1;
	if (path == NULL)
		return 1;
	if (path[0] == '\0')
		return 1;
	if (strlen(path) >= PATH_MAX)
		return 1;
	if (strcmp(wrbuf->path, path) != 0)
		return 1;
	if (wrbuf->wc.user != user)
		return 1;
	if (wrbuf->wc.group != group)
		return 1;
	if (off != (wrbuf->off + wrbuf->sz))
		return 1;
	if (buf == NULL)
		return 1;
	if (wrsz_out == NULL)
		return 1;

	if ((wrbuf->sz + sz) > MUXFS_WRBUF_SIZE)
		sz = (MUXFS_WRBUF_SIZE - wrbuf->sz);
	memcpy(&wrbuf->buf[wrbuf->sz], buf, sz);
	wrbuf->sz += sz;
	*wrsz_out = sz;

	return 0;
}

MUXFS int
muxfs_state_wrbuf_get(const struct muxfs_wrbuf **wrbuf_out)
{
	if (!muxfs_state_wrbuf_is_set())
		return 1;
	*wrbuf_out = &muxfs_global_state.wr;
	return 0;
}
