/* state.c */
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

#include <sys/types.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

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
	openlog_r("muxfs", LOG_PID|LOG_NDELAY, LOG_DAEMON,
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
