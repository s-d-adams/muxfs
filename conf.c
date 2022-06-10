/* conf.c */
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid.h>

#include "muxfs.h"

/*
 * 2 decimals at most 10 digits long (the string length of the decimal
 * representation of UINT32_MAX), plus 2 dots, plus the length of "release".
 */
#define MUXFS_VERSION_STRING_LENTH_MAX ((2*10)+2+7)

/* 2^64 is about 1.8e10^19 */
#define MUXFS_DECIMAL_UINT64_LENGTH_MAX 20

struct muxfs_dev_conf_checklist {
	int has_version, has_alg, has_sign, has_uuid, has_array,
	    has_seq_zero_time;
};

static int
muxfs_conf_version_parse(struct muxfs_dev_conf *conf, const char *version,
                         size_t version_len)
{
	char *b, *e;
	size_t len, comp_count;
	uint32_t *comp;
	char version_string_buf[MUXFS_VERSION_STRING_LENTH_MAX + 1];
	const char *errstr;

	comp_count = 0;
	memset(version_string_buf, 0, MUXFS_VERSION_STRING_LENTH_MAX + 1);
	memcpy(version_string_buf, version, version_len);

	b = version_string_buf;
	while ((e = memchr(b, '.', version_len)) != NULL) {
		len = e - b;

		switch (comp_count) {
		case 0:
			comp = &conf->version.number;
			break;
		case 1:
			comp = &conf->version.revision;
			break;
		default:
			return 1;
		}
		++comp_count;
		
		*e = '\0';
		*comp = strtonum(b, 0, INT32_MAX, &errstr);
		if (errstr != NULL)
			return 1;
		
		version_len -= (len + 1);
		b = e + 1;
	}
	/*
	 * The version components listed in the conf file are separated by dots
	 * and we do not expect a final dot at the end so there is one more
	 * component to process.
	 */
	if (version_len == 0)
		return 1;
	len = version_len;

	if (strncmp("current", b, len))
		conf->version.flavor = VF_CURRENT;
	else if (strncmp("release", b, len))
		conf->version.flavor = VF_RELEASE;
	else if (strncmp("stable", b, len))
		conf->version.flavor = VF_STABLE;
	else
		return 1;

	return 0;
}

static int
muxfs_uuid_read(uint8_t *dest, const char *src, size_t len)
{
	char *str;
	uint32_t status;
	uuid_t uuid;

	str = calloc(len + 1, sizeof(char));
	if (str == NULL)
		return 1;

	memcpy(str, src, len);
	uuid_from_string(str, &uuid, &status);
	free(str);
	if (status != uuid_s_ok)
		return 1;

	uuid_enc_le(dest, &uuid);

	return 0;
}

static int
muxfs_conf_array_parse(struct muxfs_dev_conf *conf, const char *array,
                       size_t array_len)
{
	const char *b, *e;
	size_t len, i;
	uint8_t *uuid;

	b = array;
	while ((e = memchr(b, ',', array_len)) != NULL) {
		len = e - b;
		i = conf->expected_array_count++; 
		uuid = conf->expected_array_uuids[i];
		
		if (muxfs_uuid_read(uuid, b, len))
			return 1;
		
		array_len -= (len + 1);
		b = e + 1;
	}
	/*
	 * The UUIDs listed in the conf file are separated by commas and we do
	 * not expect a final comma at the end so there is one more UUID to
	 * process.
	 */
	if (array_len == 0)
		return 1;

	len = array_len;
	i = conf->expected_array_count++; 
	uuid = conf->expected_array_uuids[i];

	if (muxfs_uuid_read(uuid, b, len))
		return 1;

	return 0;
}

static int
muxfs_conf_line_parse(struct muxfs_dev_conf *conf, const char *line,
                      size_t len, struct muxfs_dev_conf_checklist *cl)
{
	const char *eq, *key, *val;
	size_t key_len, val_len;

	char seq_zero_time_buf[MUXFS_DECIMAL_UINT64_LENGTH_MAX + 1];
	const char *errstr;

	if ((eq = memchr(line, '=', len)) == NULL)
		return 1;

	key = line;
	key_len = eq - line;
	val = eq + 1;
	val_len = len - (key_len + 1);

	if (strncmp(key, "version", key_len) == 0) {
		if (muxfs_conf_version_parse(conf, val, val_len))
			return 1;
		cl->has_version = 1;
	} else if (strncmp(key, "chk_alg", key_len) == 0) {
		if (muxfs_chk_str_to_type(&conf->chk_alg_type, val, val_len))
			return 1;
		cl->has_alg = 1;
	} else if (strncmp(key, "sign", key_len) == 0) {
		if (strncmp(val, "y", val_len) == 0)
			conf->sign = 1;
		else if (strncmp(val, "n", val_len) == 0)
			conf->sign = 0;
		else
			return 1;
		cl->has_sign = 1;
	} else if (strncmp(key, "uuid", key_len) == 0) {
		if (muxfs_uuid_read(conf->uuid, val, val_len))
			return 1;
		cl->has_uuid = 1;
	} else if (strncmp(key, "array", key_len) == 0) {
		if (muxfs_conf_array_parse(conf, val, val_len))
			return 1;
		cl->has_array = 1;
	} else if (strncmp(key, "seq_zero_time", key_len) == 0) {
		if (val_len > MUXFS_DECIMAL_UINT64_LENGTH_MAX)
			return 1;
		memset(seq_zero_time_buf, 0,
		    MUXFS_DECIMAL_UINT64_LENGTH_MAX + 1);
		memcpy(seq_zero_time_buf, val, val_len);
		conf->seq_zero_time = strtonum(seq_zero_time_buf, 0,
		    INT64_MAX, &errstr);
		if (errstr != NULL)
			return 1;
		cl->has_seq_zero_time = 1;
	} else
		return 1;

	return 0;
}

static int
muxfs_conf_check(struct muxfs_dev_conf *conf,
                 struct muxfs_dev_conf_checklist cl)
{
	size_t i;
	uint32_t found;
	const uint8_t *uuid;

	if (!(cl.has_alg && cl.has_sign && cl.has_uuid && cl.has_array &&
	    cl.has_version && cl.has_seq_zero_time))
		return 1;

	if (conf->version.number != muxfs_program_version.number)
		return 1;

	if (conf->expected_array_count == 0)
		return 1;
	for (i = 0; i < conf->expected_array_count; ++i) {
		uuid = conf->expected_array_uuids[i];
		found = bcmp(conf->uuid, uuid, MUXFS_UUID_SIZE) == 0;
		if (found)
			break;
	}
	return found ? 0 : 1;
}

MUXFS int
muxfs_conf_parse(struct muxfs_dev_conf *conf, int fd)
{
	char buf[MUXFS_BLOCK_SIZE];
	ssize_t readsz, bufsz, linesz;
	char *eol;
	struct muxfs_dev_conf_checklist cl;

	memset(conf, 0, sizeof(*conf));

	memset(buf, 0, MUXFS_BLOCK_SIZE);
	bufsz = 0;
	while ((readsz = read(fd, buf + bufsz, MUXFS_BLOCK_SIZE - bufsz)) > 0) {
		if (readsz == -1)
			return 1;

		bufsz += readsz;
		while ((eol = memchr(buf, '\n', bufsz)) != NULL) {
			linesz = eol - buf;
			if (muxfs_conf_line_parse(conf, buf, linesz, &cl))
				return 1;
			memmove(buf, eol + 1, bufsz - (linesz + 1));
			bufsz -= (linesz + 1);
		}
		if (bufsz == MUXFS_BLOCK_SIZE) {
			/* The line is longer than the buffer. */
			return 1;
		}
	}
	if (bufsz > 0) {
		/* The last line doesn't end with a newline character. */
		return 1;
	}

	if (muxfs_conf_check(conf, cl))
		return 1;

	return 0;
}

static const char *
muxfs_version_flavor_str(enum muxfs_version_flavor flavor)
{
	switch (flavor) {
	case VF_CURRENT:
		return "current";
	case VF_RELEASE:
		return "release";
	case VF_STABLE:
		return "stable";
	}
	exit(-1); /* Programming error. */
}

MUXFS int
muxfs_conf_write(struct muxfs_dev_conf *conf, int fd)
{
	uuid_t uuid;
	char *uuid_str;
	uint32_t uuid_status;
	size_t i;

	if (ftruncate(fd, 0))
		return 1;

	dprintf(fd, "version=%u.%u.%s\n", conf->version.number,
	    conf->version.revision,
	    muxfs_version_flavor_str(conf->version.flavor));
	dprintf(fd, "chk_alg=%s\n",
	    muxfs_chk_type_to_str(conf->chk_alg_type));
	dprintf(fd, "sign=%s\n", conf->sign ? "y" : "n");

	uuid_dec_le(conf->uuid, &uuid);
	uuid_to_string(&uuid, &uuid_str, &uuid_status);
	if (uuid_status != uuid_s_ok)
		return 1;
	dprintf(fd, "uuid=%s\n", uuid_str);
	free(uuid_str);
	dprintf(fd, "array=");
	for (i = 0; i < conf->expected_array_count; ++i) {
		uuid_dec_le(conf->expected_array_uuids[i], &uuid);
		uuid_to_string(&uuid, &uuid_str, &uuid_status);
		if (uuid_status != uuid_s_ok)
			return 1;
		dprintf(fd, "%s", uuid_str);
		free(uuid_str);
		if ((i + 1) < conf->expected_array_count)
			dprintf(fd, ",");
	}
	dprintf(fd, "\n");

	dprintf(fd, "seq_zero_time=%llu\n", (uint64_t)conf->seq_zero_time);

	return 0;
}
