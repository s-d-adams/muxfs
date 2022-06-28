/* newfs_muxfs.c */
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

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid.h>

#include "ds.h"
#include "muxfs.h"

#include "gen.h"

static const char *sepdotmuxfs = "/.muxfs";
static const char *sepmuxfsdotconf = "/muxfs.conf";
static const char *sepstatedotdb = "/state.db";
static const char *sepmetadotdb = "/meta.db";
static const char *sepassigndotdb = "/assign.db";
static const char *seplfile = "/lfile";

static void
muxfs_newfs_usage(void)
{
	fprintf(stderr, "usage: newfs_muxfs [-a checksum_algorithm ] "
	    "[[-d directory ] ...]\n");
}

static int
muxfs_dir_is_empty(int *empty_out, char const *path)
{
	struct muxfs_dir dir;
	size_t i, dnamelen;
	const char *dname;
	struct dirent *dirent;
	int empty;

	if (muxfs_pushdir(&dir, AT_FDCWD, path))
		return 1;

	empty = 1;
	for (i = 0; i < dir.ent_count; ++i) {
		dirent = dir.ent_array[i];
		dname = dirent->d_name;
		dnamelen = dirent->d_namlen;
		if ((dnamelen == 1) && (strncmp(".", dname, 1) == 0))
			continue;
		if ((dnamelen == 2) && (strncmp("..", dname, 1) == 0))
			continue;
		empty = 0;
		break;
	}

	if (muxfs_popdir(&dir))
		exit(-1);

	*empty_out = empty;
	return 0;
}

int
main(int argc, char *argv[])
{
	int rc, c;
	enum muxfs_chk_alg_type alg;
	char dev_roots[MUXFS_DEV_COUNT_MAX][PATH_MAX];
	char path_buf[PATH_MAX];
	size_t dev_root_count, len, i, j;
	int empty;
	struct muxfs_dev_conf confs[MUXFS_DEV_COUNT_MAX];
	time_t now;
	uuid_t uuid;
	uint32_t uuid_status;
	int fd;
	size_t chksz, metasz;
	uint64_t eno;
	struct muxfs_dev_state dstate;
	struct stat st;
	ino_t ino;
	struct muxfs_desc desc;
	struct muxfs_chk chk;
	struct muxfs_meta meta;
	struct muxfs_assign assign;

	if (muxfs_dsinit())
		return -1;

	rc = 1;
	alg = CAT_MD5;
	memset(dev_roots, 0, MUXFS_DEV_COUNT_MAX * PATH_MAX);
	dev_root_count = 0;

	c = 0;
	while ((c = getopt(argc, argv, "a:d:")) != -1) {
		switch (c) {
		case 'a':
			if (muxfs_chk_str_to_type(&alg, optarg,
			    strlen(optarg)))
				goto out;
			break;
		case 'd':
			len = strlen(optarg);
			if (len >= PATH_MAX)
				goto out;
			memcpy(dev_roots[dev_root_count++], optarg, len);
			break;
		default:
			muxfs_newfs_usage();
			exit(-1);
		}
	}
	argc -= optind;
	argv += optind;

	empty = 0;
	for (i = 0; i < dev_root_count; ++i) {
		if (muxfs_dir_is_empty(&empty, dev_roots[i]))
			goto out;
		if (!empty) {
			fprintf(stderr, "Error: Directory \"%s\" is not "
			    "empty.\n", dev_roots[i]);
			goto out;
		}
	}
	for (i = 0; i < dev_root_count; ++i) {
		if (strlen(dev_roots[i]) + strlen(sepdotmuxfs) >= PATH_MAX)
			goto out;
		memset(path_buf, 0, PATH_MAX);
		strcat(path_buf, dev_roots[i]);
		strcat(path_buf, sepdotmuxfs);
		if (mkdir(path_buf, 0700))
			goto out;
	}
	now = time(NULL);
	for (i = 0; i < dev_root_count; ++i) {
		confs[i] = (struct muxfs_dev_conf) {
			.version = muxfs_program_version,
			.chk_alg_type = alg,
			.expected_array_count = dev_root_count,
			.seq_zero_time = now,
		};
	}
	for (i = 0; i < dev_root_count; ++i) {
		uuid_create(&uuid, &uuid_status);
		if (uuid_status != uuid_s_ok)
			goto out;
		uuid_enc_le(confs[i].uuid, &uuid);
		for (j = 0; j < dev_root_count; ++j) {
			memcpy(confs[j].expected_array_uuids[i], confs[i].uuid,
			    MUXFS_UUID_SIZE);
		}
	}

	chksz = muxfs_chk_size(alg);
	if (muxfs_meta_size_raw(&metasz, alg))
		goto out;
	eno = 0;
	for (i = 0; i < dev_root_count; ++i) {
		if (strlen(dev_roots[i]) + strlen(sepdotmuxfs) +
		    strlen(sepmuxfsdotconf) >= PATH_MAX)
			goto out;
		memset(path_buf, 0, PATH_MAX);
		strcat(path_buf, dev_roots[i]);
		strcat(path_buf, sepdotmuxfs);
		strcat(path_buf, sepmuxfsdotconf);
		if ((fd = open(path_buf, O_RDWR|O_CREAT|O_EXCL, 0700)) == -1)
			goto out;
		if (muxfs_conf_write(&confs[i], fd)) {
			if (close(fd))
				exit(-1);
			goto out;
		}
		if (close(fd))
			exit(-1);

		dstate = (struct muxfs_dev_state) {
			.mounted = 0,
			.working = 0,
			.degraded = 0,
			.seq = 0,
		};
		if (strlen(dev_roots[i]) + strlen(sepdotmuxfs) +
		    strlen(sepstatedotdb) >= PATH_MAX)
			goto out;
		memset(path_buf, 0, PATH_MAX);
		strcat(path_buf, dev_roots[i]);
		strcat(path_buf, sepdotmuxfs);
		strcat(path_buf, sepstatedotdb);
		if ((fd = open(path_buf, O_RDWR|O_CREAT|O_EXCL, 0700)) == -1)
			goto out;
		if (muxfs_dev_state_write_fd(fd, &dstate)) {
			if (close(fd))
				exit(-1);
			goto out;
		}
		if (close(fd))
			exit(-1);
			
		memset(path_buf, 0, PATH_MAX);
		strcat(path_buf, dev_roots[i]);
		if (stat(path_buf, &st))
			goto out;
		ino = st.st_ino;
		if (muxfs_desc_init_from_stat(&desc, &st, eno))
			goto out;
		muxfs_chk_init(&chk, alg);
		muxfs_chk_final(desc.content_checksum, &chk);
		meta = (struct muxfs_meta) {
			.header = (struct muxfs_meta_header) {
				.flags = MF_ASSIGNED,
				.eno = eno,
			},
		};
		memcpy(&meta.checksums[chksz], desc.content_checksum, chksz);
		muxfs_desc_chk_meta(&meta.checksums[0], &desc, alg);
		if (strlen(dev_roots[i]) + strlen(sepdotmuxfs) +
		    strlen(sepmetadotdb) >= PATH_MAX)
			goto out;
		strcat(path_buf, sepdotmuxfs);
		strcat(path_buf, sepmetadotdb);
		if ((fd = open(path_buf, O_RDWR|O_CREAT|O_EXCL, 0700)) == -1)
			goto out;
		if (muxfs_meta_write_fd(fd, &meta, ino, metasz)) {
			if (close(fd))
				exit(-1);
			goto out;
		}
		if (close(fd))
			exit(-1);

		assign = (struct muxfs_assign) {
			.flags = AF_ASSIGNED,
			.ino = ino,
		};
		if (strlen(dev_roots[i]) + strlen(sepdotmuxfs) +
		    strlen(sepassigndotdb) >= PATH_MAX)
			goto out;
		memset(path_buf, 0, PATH_MAX);
		strcat(path_buf, dev_roots[i]);
		strcat(path_buf, sepdotmuxfs);
		strcat(path_buf, sepassigndotdb);
		if ((fd = open(path_buf, O_RDWR|O_CREAT|O_EXCL, 0700)) == -1)
			goto out;
		if (muxfs_assign_write_fd(fd, &assign, eno)) {
			if (close(fd))
				exit(-1);
			goto out;
		}
		if (close(fd))
			exit(-1);

		if (strlen(dev_roots[i]) + strlen(sepdotmuxfs) +
		    strlen(seplfile) >= PATH_MAX)
			goto out;
		memset(path_buf, 0, PATH_MAX);
		strcat(path_buf, dev_roots[i]);
		strcat(path_buf, sepdotmuxfs);
		strcat(path_buf, seplfile);
		if (mkdir(path_buf, 0700))
			goto out;
	}

	rc = 0;
out:
	if (muxfs_dsfinal())
		return -1;
	return rc;
}
