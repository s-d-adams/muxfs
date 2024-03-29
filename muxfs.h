/* muxfs.h */
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

#ifndef _MUXFS_H_
#define _MUXFS_H_

#include <sys/syslimits.h>
#include <sys/types.h>

struct dirent;
struct stat;

/* Internal error.  Usually unrecoverable like ENOMEM. */
#define MUXFS_EINT 1
/* File system error.  For example ENOENT. */
#define MUXFS_EFS 2
/* Checksum error.  Used to indicate that a data integrity check has failed. */
#define MUXFS_ECHK 3

#define MUXFS_DEV_COUNT_MAX 64
#define MUXFS_CHKSZ_MAX 20
#define MUXFS_BLOCK_SIZE (4*1024)
#define MUXFS_MEM_ALIGN (sizeof(uint64_t))
#define MUXFS_UUID_SIZE 16
#define MUXFS_WRBUF_SIZE (1024*1024)

#define MUXFS_DT_REG 1u
#define MUXFS_DT_DIR 2u
#define MUXFS_DT_LNK 3u

/* chk.c */
struct muxfs_chk;
enum muxfs_chk_alg_type {
	CAT_CRC32,
	CAT_MD5  ,
	CAT_SHA1 ,
	CAT_NONE
};
MUXFS size_t muxfs_chk_size(enum muxfs_chk_alg_type);
MUXFS void muxfs_chk_init(struct muxfs_chk *, enum muxfs_chk_alg_type);
MUXFS void muxfs_chk_update(struct muxfs_chk *, const uint8_t *, size_t);
MUXFS void muxfs_chk_final(uint8_t *, struct muxfs_chk *);
MUXFS int muxfs_chk_str_to_type(enum muxfs_chk_alg_type *, const char *,
    size_t);
MUXFS const char *muxfs_chk_type_to_str(enum muxfs_chk_alg_type);

/* conf.c */
enum muxfs_version_flavor {
	VF_CURRENT,
	VF_RELEASE,
	VF_STABLE
};
struct muxfs_version {
	uint32_t	number,
			revision;
	enum		muxfs_version_flavor flavor;
};
struct muxfs_dev_conf {
	struct	muxfs_version version;
	enum	muxfs_chk_alg_type chk_alg_type;

	/* UUIDs are encoded as binary, little-endian. */
	uint8_t	array_uuid[MUXFS_UUID_SIZE];
	uint8_t	dev_uuid[MUXFS_UUID_SIZE];

	/* The epoch time at which the sequence number was last at value 0. */
	time_t  seq_zero_time;
};
MUXFS int muxfs_conf_parse(struct muxfs_dev_conf *, int);
MUXFS int muxfs_conf_write(struct muxfs_dev_conf *, int);

/* dev.c */
/*
 * In muxfs a 'device' is actually a directory that has been 'formatted' for
 * use by muxfs.  Do not conflate this with an actual block device, it is only
 * analogous to a block device insofar as one is used by a more conventional
 * filesystem.
 */
struct muxfs_dev_state {
	uint64_t	seq; /* Sequence number. */
	uint64_t	mounted;
	uint64_t	working;
	uint64_t	restoring;
	uint64_t	degraded;
};
MUXFS int muxfs_dev_state_write_fd(int, struct muxfs_dev_state *);

struct muxfs_dev {
	struct		 muxfs_dev_state state;
	int		 root_fd,
			 state_fd,
			 meta_fd,
			 assign_fd,
			 lfile_fd;
	const char	*root_path;
	struct		 muxfs_dev_conf conf;
	int		 attached_now,
			 mounted_now;
};

typedef size_t dind;
MUXFS void muxfs_dev_module_init(void);
MUXFS int  muxfs_dev_append(dind *dev_index_out, const char *);
MUXFS int  muxfs_dev_mount(dind, int);
MUXFS int  muxfs_dev_unmount(dind);
MUXFS int  muxfs_dev_is_mounted(dind);
MUXFS dind muxfs_dev_count(void);
MUXFS int  muxfs_dev_get(struct muxfs_dev **, dind, int);
MUXFS int  muxfs_dev_seq_check(void);

enum muxfs_meta_flag {
	MF_ASSIGNED = 0x1
};
struct muxfs_meta_header {
	uint64_t	flags;
	uint64_t	eno;
};
struct muxfs_meta {
	struct	muxfs_meta_header header;
	/*
	 * When stack-allocated this buffer guarantees enough space for the
	 * sums.  If the content of the metadata file is loaded and cast via
	 * pointer to this struct then care must be taken to avoid reading
	 * beyond the actual bounds of the metadata entry.  Similarly the whole
	 * of this buffer should not necessarily be written to the metadata
	 * file.  Use muxfs_meta_size() to compute the actual bounds of this
	 * struct, and muxfs_chk_size() to compute the offset of the content
	 * checksum.
	 */
	uint8_t	checksums[2 * MUXFS_CHKSZ_MAX];
};
MUXFS int muxfs_meta_size(size_t *, dind);
MUXFS int muxfs_meta_size_raw(size_t *, enum muxfs_chk_alg_type);
MUXFS int muxfs_meta_read(struct muxfs_meta *, dind, uint64_t);
MUXFS int muxfs_meta_write(const struct muxfs_meta *, dind, uint64_t);
MUXFS int muxfs_meta_write_fd(int, const struct muxfs_meta *, uint64_t, size_t);

enum muxfs_assign_flag {
	AF_ASSIGNED = 0x1
};
struct muxfs_assign {
	uint64_t	flags;
	uint64_t	ino;
};
MUXFS int muxfs_assign_peek_next_eno(uint64_t *, dind);
MUXFS int muxfs_assign_read(struct muxfs_assign *, dind, uint64_t);
MUXFS int muxfs_assign_write(const struct muxfs_assign *, dind, uint64_t);
MUXFS int muxfs_assign_write_fd(int, const struct muxfs_assign *, uint64_t);

MUXFS int muxfs_working_push(dind);
MUXFS int muxfs_working_pop(dind, time_t);

MUXFS int muxfs_restoring_push(dind);
MUXFS int muxfs_restoring_pop(dind);

MUXFS int muxfs_degraded_set(dind);
MUXFS int muxfs_degraded_clear(dind);

/* desc.c */
typedef uint64_t muxfs_desc_type;
struct muxfs_desc {
	uint64_t	eno;
	muxfs_desc_type	type;
	uint64_t	owner;
	uint64_t	group;
	uint64_t	mode;
	uint64_t	size;
	uint8_t		content_checksum[MUXFS_CHKSZ_MAX];
};
MUXFS int  muxfs_desc_type_from_mode(muxfs_desc_type *, mode_t);
MUXFS int  muxfs_desc_init_from_stat(struct muxfs_desc *, struct stat *,
    uint64_t);
MUXFS void muxfs_desc_chk_provided_content(struct muxfs_desc *, const uint8_t *,
    size_t, enum muxfs_chk_alg_type);
MUXFS int  muxfs_desc_chk_reg_content(struct muxfs_desc *, dind, const char *);
MUXFS int  muxfs_desc_chk_symlink_content(struct muxfs_desc *, dind,
    const char *);
MUXFS int  muxfs_desc_chk_node_content(struct muxfs_desc *, dind, const char *);
MUXFS void muxfs_desc_chk_meta(uint8_t *, const struct muxfs_desc *,
    enum muxfs_chk_alg_type);

/* format.c */
MUXFS int muxfs_dev_format(const char *, enum muxfs_chk_alg_type, size_t,
    size_t, time_t, const uint8_t *);
MUXFS int muxfs_format_main(int, char *[]);

/* lfile.c */
struct muxfs_range {
	size_t		byte_begin,
			byte_end,
			blk_begin,
			blk_end,
			lfilesz,
			lfileoff;
	uint64_t	blk_index_begin,
			blk_index_end;
};
MUXFS void muxfs_range_compute(struct muxfs_range *, size_t);
MUXFS int muxfs_lfile_open(int *, int, ino_t, int);
MUXFS int muxfs_lfile_create(int, size_t, ino_t, size_t);
MUXFS int muxfs_lfile_resize(int, size_t, ino_t, size_t, size_t);
MUXFS int muxfs_lfile_exists(int *, int, ino_t);
MUXFS int muxfs_lfile_delete(int, ino_t);
MUXFS int muxfs_lfile_ancestors_recompute(uint8_t *, int,
    enum muxfs_chk_alg_type, ino_t, size_t, uint64_t, uint64_t);
MUXFS int muxfs_lfile_readback(uint8_t *, dind, const char *, size_t, size_t,
    const uint8_t *);

/* mount.c */
MUXFS int muxfs_mount_main(int, char *[]);

/* scan.c */
enum muxfs_scan_mode {
	MUXFS_SCAN_AUDIT,
	MUXFS_SCAN_HEAL,
};
MUXFS int muxfs_scan_main(enum muxfs_scan_mode, int, char *[]);

/* state.c */
struct muxfs_wrctx {
	uid_t user;
	gid_t group;
};
struct muxfs_wrbuf {
	char path[PATH_MAX];
	struct muxfs_wrctx wc;
	size_t sz;
	size_t off;
	uint8_t buf[MUXFS_WRBUF_SIZE];
};
MUXFS int  muxfs_init(int);
MUXFS int  muxfs_final(void);
MUXFS int  muxfs_state_syslog_init(void);
MUXFS int  muxfs_state_syslog_final(void);
MUXFS void muxfs_debug(const char *, ...);
MUXFS void muxfs_info(const char *, ...);
MUXFS void muxfs_warn(const char *, ...);
MUXFS void muxfs_alert(const char *, ...);

MUXFS int  muxfs_state_restore_queue_init(void);
MUXFS void muxfs_state_restore_queue_final(void);
MUXFS int  muxfs_state_restore_only_set(dind);
MUXFS int  muxfs_state_restore_push_back(dind, const char *);
MUXFS int  muxfs_state_restore_next_path_len(size_t *);
MUXFS int  muxfs_state_restore_pop_front(dind *, char *);

MUXFS int muxfs_state_eno_next_init(uint64_t);
MUXFS int muxfs_state_eno_next_acquire(uint64_t *);
MUXFS int muxfs_state_eno_next_return(uint64_t);

MUXFS int muxfs_state_wrbuf_is_set(void);
MUXFS int muxfs_state_wrbuf_reset(void);
MUXFS int muxfs_state_wrbuf_set(const char *, uid_t, gid_t, size_t,
    size_t, const uint8_t *);
MUXFS int muxfs_state_wrbuf_append(size_t *, const char *, uid_t, gid_t,
    size_t, size_t, const uint8_t *);
MUXFS int muxfs_state_wrbuf_get(const struct muxfs_wrbuf **);

/* sync.c */
MUXFS int muxfs_sync_main(int, char *[]);

/* util.c */
enum muxfs_cud_type {
	MUXFS_CUD_CREATE,
	MUXFS_CUD_UPDATE,
	MUXFS_CUD_DELETE
};
struct muxfs_cud {
	enum muxfs_cud_type	 type;
	const char		*path,
				*fname;
	struct muxfs_meta	 pre_meta;
};
struct muxfs_dir {
	void *base;
	struct dirent **ent_array;
	size_t ent_count;
};
struct muxfs_args {
	char	mp_path[PATH_MAX];
	char	dev_paths[MUXFS_DEV_COUNT_MAX][PATH_MAX];
	size_t	dev_count;
	int f;
};
extern struct muxfs_args muxfs_cmdline;
MUXFS int muxfs_parse_args(int, char **, int);
MUXFS int muxfs_existsat(int *, int , const char *);
MUXFS int muxfs_removeat(int, const char *);
MUXFS int muxfs_dir_is_empty(int *, char const *);
MUXFS int muxfs_path_sanitize(const char **);
MUXFS int muxfs_path_pop(const char **, char *, size_t *);
MUXFS int muxfs_pushdir(struct muxfs_dir *, int, const char *);
MUXFS int muxfs_popdir(struct muxfs_dir *);
MUXFS int muxfs_readback(dind, const char *, int, const struct muxfs_meta *);
MUXFS int muxfs_parent_readback(dind, const char *);
MUXFS int muxfs_ancestors_meta_recompute(dind, struct muxfs_cud *);
MUXFS int muxfs_dir_meta_recompute(struct muxfs_cud *, dind,
    const struct muxfs_cud *);
MUXFS int muxfs_parent_gid(gid_t *, const char *);
MUXFS int muxfs_dir_content_chk(uint8_t *, dind, struct muxfs_dir *);
MUXFS size_t muxfs_align_up(size_t, size_t);
MUXFS size_t muxfs_align_down(size_t, size_t);
MUXFS void muxfs_restore_now(void);

/* version.c */
extern struct muxfs_version muxfs_program_version;
MUXFS void muxfs_version_print(void);

#endif /* _MUXFS_H_ */
