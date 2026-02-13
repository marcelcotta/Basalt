/*
 * LamarckFUSE — libfuse-compatible public API (Windows-only)
 *
 * FUSE API for Windows, compatible with FUSE API version 26
 * (the subset used by TrueCrypt/Basalt).
 *
 * Provides typedefs for uid_t, gid_t, mode_t, off_t, dev_t,
 * and a fuse_stat struct that maps to FUSE callbacks.
 *
 * On macOS/Linux, DarwinFUSE is used instead (separate directory).
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef LAMARCKFUSE_FUSE_H
#define LAMARCKFUSE_FUSE_H

#define FUSE_USE_VERSION 26

/* Pull in platform_compat.h for all type definitions */
#include "../src/platform_compat.h"

/* On Windows, struct stat for FUSE callbacks uses our fuse_stat */
/* fuse_stat is defined in platform_compat.h */

/* For FUSE callback signatures, we use struct stat — alias it */
#ifndef _FUSE_STAT_DEFINED
#define stat fuse_stat
#define _FUSE_STAT_DEFINED
#endif

/* statvfs — minimal definition for FUSE statfs callback */
#ifndef _STATVFS_DEFINED
struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    uint64_t      f_blocks;
    uint64_t      f_bfree;
    uint64_t      f_bavail;
    uint64_t      f_files;
    uint64_t      f_ffree;
    uint64_t      f_favail;
    unsigned long f_fsid;
    unsigned long f_flag;
    unsigned long f_namemax;
};
#define _STATVFS_DEFINED
#endif

/* flock — minimal definition for FUSE lock callback */
#ifndef _FLOCK_DEFINED
struct flock {
    short  l_type;
    short  l_whence;
    off_t  l_start;
    off_t  l_len;
    pid_t  l_pid;
};
#define _FLOCK_DEFINED
#endif

/* timespec — may not be defined in MSVC */
#ifndef _TIMESPEC_DEFINED
struct timespec {
    int64_t tv_sec;
    long    tv_nsec;
};
#define _TIMESPEC_DEFINED
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Data structures ---- */

struct fuse_file_info {
    int           flags;
    unsigned long fh_old;
    int           writepage;
    unsigned int  direct_io : 1;
    unsigned int  keep_cache : 1;
    unsigned int  flush : 1;
    unsigned int  nonseekable : 1;
    unsigned int  padding : 28;
    uint64_t      fh;
    uint64_t      lock_owner;
};

struct fuse_conn_info {
    unsigned proto_major;
    unsigned proto_minor;
    unsigned async_read;
    unsigned max_write;
    unsigned max_readahead;
    unsigned capable;
    unsigned want;
    unsigned reserved[25];
};

struct fuse_context {
    uid_t  uid;
    gid_t  gid;
    pid_t  pid;
    void  *private_data;
};

typedef int (*fuse_fill_dir_t)(void *buf, const char *name,
                                const struct stat *stbuf, off_t off);

/*
 * FUSE filesystem operations.
 * Field order matches libfuse 2.6 to ensure struct-layout compatibility.
 */
struct fuse_operations {
    int (*getattr)    (const char *, struct stat *);
    int (*readlink)   (const char *, char *, size_t);
    void *_deprecated_getdir;
    int (*mknod)      (const char *, mode_t, dev_t);
    int (*mkdir)      (const char *, mode_t);
    int (*unlink)     (const char *);
    int (*rmdir)      (const char *);
    int (*symlink)    (const char *, const char *);
    int (*rename)     (const char *, const char *);
    int (*link)       (const char *, const char *);
    int (*chmod)      (const char *, mode_t);
    int (*chown)      (const char *, uid_t, gid_t);
    int (*truncate)   (const char *, off_t);
    void *_deprecated_utime;
    int (*open)       (const char *, struct fuse_file_info *);
    int (*read)       (const char *, char *, size_t, off_t,
                       struct fuse_file_info *);
    int (*write)      (const char *, const char *, size_t, off_t,
                       struct fuse_file_info *);
    int (*statfs)     (const char *, struct statvfs *);
    int (*flush)      (const char *, struct fuse_file_info *);
    int (*release)    (const char *, struct fuse_file_info *);
    int (*fsync)      (const char *, int, struct fuse_file_info *);
    int (*setxattr)   (const char *, const char *, const char *, size_t, int);
    int (*getxattr)   (const char *, const char *, char *, size_t);
    int (*listxattr)  (const char *, char *, size_t);
    int (*removexattr)(const char *, const char *);
    int (*opendir)    (const char *, struct fuse_file_info *);
    int (*readdir)    (const char *, void *, fuse_fill_dir_t, off_t,
                       struct fuse_file_info *);
    int (*releasedir) (const char *, struct fuse_file_info *);
    int (*fsyncdir)   (const char *, int, struct fuse_file_info *);
    void *(*init)     (struct fuse_conn_info *);
    void (*destroy)   (void *);
    int (*access)     (const char *, int);
    int (*create)     (const char *, mode_t, struct fuse_file_info *);
    int (*ftruncate)  (const char *, off_t, struct fuse_file_info *);
    int (*fgetattr)   (const char *, struct stat *, struct fuse_file_info *);
    int (*lock)       (const char *, struct fuse_file_info *, int,
                       struct flock *);
    int (*utimens)    (const char *, const struct timespec tv[2]);
    int (*bmap)       (const char *, size_t, uint64_t *);
};

/* ---- API functions ---- */

/*
 * Main entry point. Mounts the filesystem.
 *
 * Non-blocking. Starts iSCSI target on 127.0.0.1:3260,
 * connects Windows iSCSI Initiator, assigns drive letter,
 * and returns immediately. Call fuse_teardown() to unmount.
 *
 * argc/argv: typically device_type, mount_point, -o options...
 * op:        filesystem callbacks (only init/destroy used)
 * user_data: passed to op->init
 *
 * Returns 0 on success, non-zero on failure.
 */
int fuse_main(int argc, char *argv[],
              const struct fuse_operations *op, void *user_data);

/*
 * Stop the iSCSI server, disconnect iSCSI session, and free all resources.
 * mount_point: the drive letter used in fuse_main (e.g. "Z:").
 */
void fuse_teardown(const char *mount_point);

/*
 * Returns the FUSE context for the current request.
 */
struct fuse_context *fuse_get_context(void);

#ifdef __cplusplus
}
#endif

#endif /* LAMARCKFUSE_FUSE_H */
