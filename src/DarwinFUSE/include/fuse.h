/*
 * DarwinFUSE — libfuse-compatible public API
 *
 * Drop-in replacement for macFUSE / OSXFUSE / libfuse on macOS.
 * Compatible with FUSE API version 26 (the subset used by TrueCrypt/Basalt).
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef DARWINFUSE_FUSE_H
#define DARWINFUSE_FUSE_H

#define FUSE_USE_VERSION 26

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>

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
 * Unused callbacks should be set to NULL.
 */
struct fuse_operations {
    int (*getattr)    (const char *, struct stat *);
    int (*readlink)   (const char *, char *, size_t);
    /* getdir — deprecated, was removed in FUSE 3.x */
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
    /* utime — deprecated */
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
 * Main entry point. Parses arguments, starts NFSv4 server, mounts,
 * and runs event loop. Blocks until the filesystem is unmounted.
 *
 * argc/argv: typically device_type, mount_point, -o options...
 *            (matches the calling convention in FuseService::Mount)
 * op:        filesystem callbacks
 * user_data: passed to op->init via conn_info
 *
 * Returns 0 on success, non-zero on failure.
 */
int fuse_main(int argc, char *argv[],
              const struct fuse_operations *op, void *user_data);

/*
 * Returns the FUSE context for the current request.
 * The uid/gid fields reflect the calling process's credentials
 * (extracted from NFS AUTH_SYS).
 */
struct fuse_context *fuse_get_context(void);

#ifdef __cplusplus
}
#endif

#endif /* DARWINFUSE_FUSE_H */
