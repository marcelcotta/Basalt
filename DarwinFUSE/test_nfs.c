/*
 * Minimal test: start DarwinFUSE NFSv4 server and try mounting.
 * Run as root: sudo ./test_nfs /tmp/dfuse_test
 *
 * This creates a simple virtual filesystem with one file (/hello.txt)
 * and mounts it via NFS. Press Ctrl-C to unmount and exit.
 */

#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char *hello_content = "Hello from DarwinFUSE NFSv4!\n";

static int test_getattr(const char *path, struct stat *st)
{
    memset(st, 0, sizeof(*st));
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = st->st_mtime = st->st_ctime = time(NULL);

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    if (strcmp(path, "/hello.txt") == 0) {
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = (off_t)strlen(hello_content);
        return 0;
    }
    return -ENOENT;
}

static int test_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    (void)offset; (void)fi;
    if (strcmp(path, "/") != 0) return -ENOENT;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, "hello.txt", NULL, 0);
    return 0;
}

static int test_open(const char *path, struct fuse_file_info *fi)
{
    if (strcmp(path, "/hello.txt") != 0) return -ENOENT;
    return 0;
}

static int test_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, "/hello.txt") != 0) return -ENOENT;
    size_t len = strlen(hello_content);
    if ((size_t)offset >= len) return 0;
    if (offset + size > len) size = len - (size_t)offset;
    memcpy(buf, hello_content + offset, size);
    return (int)size;
}

static int test_access(const char *path, int mask)
{
    (void)mask;
    if (strcmp(path, "/") == 0 || strcmp(path, "/hello.txt") == 0)
        return 0;
    return -ENOENT;
}

static void *test_init(struct fuse_conn_info *conn)
{
    (void)conn;
    fprintf(stderr, "[test] init called\n");
    return NULL;
}

static void test_destroy(void *userdata)
{
    (void)userdata;
    fprintf(stderr, "[test] destroy called\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: sudo %s <mount_point>\n", argv[0]);
        return 1;
    }

    /* Create mount point if needed */
    mkdir(argv[1], 0755);

    static struct fuse_operations ops;
    memset(&ops, 0, sizeof(ops));
    ops.getattr = test_getattr;
    ops.readdir = test_readdir;
    ops.open    = test_open;
    ops.read    = test_read;
    ops.access  = test_access;
    ops.init    = test_init;
    ops.destroy = test_destroy;

    /* Build fuse-style argv: ["test_nfs", mountpoint] */
    char *fuse_argv[] = { argv[0], argv[1], NULL };
    int fuse_argc = 2;

    fprintf(stderr, "[test] Starting DarwinFUSE on %s\n", argv[1]);
    int rc = fuse_main(fuse_argc, fuse_argv, &ops, NULL);
    fprintf(stderr, "[test] fuse_main returned %d\n", rc);
    return rc;
}
