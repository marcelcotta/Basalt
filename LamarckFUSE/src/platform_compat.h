/*
 * LamarckFUSE — platform compatibility layer (Windows-only)
 *
 * Provides POSIX-like APIs (socket abstraction, type definitions, etc.)
 * for Windows (Winsock2/Win32).
 *
 * On macOS/Linux, DarwinFUSE is used instead (separate directory).
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef LAMARCKFUSE_PLATFORM_COMPAT_H
#define LAMARCKFUSE_PLATFORM_COMPAT_H

/* ---- Windows ---- */

/* Must come before windows.h to get Winsock2 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

/* ---- Socket abstraction ---- */

typedef SOCKET sock_t;
#define INVALID_SOCK INVALID_SOCKET

static inline ssize_t sock_read(sock_t s, void *buf, size_t len)
{
    return recv(s, (char *)buf, (int)len, 0);
}

static inline ssize_t sock_write(sock_t s, const void *buf, size_t len)
{
    return send(s, (const char *)buf, (int)len, 0);
}

static inline void sock_close(sock_t s)
{
    if (s != INVALID_SOCKET)
        closesocket(s);
}

static inline int sock_set_nonblocking(sock_t s)
{
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode);
}

static inline int sock_error(void)
{
    return WSAGetLastError();
}

/* Map WSAPoll to poll-like interface */
#define poll_fd_t     WSAPOLLFD
#define POLL_IN       POLLIN
#define POLL_OUT      POLLOUT
#define POLL_ERR      POLLERR
#define POLL_HUP      POLLHUP
#define platform_poll WSAPoll

/* ---- POSIX type definitions ---- */
/*
 * MinGW provides pid_t, mode_t, dev_t, ssize_t, off_t via <sys/types.h>.
 * MSVC provides none of these. uid_t/gid_t are missing from both.
 */

/* uid_t and gid_t: missing from both MSVC and MinGW */
#ifndef _UID_T_DEFINED
typedef uint32_t uid_t;
#define _UID_T_DEFINED
#endif

#ifndef _GID_T_DEFINED
typedef uint32_t gid_t;
#define _GID_T_DEFINED
#endif

/* Types provided by MinGW but not MSVC */
#ifndef __MINGW32__

#ifndef _PID_T_DEFINED
typedef int pid_t;
#define _PID_T_DEFINED
#endif

#ifndef _MODE_T_DEFINED
typedef uint32_t mode_t;
#define _MODE_T_DEFINED
#endif

#ifndef _DEV_T_DEFINED
typedef uint32_t dev_t;
#define _DEV_T_DEFINED
#endif

#ifndef _SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#define _SSIZE_T_DEFINED
#endif

/* off_t: MSVC defines it as long (32-bit); we need 64-bit for FUSE */
#ifdef off_t
#undef off_t
#endif
#define off_t int64_t

#endif /* !__MINGW32__ */

/* ---- stat compatibility ---- */

/* Windows struct stat doesn't have st_blocks, st_blksize etc.
 * We define our own for FUSE callbacks. */
struct fuse_stat {
    dev_t     st_dev;
    uint64_t  st_ino;
    mode_t    st_mode;
    uint32_t  st_nlink;
    uid_t     st_uid;
    gid_t     st_gid;
    dev_t     st_rdev;
    int64_t   st_size;
    int64_t   st_atime;
    int64_t   st_mtime;
    int64_t   st_ctime;
    int32_t   st_blksize;
    int64_t   st_blocks;
};

/* ---- File mode macros ---- */
/* Define each individually — MinGW provides some but not all */

#ifndef S_IFMT
#define S_IFMT   0xF000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0xC000
#endif
#ifndef S_IFLNK
#define S_IFLNK  0xA000
#endif
#ifndef S_IFREG
#define S_IFREG  0x8000
#endif
#ifndef S_IFBLK
#define S_IFBLK  0x6000
#endif
#ifndef S_IFDIR
#define S_IFDIR  0x4000
#endif
#ifndef S_IFCHR
#define S_IFCHR  0x2000
#endif
#ifndef S_IFIFO
#define S_IFIFO  0x1000
#endif

#ifndef S_ISREG
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISCHR
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#endif
#ifndef S_ISBLK
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISLNK
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif

/* Permission bits */
#ifndef S_IRWXU
#define S_IRWXU 0700
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRWXG 0070
#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010
#define S_IRWXO 0007
#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001
#endif

/* Access mode checks */
#ifndef R_OK
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0
#endif

/* ---- Byte order (htonl/ntohl) ---- */

/* Winsock2 provides htonl/ntohl/htons/ntohs */

/* ---- Random number generation ---- */

static inline uint32_t platform_arc4random(void)
{
    uint32_t val;
    BCryptGenRandom(NULL, (PUCHAR)&val, sizeof(val),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return val;
}

#define arc4random platform_arc4random

/* ---- Wakeup pipe (TCP loopback socketpair) ---- */

/*
 * POSIX pipe() doesn't work with WSAPoll().
 * We create a TCP loopback socketpair instead.
 * fds[0] = read end, fds[1] = write end.
 * Returns 0 on success, -1 on error.
 */
static inline int platform_socketpair(sock_t fds[2])
{
    int addrlen;
    struct sockaddr_in addr;

    fds[0] = INVALID_SOCKET;
    fds[1] = INVALID_SOCKET;

    /* Create listener on loopback */
    sock_t listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  /* ephemeral */

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        goto fail;

    addrlen = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) < 0)
        goto fail;

    if (listen(listener, 1) < 0)
        goto fail;

    /* Connect */
    fds[1] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fds[1] == INVALID_SOCKET)
        goto fail;

    if (connect(fds[1], (struct sockaddr *)&addr, sizeof(addr)) < 0)
        goto fail;

    /* Accept */
    fds[0] = accept(listener, NULL, NULL);
    if (fds[0] == INVALID_SOCKET)
        goto fail;

    closesocket(listener);
    return 0;

fail:
    if (fds[0] != INVALID_SOCKET) closesocket(fds[0]);
    if (fds[1] != INVALID_SOCKET) closesocket(fds[1]);
    fds[0] = INVALID_SOCKET;
    fds[1] = INVALID_SOCKET;
    closesocket(listener);
    return -1;
}

/* ---- Thread-local storage ---- */

#ifdef __MINGW32__
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL __declspec(thread)
#endif

/* ---- getpid / getuid / getgid ---- */

static inline pid_t platform_getpid(void) { return (pid_t)GetCurrentProcessId(); }
static inline uid_t platform_getuid(void) { return 0; }
static inline gid_t platform_getgid(void) { return 0; }

#define getpid  platform_getpid
#define getuid  platform_getuid
#define getgid  platform_getgid

/* ---- Sleep ---- */

static inline void platform_usleep(unsigned int usec)
{
    Sleep(usec / 1000);
}

#endif /* LAMARCKFUSE_PLATFORM_COMPAT_H */
