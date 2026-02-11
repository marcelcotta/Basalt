/*
 * LamarckFUSE — internal shared definitions
 *
 * Windows adaptation of DarwinFUSE's darwinfuse_internal.h.
 * Same constants, adapted logging paths and macros.
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef LAMARCKFUSE_INTERNAL_H
#define LAMARCKFUSE_INTERNAL_H

#include "platform_compat.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ---------- NFS constants (RFC 7530) ---------- */

#define NFS_PROGRAM         100003
#define NFS_V4              4
#define NFSPROC4_NULL       0
#define NFSPROC4_COMPOUND   1

/* ---------- ONC RPC constants (RFC 5531) ---------- */

#define RPC_MSG_VERSION     2
#define RPC_CALL            0
#define RPC_REPLY           1

/* Reply stat */
#define MSG_ACCEPTED        0
#define MSG_DENIED          1

/* Accept stat */
#define ACCEPT_SUCCESS      0
#define ACCEPT_PROG_UNAVAIL 1
#define ACCEPT_PROG_MISMATCH 2
#define ACCEPT_PROC_UNAVAIL 3
#define ACCEPT_GARBAGE_ARGS 4

/* Auth flavors */
#define AUTH_NONE           0
#define AUTH_SYS            1  /* AUTH_UNIX */

/* ---------- LamarckFUSE filehandle scheme ---------- */

/*
 * Same scheme as DarwinFUSE: small fixed filehandles for our
 * 3-entry virtual filesystem.
 */
#define LFUSE_FH_LEN        4
#define LFUSE_FH_ROOT       1
#define LFUSE_FH_VOLUME     2
#define LFUSE_FH_CONTROL    3

/* DarwinFUSE compatibility aliases */
#define DFUSE_FH_LEN        LFUSE_FH_LEN
#define DFUSE_FH_ROOT       LFUSE_FH_ROOT
#define DFUSE_FH_VOLUME     LFUSE_FH_VOLUME
#define DFUSE_FH_CONTROL    LFUSE_FH_CONTROL

/* ---------- Buffer sizes ---------- */

#define LFUSE_XDR_MAXBUF    (512 * 1024)
#define LFUSE_MAX_CLIENTS   8
#define LFUSE_READ_BUFSIZE  (256 * 1024)

/* DarwinFUSE compatibility aliases */
#define DFUSE_XDR_MAXBUF    LFUSE_XDR_MAXBUF
#define DFUSE_MAX_CLIENTS   LFUSE_MAX_CLIENTS
#define DFUSE_READ_BUFSIZE  LFUSE_READ_BUFSIZE

/* ---------- NFS port ---------- */

/*
 * Windows NFS client hardcodes port 2049 (no -o port= option).
 * LamarckFUSE must bind to this port.
 */
#define LAMARCKFUSE_NFS_PORT  2049

/* ---------- Logging ---------- */

#ifdef _WIN32

/*
 * On Windows, log to %TEMP%\lamarckfuse.log.
 * We use a helper to get the path since getenv isn't async-signal-safe
 * (but that doesn't matter on Windows — no signals).
 */
static inline const char *lfuse_log_path(void)
{
    static char path[MAX_PATH] = {0};
    if (path[0] == '\0') {
        const char *tmp = getenv("TEMP");
        if (!tmp) tmp = getenv("TMP");
        if (!tmp) tmp = "C:\\Windows\\Temp";
        snprintf(path, sizeof(path), "%s\\lamarckfuse.log", tmp);
    }
    return path;
}

#define LFUSE_LOG(fmt, ...) do { \
    FILE *_f = fopen(lfuse_log_path(), "a"); \
    if (_f) { fprintf(_f, "[LamarckFUSE] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[LamarckFUSE] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define LFUSE_ERR(fmt, ...) do { \
    FILE *_f = fopen(lfuse_log_path(), "a"); \
    if (_f) { fprintf(_f, "[LamarckFUSE ERROR] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[LamarckFUSE ERROR] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#else  /* POSIX */

#define LFUSE_LOG(fmt, ...) do { \
    FILE *_f = fopen("/tmp/lamarckfuse.log", "a"); \
    if (_f) { fprintf(_f, "[LamarckFUSE] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[LamarckFUSE] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define LFUSE_ERR(fmt, ...) do { \
    FILE *_f = fopen("/tmp/lamarckfuse.log", "a"); \
    if (_f) { fprintf(_f, "[LamarckFUSE ERROR] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[LamarckFUSE ERROR] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#endif /* _WIN32 */

/* DarwinFUSE compatibility aliases (so nfs4_ops.c compiles with minimal changes) */
#define DFUSE_LOG  LFUSE_LOG
#define DFUSE_ERR  LFUSE_ERR

#endif /* LAMARCKFUSE_INTERNAL_H */
