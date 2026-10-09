/*
 * DarwinFUSE — internal shared definitions
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef DARWINFUSE_INTERNAL_H
#define DARWINFUSE_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
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

/* ---------- DarwinFUSE filehandle scheme ---------- */

/*
 * We use small fixed filehandles for our 3-entry virtual filesystem.
 * Each FH is 4 bytes containing a uint32.
 */
#define DFUSE_FH_LEN        4
#define DFUSE_FH_ROOT       1
#define DFUSE_FH_VOLUME     2
#define DFUSE_FH_CONTROL    3

/* ---------- Buffer sizes ---------- */

#define DFUSE_XDR_MAXBUF    (512 * 1024)
#define DFUSE_MAX_CLIENTS   8
#define DFUSE_READ_BUFSIZE  (256 * 1024)

/* ---------- Logging ---------- */

/*
 * Logging never writes files by default: mount points, NFS operations and
 * file names must not leave traces on disk, and a fixed path in /tmp would
 * allow symlink attacks when running as root.
 *
 *   DFUSE_ERR  always goes to stderr (redirected to /dev/null once the
 *              daemon detaches).
 *   DFUSE_LOG  is compiled out unless DFUSE_DEBUG_LOG is defined.
 *
 * For debugging, build with -DDFUSE_DEBUG_LOG and optionally
 * -DDFUSE_LOG_FILE='"/path/to/log"' (opened with O_NOFOLLOW, mode 0600).
 */
void dfuse_logf(int is_error, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#ifdef DFUSE_DEBUG_LOG
#define DFUSE_LOG(fmt, ...) dfuse_logf(0, fmt, ##__VA_ARGS__)
#else
#define DFUSE_LOG(fmt, ...) do { if (0) dfuse_logf(0, fmt, ##__VA_ARGS__); } while (0)
#endif

#define DFUSE_ERR(fmt, ...) dfuse_logf(1, fmt, ##__VA_ARGS__)

#endif /* DARWINFUSE_INTERNAL_H */
