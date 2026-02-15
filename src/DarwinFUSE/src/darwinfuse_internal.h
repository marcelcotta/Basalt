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
 * Logging: write to /tmp/darwinfuse.log so logs survive the
 * Process::Execute stderr redirect in Basalt's FuseService.
 */
#define DFUSE_LOG(fmt, ...) do { \
    FILE *_f = fopen("/tmp/darwinfuse.log", "a"); \
    if (_f) { fprintf(_f, "[DarwinFUSE] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[DarwinFUSE] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define DFUSE_ERR(fmt, ...) do { \
    FILE *_f = fopen("/tmp/darwinfuse.log", "a"); \
    if (_f) { fprintf(_f, "[DarwinFUSE ERROR] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[DarwinFUSE ERROR] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#endif /* DARWINFUSE_INTERNAL_H */
