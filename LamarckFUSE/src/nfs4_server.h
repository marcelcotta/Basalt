/*
 * LamarckFUSE — NFSv4 TCP server lifecycle
 *
 * Adapted from DarwinFUSE: uses platform_compat.h for sock_t/uid_t/gid_t.
 * API is identical except for removed POSIX-only functions
 * (close_inherited_fds/pipes — not applicable on Windows).
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef LAMARCKFUSE_NFS4_SERVER_H
#define LAMARCKFUSE_NFS4_SERVER_H

#include "platform_compat.h"
#include <stdint.h>

/* Forward declaration */
struct fuse_operations;

/* Server configuration passed from fuse_main shim */
typedef struct {
    const struct fuse_operations *ops;
    void       *user_data;
    uid_t       uid;            /* Owner UID (for access control) */
    gid_t       gid;            /* Owner GID */
    const char *volume_path;    /* e.g. "/volume.dmg" or "/volume" */
    const char *control_path;   /* "/control" */
} darwinfuse_config_t;

/* LamarckFUSE compatibility alias */
typedef darwinfuse_config_t lamarckfuse_config_t;

/* Opaque server state */
typedef struct lamarckfuse_server lamarckfuse_server_t;

/* DarwinFUSE compatibility aliases */
typedef lamarckfuse_server_t darwinfuse_server_t;

/*
 * Create and bind the TCP server on 127.0.0.1.
 * On Windows: binds to port 2049 (required by Windows NFS client).
 * On POSIX: binds to an ephemeral port.
 * On success, sets *port to the bound port number and returns the server.
 * On failure, returns NULL.
 */
lamarckfuse_server_t *nfs4_server_create(const lamarckfuse_config_t *config,
                                          uint16_t *port);

/*
 * Run the NFS event loop. Blocks until the server is stopped
 * (via nfs4_server_stop or when all clients disconnect after mount).
 * Returns 0 on clean exit, -1 on error.
 */
int nfs4_server_run(lamarckfuse_server_t *srv);

/*
 * Signal the server to stop (safe to call from any thread or signal handler).
 */
void nfs4_server_stop(lamarckfuse_server_t *srv);

/*
 * Re-arm the server after stop so nfs4_server_run() can be called again.
 * Used on POSIX after fork() to restart the event loop in the child process.
 * On Windows this is a no-op (no fork).
 */
void nfs4_server_restart(lamarckfuse_server_t *srv);

/*
 * Destroy and free all server resources.
 */
void nfs4_server_destroy(lamarckfuse_server_t *srv);

#ifndef _WIN32
/*
 * Close all file descriptors that do NOT belong to the server.
 * Used after daemonizing to release inherited pipes/fds from the parent.
 * POSIX only — not applicable on Windows.
 */
void nfs4_server_close_inherited_fds(lamarckfuse_server_t *srv);

/*
 * Close only inherited PIPE-type FDs (not regular files or sockets).
 * POSIX only — not applicable on Windows.
 */
void nfs4_server_close_inherited_pipes(lamarckfuse_server_t *srv);
#endif

#endif /* LAMARCKFUSE_NFS4_SERVER_H */
