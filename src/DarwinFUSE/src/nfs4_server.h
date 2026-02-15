/*
 * DarwinFUSE — NFSv4 TCP server lifecycle
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef DARWINFUSE_NFS4_SERVER_H
#define DARWINFUSE_NFS4_SERVER_H

#include <stdint.h>
#include <sys/types.h>

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

/* Opaque server state */
typedef struct darwinfuse_server darwinfuse_server_t;

/*
 * Create and bind the TCP server on 127.0.0.1 with an ephemeral port.
 * On success, sets *port to the bound port number and returns the server.
 * On failure, returns NULL.
 */
darwinfuse_server_t *nfs4_server_create(const darwinfuse_config_t *config,
                                         uint16_t *port);

/*
 * Run the NFS event loop. Blocks until the server is stopped
 * (via nfs4_server_stop or when all clients disconnect after mount).
 * Returns 0 on clean exit, -1 on error.
 */
int nfs4_server_run(darwinfuse_server_t *srv);

/*
 * Signal the server to stop (safe to call from signal handler).
 */
void nfs4_server_stop(darwinfuse_server_t *srv);

/*
 * Re-arm the server after stop so nfs4_server_run() can be called again.
 * Used after fork() to restart the event loop in the child process.
 */
void nfs4_server_restart(darwinfuse_server_t *srv);

/*
 * Destroy and free all server resources.
 */
void nfs4_server_destroy(darwinfuse_server_t *srv);

/*
 * Close all file descriptors that do NOT belong to the server.
 * Used after daemonizing to release inherited pipes/fds from the parent.
 * Keeps: listen_fd, wakeup_pipe, client fds, and stdin/stdout/stderr.
 */
void nfs4_server_close_inherited_fds(darwinfuse_server_t *srv);

/*
 * Close only inherited PIPE-type FDs (not regular files or sockets).
 * This is used by the daemon child to release Process::Execute's
 * exceptionPipe without closing the volume's file descriptor.
 * Keeps: server's wakeup_pipe, stdin/stdout/stderr, all non-pipe FDs.
 */
void nfs4_server_close_inherited_pipes(darwinfuse_server_t *srv);

#endif /* DARWINFUSE_NFS4_SERVER_H */
