/*
 * DarwinFUSE — NFSv4 TCP server
 *
 * Single-threaded poll()-based event loop serving NFSv4 COMPOUND requests
 * over TCP on localhost. Designed for the simple use case of a FUSE
 * filesystem replacement where only the macOS NFS client connects.
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#include "nfs4_server.h"
#include "nfs4_ops.h"
#include "nfs4_xdr.h"
#include "rpc.h"
#include "darwinfuse_internal.h"
#include "fuse_context.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ---- Client connection ---- */

typedef enum {
    CLIENT_STATE_READ_MARK,     /* Reading 4-byte record mark */
    CLIENT_STATE_READ_PAYLOAD   /* Reading payload bytes */
} client_read_state_t;

typedef struct {
    int                 fd;
    client_read_state_t read_state;
    uint8_t             mark_buf[4];
    size_t              mark_read;      /* bytes of record mark read so far */
    uint8_t            *payload_buf;
    size_t              payload_len;    /* expected payload length */
    size_t              payload_read;   /* bytes of payload read so far */
    int                 last_fragment;
    nfs4_conn_state_t   nfs_state;
} client_conn_t;

/* ---- Server state ---- */

struct darwinfuse_server {
    darwinfuse_config_t config;
    int                 listen_fd;
    int                 wakeup_pipe[2]; /* self-pipe for stop signal */
    volatile int        running;
    int                 had_client;     /* true once a client connected */

    client_conn_t       clients[DFUSE_MAX_CLIENTS];
    int                 num_clients;
};

/* ---- Helpers ---- */

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_tcp_nodelay(int fd)
{
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static void client_init(client_conn_t *c, int fd)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->read_state = CLIENT_STATE_READ_MARK;
}

static void client_close(client_conn_t *c)
{
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    free(c->payload_buf);
    c->payload_buf = NULL;
}

/* Process one complete RPC message from a client */
static int handle_rpc_message(darwinfuse_server_t *srv, client_conn_t *c)
{
    /* Decode RPC call */
    xdr_buf_t req;
    xdr_init(&req, c->payload_buf, c->payload_len);

    rpc_call_header_t rpc_hdr;
    if (rpc_parse_call(&req, &rpc_hdr) < 0) {
        DFUSE_ERR("Failed to parse RPC call");
        return -1;
    }

    /* Prepare reply buffer (record mark placeholder + RPC + NFS reply) */
    uint8_t *reply_buf = malloc(DFUSE_XDR_MAXBUF + 4);
    if (!reply_buf)
        return -1;

    xdr_buf_t rep;
    xdr_init(&rep, reply_buf + 4, DFUSE_XDR_MAXBUF);  /* leave 4 bytes for record mark */

    /* Check NFS program and version */
    if (rpc_hdr.program != NFS_PROGRAM) {
        rpc_encode_reply_error(&rep, rpc_hdr.xid, ACCEPT_PROG_UNAVAIL);
    } else if (rpc_hdr.version != NFS_V4) {
        rpc_encode_reply_error(&rep, rpc_hdr.xid, ACCEPT_PROG_MISMATCH);
    } else if (rpc_hdr.procedure == NFSPROC4_NULL) {
        /* NULL procedure — just reply with success (empty body) */
        rpc_encode_reply_accepted(&rep, rpc_hdr.xid);
    } else if (rpc_hdr.procedure == NFSPROC4_COMPOUND) {
        /* Set FUSE context from RPC credentials */
        darwinfuse_set_context(rpc_hdr.cred_uid, rpc_hdr.cred_gid);

        /* Encode RPC reply header */
        rpc_encode_reply_accepted(&rep, rpc_hdr.xid);

        /* Dispatch COMPOUND */
        if (nfs4_dispatch_compound(&srv->config, &c->nfs_state,
                                    &req, &rep) < 0) {
            DFUSE_ERR("COMPOUND dispatch failed");
            free(reply_buf);
            return -1;
        }
    } else {
        rpc_encode_reply_error(&rep, rpc_hdr.xid, ACCEPT_PROC_UNAVAIL);
    }

    /* Send reply with TCP record marking */
    uint32_t reply_len = (uint32_t)xdr_getpos(&rep);
    rpc_encode_record_mark(reply_buf, reply_len, 1);

    /* Write entire reply (reply_buf has 4 bytes record mark + reply_len payload) */
    size_t total = 4 + reply_len;
    size_t written = 0;
    while (written < total) {
        ssize_t n = write(c->fd, reply_buf + written, total - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* For simplicity, busy-wait briefly on non-blocking socket */
                usleep(100);
                continue;
            }
            DFUSE_ERR("write failed: %s", strerror(errno));
            free(reply_buf);
            return -1;
        }
        written += (size_t)n;
    }

    free(reply_buf);
    return 0;
}

/* Read available data for a client. Returns 0 if OK, -1 if client should be closed. */
static int client_read(darwinfuse_server_t *srv, client_conn_t *c)
{
    for (;;) {
        if (c->read_state == CLIENT_STATE_READ_MARK) {
            /* Read the 4-byte TCP record mark */
            size_t need = 4 - c->mark_read;
            ssize_t n = read(c->fd, c->mark_buf + c->mark_read, need);
            if (n == 0) return -1;  /* client disconnected */
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
                return -1;
            }
            c->mark_read += (size_t)n;
            if (c->mark_read < 4)
                return 0;

            /* Parse record mark */
            c->payload_len = rpc_parse_record_mark(c->mark_buf, &c->last_fragment);
            if (c->payload_len == 0 || c->payload_len > DFUSE_XDR_MAXBUF) {
                DFUSE_ERR("Invalid record mark length: %zu", c->payload_len);
                return -1;
            }

            c->payload_buf = malloc(c->payload_len);
            if (!c->payload_buf) return -1;
            c->payload_read = 0;
            c->read_state = CLIENT_STATE_READ_PAYLOAD;
        }

        if (c->read_state == CLIENT_STATE_READ_PAYLOAD) {
            size_t need = c->payload_len - c->payload_read;
            ssize_t n = read(c->fd, c->payload_buf + c->payload_read, need);
            if (n == 0) return -1;
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
                return -1;
            }
            c->payload_read += (size_t)n;
            if (c->payload_read < c->payload_len)
                return 0;

            /* Complete message received — process it */
            int rc = handle_rpc_message(srv, c);

            /* Reset for next message */
            free(c->payload_buf);
            c->payload_buf = NULL;
            c->payload_len = 0;
            c->payload_read = 0;
            c->mark_read = 0;
            c->read_state = CLIENT_STATE_READ_MARK;

            if (rc < 0)
                return -1;
        }
    }
}

/* ---- Public API ---- */

darwinfuse_server_t *nfs4_server_create(const darwinfuse_config_t *config,
                                         uint16_t *port)
{
    darwinfuse_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;

    srv->config = *config;
    srv->listen_fd = -1;
    srv->wakeup_pipe[0] = -1;
    srv->wakeup_pipe[1] = -1;

    /* Self-pipe for stop signaling */
    if (pipe(srv->wakeup_pipe) < 0) {
        free(srv);
        return NULL;
    }
    set_nonblocking(srv->wakeup_pipe[0]);
    set_nonblocking(srv->wakeup_pipe[1]);

    /* Create TCP listen socket */
    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) {
        DFUSE_ERR("socket: %s", strerror(errno));
        goto fail;
    }

    int reuse = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  /* ephemeral port */

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DFUSE_ERR("bind: %s", strerror(errno));
        goto fail;
    }

    if (listen(srv->listen_fd, 5) < 0) {
        DFUSE_ERR("listen: %s", strerror(errno));
        goto fail;
    }

    /* Retrieve the assigned port */
    socklen_t addrlen = sizeof(addr);
    if (getsockname(srv->listen_fd, (struct sockaddr *)&addr, &addrlen) < 0) {
        DFUSE_ERR("getsockname: %s", strerror(errno));
        goto fail;
    }
    *port = ntohs(addr.sin_port);

    set_nonblocking(srv->listen_fd);
    srv->running = 1;

    DFUSE_LOG("NFS server listening on 127.0.0.1:%u", *port);
    return srv;

fail:
    if (srv->listen_fd >= 0) close(srv->listen_fd);
    if (srv->wakeup_pipe[0] >= 0) close(srv->wakeup_pipe[0]);
    if (srv->wakeup_pipe[1] >= 0) close(srv->wakeup_pipe[1]);
    free(srv);
    return NULL;
}

int nfs4_server_run(darwinfuse_server_t *srv)
{
    /* pollfd layout: [0] = listen_fd, [1] = wakeup_pipe, [2..N+1] = clients */
    struct pollfd pfds[2 + DFUSE_MAX_CLIENTS];

    while (srv->running) {
        int nfds = 0;

        /* Listen socket */
        pfds[nfds].fd = srv->listen_fd;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;

        /* Wakeup pipe */
        pfds[nfds].fd = srv->wakeup_pipe[0];
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;

        /* Client connections */
        for (int i = 0; i < srv->num_clients; i++) {
            pfds[nfds].fd = srv->clients[i].fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        int ret = poll(pfds, (nfds_t)nfds, 1000);  /* 1-second timeout */
        if (ret < 0) {
            if (errno == EINTR) continue;
            DFUSE_ERR("poll: %s", strerror(errno));
            return -1;
        }

        /* Check wakeup pipe */
        if (pfds[1].revents & POLLIN) {
            char dummy[16];
            while (read(srv->wakeup_pipe[0], dummy, sizeof(dummy)) > 0)
                ;
            if (!srv->running)
                break;
        }

        /* Accept new connections */
        if (pfds[0].revents & POLLIN) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int cfd = accept(srv->listen_fd, (struct sockaddr *)&client_addr,
                             &client_len);
            if (cfd >= 0) {
                if (srv->num_clients >= DFUSE_MAX_CLIENTS) {
                    close(cfd);
                } else {
                    set_nonblocking(cfd);
                    set_tcp_nodelay(cfd);
                    client_init(&srv->clients[srv->num_clients], cfd);
                    srv->num_clients++;
                    srv->had_client = 1;
                    DFUSE_LOG("Client connected (fd=%d, total=%d)", cfd, srv->num_clients);
                }
            }
        }

        /* Process client data */
        for (int i = 0; i < srv->num_clients; i++) {
            int pfd_idx = 2 + i;
            if (pfds[pfd_idx].revents & (POLLIN | POLLERR | POLLHUP)) {
                if (client_read(srv, &srv->clients[i]) < 0) {
                    DFUSE_LOG("Client disconnected (fd=%d)", srv->clients[i].fd);
                    client_close(&srv->clients[i]);
                    /* Compact: move last client to this slot */
                    srv->num_clients--;
                    if (i < srv->num_clients)
                        srv->clients[i] = srv->clients[srv->num_clients];
                    i--;  /* re-check this slot */
                }
            }
        }

        /*
         * If we had a client connection and all clients disconnected,
         * the mount has been unmounted. Exit the event loop.
         */
        if (srv->had_client && srv->num_clients == 0) {
            DFUSE_LOG("All clients disconnected — exiting event loop");
            break;
        }
    }

    return 0;
}

void nfs4_server_stop(darwinfuse_server_t *srv)
{
    if (!srv) return;
    srv->running = 0;
    /* Wake up poll */
    char c = 1;
    if (write(srv->wakeup_pipe[1], &c, 1) < 0) {
        /* ignore — best effort */
    }
}

void nfs4_server_restart(darwinfuse_server_t *srv)
{
    if (!srv) return;

    /* Re-arm the running flag so nfs4_server_run() works again */
    srv->running = 1;
    srv->had_client = 0;

    /* Drain the wakeup pipe (may have leftover data from stop) */
    char buf[16];
    while (read(srv->wakeup_pipe[0], buf, sizeof(buf)) > 0)
        ;

    DFUSE_LOG("Server re-armed for new event loop");
}

void nfs4_server_destroy(darwinfuse_server_t *srv)
{
    if (!srv) return;

    for (int i = 0; i < srv->num_clients; i++)
        client_close(&srv->clients[i]);

    if (srv->listen_fd >= 0) close(srv->listen_fd);
    if (srv->wakeup_pipe[0] >= 0) close(srv->wakeup_pipe[0]);
    if (srv->wakeup_pipe[1] >= 0) close(srv->wakeup_pipe[1]);

    free(srv);
}

void nfs4_server_close_inherited_fds(darwinfuse_server_t *srv)
{
    if (!srv) return;

    /* Build a set of FDs the server needs to keep */
    int keep[3 + DFUSE_MAX_CLIENTS];
    int nkeep = 0;
    if (srv->listen_fd >= 0) keep[nkeep++] = srv->listen_fd;
    if (srv->wakeup_pipe[0] >= 0) keep[nkeep++] = srv->wakeup_pipe[0];
    if (srv->wakeup_pipe[1] >= 0) keep[nkeep++] = srv->wakeup_pipe[1];
    for (int i = 0; i < srv->num_clients; i++)
        if (srv->clients[i].fd >= 0) keep[nkeep++] = srv->clients[i].fd;

    /* Close everything from fd 3 up to a reasonable limit */
    int maxfd = (int)sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) maxfd = 4096;

    for (int fd = 3; fd < maxfd; fd++) {
        int needed = 0;
        for (int k = 0; k < nkeep; k++) {
            if (keep[k] == fd) { needed = 1; break; }
        }
        if (!needed) close(fd);
    }
}

void nfs4_server_close_inherited_pipes(darwinfuse_server_t *srv)
{
    if (!srv) return;

    /* Build a set of PIPE FDs the server needs to keep */
    int keep[2];
    int nkeep = 0;
    if (srv->wakeup_pipe[0] >= 0) keep[nkeep++] = srv->wakeup_pipe[0];
    if (srv->wakeup_pipe[1] >= 0) keep[nkeep++] = srv->wakeup_pipe[1];

    int maxfd = (int)sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) maxfd = 4096;

    for (int fd = 3; fd < maxfd; fd++) {
        /* Skip server's wakeup pipe */
        int needed = 0;
        for (int k = 0; k < nkeep; k++) {
            if (keep[k] == fd) { needed = 1; break; }
        }
        if (needed) continue;

        /* Only close PIPE-type FDs; keep regular files, sockets, etc. */
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode)) {
            close(fd);
        }
    }
}
