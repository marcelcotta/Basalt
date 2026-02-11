/*
 * LamarckFUSE — NFSv4 TCP server
 *
 * Single-threaded event-loop serving NFSv4 COMPOUND requests over TCP
 * on localhost. Adapted from DarwinFUSE to be cross-platform:
 *
 * - poll() → WSAPoll() / poll() via platform_compat.h
 * - read/write → recv/send via sock_read/sock_write
 * - pipe() → TCP loopback socketpair via platform_socketpair
 * - close() → closesocket() via sock_close
 * - fcntl() → ioctlsocket() via sock_set_nonblocking
 * - errno → WSAGetLastError() via sock_error
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#include "nfs4_server.h"
#include "nfs4_ops.h"
#include "nfs4_xdr.h"
#include "rpc.h"
#include "lamarckfuse_internal.h"
#include "fuse_context.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
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
#endif

/* ---- Client connection ---- */

typedef enum {
    CLIENT_STATE_READ_MARK,     /* Reading 4-byte record mark */
    CLIENT_STATE_READ_PAYLOAD   /* Reading payload bytes */
} client_read_state_t;

typedef struct {
    sock_t              fd;
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

struct lamarckfuse_server {
    lamarckfuse_config_t config;
    sock_t              listen_fd;
    sock_t              wakeup_pipe[2]; /* self-pipe for stop signal */
    volatile int        running;
    int                 had_client;     /* true once a client connected */

    client_conn_t       clients[LFUSE_MAX_CLIENTS];
    int                 num_clients;
};

/* ---- Helpers ---- */

static void set_tcp_nodelay(sock_t fd)
{
    int flag = 1;
#ifdef _WIN32
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
#else
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
#endif
}

static void client_init(client_conn_t *c, sock_t fd)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->read_state = CLIENT_STATE_READ_MARK;
}

static void client_close(client_conn_t *c)
{
    if (c->fd != INVALID_SOCK) {
        sock_close(c->fd);
        c->fd = INVALID_SOCK;
    }
    free(c->payload_buf);
    c->payload_buf = NULL;
}

/* ---- Error handling helpers ---- */

static inline int is_wouldblock(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
    return (err == WSAEWOULDBLOCK);
#else
    return (errno == EAGAIN || errno == EWOULDBLOCK);
#endif
}

static inline int is_interrupted(void)
{
#ifdef _WIN32
    return 0;  /* Winsock doesn't have EINTR */
#else
    return (errno == EINTR);
#endif
}

static inline const char *sock_strerror(void)
{
#ifdef _WIN32
    static THREAD_LOCAL char buf[64];
    snprintf(buf, sizeof(buf), "WSA error %d", WSAGetLastError());
    return buf;
#else
    return strerror(errno);
#endif
}

/* Process one complete RPC message from a client */
static int handle_rpc_message(lamarckfuse_server_t *srv, client_conn_t *c)
{
    /* Decode RPC call */
    xdr_buf_t req;
    xdr_init(&req, c->payload_buf, c->payload_len);

    rpc_call_header_t rpc_hdr;
    if (rpc_parse_call(&req, &rpc_hdr) < 0) {
        LFUSE_ERR("Failed to parse RPC call");
        return -1;
    }

    /* Prepare reply buffer (record mark placeholder + RPC + NFS reply) */
    uint8_t *reply_buf = malloc(LFUSE_XDR_MAXBUF + 4);
    if (!reply_buf)
        return -1;

    xdr_buf_t rep;
    xdr_init(&rep, reply_buf + 4, LFUSE_XDR_MAXBUF);  /* leave 4 bytes for record mark */

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
        lamarckfuse_set_context(rpc_hdr.cred_uid, rpc_hdr.cred_gid);

        /* Encode RPC reply header */
        rpc_encode_reply_accepted(&rep, rpc_hdr.xid);

        /* Dispatch COMPOUND */
        if (nfs4_dispatch_compound(&srv->config, &c->nfs_state,
                                    &req, &rep) < 0) {
            LFUSE_ERR("COMPOUND dispatch failed");
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
        ssize_t n = sock_write(c->fd, reply_buf + written, total - written);
        if (n < 0) {
            if (is_interrupted()) continue;
            if (is_wouldblock()) {
                /* For simplicity, busy-wait briefly on non-blocking socket */
#ifdef _WIN32
                Sleep(1);
#else
                usleep(100);
#endif
                continue;
            }
            LFUSE_ERR("write failed: %s", sock_strerror());
            free(reply_buf);
            return -1;
        }
        written += (size_t)n;
    }

    free(reply_buf);
    return 0;
}

/* Read available data for a client. Returns 0 if OK, -1 if client should be closed. */
static int client_read(lamarckfuse_server_t *srv, client_conn_t *c)
{
    for (;;) {
        if (c->read_state == CLIENT_STATE_READ_MARK) {
            /* Read the 4-byte TCP record mark */
            size_t need = 4 - c->mark_read;
            ssize_t n = sock_read(c->fd, c->mark_buf + c->mark_read, need);
            if (n == 0) return -1;  /* client disconnected */
            if (n < 0) {
                if (is_interrupted()) continue;
                if (is_wouldblock()) return 0;
                return -1;
            }
            c->mark_read += (size_t)n;
            if (c->mark_read < 4)
                return 0;

            /* Parse record mark */
            c->payload_len = rpc_parse_record_mark(c->mark_buf, &c->last_fragment);
            if (c->payload_len == 0 || c->payload_len > LFUSE_XDR_MAXBUF) {
                LFUSE_ERR("Invalid record mark length: %zu", c->payload_len);
                return -1;
            }

            c->payload_buf = malloc(c->payload_len);
            if (!c->payload_buf) return -1;
            c->payload_read = 0;
            c->read_state = CLIENT_STATE_READ_PAYLOAD;
        }

        if (c->read_state == CLIENT_STATE_READ_PAYLOAD) {
            size_t need = c->payload_len - c->payload_read;
            ssize_t n = sock_read(c->fd, c->payload_buf + c->payload_read, need);
            if (n == 0) return -1;
            if (n < 0) {
                if (is_interrupted()) continue;
                if (is_wouldblock()) return 0;
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

lamarckfuse_server_t *nfs4_server_create(const lamarckfuse_config_t *config,
                                          uint16_t *port)
{
    lamarckfuse_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;

    srv->config = *config;
    srv->listen_fd = INVALID_SOCK;
    srv->wakeup_pipe[0] = INVALID_SOCK;
    srv->wakeup_pipe[1] = INVALID_SOCK;

    /* Self-pipe (or TCP socketpair on Windows) for stop signaling */
    if (platform_socketpair(srv->wakeup_pipe) < 0) {
        free(srv);
        return NULL;
    }
    sock_set_nonblocking(srv->wakeup_pipe[0]);
    sock_set_nonblocking(srv->wakeup_pipe[1]);

    /* Create TCP listen socket */
    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd == INVALID_SOCK) {
        LFUSE_ERR("socket: %s", sock_strerror());
        goto fail;
    }

    int reuse = 1;
#ifdef _WIN32
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&reuse, sizeof(reuse));
#else
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR,
               &reuse, sizeof(reuse));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

#ifdef _WIN32
    /* Windows NFS client hardcodes port 2049 */
    addr.sin_port = htons(LAMARCKFUSE_NFS_PORT);
#else
    addr.sin_port = 0;  /* ephemeral port */
#endif

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LFUSE_ERR("bind: %s", sock_strerror());
        goto fail;
    }

    if (listen(srv->listen_fd, 5) < 0) {
        LFUSE_ERR("listen: %s", sock_strerror());
        goto fail;
    }

    /* Retrieve the assigned port */
#ifdef _WIN32
    int addrlen = sizeof(addr);
#else
    socklen_t addrlen = sizeof(addr);
#endif
    if (getsockname(srv->listen_fd, (struct sockaddr *)&addr, &addrlen) < 0) {
        LFUSE_ERR("getsockname: %s", sock_strerror());
        goto fail;
    }
    *port = ntohs(addr.sin_port);

    sock_set_nonblocking(srv->listen_fd);
    srv->running = 1;

    LFUSE_LOG("NFS server listening on 127.0.0.1:%u", *port);
    return srv;

fail:
    sock_close(srv->listen_fd);
    sock_close(srv->wakeup_pipe[0]);
    sock_close(srv->wakeup_pipe[1]);
    free(srv);
    return NULL;
}

int nfs4_server_run(lamarckfuse_server_t *srv)
{
    /* pollfd layout: [0] = listen_fd, [1] = wakeup_pipe, [2..N+1] = clients */
    poll_fd_t pfds[2 + LFUSE_MAX_CLIENTS];

    while (srv->running) {
        int nfds = 0;

        /* Listen socket */
        pfds[nfds].fd = srv->listen_fd;
        pfds[nfds].events = POLL_IN;
        pfds[nfds].revents = 0;
        nfds++;

        /* Wakeup pipe */
        pfds[nfds].fd = srv->wakeup_pipe[0];
        pfds[nfds].events = POLL_IN;
        pfds[nfds].revents = 0;
        nfds++;

        /* Client connections */
        for (int i = 0; i < srv->num_clients; i++) {
            pfds[nfds].fd = srv->clients[i].fd;
            pfds[nfds].events = POLL_IN;
            pfds[nfds].revents = 0;
            nfds++;
        }

#ifdef _WIN32
        int ret = WSAPoll(pfds, (ULONG)nfds, 1000);  /* 1-second timeout */
        if (ret == SOCKET_ERROR) {
            LFUSE_ERR("WSAPoll: %s", sock_strerror());
            return -1;
        }
#else
        int ret = poll(pfds, (nfds_t)nfds, 1000);  /* 1-second timeout */
        if (ret < 0) {
            if (errno == EINTR) continue;
            LFUSE_ERR("poll: %s", strerror(errno));
            return -1;
        }
#endif

        /* Check wakeup pipe */
        if (pfds[1].revents & POLL_IN) {
            char dummy[16];
            while (sock_read(srv->wakeup_pipe[0], dummy, sizeof(dummy)) > 0)
                ;
            if (!srv->running)
                break;
        }

        /* Accept new connections */
        if (pfds[0].revents & POLL_IN) {
            struct sockaddr_in client_addr;
#ifdef _WIN32
            int client_len = sizeof(client_addr);
#else
            socklen_t client_len = sizeof(client_addr);
#endif
            sock_t cfd = accept(srv->listen_fd, (struct sockaddr *)&client_addr,
                                &client_len);
            if (cfd != INVALID_SOCK) {
                if (srv->num_clients >= LFUSE_MAX_CLIENTS) {
                    sock_close(cfd);
                } else {
                    sock_set_nonblocking(cfd);
                    set_tcp_nodelay(cfd);
                    client_init(&srv->clients[srv->num_clients], cfd);
                    srv->num_clients++;
                    srv->had_client = 1;
                    LFUSE_LOG("Client connected (total=%d)", srv->num_clients);
                }
            }
        }

        /* Process client data */
        for (int i = 0; i < srv->num_clients; i++) {
            int pfd_idx = 2 + i;
            if (pfds[pfd_idx].revents & (POLL_IN | POLL_ERR | POLL_HUP)) {
                if (client_read(srv, &srv->clients[i]) < 0) {
                    LFUSE_LOG("Client disconnected");
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
            LFUSE_LOG("All clients disconnected — exiting event loop");
            break;
        }
    }

    return 0;
}

void nfs4_server_stop(lamarckfuse_server_t *srv)
{
    if (!srv) return;
    srv->running = 0;
    /* Wake up poll */
    char c = 1;
    sock_write(srv->wakeup_pipe[1], &c, 1);
}

void nfs4_server_restart(lamarckfuse_server_t *srv)
{
    if (!srv) return;

    /* Re-arm the running flag so nfs4_server_run() works again */
    srv->running = 1;
    srv->had_client = 0;

    /* Drain the wakeup pipe (may have leftover data from stop) */
    char buf[16];
    while (sock_read(srv->wakeup_pipe[0], buf, sizeof(buf)) > 0)
        ;

    LFUSE_LOG("Server re-armed for new event loop");
}

void nfs4_server_destroy(lamarckfuse_server_t *srv)
{
    if (!srv) return;

    for (int i = 0; i < srv->num_clients; i++)
        client_close(&srv->clients[i]);

    sock_close(srv->listen_fd);
    sock_close(srv->wakeup_pipe[0]);
    sock_close(srv->wakeup_pipe[1]);

    free(srv);
}

/* ---- POSIX-only: inherited FD cleanup (for daemonization) ---- */

#ifndef _WIN32

void nfs4_server_close_inherited_fds(lamarckfuse_server_t *srv)
{
    if (!srv) return;

    /* Build a set of FDs the server needs to keep */
    int keep[3 + LFUSE_MAX_CLIENTS];
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

void nfs4_server_close_inherited_pipes(lamarckfuse_server_t *srv)
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

#endif /* !_WIN32 */
