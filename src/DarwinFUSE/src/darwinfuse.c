/*
 * DarwinFUSE — fuse_main() and fuse_get_context() implementation
 *
 * This is the public entry point that replaces libfuse's fuse_main().
 * It starts an NFSv4 server on localhost, calls mount_nfs to mount,
 * and runs the event loop until the filesystem is unmounted.
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#include <fuse.h>

#include "nfs4_server.h"
#include "darwinfuse_internal.h"
#include "fuse_context.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/wait.h>

/* ---- Logging ---- */

void dfuse_logf(int is_error, const char *fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    const char *prefix = is_error ? "[DarwinFUSE ERROR] " : "[DarwinFUSE] ";
    fprintf(stderr, "%s%s\n", prefix, msg);

#ifdef DFUSE_LOG_FILE
    int fd = open(DFUSE_LOG_FILE, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0) {
        dprintf(fd, "%s%s\n", prefix, msg);
        close(fd);
    }
#endif
}

/* ---- Thread-local FUSE context ---- */

static __thread struct fuse_context tls_context;

struct fuse_context *fuse_get_context(void)
{
    return &tls_context;
}

void darwinfuse_set_context(uid_t uid, gid_t gid)
{
    tls_context.uid = uid;
    tls_context.gid = gid;
    tls_context.pid = getpid();
}

/* ---- Global server pointer for signal handling ---- */

static darwinfuse_server_t *g_server = NULL;
static volatile sig_atomic_t g_signalled = 0;

static void signal_handler(int sig)
{
    (void)sig;
    g_signalled = 1;
    if (g_server)
        nfs4_server_stop(g_server);
}

/* ---- Argument parsing ---- */

/*
 * Parse -o options from argv.
 * Extracts mount-relevant options (nosuid, nodev, nobrowse etc.)
 * that should be forwarded to mount_nfs.
 *
 * Basalt calls with: argv = ["truecrypt", mountpoint, "-o", "noping_diskarb",
 *                             "-o", "nobrowse", "-o", "allow_other",
 *                             "-o", "nosuid,nodev"]
 */
typedef struct {
    const char *mount_point;
    int         nosuid;
    int         nodev;
    int         rdonly;
    int         nobrowse;
} parsed_args_t;

static int parse_args(int argc, char *argv[], parsed_args_t *out)
{
    memset(out, 0, sizeof(*out));

    /* argv[0] = device type (e.g. "truecrypt"), argv[1] = mount point */
    if (argc < 2) {
        DFUSE_ERR("Usage: <device_type> <mount_point> [-o options...]");
        return -1;
    }

    out->mount_point = argv[1];

    /* Scan for -o options */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            i++;
            const char *opts = argv[i];

            /* Parse comma-separated option tokens */
            char buf[1024];
            strncpy(buf, opts, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';

            char *saveptr = NULL;
            for (char *tok = strtok_r(buf, ",", &saveptr);
                 tok != NULL;
                 tok = strtok_r(NULL, ",", &saveptr))
            {
                if (strcmp(tok, "nosuid") == 0)       out->nosuid = 1;
                else if (strcmp(tok, "nodev") == 0)  out->nodev = 1;
                else if (strcmp(tok, "ro") == 0)     out->rdonly = 1;
                else if (strcmp(tok, "nobrowse") == 0) out->nobrowse = 1;
                /* Other FUSE-specific options (noping_diskarb,
                   allow_other) are silently ignored — not applicable to NFS */
            }
        }
    }

    return 0;
}

/* ---- Volume path detection ---- */

static const char *detect_volume_path(void)
{
#ifdef TC_MACOSX
    return "/volume.dmg";
#elif defined(__APPLE__)
    return "/volume.dmg";
#else
    return "/volume";
#endif
}

/* ---- Mount via mount_nfs ---- */

/*
 * Transport selection. The NFS server preferably listens on a Unix domain
 * socket in a private 0700 directory (supported by macOS' mount_nfs and NFS
 * client since 10.15 via "proto=ticotsord,port=/path"). A loopback TCP port
 * would be reachable by every local user and process, and the AUTH_SYS
 * credentials an NFS client sends are not authenticated.
 *
 * "nocallback" is required for the local socket: with NFSv4 callbacks
 * enabled, the kernel's SETCLIENTID needs an IPv4/IPv6 address of its own
 * socket for the callback channel and fails with EINVAL on AF_LOCAL
 * (nfs4_setclientid() in Apple's NFS client). The server never uses
 * callbacks (no delegations), and without them the kernel does not open its
 * NFSv4 callback listener.
 *
 * DFUSE_TCP_FALLBACK=1 retries over loopback TCP if the local-socket mount
 * fails. Set it to 0 to fail closed once the local transport has been
 * verified on all supported macOS versions.
 */
#ifndef DFUSE_TCP_FALLBACK
#define DFUSE_TCP_FALLBACK 1
#endif

static int do_mount_nfs(uint16_t port, const char *socket_path,
                        const parsed_args_t *args)
{
    /*
     * Build mount options string.
     *
     * NFSv4 notes:
     * - locallocks/nolocks are NFSv2/v3 only — omit for v4
     * - noac: disable attribute caching (we serve fresh data each time)
     * - nocallback: no NFSv4 callback channel (see above; required for
     *   the local socket)
     * - noacl: disable ACL support (simplifies our server)
     * - noresvport: use unprivileged source port so mount works without root
     *   (XNU allows non-root mount() if user owns the mountpoint dir)
     * - soft,intr: allow interruption/timeout rather than hanging
     * - retrycnt=0: fail fast on initial mount attempt
     */
    char opts[512];
    char spec[200];
    int len;

    if (socket_path) {
        len = snprintf(opts, sizeof(opts),
            "vers=4,proto=ticotsord,port=%s,nocallback,noac,noacl,noresvport,"
            "rsize=65536,wsize=65536,"
            "soft,intr,retrycnt=0",
            socket_path);
        snprintf(spec, sizeof(spec), "<%s>:/", socket_path);
    } else {
        len = snprintf(opts, sizeof(opts),
            "vers=4,tcp,nocallback,noac,noacl,noresvport,"
            "rsize=65536,wsize=65536,"
            "soft,intr,retrycnt=0,"
            "port=%u",
            (unsigned)port);
        snprintf(spec, sizeof(spec), "127.0.0.1:/");
    }

    if (args->nosuid)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",nosuid");
    if (args->nodev)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",nodev");
    if (args->rdonly)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",rdonly");
    if (args->nobrowse)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",nobrowse");

    if (len < 0 || (size_t)len >= sizeof(opts)) {
        DFUSE_ERR("mount options too long");
        return -1;
    }

    DFUSE_LOG("mount_nfs -o %s %s %s", opts, spec, args->mount_point);

    /* Create a pipe to capture mount_nfs stderr output */
    int err_pipe[2];
    if (pipe(err_pipe) < 0) {
        DFUSE_ERR("pipe for mount_nfs stderr failed");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        DFUSE_ERR("fork failed: %s", strerror(errno));
        close(err_pipe[0]);
        close(err_pipe[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: redirect stderr to pipe, then exec mount_nfs.
         * Absolute path: never resolve system tools via $PATH. */
        close(err_pipe[0]);
        dup2(err_pipe[1], STDERR_FILENO);
        close(err_pipe[1]);

        execl("/sbin/mount_nfs", "mount_nfs",
              "-o", opts,
              spec,
              args->mount_point,
              (char *)NULL);
        _exit(127);
    }

    /* Parent: read mount_nfs stderr, then wait */
    close(err_pipe[1]);

    char errbuf[1024];
    ssize_t errlen = 0;
    ssize_t n;
    while (errlen < (ssize_t)sizeof(errbuf) - 1 &&
           (n = read(err_pipe[0], errbuf + errlen,
                     sizeof(errbuf) - 1 - (size_t)errlen)) > 0)
        errlen += n;
    errbuf[errlen] = '\0';
    close(err_pipe[0]);

    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        DFUSE_ERR("waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        DFUSE_ERR("mount_nfs failed (exit status %d): %s",
                  WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                  errlen > 0 ? errbuf : "(no stderr output)");
        return -1;
    }

    DFUSE_LOG("mount_nfs succeeded");
    return 0;
}

/* pthread start routine for the server event loop (the int result is unused) */
static void *server_thread_main(void *arg)
{
    nfs4_server_run((darwinfuse_server_t *)arg);
    return NULL;
}

/*
 * Start the server event loop in a background thread (so it can answer the
 * kernel's requests during mount) and run mount_nfs. On failure the server
 * is stopped and destroyed.
 */
static int serve_and_mount(darwinfuse_server_t *srv, uint16_t port,
                           const char *socket_path, const parsed_args_t *args,
                           pthread_t *srv_thread)
{
    g_server = srv;

    if (pthread_create(srv_thread, NULL, server_thread_main, srv) != 0) {
        DFUSE_ERR("Failed to create server thread");
        nfs4_server_destroy(srv);
        g_server = NULL;
        return -1;
    }

    /*
     * Call mount_nfs in THIS process (the parent), which still has the
     * full sudo/root authorization context.  Calling mount_nfs after
     * fork()+setsid() would lose the authorization chain on macOS Sonoma+.
     */
    if (do_mount_nfs(port, socket_path, args) < 0) {
        nfs4_server_stop(srv);
        pthread_join(*srv_thread, NULL);
        nfs4_server_destroy(srv);
        g_server = NULL;
        return -1;
    }

    return 0;
}

/* ---- fuse_main ---- */

int fuse_main(int argc, char *argv[],
              const struct fuse_operations *op, void *user_data)
{
    if (!op) return -1;

    /* Parse arguments */
    parsed_args_t args;
    if (parse_args(argc, argv, &args) < 0)
        return -1;

    DFUSE_LOG("fuse_main: uid=%u euid=%u mount_point=%s",
              getuid(), geteuid(), args.mount_point);

    /* Set initial FUSE context */
    darwinfuse_set_context(getuid(), getgid());

    /*
     * NOTE: We do NOT call op->init() here.  The init callback
     * (fuse_service_init) starts the EncryptionThreadPool, which
     * creates worker threads.  Those threads would not survive the
     * daemon fork() below, leaving the child with a stale
     * ThreadPoolRunning=true but no actual threads — deadlock.
     *
     * Instead, we call op->init() AFTER the fork, in the daemon child.
     * The NFS server can handle mount-time operations (GETATTR, READDIR,
     * ACCESS, LOOKUP) without the thread pool; only READ/WRITE need it,
     * and those only arrive after hdiutil attach, post-mount.
     */
    void *init_result = NULL;

    /* Configure NFS server */
    darwinfuse_config_t config;
    memset(&config, 0, sizeof(config));
    config.ops = op;
    config.user_data = user_data;
    config.uid = getuid();
    config.gid = getgid();
    config.volume_path = detect_volume_path();
    config.control_path = "/control";

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /*
     * Create the NFS server (binds the listen socket) and mount it. The
     * event loop runs in a background thread so the server can answer the
     * kernel's NFSv4 COMPOUND requests during mount.
     */
    pthread_t srv_thread;
    darwinfuse_server_t *srv = NULL;
    const char *socket_path = NULL;
    int mounted = 0;

    srv = nfs4_server_create_local(&config, &socket_path);
    if (srv && serve_and_mount(srv, 0, socket_path, &args, &srv_thread) == 0)
        mounted = 1;

#if DFUSE_TCP_FALLBACK
    if (!mounted && !g_signalled) {
        DFUSE_ERR("Local-socket NFS mount failed; falling back to loopback TCP "
                  "(reachable by other local users)");
        uint16_t port = 0;
        srv = nfs4_server_create(&config, &port);
        if (srv && serve_and_mount(srv, port, NULL, &args, &srv_thread) == 0)
            mounted = 1;
    }
#endif

    if (!mounted) {
        DFUSE_ERR("Failed to mount NFS");
        return -1;
    }

    /*
     * Mount succeeded.  Now daemonize: fork a child to continue running
     * the NFS server, and have the parent _exit(0) so that
     * Process::Execute in Basalt's GUI collects the exit status.
     *
     * Note: after fork(), only the calling thread survives in the child.
     * The server pthread does NOT survive the fork.  So we must stop the
     * old server thread and restart it in the child.
     *
     * FD management:
     *   - Parent: _exit(0) closes all FDs → Process::Execute sees EOF
     *   - Child (daemon): must close inherited pipe write-ends so that
     *     Process::Execute also sees EOF (it waits for ALL holders to close).
     *     But we must NOT close the volume FD (regular file) or server FDs.
     *     Strategy: redirect stdio to /dev/null, then close only PIPE-type
     *     FDs (except the server's wakeup_pipe).
     */
    nfs4_server_stop(srv);
    pthread_join(srv_thread, NULL);

    DFUSE_LOG("mount succeeded, daemonizing");

    pid_t daemon_pid = fork();
    if (daemon_pid < 0) {
        nfs4_server_destroy(srv);
        g_server = NULL;
        return -1;
    }

    if (daemon_pid > 0) {
        /* Parent: exit immediately.  _exit closes all FDs in this process,
         * which releases the Process::Execute pipe write-ends.
         */
        DFUSE_LOG("Parent: _exit(0), daemon pid=%d", daemon_pid);
        _exit(0);
    }

    /* ---- Child (daemon): take over the NFS server ---- */
    setsid();

    /* Redirect stdio to /dev/null */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO)
            close(devnull);
    }

    /* Close inherited PIPE FDs (Process::Execute's exceptionPipe etc.)
     * but keep regular files (volume FD), sockets (NFS listen), and
     * the server's wakeup_pipe.
     */
    nfs4_server_close_inherited_pipes(srv);

    /*
     * Now call op->init() in the daemon child.  This starts the
     * EncryptionThreadPool with fresh worker threads.
     *
     * We deliberately deferred init to after fork because:
     * - Worker threads don't survive fork() (POSIX: only calling thread)
     * - ThreadPoolRunning would be stale true with no actual threads
     * - DoWork() would deadlock waiting for non-existent workers
     *
     * The mount-time NFS operations (GETATTR, READDIR, ACCESS, LOOKUP)
     * don't need the thread pool — only READ/WRITE (encryption) do.
     */
    if (op->init) {
        struct fuse_conn_info conn_info;
        memset(&conn_info, 0, sizeof(conn_info));
        conn_info.proto_major = 7;
        conn_info.proto_minor = 26;
        conn_info.max_write = 65536;
        conn_info.max_readahead = 65536;
        init_result = op->init(&conn_info);
    }

    /* Reinstall our signal handlers — op->init() may have set SIG_IGN
     * (fuse_service_init does this for the original FUSE architecture).
     * The daemon needs SIGTERM/SIGINT to trigger clean shutdown.
     */
    {
        struct sigaction sa2;
        memset(&sa2, 0, sizeof(sa2));
        sa2.sa_handler = signal_handler;
        sigaction(SIGTERM, &sa2, NULL);
        sigaction(SIGINT, &sa2, NULL);
    }

    /* Re-arm the server (was stopped for the fork) */
    nfs4_server_restart(srv);

    /* Run event loop directly in this process (no extra thread needed) */
    DFUSE_LOG("Daemon: running event loop (pid=%d)", getpid());

    nfs4_server_run(srv);

    DFUSE_LOG("Daemon: server exited");

    nfs4_server_destroy(srv);
    g_server = NULL;

    if (op->destroy)
        op->destroy(init_result);

    _exit(0);
}
