/*
 * LamarckFUSE — fuse_main() and fuse_get_context() implementation
 *
 * Windows adaptation of DarwinFUSE's darwinfuse.c.
 *
 * Key differences from DarwinFUSE:
 * - No fork()/daemonize — uses CreateThread for background NFS server
 * - Mount via mount.exe (Windows NFS client) on port 2049
 * - Unmount via umount.exe or WNetCancelConnection2
 * - SetConsoleCtrlHandler for SIGTERM equivalent
 * - WSAStartup/WSACleanup for Winsock initialization
 * - op->init() called directly (no fork problem)
 *
 * On POSIX, this file falls through to the DarwinFUSE-compatible path
 * (fork, mount_nfs, daemonize).
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#include <fuse.h>

#include "nfs4_server.h"
#include "lamarckfuse_internal.h"
#include "fuse_context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

/* ============================================================
 * WINDOWS IMPLEMENTATION
 * ============================================================ */

#include <windows.h>
#include <winnetwk.h>
#pragma comment(lib, "mpr.lib")  /* For WNetAddConnection2/WNetCancelConnection2 */

/* ---- Thread-local FUSE context ---- */

static THREAD_LOCAL struct fuse_context tls_context;

struct fuse_context *fuse_get_context(void)
{
    return &tls_context;
}

void lamarckfuse_set_context(uid_t uid, gid_t gid)
{
    tls_context.uid = uid;
    tls_context.gid = gid;
    tls_context.pid = platform_getpid();
}

/* ---- Global server pointer for Ctrl+C handling ---- */

static lamarckfuse_server_t *g_server = NULL;

static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
    (void)dwCtrlType;
    if (g_server)
        nfs4_server_stop(g_server);
    return TRUE;
}

/* ---- NFS Client availability check ---- */

static int check_nfs_client(void)
{
    /*
     * Check if Windows NFS client is available.
     * The mount.exe command is in C:\Windows\System32 when
     * "Services for NFS" → "Client for NFS" is enabled.
     */
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, sizeof(sysdir));

    char mount_path[MAX_PATH];
    snprintf(mount_path, sizeof(mount_path), "%s\\mount.exe", sysdir);

    DWORD attrs = GetFileAttributesA(mount_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        LFUSE_ERR("NFS Client not found (%s)", mount_path);
        LFUSE_ERR("Enable via: Windows Features -> Services for NFS -> Client for NFS");
        LFUSE_ERR("Or: Enable-WindowsOptionalFeature -Online -FeatureName ServicesForNFS-ClientOnly");
        return -1;
    }

    return 0;
}

/* ---- Mount via WNetAddConnection2 ---- */

static int do_mount_win(const char *mount_point)
{
    /*
     * Mount 127.0.0.1:/ as a network drive.
     * mount_point should be a drive letter like "Z:" or "Z:\\"
     */

    /* Build UNC path: \\127.0.0.1\nfs */
    NETRESOURCEA nr;
    memset(&nr, 0, sizeof(nr));
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpLocalName = (LPSTR)mount_point;
    nr.lpRemoteName = "\\\\127.0.0.1\\nfs";
    nr.lpProvider = NULL;

    LFUSE_LOG("Mounting %s -> %s", mount_point, nr.lpRemoteName);

    DWORD result = WNetAddConnection2A(&nr, NULL, NULL, 0);
    if (result != NO_ERROR) {
        LFUSE_ERR("WNetAddConnection2 failed: error %lu", (unsigned long)result);

        /* Fallback: try mount.exe command */
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "mount.exe -o nolock,mtype=hard \\\\127.0.0.1\\nfs %s",
                 mount_point);

        LFUSE_LOG("Fallback: %s", cmd);
        int rc = system(cmd);
        if (rc != 0) {
            LFUSE_ERR("mount.exe also failed (exit code %d)", rc);
            return -1;
        }
    }

    LFUSE_LOG("Mount succeeded: %s", mount_point);
    return 0;
}

/* ---- Unmount ---- */

static void do_unmount_win(const char *mount_point)
{
    DWORD result = WNetCancelConnection2A(mount_point, 0, TRUE);
    if (result != NO_ERROR) {
        LFUSE_ERR("WNetCancelConnection2 failed: error %lu", (unsigned long)result);
        /* Fallback */
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "umount.exe %s", mount_point);
        system(cmd);
    }
}

/* ---- Argument parsing ---- */

typedef struct {
    const char *mount_point;
    int         rdonly;
} parsed_args_t;

static int parse_args(int argc, char *argv[], parsed_args_t *out)
{
    memset(out, 0, sizeof(*out));

    if (argc < 2) {
        LFUSE_ERR("Usage: <device_type> <mount_point> [-o options...]");
        return -1;
    }

    out->mount_point = argv[1];

    /* Scan for -o options */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            i++;
            const char *opts = argv[i];
            char buf[1024];
            strncpy(buf, opts, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';

            char *saveptr = NULL;
            for (char *tok = strtok_s(buf, ",", &saveptr);
                 tok != NULL;
                 tok = strtok_s(NULL, ",", &saveptr))
            {
                if (strcmp(tok, "ro") == 0)
                    out->rdonly = 1;
                /* nosuid, nodev, nobrowse: not applicable on Windows */
            }
        }
    }

    return 0;
}

/* ---- Server thread ---- */

typedef struct {
    lamarckfuse_server_t *srv;
    const struct fuse_operations *ops;
} server_thread_ctx_t;

static DWORD WINAPI server_thread_func(LPVOID param)
{
    server_thread_ctx_t *ctx = (server_thread_ctx_t *)param;
    nfs4_server_run(ctx->srv);
    return 0;
}

/* ---- fuse_main (Windows) ---- */

int fuse_main(int argc, char *argv[],
              const struct fuse_operations *op, void *user_data)
{
    if (!op) return -1;

    /* Initialize Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        LFUSE_ERR("WSAStartup failed");
        return -1;
    }

    /* Check NFS client availability */
    if (check_nfs_client() < 0) {
        WSACleanup();
        return -1;
    }

    /* Parse arguments */
    parsed_args_t args;
    if (parse_args(argc, argv, &args) < 0) {
        WSACleanup();
        return -1;
    }

    LFUSE_LOG("fuse_main: mount_point=%s", args.mount_point);

    /* Set initial FUSE context */
    lamarckfuse_set_context(0, 0);

    /* Configure NFS server */
    lamarckfuse_config_t config;
    memset(&config, 0, sizeof(config));
    config.ops = op;
    config.user_data = user_data;
    config.uid = 0;
    config.gid = 0;
    config.volume_path = "/volume";
    config.control_path = "/control";

    /* Create NFS server (binds to port 2049) */
    uint16_t port = 0;
    lamarckfuse_server_t *srv = nfs4_server_create(&config, &port);
    if (!srv) {
        LFUSE_ERR("Failed to create NFS server");
        WSACleanup();
        return -1;
    }

    g_server = srv;

    /* Install Ctrl+C handler */
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    /*
     * Call op->init() BEFORE starting the server thread.
     * On Windows there's no fork, so no thread-survival issue.
     * The encryption thread pool starts immediately.
     */
    void *init_result = NULL;
    if (op->init) {
        struct fuse_conn_info conn_info;
        memset(&conn_info, 0, sizeof(conn_info));
        conn_info.proto_major = 7;
        conn_info.proto_minor = 26;
        conn_info.max_write = 65536;
        conn_info.max_readahead = 65536;
        init_result = op->init(&conn_info);
    }

    /* Start NFS server in background thread */
    server_thread_ctx_t thread_ctx = { srv, op };
    HANDLE hThread = CreateThread(NULL, 0, server_thread_func,
                                   &thread_ctx, 0, NULL);
    if (!hThread) {
        LFUSE_ERR("Failed to create server thread");
        nfs4_server_destroy(srv);
        g_server = NULL;
        if (op->destroy) op->destroy(init_result);
        WSACleanup();
        return -1;
    }

    /* Mount NFS share */
    if (do_mount_win(args.mount_point) < 0) {
        LFUSE_ERR("Failed to mount NFS");
        nfs4_server_stop(srv);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        nfs4_server_destroy(srv);
        g_server = NULL;
        if (op->destroy) op->destroy(init_result);
        WSACleanup();
        return -1;
    }

    /* Wait for server thread to finish
     * (exits when all NFS clients disconnect = volume unmounted) */
    LFUSE_LOG("Waiting for server thread...");
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    LFUSE_LOG("Server thread exited");

    /* Cleanup */
    do_unmount_win(args.mount_point);
    nfs4_server_destroy(srv);
    g_server = NULL;

    if (op->destroy)
        op->destroy(init_result);

    SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
    WSACleanup();

    return 0;
}

#else /* !_WIN32 */

/* ============================================================
 * POSIX IMPLEMENTATION (DarwinFUSE-compatible)
 * ============================================================ */

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/wait.h>

/* ---- Thread-local FUSE context ---- */

static __thread struct fuse_context tls_context;

struct fuse_context *fuse_get_context(void)
{
    return &tls_context;
}

void lamarckfuse_set_context(uid_t uid, gid_t gid)
{
    tls_context.uid = uid;
    tls_context.gid = gid;
    tls_context.pid = getpid();
}

/* ---- Global server pointer for signal handling ---- */

static lamarckfuse_server_t *g_server = NULL;

static void signal_handler(int sig)
{
    (void)sig;
    if (g_server)
        nfs4_server_stop(g_server);
}

/* ---- Argument parsing ---- */

typedef struct {
    const char *mount_point;
    int         nosuid;
    int         nodev;
    int         rdonly;
    int         nobrowse;
} posix_parsed_args_t;

static int posix_parse_args(int argc, char *argv[], posix_parsed_args_t *out)
{
    memset(out, 0, sizeof(*out));

    if (argc < 2) {
        LFUSE_ERR("Usage: <device_type> <mount_point> [-o options...]");
        return -1;
    }

    out->mount_point = argv[1];

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            i++;
            const char *opts = argv[i];
            char buf[1024];
            strncpy(buf, opts, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';

            char *saveptr = NULL;
            for (char *tok = strtok_r(buf, ",", &saveptr);
                 tok != NULL;
                 tok = strtok_r(NULL, ",", &saveptr))
            {
                if (strcmp(tok, "nosuid") == 0)       out->nosuid = 1;
                else if (strcmp(tok, "nodev") == 0)   out->nodev = 1;
                else if (strcmp(tok, "ro") == 0)      out->rdonly = 1;
                else if (strcmp(tok, "nobrowse") == 0) out->nobrowse = 1;
            }
        }
    }

    return 0;
}

/* ---- Volume path detection ---- */

static const char *detect_volume_path(void)
{
#ifdef __APPLE__
    return "/volume.dmg";
#else
    return "/volume";
#endif
}

/* ---- Mount via mount_nfs ---- */

static int do_mount_nfs(uint16_t port, const posix_parsed_args_t *args)
{
    char opts[512];
    int len = snprintf(opts, sizeof(opts),
        "vers=4,tcp,noac,noacl,noresvport,"
        "rsize=65536,wsize=65536,"
        "soft,intr,retrycnt=0,"
        "port=%u",
        (unsigned)port);

    if (args->nosuid)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",nosuid");
    if (args->nodev)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",nodev");
    if (args->rdonly)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",rdonly");
    if (args->nobrowse)
        len += snprintf(opts + len, sizeof(opts) - (size_t)len, ",nobrowse");

    LFUSE_LOG("mount_nfs -o %s 127.0.0.1:/ %s", opts, args->mount_point);

    int err_pipe[2];
    if (pipe(err_pipe) < 0) {
        LFUSE_ERR("pipe for mount_nfs stderr failed");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        LFUSE_ERR("fork failed: %s", strerror(errno));
        close(err_pipe[0]);
        close(err_pipe[1]);
        return -1;
    }

    if (pid == 0) {
        close(err_pipe[0]);
        dup2(err_pipe[1], STDERR_FILENO);
        close(err_pipe[1]);

        execlp("mount_nfs", "mount_nfs",
               "-o", opts,
               "127.0.0.1:/",
               args->mount_point,
               NULL);
        _exit(127);
    }

    close(err_pipe[1]);

    char errbuf[1024];
    ssize_t errlen = 0;
    ssize_t n;
    while ((n = read(err_pipe[0], errbuf + errlen,
                     sizeof(errbuf) - 1 - (size_t)errlen)) > 0)
        errlen += n;
    errbuf[errlen] = '\0';
    close(err_pipe[0]);

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        LFUSE_ERR("waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        LFUSE_ERR("mount_nfs failed (exit status %d): %s",
                  WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                  errlen > 0 ? errbuf : "(no stderr output)");
        return -1;
    }

    LFUSE_LOG("mount_nfs succeeded");
    return 0;
}

/* ---- fuse_main (POSIX) ---- */

int fuse_main(int argc, char *argv[],
              const struct fuse_operations *op, void *user_data)
{
    if (!op) return -1;

    posix_parsed_args_t args;
    if (posix_parse_args(argc, argv, &args) < 0)
        return -1;

    LFUSE_LOG("fuse_main: uid=%u euid=%u mount_point=%s",
              getuid(), geteuid(), args.mount_point);

    lamarckfuse_set_context(getuid(), getgid());

    void *init_result = NULL;

    lamarckfuse_config_t config;
    memset(&config, 0, sizeof(config));
    config.ops = op;
    config.user_data = user_data;
    config.uid = getuid();
    config.gid = getgid();
    config.volume_path = detect_volume_path();
    config.control_path = "/control";

    uint16_t port = 0;
    lamarckfuse_server_t *srv = nfs4_server_create(&config, &port);
    if (!srv) {
        LFUSE_ERR("Failed to create NFS server");
        return -1;
    }

    g_server = srv;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    pthread_t srv_thread;
    if (pthread_create(&srv_thread, NULL,
                       (void *(*)(void *))nfs4_server_run, srv) != 0) {
        LFUSE_ERR("Failed to create server thread");
        nfs4_server_destroy(srv);
        g_server = NULL;
        return -1;
    }

    if (do_mount_nfs(port, &args) < 0) {
        LFUSE_ERR("Failed to mount NFS");
        nfs4_server_stop(srv);
        pthread_join(srv_thread, NULL);
        nfs4_server_destroy(srv);
        g_server = NULL;
        return -1;
    }

    nfs4_server_stop(srv);
    pthread_join(srv_thread, NULL);

    LFUSE_LOG("mount succeeded, daemonizing");

    pid_t daemon_pid = fork();
    if (daemon_pid < 0) {
        nfs4_server_destroy(srv);
        g_server = NULL;
        return -1;
    }

    if (daemon_pid > 0) {
        LFUSE_LOG("Parent: _exit(0), daemon pid=%d", daemon_pid);
        _exit(0);
    }

    /* ---- Child (daemon) ---- */
    setsid();

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO)
            close(devnull);
    }

    nfs4_server_close_inherited_pipes(srv);

    if (op->init) {
        struct fuse_conn_info conn_info;
        memset(&conn_info, 0, sizeof(conn_info));
        conn_info.proto_major = 7;
        conn_info.proto_minor = 26;
        conn_info.max_write = 65536;
        conn_info.max_readahead = 65536;
        init_result = op->init(&conn_info);
    }

    {
        struct sigaction sa2;
        memset(&sa2, 0, sizeof(sa2));
        sa2.sa_handler = signal_handler;
        sigaction(SIGTERM, &sa2, NULL);
        sigaction(SIGINT, &sa2, NULL);
    }

    nfs4_server_restart(srv);

    LFUSE_LOG("Daemon: running event loop (pid=%d)", getpid());

    nfs4_server_run(srv);

    LFUSE_LOG("Daemon: server exited");

    nfs4_server_destroy(srv);
    g_server = NULL;

    if (op->destroy)
        op->destroy(init_result);

    _exit(0);
}

#endif /* _WIN32 */
