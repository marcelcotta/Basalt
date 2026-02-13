/*
 * LamarckFUSE — fuse_main() and fuse_get_context() implementation
 *
 * Windows-only FUSE implementation using iSCSI:
 *
 * - iSCSI target on 127.0.0.1:3260 serves encrypted volume data
 * - Windows iSCSI Initiator creates a real local block device
 * - No NFS, no VHD, no loopback filesystem restrictions
 * - Non-blocking: CreateThread for background iSCSI server
 * - SetConsoleCtrlHandler for SIGTERM equivalent
 *
 * On macOS/Linux, DarwinFUSE is used instead (separate directory).
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#include <fuse.h>

#include "lamarckfuse_internal.h"
#include "fuse_context.h"
#include "iscsi_target.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winioctl.h>
#include <ctype.h>
#include <signal.h>

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

/* ---- Global state for lifecycle management ---- */

static iscsi_server_t *g_iscsi_server = NULL;
static HANDLE g_iscsi_thread = NULL;
static const struct fuse_operations *g_ops = NULL;
static void *g_init_result = NULL;

/* iSCSI block-I/O callbacks (defined in FuseServiceWindows.cpp) */
extern int      basalt_iscsi_read(void *ctx, uint8_t *buf, uint64_t offset, uint32_t len);
extern int      basalt_iscsi_write(void *ctx, const uint8_t *buf, uint64_t offset, uint32_t len);
extern uint64_t basalt_iscsi_get_size(void *ctx);
extern uint32_t basalt_iscsi_get_sector_size(void *ctx);

static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
    (void)dwCtrlType;
    /* Only raise SIGINT — the CLI's signal handler sets TerminationRequested,
     * which breaks its wait loop and triggers DismountVolume → fuse_teardown.
     * Do NOT stop the iSCSI server here — fuse_teardown handles the proper
     * shutdown sequence (remove drive letter → remove portal → stop server). */
    raise(SIGINT);
    return TRUE;
}

/* ---- Command execution with timeout ---- */

/*
 * Run a command with a timeout using CreateProcessA.
 * Returns the exit code of the child process, or -1 on timeout/error.
 * Uses CREATE_NO_WINDOW to prevent console window popups.
 */
static int run_cmd_timeout(const char *cmd, DWORD timeout_ms)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    /* CreateProcessA needs a mutable command line */
    size_t len = strlen(cmd) + 1;
    char *cmdline = (char *)malloc(len);
    if (!cmdline) return -1;
    memcpy(cmdline, cmd, len);

    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmdline);
    if (!ok) {
        LFUSE_ERR("CreateProcess failed (error %lu): %s", GetLastError(), cmd);
        return -1;
    }

    DWORD wait = WaitForSingleObject(pi.hProcess, timeout_ms);
    if (wait == WAIT_TIMEOUT) {
        LFUSE_ERR("Command timed out after %lu ms: %s", timeout_ms, cmd);
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)exit_code;
}

/*
 * Detect the iSCSI disk number by probing PhysicalDrive devices.
 * Opens \\.\PhysicalDrive1, \\.\PhysicalDrive2, etc. and checks
 * IOCTL_STORAGE_QUERY_PROPERTY for BusType == BusTypeiScsi (9).
 * Returns the disk number (>=1) or 1 as last-resort fallback.
 */
static int detect_iscsi_disk_number(void)
{
    /* Try disks 1..15 (skip 0 = system disk) */
    for (int i = 1; i <= 15; i++) {
        char path[64];
        snprintf(path, sizeof(path), "\\\\.\\PhysicalDrive%d", i);
        HANDLE hDisk = CreateFileA(path, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, 0, NULL);
        if (hDisk == INVALID_HANDLE_VALUE)
            continue;

        /* Query storage adapter/device property for BusType */
        STORAGE_PROPERTY_QUERY query;
        memset(&query, 0, sizeof(query));
        query.PropertyId = StorageDeviceProperty;  /* 0 */
        query.QueryType  = PropertyStandardQuery;  /* 0 */

        uint8_t desc_buf[256];
        DWORD bytes_ret = 0;
        BOOL ok = DeviceIoControl(hDisk,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query, sizeof(query),
            desc_buf, sizeof(desc_buf),
            &bytes_ret, NULL);
        CloseHandle(hDisk);

        if (ok && bytes_ret >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            STORAGE_DEVICE_DESCRIPTOR *desc = (STORAGE_DEVICE_DESCRIPTOR *)desc_buf;
            /* BusTypeiScsi = 9 */
            if (desc->BusType == 9)
                return i;
        }
    }

    return -1;  /* Not found */
}

/* ---- iSCSI mount automation ---- */

/*
 * Self-test: try to TCP-connect to 127.0.0.1:port from within our process.
 * This verifies the iSCSI server is actually reachable before calling iscsicli.
 * Returns 0 on success, -1 on failure.
 */
static int iscsi_self_test(uint16_t port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        LFUSE_ERR("Self-test: socket() failed (error %d)", WSAGetLastError());
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    /* Set a 5-second connect timeout */
    DWORD timeout = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    int rc = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == SOCKET_ERROR) {
        LFUSE_ERR("Self-test: connect to 127.0.0.1:%u failed (error %d)",
                  (unsigned)port, WSAGetLastError());
        closesocket(s);
        return -1;
    }

    LFUSE_LOG("Self-test: TCP connect to 127.0.0.1:%u OK", (unsigned)port);
    closesocket(s);
    return 0;
}

/*
 * Pre-cleanup: Start MSiSCSI service and remove stale portals.
 * MUST be called BEFORE the iSCSI server starts listening,
 * otherwise the service will auto-connect to our port on startup
 * and cause session storms (TSIH 1-6 before we're ready).
 */
static void do_pre_cleanup_iscsi(void)
{
    LFUSE_LOG("Starting MSiSCSI service...");
    run_cmd_timeout("cmd.exe /c sc start MSiSCSI >NUL 2>&1", 10000);
    Sleep(500);

    /* Remove stale portal from any previous Basalt run.
     * This must happen while our port 3260 is NOT yet open,
     * so the service can't auto-reconnect. */
    LFUSE_LOG("Cleaning up stale iSCSI portals...");
    run_cmd_timeout("cmd.exe /c iscsicli RemoveTargetPortal 127.0.0.1 3260 * * >NUL 2>&1", 5000);
    Sleep(500);
}

/*
 * Connect to our iSCSI target, find the new disk,
 * and assign the requested drive letter.
 *
 * Called AFTER the iSCSI server is already listening.
 * All external commands run with timeouts to prevent indefinite hangs.
 */
static int do_mount_iscsi(const char *mount_point)
{
    char mp[16];
    memset(mp, 0, sizeof(mp));
    strncpy(mp, mount_point, sizeof(mp) - 1);
    size_t mplen = strlen(mp);
    while (mplen > 0 && (mp[mplen - 1] == '/' || mp[mplen - 1] == '\\')) {
        mp[--mplen] = '\0';
    }
    char target_letter = (char)toupper((unsigned char)mp[0]);

    /* Step 1: Self-test — verify our iSCSI server is reachable */
    LFUSE_LOG("Verifying iSCSI server is reachable...");
    if (iscsi_self_test(ISCSI_DEFAULT_PORT) != 0) {
        LFUSE_ERR("iSCSI server self-test failed!");
        LFUSE_ERR("The server may not be listening, or a firewall is blocking port %u",
                  (unsigned)ISCSI_DEFAULT_PORT);

        /* Try adding a firewall exception */
        LFUSE_LOG("Attempting to add Windows Firewall exception...");
        run_cmd_timeout("cmd.exe /c netsh advfirewall firewall add rule"
                        " name=\"Basalt iSCSI\" dir=in action=allow"
                        " protocol=tcp localport=3260"
                        " remoteip=127.0.0.1 >NUL 2>&1", 10000);
        Sleep(500);

        /* Retry self-test */
        if (iscsi_self_test(ISCSI_DEFAULT_PORT) != 0) {
            LFUSE_ERR("iSCSI server still unreachable after firewall exception");
            return -1;
        }
    }

    /* Step 2: Check if the Initiator already auto-connected (from persistent portal).
     * If the iSCSI disk is already present, skip discovery + login entirely. */
    {
        int disk = detect_iscsi_disk_number();
        if (disk > 0) {
            LFUSE_LOG("iSCSI disk already present (PhysicalDrive%d) — skipping discovery", disk);
            goto disk_ready;
        }
    }

    /* Step 3: Add target portal — triggers SendTargets discovery.
     * Use a short timeout — if it hangs (e.g. stale state), fall back to
     * direct LoginTarget which doesn't need a portal. */
    LFUSE_LOG("Adding iSCSI target portal...");
    {
        int rc = run_cmd_timeout("cmd.exe /c iscsicli QAddTargetPortal 127.0.0.1 >NUL 2>&1", 8000);
        if (rc == 0)
            Sleep(2000);  /* Wait for SendTargets discovery */
    }

    /* Step 4: Login to target.
     * Try QLoginTarget first (needs discovery), then full LoginTarget as fallback. */
    LFUSE_LOG("Logging in to iSCSI target...");
    {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
                 "cmd.exe /c iscsicli QLoginTarget %s",
                 ISCSI_DEFAULT_TARGET_IQN);
        int rc = run_cmd_timeout(cmd, 10000);

        if (rc != 0) {
            /* QLoginTarget failed — try full LoginTarget with explicit address.
             * This works even without a prior QAddTargetPortal. */
            snprintf(cmd, sizeof(cmd),
                     "cmd.exe /c iscsicli LoginTarget"
                     " %s T 127.0.0.1 3260"
                     " * * * * * * * * * * * 0 * 0",
                     ISCSI_DEFAULT_TARGET_IQN);
            run_cmd_timeout(cmd, 10000);
        }
    }

disk_ready:

    LFUSE_LOG("Waiting for iSCSI disk to appear...");

    /* Poll for the iSCSI disk to appear (BusType probing).
     * The Windows Initiator may take a few seconds to create the device. */
    int iscsi_disk_num = -1;
    for (int attempt = 0; attempt < 15; attempt++) {
        Sleep(1000);
        iscsi_disk_num = detect_iscsi_disk_number();
        if (iscsi_disk_num > 0) {
            /* Found! Wait 2 more seconds for volume to be populated */
            Sleep(2000);
            break;
        }
    }
    if (iscsi_disk_num <= 0) {
        LFUSE_ERR("iSCSI disk did not appear within 15 seconds");
        iscsi_disk_num = 1; /* Last resort fallback */
    }
    LFUSE_LOG("Using iSCSI disk number: %d", iscsi_disk_num);

    /* Step 7: Find iSCSI volume and assign the correct drive letter.
     *
     * The iSCSI disk is a superfloppy (no partition table, FAT at LBA 0)
     * reported as removable (RMB=1) so Windows auto-creates a volume and
     * brings the disk online automatically. No diskpart needed.
     *
     * Strategy:
     *   1. Find ALL volumes on our iSCSI disk
     *   2. Remove any auto-assigned letters that aren't the requested one
     *   3. Assign the requested letter to the primary volume
     */
    {

        /* --- Phase 3: find ALL iSCSI volumes, remove wrong letters, assign correct one ---
         *
         * Windows may auto-mount the iSCSI disk with one or more drive letters.
         * We need to:
         *   1. Find ALL volumes belonging to our iSCSI disk
         *   2. Remove any auto-assigned letters that aren't the requested one
         *   3. Assign the requested letter to the primary (first) volume
         */
        int assigned = 0;
        char iscsi_vol_name[MAX_PATH] = {0};  /* First iSCSI volume (for mount) */

        LFUSE_LOG("Searching for iSCSI volumes on disk %d...", iscsi_disk_num);
        {
            char vol_name[MAX_PATH];
            HANDLE hFind = FindFirstVolumeA(vol_name, sizeof(vol_name));
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    /* Check current mount point(s) */
                    char paths[512];
                    DWORD paths_len = 0;
                    BOOL has_path = GetVolumePathNamesForVolumeNameA(
                        vol_name, paths, sizeof(paths), &paths_len);
                    char cur_letter = 0;
                    if (has_path && paths[0] != '\0' &&
                        paths[1] == ':' && paths[2] == '\\')
                    {
                        cur_letter = (char)toupper((unsigned char)paths[0]);
                    }

                    /* Open volume and check device number */
                    char vol_dev[MAX_PATH];
                    strncpy(vol_dev, vol_name, sizeof(vol_dev) - 1);
                    vol_dev[sizeof(vol_dev) - 1] = '\0';
                    size_t vlen = strlen(vol_dev);
                    if (vlen > 0 && vol_dev[vlen - 1] == '\\')
                        vol_dev[vlen - 1] = '\0';

                    HANDLE hVol = CreateFileA(vol_dev, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
                    if (hVol != INVALID_HANDLE_VALUE) {
                        STORAGE_DEVICE_NUMBER sdn;
                        DWORD bytes_ret = 0;
                        if (DeviceIoControl(hVol,
                                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                NULL, 0, &sdn, sizeof(sdn),
                                &bytes_ret, NULL))
                        {
                            if ((int)sdn.DeviceNumber == iscsi_disk_num) {
                                LFUSE_LOG("  Disk %d volume: %s DevType=%lu (letter=%c)",
                                    iscsi_disk_num, vol_name,
                                    (unsigned long)sdn.DeviceType,
                                    cur_letter ? cur_letter : '-');

                                if (sdn.DeviceType == 7 /* FILE_DEVICE_DISK */) {
                                    /* This is the actual disk volume — use for mount */
                                    if (iscsi_vol_name[0] == '\0') {
                                        size_t n = strlen(vol_name);
                                        if (n >= sizeof(iscsi_vol_name))
                                            n = sizeof(iscsi_vol_name) - 1;
                                        memcpy(iscsi_vol_name, vol_name, n);
                                        iscsi_vol_name[n] = '\0';
                                    }

                                    if (cur_letter == target_letter) {
                                        assigned = 1;
                                    } else if (cur_letter != 0) {
                                        char old_mount[8];
                                        snprintf(old_mount, sizeof(old_mount),
                                                 "%c:\\", cur_letter);
                                        LFUSE_LOG("  Removing auto-assigned letter %c: ...",
                                                  cur_letter);
                                        DeleteVolumeMountPointA(old_mount);
                                    }
                                } else if (cur_letter != 0 && cur_letter != target_letter) {
                                    /* Non-disk volume (CD-ROM, etc.) on same device —
                                     * remove its auto-assigned letter too */
                                    char old_mount[8];
                                    snprintf(old_mount, sizeof(old_mount),
                                             "%c:\\", cur_letter);
                                    LFUSE_LOG("  Removing phantom volume letter %c: (DevType=%lu)...",
                                              cur_letter, (unsigned long)sdn.DeviceType);
                                    DeleteVolumeMountPointA(old_mount);
                                }
                            }
                        }
                        CloseHandle(hVol);
                    }
                } while (FindNextVolumeA(hFind, vol_name, sizeof(vol_name)));
                FindVolumeClose(hFind);
            }
        }

        if (assigned) {
            LFUSE_LOG("Volume already mounted at %c: — nothing to do", target_letter);
        } else if (iscsi_vol_name[0] != '\0') {
            /* Assign the requested letter to the first iSCSI volume */
            Sleep(500);
            char mount_path[8];
            snprintf(mount_path, sizeof(mount_path), "%c:\\", target_letter);
            LFUSE_LOG("Assigning drive letter %c: ...", target_letter);
            if (SetVolumeMountPointA(mount_path, iscsi_vol_name)) {
                LFUSE_LOG("Drive %c: assigned!", target_letter);
                assigned = 1;
            } else {
                LFUSE_LOG("SetVolumeMountPoint failed (err=%lu)", GetLastError());
            }
        }

        if (!assigned) {
            LFUSE_LOG("Could not assign drive letter %c:", target_letter);
            LFUSE_LOG("Try manually: diskmgmt.msc -> find iSCSI disk -> assign letter %c:",
                      target_letter);
        }

    }

    LFUSE_LOG("Mount automation completed for %s (via iSCSI)", mp);
    return 0;
}

static void do_unmount_iscsi(const char *mount_point)
{
    /* Step 1: Remove the drive letter (volume mount point) so Windows
     * stops accessing the volume through this path. */
    if (mount_point && mount_point[0]) {
        char target_letter = (char)toupper((unsigned char)mount_point[0]);
        char mount_path[8];
        snprintf(mount_path, sizeof(mount_path), "%c:\\", target_letter);
        LFUSE_LOG("Removing drive letter %c: ...", target_letter);
        if (!DeleteVolumeMountPointA(mount_path))
            LFUSE_LOG("DeleteVolumeMountPoint failed (err=%lu)", GetLastError());
        Sleep(500);
    }

    /* Step 2: Remove the target portal FIRST — this tells the Windows Initiator
     * to stop reconnecting to our target. Without this, the Initiator will
     * immediately try to reconnect after we close sessions. */
    LFUSE_LOG("Removing iSCSI target portal...");
    run_cmd_timeout("cmd.exe /c iscsicli RemoveTargetPortal 127.0.0.1 3260 * * >NUL 2>&1", 5000);

    /* Step 3: Stop the iSCSI server — this closes all session sockets,
     * which forces the Windows Initiator to detect the disconnection.
     * The server thread will exit after this. */
    LFUSE_LOG("Stopping iSCSI server...");
    if (g_iscsi_server)
        iscsi_server_stop(g_iscsi_server);

    /* Wait for server thread to exit */
    if (g_iscsi_thread) {
        WaitForSingleObject(g_iscsi_thread, 10000);
        CloseHandle(g_iscsi_thread);
        g_iscsi_thread = NULL;
    }

    /* Give Windows time to process the disk removal */
    Sleep(1000);

    LFUSE_LOG("iSCSI disconnected");
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
            }
        }
    }

    return 0;
}

/* ---- iSCSI server thread ---- */

static DWORD WINAPI iscsi_thread_func(LPVOID param)
{
    iscsi_server_t *srv = (iscsi_server_t *)param;
    iscsi_server_run(srv);
    return 0;
}

/* ---- fuse_main (Windows) — NON-BLOCKING ----
 *
 * On Windows, fuse_main() starts the iSCSI target server, connects
 * the Windows iSCSI Initiator, assigns a drive letter, and returns
 * immediately. The iSCSI server runs on a background thread.
 * Call fuse_teardown() to stop the server and clean up.
 */

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

    /* Parse arguments */
    parsed_args_t args;
    if (parse_args(argc, argv, &args) < 0) {
        WSACleanup();
        return -1;
    }

    LFUSE_LOG("fuse_main: mount_point=%s (iSCSI mode)", args.mount_point);

    /* Set initial FUSE context */
    lamarckfuse_set_context(0, 0);

    g_ops = op;

    /*
     * Call op->init() to start the encryption thread pool.
     * On Windows there's no fork, so this is straightforward.
     */
    if (op->init) {
        struct fuse_conn_info conn_info;
        memset(&conn_info, 0, sizeof(conn_info));
        conn_info.proto_major = 7;
        conn_info.proto_minor = 26;
        conn_info.max_write = 65536;
        conn_info.max_readahead = 65536;
        g_init_result = op->init(&conn_info);
    }

    /* Install Ctrl+C handler */
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    /* Clean up stale iSCSI state BEFORE starting our server.
     * This prevents MSiSCSI from auto-connecting to our port on startup. */
    do_pre_cleanup_iscsi();

    /* Create iSCSI server with crypto callbacks */
    iscsi_config_t iscsi_config;
    memset(&iscsi_config, 0, sizeof(iscsi_config));
    iscsi_config.read_sectors    = basalt_iscsi_read;
    iscsi_config.write_sectors   = basalt_iscsi_write;
    iscsi_config.get_volume_size = basalt_iscsi_get_size;
    iscsi_config.get_sector_size = basalt_iscsi_get_sector_size;
    iscsi_config.ctx             = NULL;
    iscsi_config.target_iqn      = ISCSI_DEFAULT_TARGET_IQN;
    iscsi_config.port            = ISCSI_DEFAULT_PORT;
    iscsi_config.readonly        = args.rdonly;

    g_iscsi_server = iscsi_server_create(&iscsi_config);
    if (!g_iscsi_server) {
        LFUSE_ERR("Failed to create iSCSI server");
        if (op->destroy) op->destroy(g_init_result);
        g_init_result = NULL;
        g_ops = NULL;
        WSACleanup();
        return -1;
    }

    /* Start iSCSI server in background thread */
    g_iscsi_thread = CreateThread(NULL, 0, iscsi_thread_func,
                                   g_iscsi_server, 0, NULL);
    if (!g_iscsi_thread) {
        LFUSE_ERR("Failed to create iSCSI server thread");
        iscsi_server_destroy(g_iscsi_server);
        g_iscsi_server = NULL;
        if (op->destroy) op->destroy(g_init_result);
        g_init_result = NULL;
        g_ops = NULL;
        WSACleanup();
        return -1;
    }

    /* Give the server a moment to start listening.
     * The self-test in do_mount_iscsi will verify connectivity. */
    Sleep(1000);

    /* Connect Windows iSCSI Initiator and assign drive letter */
    if (do_mount_iscsi(args.mount_point) < 0) {
        LFUSE_ERR("Failed to mount via iSCSI");
        iscsi_server_stop(g_iscsi_server);
        WaitForSingleObject(g_iscsi_thread, 5000);
        CloseHandle(g_iscsi_thread);
        g_iscsi_thread = NULL;
        iscsi_server_destroy(g_iscsi_server);
        g_iscsi_server = NULL;
        if (op->destroy) op->destroy(g_init_result);
        g_init_result = NULL;
        g_ops = NULL;
        WSACleanup();
        return -1;
    }

    LFUSE_LOG("fuse_main: mount succeeded, iSCSI server running in background");

    /* Return immediately — server runs in background.
     * Caller uses fuse_teardown() to stop everything. */
    return 0;
}

/* ---- fuse_teardown (Windows) ---- */

void fuse_teardown(const char *mount_point)
{
    LFUSE_LOG("fuse_teardown: unmounting %s", mount_point ? mount_point : "(null)");

    /* Unmount: remove drive letter, disconnect iSCSI, stop server */
    do_unmount_iscsi(mount_point);

    /* Destroy server (already stopped by do_unmount_iscsi) */
    if (g_iscsi_server) {
        iscsi_server_destroy(g_iscsi_server);
        g_iscsi_server = NULL;
    }

    /* Call op->destroy */
    if (g_ops && g_ops->destroy) {
        g_ops->destroy(g_init_result);
    }
    g_ops = NULL;
    g_init_result = NULL;

    /* Cleanup */
    SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
    WSACleanup();

    LFUSE_LOG("fuse_teardown: done");
}

