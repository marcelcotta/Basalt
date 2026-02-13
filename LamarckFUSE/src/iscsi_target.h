/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

/*
 * Minimal iSCSI target for Basalt.
 * Runs on 127.0.0.1:3260, serves a single LUN backed by encrypted volume data.
 * The Windows iSCSI Initiator connects and creates a real local block device.
 *
 * Architecture:
 *   Crypto layer (FuseService) → iSCSI Target → Windows iSCSI Initiator → \\.\PhysicalDriveN → M:
 *
 * No NFS, no VHD, no loopback filesystem restrictions.
 */

#ifndef ISCSI_TARGET_H
#define ISCSI_TARGET_H

#ifdef _WIN32

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Configuration
 * ============================================================ */
typedef struct {
    /* Block-I/O callbacks — call into FuseService crypto layer */
    int      (*read_sectors)(void *ctx, uint8_t *buf, uint64_t offset, uint32_t len);
    int      (*write_sectors)(void *ctx, const uint8_t *buf, uint64_t offset, uint32_t len);
    uint64_t (*get_volume_size)(void *ctx);
    uint32_t (*get_sector_size)(void *ctx);
    void     *ctx;

    const char *target_iqn;   /* e.g. "iqn.2025-01.org.basalt:vol0" */
    uint16_t    port;         /* Default: 3260 */
    int         readonly;     /* 1 = read-only volume */
} iscsi_config_t;

/* Opaque server handle */
typedef struct iscsi_server iscsi_server_t;

/* ============================================================
 * Server lifecycle
 * ============================================================ */

/*
 * Create an iSCSI server with the given configuration.
 * Does NOT start listening — call iscsi_server_run() for that.
 * Returns NULL on error.
 */
iscsi_server_t *iscsi_server_create(const iscsi_config_t *config);

/*
 * Run the iSCSI server (BLOCKING).
 * Listens on 127.0.0.1:port, accepts connections, handles sessions.
 * Returns when iscsi_server_stop() is called from another thread.
 * Returns 0 on clean shutdown, -1 on error.
 */
int iscsi_server_run(iscsi_server_t *srv);

/*
 * Signal the server to stop (THREAD-SAFE).
 * Can be called from any thread. iscsi_server_run() will return.
 */
void iscsi_server_stop(iscsi_server_t *srv);

/*
 * Free server resources. Call after iscsi_server_run() has returned.
 */
void iscsi_server_destroy(iscsi_server_t *srv);

/* Default target IQN and port */
#define ISCSI_DEFAULT_TARGET_IQN  "iqn.2025-01.org.basalt:vol0"
#define ISCSI_DEFAULT_PORT        3260
#define ISCSI_BASE_PORT           3260

/*
 * Get the iSCSI port for a given slot number.
 * Port = ISCSI_BASE_PORT + (slot - 1), so slot 1 → 3260, slot 2 → 3261, etc.
 */
static inline uint16_t iscsi_port_for_slot(int slot)
{
    return (uint16_t)(ISCSI_BASE_PORT + (slot > 0 ? slot - 1 : 0));
}

/*
 * Build a unique IQN for a given slot number.
 * Format: "iqn.2025-01.org.basalt:vol{slot}"
 * Buffer must be at least 64 bytes.
 */
static inline void iscsi_iqn_for_slot(int slot, char *buf, size_t bufsize)
{
    snprintf(buf, bufsize, "iqn.2025-01.org.basalt:vol%d", slot);
}

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* ISCSI_TARGET_H */
