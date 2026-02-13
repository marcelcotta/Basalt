/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

/*
 * SCSI command definitions and dispatch for Basalt's iSCSI target.
 * Implements the minimal SCSI command set needed by the Windows iSCSI Initiator
 * to present a block device (SBC-3 subset).
 */

#ifndef ISCSI_SCSI_H
#define ISCSI_SCSI_H

#ifdef _WIN32

#include <stdint.h>
#include <winsock2.h>
#include "iscsi_pdu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SCSI CDB opcodes (SPC-4 / SBC-3 subset)
 * ============================================================ */
#define SCSI_OP_TEST_UNIT_READY     0x00
#define SCSI_OP_REQUEST_SENSE       0x03
#define SCSI_OP_INQUIRY             0x12
#define SCSI_OP_MODE_SENSE_6        0x1A
#define SCSI_OP_PREVENT_ALLOW_MEDIUM_REMOVAL 0x1E
#define SCSI_OP_READ_CAPACITY_10    0x25
#define SCSI_OP_READ_10             0x28
#define SCSI_OP_WRITE_10            0x2A
#define SCSI_OP_SYNC_CACHE_10       0x35
#define SCSI_OP_MODE_SENSE_10       0x5A
#define SCSI_OP_READ_16             0x88
#define SCSI_OP_WRITE_16            0x8A
#define SCSI_OP_READ_CAPACITY_16    0x9E  /* SERVICE ACTION IN (16) */
#define SCSI_OP_REPORT_LUNS         0xA0

/* SERVICE ACTION for READ CAPACITY(16) */
#define SCSI_SA_READ_CAPACITY_16    0x10

/* SCSI sense key codes */
#define SCSI_SENSE_NO_SENSE         0x00
#define SCSI_SENSE_NOT_READY        0x02
#define SCSI_SENSE_ILLEGAL_REQUEST  0x05
#define SCSI_SENSE_DATA_PROTECT     0x07

/* Additional Sense Code (ASC) + ASCQ */
#define SCSI_ASC_INVALID_CDB        0x2400  /* Invalid field in CDB */
#define SCSI_ASC_LBA_OOB            0x2100  /* Logical block address out of range */
#define SCSI_ASC_WRITE_PROTECTED    0x2700  /* Write protected */

/* INQUIRY VPD page codes */
#define SCSI_VPD_SUPPORTED_PAGES    0x00
#define SCSI_VPD_UNIT_SERIAL_NUM    0x80
#define SCSI_VPD_DEVICE_ID          0x83

/* ============================================================
 * Block I/O callback interface (set by iSCSI target)
 * ============================================================ */
typedef struct {
    int      (*read_sectors)(void *ctx, uint8_t *buf, uint64_t offset, uint32_t len);
    int      (*write_sectors)(void *ctx, const uint8_t *buf, uint64_t offset, uint32_t len);
    uint64_t (*get_volume_size)(void *ctx);
    uint32_t (*get_sector_size)(void *ctx);
    void     *ctx;
    int       readonly;
} scsi_io_t;

/* ============================================================
 * SCSI command processing context
 * ============================================================ */
typedef struct {
    scsi_io_t   io;             /* Block I/O callbacks */

    /* iSCSI session sequence numbers (updated by dispatch) */
    uint32_t    stat_sn;
    uint32_t    exp_cmd_sn;
    uint32_t    max_cmd_sn;

    /* Max data-in payload per PDU (negotiated) */
    uint32_t    max_recv_data_seg_len;

    /* Pending sense data */
    uint8_t     sense_key;
    uint16_t    sense_asc_ascq;  /* ASC << 8 | ASCQ */
} scsi_ctx_t;

/* ============================================================
 * SCSI command dispatch
 * ============================================================ */

/*
 * Process a SCSI Command PDU.
 *
 * req: incoming SCSI Command PDU (opcode 0x01)
 * ctx: SCSI processing context with I/O callbacks
 * sock: socket to send Data-In / Response PDUs on
 *
 * This function handles:
 *   - Parsing the CDB from the request PDU
 *   - Executing the command (read from / write to volume via callbacks)
 *   - Sending Data-In PDUs for reads
 *   - Sending SCSI Response PDU
 *
 * For WRITE commands: caller must handle R2T/Data-Out exchange
 * before calling this. The write data should be in req->data.
 *
 * Returns 0 on success, -1 on socket error.
 */
int scsi_dispatch(SOCKET sock, const iscsi_pdu_t *req, scsi_ctx_t *ctx);

/*
 * Build and send a SCSI Response PDU with CHECK CONDITION status.
 * Used when a command encounters an error.
 */
int scsi_send_check_condition(SOCKET sock, const iscsi_pdu_t *req,
                               scsi_ctx_t *ctx,
                               uint8_t sense_key, uint16_t asc_ascq);

/*
 * Build and send a SCSI Response PDU with GOOD status.
 */
int scsi_send_response_good(SOCKET sock, const iscsi_pdu_t *req,
                             scsi_ctx_t *ctx, uint32_t residual);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* ISCSI_SCSI_H */
