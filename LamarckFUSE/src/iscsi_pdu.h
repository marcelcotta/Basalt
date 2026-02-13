/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

/*
 * Minimal iSCSI PDU definitions for Basalt's userspace iSCSI target.
 * Implements only the subset needed by the Windows iSCSI Initiator.
 * Reference: RFC 7143 (iSCSI Protocol)
 */

#ifndef ISCSI_PDU_H
#define ISCSI_PDU_H

#ifdef _WIN32

#include <stdint.h>
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * iSCSI Opcode definitions (Initiator → Target)
 * ============================================================ */
#define ISCSI_OP_NOP_OUT            0x00
#define ISCSI_OP_SCSI_CMD           0x01
#define ISCSI_OP_TASK_MGT_REQ       0x02
#define ISCSI_OP_LOGIN_REQ          0x03
#define ISCSI_OP_TEXT_REQ           0x04
#define ISCSI_OP_DATA_OUT           0x05
#define ISCSI_OP_LOGOUT_REQ         0x06

/* Target → Initiator */
#define ISCSI_OP_NOP_IN             0x20
#define ISCSI_OP_SCSI_RESP          0x21
#define ISCSI_OP_TASK_MGT_RESP      0x22
#define ISCSI_OP_LOGIN_RESP         0x23
#define ISCSI_OP_TEXT_RESP          0x24
#define ISCSI_OP_DATA_IN            0x25
#define ISCSI_OP_LOGOUT_RESP        0x26
#define ISCSI_OP_R2T                0x31
#define ISCSI_OP_REJECT             0x3F

/* Opcode mask (low 6 bits) */
#define ISCSI_OPCODE_MASK           0x3F

/* BHS flags */
#define ISCSI_FLAG_IMMEDIATE        0x40  /* Immediate delivery */
#define ISCSI_FLAG_FINAL            0x80  /* Final PDU in sequence */

/* SCSI Command flags (byte 1) */
#define ISCSI_FLAG_CMD_READ         0x40
#define ISCSI_FLAG_CMD_WRITE        0x20
#define ISCSI_FLAG_CMD_ATTR_MASK    0x07
#define ISCSI_CMD_ATTR_SIMPLE       0x00
#define ISCSI_CMD_ATTR_ORDERED      0x01
#define ISCSI_CMD_ATTR_HEAD_OF_Q    0x02
#define ISCSI_CMD_ATTR_ACA          0x03
#define ISCSI_CMD_ATTR_UNTAGGED     0x00

/* Data-In flags (byte 1) */
#define ISCSI_FLAG_DATA_ACK         0x40
#define ISCSI_FLAG_DATA_OVERFLOW    0x04
#define ISCSI_FLAG_DATA_UNDERFLOW   0x02
#define ISCSI_FLAG_DATA_STATUS      0x01  /* Status is valid */

/* Login flags (byte 1) */
#define ISCSI_FLAG_LOGIN_TRANSIT    0x80  /* Transition to next stage */
#define ISCSI_FLAG_LOGIN_CONTINUE   0x40  /* More login PDUs to follow */

/* Login stages (CSG/NSG in byte 1) */
#define ISCSI_LOGIN_CSG_MASK        0x0C
#define ISCSI_LOGIN_NSG_MASK        0x03
#define ISCSI_LOGIN_STAGE_SECURITY  0x00
#define ISCSI_LOGIN_STAGE_OPERATE   0x01
#define ISCSI_LOGIN_STAGE_FULL      0x03

/* Login status classes */
#define ISCSI_LOGIN_STATUS_SUCCESS  0x0000
#define ISCSI_LOGIN_STATUS_MOVED    0x0100
#define ISCSI_LOGIN_STATUS_INIT_ERR 0x0200
#define ISCSI_LOGIN_STATUS_TGT_ERR  0x0300

/* Task Management function codes */
#define ISCSI_TMF_ABORT_TASK        1
#define ISCSI_TMF_ABORT_TASK_SET    2
#define ISCSI_TMF_CLEAR_ACA         3
#define ISCSI_TMF_CLEAR_TASK_SET    4
#define ISCSI_TMF_LUN_RESET         5
#define ISCSI_TMF_TARGET_WARM_RESET 6
#define ISCSI_TMF_TARGET_COLD_RESET 7

/* Task Management response codes */
#define ISCSI_TMF_RSP_COMPLETE      0
#define ISCSI_TMF_RSP_NOT_SUPPORTED 5

/* Logout reason codes */
#define ISCSI_LOGOUT_CLOSE_SESSION  0
#define ISCSI_LOGOUT_CLOSE_CONN     1
#define ISCSI_LOGOUT_REMOVE_CONN    2

/* SCSI status codes */
#define SCSI_STATUS_GOOD            0x00
#define SCSI_STATUS_CHECK_CONDITION 0x02
#define SCSI_STATUS_BUSY            0x08

/* iSCSI response codes */
#define ISCSI_CMD_RSP_COMPLETED     0x00
#define ISCSI_CMD_RSP_TARGET_FAIL   0x01

/* SCSI response overflow/underflow */
#define ISCSI_FLAG_RSP_OVERFLOW     0x04
#define ISCSI_FLAG_RSP_UNDERFLOW    0x02

/* ============================================================
 * Basic Header Segment (BHS) — 48 bytes, always present
 * ============================================================ */
#pragma pack(push, 1)
typedef struct {
    uint8_t  opcode;           /* Opcode + Immediate flag */
    uint8_t  flags;            /* Opcode-specific flags */
    uint8_t  rsvd2[2];        /* Opcode-specific or reserved */
    uint8_t  total_ahs_len;    /* Total AHS length (in 4-byte words) */
    uint8_t  data_seg_len[3];  /* Data segment length (24-bit big-endian) */

    uint8_t  lun[8];           /* Logical Unit Number */

    uint32_t init_task_tag;    /* Initiator Task Tag */

    /* Bytes 20-47: opcode-specific fields */
    union {
        /* Generic 28 bytes */
        uint8_t raw[28];

        /* SCSI Command (opcode 0x01) */
        struct {
            uint32_t exp_data_xfer_len;   /* Expected data transfer length */
            uint32_t cmd_sn;
            uint32_t exp_stat_sn;
            uint8_t  cdb[16];             /* SCSI CDB */
        } scsi_cmd;

        /* SCSI Response (opcode 0x21) */
        struct {
            uint32_t stat_sn;
            uint32_t exp_cmd_sn;
            uint32_t max_cmd_sn;
            uint32_t exp_data_sn;
            uint32_t bi_residual_count;
            uint32_t residual_count;
            uint32_t rsvd;
        } scsi_resp;

        /* Data-In (opcode 0x25) */
        struct {
            uint32_t tgt_xfer_tag;
            uint32_t stat_sn;
            uint32_t exp_cmd_sn;
            uint32_t max_cmd_sn;
            uint32_t data_sn;
            uint32_t buffer_offset;
            uint32_t residual_count;
        } data_in;

        /* Data-Out (opcode 0x05) */
        struct {
            uint32_t tgt_xfer_tag;
            uint32_t rsvd1;
            uint32_t exp_stat_sn;
            uint32_t rsvd2;
            uint32_t data_sn;
            uint32_t buffer_offset;
            uint32_t rsvd3;
        } data_out;

        /* R2T (opcode 0x31) */
        struct {
            uint32_t tgt_xfer_tag;
            uint32_t stat_sn;
            uint32_t exp_cmd_sn;
            uint32_t max_cmd_sn;
            uint32_t r2t_sn;
            uint32_t buffer_offset;
            uint32_t desired_data_xfer_len;
        } r2t;

        /* Login Request/Response (opcode 0x03/0x23) */
        struct {
            uint32_t cid_or_status;    /* CID (req) or Status (resp) */
            uint32_t cmd_sn_or_stat_sn;
            uint32_t exp_sn;           /* ExpStatSN (req) or ExpCmdSN (resp) */
            uint32_t max_cmd_sn;       /* MaxCmdSN (resp only) */
            uint8_t  isid[6];          /* Initiator Session ID */
            uint16_t tsih;             /* Target Session Handle */
        } login;

        /* Text Request/Response (opcode 0x04/0x24) */
        struct {
            uint32_t tgt_xfer_tag;
            uint32_t cmd_sn;
            uint32_t exp_stat_sn;
            uint8_t  rsvd[16];
        } text;

        /* NOP-Out/NOP-In (opcode 0x00/0x20) */
        struct {
            uint32_t tgt_xfer_tag;
            uint32_t cmd_sn;
            uint32_t exp_stat_sn;
            uint8_t  rsvd[16];
        } nop;

        /* Task Management Request (opcode 0x02) */
        struct {
            uint32_t ref_task_tag;
            uint32_t cmd_sn;
            uint32_t exp_stat_sn;
            uint32_t ref_cmd_sn;
            uint32_t exp_data_sn;
            uint8_t  rsvd[8];
        } task_mgmt;

        /* Task Management Response (opcode 0x22) */
        struct {
            uint32_t rsvd1;
            uint32_t stat_sn;
            uint32_t exp_cmd_sn;
            uint32_t max_cmd_sn;
            uint8_t  rsvd2[12];
        } task_mgmt_resp;

        /* Logout Request/Response (opcode 0x06/0x26) */
        struct {
            uint32_t cid;
            uint32_t cmd_sn_or_stat_sn;
            uint32_t exp_sn;
            uint32_t max_cmd_sn;  /* Response only */
            uint8_t  rsvd[12];
        } logout;
    } u;
} iscsi_bhs_t;
#pragma pack(pop)

/* Verify BHS is exactly 48 bytes */
typedef char static_assert_bhs_size[(sizeof(iscsi_bhs_t) == 48) ? 1 : -1];

/* ============================================================
 * PDU container (BHS + optional data segment)
 * ============================================================ */
typedef struct {
    iscsi_bhs_t  bhs;
    uint8_t     *data;          /* Data segment (malloc'd, may be NULL) */
    uint32_t     data_len;      /* Length of data segment */
} iscsi_pdu_t;

/* ============================================================
 * Helper functions for 24-bit data segment length field
 * ============================================================ */
static inline uint32_t iscsi_get_data_seg_len(const iscsi_bhs_t *bhs)
{
    return ((uint32_t)bhs->data_seg_len[0] << 16) |
           ((uint32_t)bhs->data_seg_len[1] << 8)  |
           ((uint32_t)bhs->data_seg_len[2]);
}

static inline void iscsi_set_data_seg_len(iscsi_bhs_t *bhs, uint32_t len)
{
    bhs->data_seg_len[0] = (uint8_t)(len >> 16);
    bhs->data_seg_len[1] = (uint8_t)(len >> 8);
    bhs->data_seg_len[2] = (uint8_t)(len);
}

/* Padding: iSCSI data segments are padded to 4-byte boundaries */
static inline uint32_t iscsi_pad4(uint32_t len)
{
    return (len + 3) & ~3u;
}

/* ============================================================
 * PDU I/O functions
 * ============================================================ */

/*
 * Read a complete PDU from socket.
 * Returns 0 on success, -1 on error/disconnect.
 * Caller must call iscsi_pdu_free() when done.
 */
int iscsi_pdu_read(SOCKET sock, iscsi_pdu_t *pdu);

/*
 * Write a complete PDU to socket.
 * Returns 0 on success, -1 on error.
 */
int iscsi_pdu_write(SOCKET sock, const iscsi_pdu_t *pdu);

/*
 * Free data segment of a PDU.
 */
void iscsi_pdu_free(iscsi_pdu_t *pdu);

/*
 * Initialize a PDU to zeros.
 */
void iscsi_pdu_init(iscsi_pdu_t *pdu);

/* ============================================================
 * Key-Value text parameter parsing (for Login/Text PDUs)
 * ============================================================ */

/* Callback for each key=value pair found */
typedef void (*iscsi_kv_callback_t)(const char *key, const char *value, void *ctx);

/*
 * Parse a NUL-separated key=value list from a data segment.
 * Calls cb for each key=value pair found.
 * data: pointer to NUL-separated "key=value\0key=value\0..." buffer
 * len: total length of buffer
 */
void iscsi_kv_parse(const uint8_t *data, uint32_t len,
                    iscsi_kv_callback_t cb, void *ctx);

/*
 * Append a key=value pair to a buffer.
 * Returns new length (including NUL terminator).
 * buf must have enough space. Returns 0 on error.
 */
uint32_t iscsi_kv_append(uint8_t *buf, uint32_t buf_size, uint32_t offset,
                         const char *key, const char *value);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* ISCSI_PDU_H */
