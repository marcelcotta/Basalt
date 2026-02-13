/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

/*
 * SCSI command handlers for Basalt's iSCSI target.
 * Implements a minimal SBC-3 block device for the Windows iSCSI Initiator.
 * Reference: SPC-4, SBC-3, RFC 7143
 */

#ifdef _WIN32

#include "iscsi_scsi.h"
#include "iscsi_pdu.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================
 * Big-endian helpers
 * ============================================================ */

static inline void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static inline void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static inline void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)(v));
}

static inline uint16_t get_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static inline uint64_t get_be64(const uint8_t *p)
{
    return ((uint64_t)get_be32(p) << 32) | get_be32(p + 4);
}

/* ============================================================
 * Response PDU builders
 * ============================================================ */

int scsi_send_response_good(SOCKET sock, const iscsi_pdu_t *req,
                             scsi_ctx_t *ctx, uint32_t residual)
{
    iscsi_pdu_t resp;
    iscsi_pdu_init(&resp);

    resp.bhs.opcode = ISCSI_OP_SCSI_RESP;
    resp.bhs.flags  = ISCSI_FLAG_FINAL;            /* F-bit in byte 1 per RFC 7143 */
    resp.bhs.rsvd2[0] = ISCSI_CMD_RSP_COMPLETED;  /* iSCSI response */
    resp.bhs.rsvd2[1] = SCSI_STATUS_GOOD;          /* SCSI status */
    resp.bhs.init_task_tag = req->bhs.init_task_tag;

    resp.bhs.u.scsi_resp.stat_sn    = htonl(ctx->stat_sn++);
    resp.bhs.u.scsi_resp.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    resp.bhs.u.scsi_resp.max_cmd_sn = htonl(ctx->max_cmd_sn);

    if (residual > 0)
    {
        resp.bhs.flags |= ISCSI_FLAG_RSP_UNDERFLOW;
        resp.bhs.u.scsi_resp.residual_count = htonl(residual);
    }

    return iscsi_pdu_write(sock, &resp);
}

int scsi_send_check_condition(SOCKET sock, const iscsi_pdu_t *req,
                               scsi_ctx_t *ctx,
                               uint8_t sense_key, uint16_t asc_ascq)
{
    iscsi_pdu_t resp;
    iscsi_pdu_init(&resp);

    /* Build fixed-format sense data (18 bytes) in data segment */
    uint8_t sense[18];
    memset(sense, 0, sizeof(sense));
    sense[0] = 0x70;                          /* Response code: current, fixed */
    sense[2] = sense_key;                     /* Sense key */
    sense[7] = 10;                            /* Additional sense length */
    sense[12] = (uint8_t)(asc_ascq >> 8);    /* ASC */
    sense[13] = (uint8_t)(asc_ascq);         /* ASCQ */

    resp.bhs.opcode = ISCSI_OP_SCSI_RESP;
    resp.bhs.flags  = ISCSI_FLAG_FINAL;            /* F-bit in byte 1 per RFC 7143 */
    resp.bhs.rsvd2[0] = ISCSI_CMD_RSP_COMPLETED;
    resp.bhs.rsvd2[1] = SCSI_STATUS_CHECK_CONDITION;
    resp.bhs.init_task_tag = req->bhs.init_task_tag;

    resp.bhs.u.scsi_resp.stat_sn    = htonl(ctx->stat_sn++);
    resp.bhs.u.scsi_resp.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    resp.bhs.u.scsi_resp.max_cmd_sn = htonl(ctx->max_cmd_sn);

    /* Sense data in data segment (2-byte length prefix + sense data) */
    uint8_t *data = (uint8_t *)malloc(2 + sizeof(sense));
    if (!data)
        return -1;

    put_be16(data, sizeof(sense));
    memcpy(data + 2, sense, sizeof(sense));

    resp.data = data;
    resp.data_len = 2 + sizeof(sense);
    iscsi_set_data_seg_len(&resp.bhs, resp.data_len);

    int rc = iscsi_pdu_write(sock, &resp);
    free(data);
    return rc;
}

/* ============================================================
 * INQUIRY (0x12) — Standard + VPD pages
 * ============================================================ */

static int handle_inquiry(SOCKET sock, const iscsi_pdu_t *req, scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    int evpd = cdb[1] & 0x01;
    uint8_t page_code = cdb[2];
    uint16_t alloc_len = get_be16(cdb + 3);
    uint8_t buf[256];
    uint32_t resp_len = 0;

    memset(buf, 0, sizeof(buf));

    if (!evpd)
    {
        /* Standard INQUIRY response */
        buf[0] = 0x00;   /* Device type: SBC (block device) */
        buf[1] = 0x80;   /* RMB=1: Removable media (needed for superfloppy support) */
        buf[2] = 0x05;   /* SPC-3 compliance */
        buf[3] = 0x02;   /* Response data format: SPC-3 */
        buf[4] = 91;     /* Additional length */
        buf[5] = 0x00;
        buf[6] = 0x00;
        buf[7] = 0x02;   /* CmdQue=1 (tagged command queuing) */

        /* T10 Vendor ID (8 bytes, space-padded) */
        memcpy(buf + 8, "BASALT  ", 8);
        /* Product ID (16 bytes, space-padded) */
        memcpy(buf + 16, "Encrypted Vol   ", 16);
        /* Product revision (4 bytes) */
        memcpy(buf + 32, "1.0 ", 4);

        resp_len = 96;
    }
    else
    {
        switch (page_code)
        {
        case SCSI_VPD_SUPPORTED_PAGES:
            buf[0] = 0x00;  /* Device type */
            buf[1] = 0x00;  /* Page code */
            buf[3] = 3;     /* Page length */
            buf[4] = 0x00;  /* Supported VPD Pages */
            buf[5] = 0x80;  /* Unit Serial Number */
            buf[6] = 0x83;  /* Device Identification */
            resp_len = 7;
            break;

        case SCSI_VPD_UNIT_SERIAL_NUM:
            buf[0] = 0x00;
            buf[1] = 0x80;
            buf[3] = 16;    /* Serial number length */
            memcpy(buf + 4, "BASALT0000000001", 16);
            resp_len = 20;
            break;

        case SCSI_VPD_DEVICE_ID:
        {
            buf[0] = 0x00;
            buf[1] = 0x83;
            /* NAA identifier (8 bytes) */
            uint8_t *desc = buf + 4;
            desc[0] = 0x01;  /* Protocol: iSCSI */
            desc[1] = 0x03;  /* Code set: UTF-8 */
            desc[2] = 0x00;  /* PIV=0, Association=LUN */
            desc[3] = (uint8_t)strlen("iqn.2025-01.org.basalt:vol0");
            memcpy(desc + 4, "iqn.2025-01.org.basalt:vol0",
                   strlen("iqn.2025-01.org.basalt:vol0"));
            uint32_t desc_len = 4 + desc[3];
            put_be16(buf + 2, (uint16_t)desc_len);
            resp_len = 4 + desc_len;
            break;
        }

        default:
            return scsi_send_check_condition(sock, req, ctx,
                       SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_CDB);
        }
    }

    /* Clamp to allocation length */
    if (resp_len > alloc_len)
        resp_len = alloc_len;

    /* Send Data-In PDU */
    iscsi_pdu_t din;
    iscsi_pdu_init(&din);
    din.bhs.opcode = ISCSI_OP_DATA_IN;
    din.bhs.flags  = ISCSI_FLAG_FINAL | ISCSI_FLAG_DATA_STATUS;  /* F-bit + Status valid */
    din.bhs.rsvd2[1] = SCSI_STATUS_GOOD;
    din.bhs.init_task_tag = req->bhs.init_task_tag;
    din.bhs.u.data_in.tgt_xfer_tag = htonl(0xFFFFFFFF);
    din.bhs.u.data_in.stat_sn    = htonl(ctx->stat_sn++);
    din.bhs.u.data_in.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    din.bhs.u.data_in.max_cmd_sn = htonl(ctx->max_cmd_sn);
    din.bhs.u.data_in.data_sn    = htonl(0);
    din.bhs.u.data_in.buffer_offset = htonl(0);

    iscsi_set_data_seg_len(&din.bhs, resp_len);
    din.data = buf;
    din.data_len = resp_len;

    uint32_t exp_xfer = ntohl(req->bhs.u.scsi_cmd.exp_data_xfer_len);
    if (resp_len < exp_xfer)
    {
        din.bhs.flags |= ISCSI_FLAG_DATA_UNDERFLOW;
        din.bhs.u.data_in.residual_count = htonl(exp_xfer - resp_len);
    }

    int rc = iscsi_pdu_write(sock, &din);
    din.data = NULL;  /* Don't free stack buffer */
    return rc;
}

/* ============================================================
 * READ CAPACITY (10) — 0x25
 * ============================================================ */

static int handle_read_capacity_10(SOCKET sock, const iscsi_pdu_t *req,
                                    scsi_ctx_t *ctx)
{
    uint64_t vol_size = ctx->io.get_volume_size(ctx->io.ctx);
    uint32_t sector_size = ctx->io.get_sector_size(ctx->io.ctx);

    if (sector_size == 0) sector_size = 512;
    if (vol_size == 0 || vol_size < sector_size)
    {
        fprintf(stderr, "[iSCSI] READ_CAPACITY(10): vol_size=%llu sector_size=%u — NOT READY\n",
                (unsigned long long)vol_size, sector_size);
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_NOT_READY, 0x0401);  /* LUN not ready, becoming ready */
    }

    uint64_t last_lba = (vol_size / sector_size) - 1;

    uint8_t buf[8];
    /* If >2TB, report 0xFFFFFFFF and let initiator use READ CAPACITY(16) */
    if (last_lba > 0xFFFFFFFFULL)
        put_be32(buf, 0xFFFFFFFF);
    else
        put_be32(buf, (uint32_t)last_lba);
    put_be32(buf + 4, sector_size);

    iscsi_pdu_t din;
    iscsi_pdu_init(&din);
    din.bhs.opcode = ISCSI_OP_DATA_IN;
    din.bhs.flags  = ISCSI_FLAG_FINAL | ISCSI_FLAG_DATA_STATUS;
    din.bhs.rsvd2[1] = SCSI_STATUS_GOOD;
    din.bhs.init_task_tag = req->bhs.init_task_tag;
    din.bhs.u.data_in.tgt_xfer_tag = htonl(0xFFFFFFFF);
    din.bhs.u.data_in.stat_sn    = htonl(ctx->stat_sn++);
    din.bhs.u.data_in.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    din.bhs.u.data_in.max_cmd_sn = htonl(ctx->max_cmd_sn);
    din.bhs.u.data_in.data_sn    = htonl(0);
    din.bhs.u.data_in.buffer_offset = htonl(0);

    iscsi_set_data_seg_len(&din.bhs, 8);
    din.data = buf;
    din.data_len = 8;

    /* Check for underflow: actual data < expected transfer length */
    uint32_t rc10_exp_xfer = ntohl(req->bhs.u.scsi_cmd.exp_data_xfer_len);
    if (8 < rc10_exp_xfer)
    {
        din.bhs.flags |= ISCSI_FLAG_DATA_UNDERFLOW;
        din.bhs.u.data_in.residual_count = htonl(rc10_exp_xfer - 8);
    }

    int rc = iscsi_pdu_write(sock, &din);
    din.data = NULL;
    return rc;
}

/* ============================================================
 * READ CAPACITY (16) — 0x9E/0x10
 * ============================================================ */

static int handle_read_capacity_16(SOCKET sock, const iscsi_pdu_t *req,
                                    scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    uint32_t alloc_len = get_be32(cdb + 10);

    uint64_t vol_size = ctx->io.get_volume_size(ctx->io.ctx);
    uint32_t sector_size = ctx->io.get_sector_size(ctx->io.ctx);

    if (sector_size == 0) sector_size = 512;
    if (vol_size == 0 || vol_size < sector_size)
    {
        fprintf(stderr, "[iSCSI] READ_CAPACITY(16): vol_size=%llu sector_size=%u — NOT READY\n",
                (unsigned long long)vol_size, sector_size);
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_NOT_READY, 0x0401);
    }

    uint64_t last_lba = (vol_size / sector_size) - 1;

    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    put_be64(buf, last_lba);
    put_be32(buf + 8, sector_size);
    /* Bytes 12-31: optional protection info, zeros are fine */

    uint32_t resp_len = 32;
    if (resp_len > alloc_len)
        resp_len = alloc_len;

    iscsi_pdu_t din;
    iscsi_pdu_init(&din);
    din.bhs.opcode = ISCSI_OP_DATA_IN;
    din.bhs.flags  = ISCSI_FLAG_FINAL | ISCSI_FLAG_DATA_STATUS;
    din.bhs.rsvd2[1] = SCSI_STATUS_GOOD;
    din.bhs.init_task_tag = req->bhs.init_task_tag;
    din.bhs.u.data_in.tgt_xfer_tag = htonl(0xFFFFFFFF);
    din.bhs.u.data_in.stat_sn    = htonl(ctx->stat_sn++);
    din.bhs.u.data_in.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    din.bhs.u.data_in.max_cmd_sn = htonl(ctx->max_cmd_sn);
    din.bhs.u.data_in.data_sn    = htonl(0);
    din.bhs.u.data_in.buffer_offset = htonl(0);

    iscsi_set_data_seg_len(&din.bhs, resp_len);
    din.data = buf;
    din.data_len = resp_len;

    /* Check for underflow: actual data < expected transfer length */
    uint32_t rc16_exp_xfer = ntohl(req->bhs.u.scsi_cmd.exp_data_xfer_len);
    if (resp_len < rc16_exp_xfer)
    {
        din.bhs.flags |= ISCSI_FLAG_DATA_UNDERFLOW;
        din.bhs.u.data_in.residual_count = htonl(rc16_exp_xfer - resp_len);
    }

    int rc = iscsi_pdu_write(sock, &din);
    din.data = NULL;
    return rc;
}

/* ============================================================
 * READ (10/16) — 0x28 / 0x88
 * ============================================================ */

static int handle_read(SOCKET sock, const iscsi_pdu_t *req, scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    uint64_t lba;
    uint32_t xfer_len_blocks;

    if (cdb[0] == SCSI_OP_READ_10)
    {
        lba = get_be32(cdb + 2);
        xfer_len_blocks = get_be16(cdb + 7);
    }
    else /* READ(16) */
    {
        lba = get_be64(cdb + 2);
        xfer_len_blocks = get_be32(cdb + 10);
    }

    if (xfer_len_blocks == 0)
        return scsi_send_response_good(sock, req, ctx, 0);

    uint32_t sector_size = ctx->io.get_sector_size(ctx->io.ctx);
    uint64_t vol_size = ctx->io.get_volume_size(ctx->io.ctx);
    if (sector_size == 0) sector_size = 512;

    uint64_t offset = lba * sector_size;
    uint64_t total_bytes = (uint64_t)xfer_len_blocks * sector_size;

    /* Only log large reads to reduce noise */
    if (total_bytes > 65536)
        fprintf(stderr, "[iSCSI] READ: lba=%llu blocks=%u bytes=%llu\n",
                (unsigned long long)lba, xfer_len_blocks, (unsigned long long)total_bytes);

    /* Bounds check */
    if (vol_size == 0 || offset + total_bytes > vol_size)
    {
        fprintf(stderr, "[iSCSI] READ: out of bounds!\n");
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_LBA_OOB);
    }

    /*
     * Send Data-In PDUs, splitting at max_recv_data_seg_len boundary.
     * The last PDU carries the SCSI status to avoid a separate Response PDU.
     */
    uint32_t max_payload = ctx->max_recv_data_seg_len;
    if (max_payload == 0)
        max_payload = 8192;

    /* Allocate read buffer (reused for all chunks) */
    uint8_t *buf = (uint8_t *)malloc(max_payload);
    if (!buf)
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_NOT_READY, 0x0000);

    uint32_t data_sn = 0;
    uint64_t remaining = total_bytes;
    uint64_t buf_offset = 0;

    while (remaining > 0)
    {
        uint32_t chunk = (remaining > max_payload) ? max_payload : (uint32_t)remaining;
        int is_last = (remaining - chunk == 0);

        /* Read decrypted data from volume */
        if (ctx->io.read_sectors(ctx->io.ctx, buf, offset + buf_offset, chunk) != 0)
        {
            free(buf);
            return scsi_send_check_condition(sock, req, ctx,
                       SCSI_SENSE_NOT_READY, 0x0000);
        }

        iscsi_pdu_t din;
        iscsi_pdu_init(&din);
        din.bhs.opcode = ISCSI_OP_DATA_IN;  /* 0x25 — no flags in opcode byte */
        if (is_last)
        {
            din.bhs.flags = ISCSI_FLAG_FINAL | ISCSI_FLAG_DATA_STATUS;  /* F-bit + S-bit in byte 1 */
            din.bhs.rsvd2[1] = SCSI_STATUS_GOOD;
            din.bhs.u.data_in.stat_sn = htonl(ctx->stat_sn++);
        }
        else
        {
            din.bhs.flags = 0;
            din.bhs.u.data_in.stat_sn = htonl(0);
        }

        din.bhs.init_task_tag = req->bhs.init_task_tag;
        din.bhs.u.data_in.tgt_xfer_tag = htonl(0xFFFFFFFF);
        din.bhs.u.data_in.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
        din.bhs.u.data_in.max_cmd_sn = htonl(ctx->max_cmd_sn);
        din.bhs.u.data_in.data_sn    = htonl(data_sn++);
        din.bhs.u.data_in.buffer_offset = htonl((uint32_t)buf_offset);

        iscsi_set_data_seg_len(&din.bhs, chunk);
        din.data = buf;
        din.data_len = chunk;

        int rc = iscsi_pdu_write(sock, &din);
        din.data = NULL;

        if (rc != 0)
        {
            free(buf);
            return -1;
        }

        remaining -= chunk;
        buf_offset += chunk;
    }

    free(buf);
    return 0;
}

/* ============================================================
 * WRITE (10/16) — 0x2A / 0x8A
 * Called AFTER Data-Out has been accumulated by the server.
 * req->data contains the write payload.
 * ============================================================ */

static int handle_write(SOCKET sock, const iscsi_pdu_t *req, scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    uint64_t lba;
    uint32_t xfer_len_blocks;

    if (cdb[0] == SCSI_OP_WRITE_10)
    {
        lba = get_be32(cdb + 2);
        xfer_len_blocks = get_be16(cdb + 7);
    }
    else /* WRITE(16) */
    {
        lba = get_be64(cdb + 2);
        xfer_len_blocks = get_be32(cdb + 10);
    }

    if (ctx->io.readonly)
    {
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_DATA_PROTECT, SCSI_ASC_WRITE_PROTECTED);
    }

    if (xfer_len_blocks == 0)
        return scsi_send_response_good(sock, req, ctx, 0);

    uint32_t sector_size = ctx->io.get_sector_size(ctx->io.ctx);
    uint64_t vol_size = ctx->io.get_volume_size(ctx->io.ctx);
    if (sector_size == 0) sector_size = 512;

    uint64_t offset = lba * sector_size;
    uint64_t total_bytes = (uint64_t)xfer_len_blocks * sector_size;

    /* Only log large writes to reduce noise */
    if (total_bytes > 65536)
        fprintf(stderr, "[iSCSI] WRITE: lba=%llu blocks=%u bytes=%llu\n",
                (unsigned long long)lba, xfer_len_blocks, (unsigned long long)total_bytes);

    /* Bounds check */
    if (vol_size == 0 || offset + total_bytes > vol_size)
    {
        fprintf(stderr, "[iSCSI] WRITE: out of bounds!\n");
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_LBA_OOB);
    }

    /* Verify we have the data */
    if (!req->data || req->data_len < total_bytes)
    {
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_CDB);
    }

    /* Write encrypted data to volume */
    if (ctx->io.write_sectors(ctx->io.ctx, req->data, offset, (uint32_t)total_bytes) != 0)
    {
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_NOT_READY, 0x0000);
    }

    return scsi_send_response_good(sock, req, ctx, 0);
}

/* ============================================================
 * TEST UNIT READY (0x00)
 * ============================================================ */

static int handle_test_unit_ready(SOCKET sock, const iscsi_pdu_t *req,
                                   scsi_ctx_t *ctx)
{
    return scsi_send_response_good(sock, req, ctx, 0);
}

/* ============================================================
 * REQUEST SENSE (0x03)
 * ============================================================ */

static int handle_request_sense(SOCKET sock, const iscsi_pdu_t *req,
                                 scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    uint8_t alloc_len = cdb[4];

    uint8_t buf[18];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x70;   /* Response code: current, fixed format */
    buf[2] = ctx->sense_key;
    buf[7] = 10;     /* Additional sense length */
    buf[12] = (uint8_t)(ctx->sense_asc_ascq >> 8);
    buf[13] = (uint8_t)(ctx->sense_asc_ascq);

    /* Clear pending sense */
    ctx->sense_key = SCSI_SENSE_NO_SENSE;
    ctx->sense_asc_ascq = 0;

    uint32_t resp_len = 18;
    if (resp_len > alloc_len)
        resp_len = alloc_len;

    iscsi_pdu_t din;
    iscsi_pdu_init(&din);
    din.bhs.opcode = ISCSI_OP_DATA_IN;
    din.bhs.flags  = ISCSI_FLAG_FINAL | ISCSI_FLAG_DATA_STATUS;
    din.bhs.rsvd2[1] = SCSI_STATUS_GOOD;
    din.bhs.init_task_tag = req->bhs.init_task_tag;
    din.bhs.u.data_in.tgt_xfer_tag = htonl(0xFFFFFFFF);
    din.bhs.u.data_in.stat_sn    = htonl(ctx->stat_sn++);
    din.bhs.u.data_in.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    din.bhs.u.data_in.max_cmd_sn = htonl(ctx->max_cmd_sn);
    din.bhs.u.data_in.data_sn    = htonl(0);
    din.bhs.u.data_in.buffer_offset = htonl(0);

    iscsi_set_data_seg_len(&din.bhs, resp_len);
    din.data = buf;
    din.data_len = resp_len;

    /* Check for underflow: actual data < expected transfer length */
    uint32_t rs_exp_xfer = ntohl(req->bhs.u.scsi_cmd.exp_data_xfer_len);
    if (resp_len < rs_exp_xfer)
    {
        din.bhs.flags |= ISCSI_FLAG_DATA_UNDERFLOW;
        din.bhs.u.data_in.residual_count = htonl(rs_exp_xfer - resp_len);
    }

    int rc = iscsi_pdu_write(sock, &din);
    din.data = NULL;
    return rc;
}

/* ============================================================
 * MODE SENSE (6/10) — 0x1A / 0x5A
 * ============================================================ */

static int handle_mode_sense(SOCKET sock, const iscsi_pdu_t *req,
                              scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    int is_10 = (cdb[0] == SCSI_OP_MODE_SENSE_10);
    uint8_t page_code = cdb[2] & 0x3F;
    uint8_t pc = (cdb[2] >> 6) & 0x03;  /* Page control */

    uint16_t alloc_len;
    if (is_10)
        alloc_len = get_be16(cdb + 7);
    else
        alloc_len = cdb[4];

    (void)pc;  /* Used for debug only */

    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    /* Reserve space for mode parameter header */
    uint32_t hdr_len = is_10 ? 8 : 4;
    uint32_t pos = hdr_len;  /* Current write position after header */

    /* Append mode pages based on requested page code */
    if (page_code == 0x08 || page_code == 0x3F)
    {
        /* Caching Mode Page (SBC-3 §6.4.5) — 20 bytes total */
        buf[pos]     = 0x08;  /* Page code */
        buf[pos + 1] = 0x12;  /* Page length (18 bytes follow) */
        /* All zeros = no caching (WCE=0, RCD=0) — safe defaults */
        pos += 20;
    }

    if (page_code == 0x0A || page_code == 0x3F)
    {
        /* Control Mode Page (SPC-4 §7.5.6) — 12 bytes total */
        buf[pos]     = 0x0A;  /* Page code */
        buf[pos + 1] = 0x0A;  /* Page length (10 bytes follow) */
        /* All zeros = default control settings */
        pos += 12;
    }

    if (page_code == 0x1C || page_code == 0x3F)
    {
        /* Informational Exceptions Control Mode Page (SPC-4 §7.5.11) — 12 bytes */
        buf[pos]     = 0x1C;  /* Page code */
        buf[pos + 1] = 0x0A;  /* Page length (10 bytes follow) */
        /* All zeros = exceptions disabled (DEXCPT=0, MRIE=0) */
        pos += 12;
    }

    /* Fill in mode parameter header */
    if (is_10)
    {
        uint16_t data_len = (uint16_t)(pos - 2);  /* Everything after the length field */
        put_be16(buf, data_len);
        buf[2] = 0x00;  /* Medium type */
        buf[3] = ctx->io.readonly ? 0x80 : 0x00;  /* Device-specific: WP bit */
        /* buf[4]: LONGLBA=0, buf[5]: reserved */
        /* buf[6..7]: Block descriptor length = 0 */
    }
    else
    {
        buf[0] = (uint8_t)(pos - 1);  /* Mode data length (everything after this byte) */
        buf[1] = 0x00;  /* Medium type */
        buf[2] = ctx->io.readonly ? 0x80 : 0x00;  /* Device-specific: WP bit */
        buf[3] = 0x00;  /* Block descriptor length = 0 */
    }

    uint32_t resp_len = pos;
    if (resp_len > alloc_len)
        resp_len = alloc_len;

    (void)0;  /* MODE_SENSE logging removed to reduce noise */

    iscsi_pdu_t din;
    iscsi_pdu_init(&din);
    din.bhs.opcode = ISCSI_OP_DATA_IN;
    din.bhs.flags  = ISCSI_FLAG_FINAL | ISCSI_FLAG_DATA_STATUS;
    din.bhs.rsvd2[1] = SCSI_STATUS_GOOD;
    din.bhs.init_task_tag = req->bhs.init_task_tag;
    din.bhs.u.data_in.tgt_xfer_tag = htonl(0xFFFFFFFF);
    din.bhs.u.data_in.stat_sn    = htonl(ctx->stat_sn++);
    din.bhs.u.data_in.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    din.bhs.u.data_in.max_cmd_sn = htonl(ctx->max_cmd_sn);
    din.bhs.u.data_in.data_sn    = htonl(0);
    din.bhs.u.data_in.buffer_offset = htonl(0);

    iscsi_set_data_seg_len(&din.bhs, resp_len);
    din.data = buf;
    din.data_len = resp_len;

    /* Check for underflow: actual data < expected transfer length */
    uint32_t ms_exp_xfer = ntohl(req->bhs.u.scsi_cmd.exp_data_xfer_len);
    if (resp_len < ms_exp_xfer)
    {
        din.bhs.flags |= ISCSI_FLAG_DATA_UNDERFLOW;
        din.bhs.u.data_in.residual_count = htonl(ms_exp_xfer - resp_len);
    }

    int rc = iscsi_pdu_write(sock, &din);
    din.data = NULL;
    return rc;
}

/* ============================================================
 * REPORT LUNS (0xA0)
 * ============================================================ */

static int handle_report_luns(SOCKET sock, const iscsi_pdu_t *req,
                               scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    uint32_t alloc_len = get_be32(cdb + 6);

    /* Single LUN 0 — 8 bytes header + 8 bytes per LUN */
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    put_be32(buf, 8);    /* LUN list length (8 bytes = 1 LUN) */
    /* LUN 0 is already all zeros (buf + 8..15) */

    uint32_t resp_len = 16;
    if (resp_len > alloc_len)
        resp_len = alloc_len;

    iscsi_pdu_t din;
    iscsi_pdu_init(&din);
    din.bhs.opcode = ISCSI_OP_DATA_IN;
    din.bhs.flags  = ISCSI_FLAG_FINAL | ISCSI_FLAG_DATA_STATUS;
    din.bhs.rsvd2[1] = SCSI_STATUS_GOOD;
    din.bhs.init_task_tag = req->bhs.init_task_tag;
    din.bhs.u.data_in.tgt_xfer_tag = htonl(0xFFFFFFFF);
    din.bhs.u.data_in.stat_sn    = htonl(ctx->stat_sn++);
    din.bhs.u.data_in.exp_cmd_sn = htonl(ctx->exp_cmd_sn);
    din.bhs.u.data_in.max_cmd_sn = htonl(ctx->max_cmd_sn);
    din.bhs.u.data_in.data_sn    = htonl(0);
    din.bhs.u.data_in.buffer_offset = htonl(0);

    iscsi_set_data_seg_len(&din.bhs, resp_len);
    din.data = buf;
    din.data_len = resp_len;

    /* Check for underflow: actual data < expected transfer length */
    uint32_t rl_exp_xfer = ntohl(req->bhs.u.scsi_cmd.exp_data_xfer_len);
    if (resp_len < rl_exp_xfer)
    {
        din.bhs.flags |= ISCSI_FLAG_DATA_UNDERFLOW;
        din.bhs.u.data_in.residual_count = htonl(rl_exp_xfer - resp_len);
    }

    int rc = iscsi_pdu_write(sock, &din);
    din.data = NULL;
    return rc;
}

/* ============================================================
 * PREVENT ALLOW MEDIUM REMOVAL (0x1E) — needed for RMB=1 devices
 * ============================================================ */

static int handle_prevent_allow_medium_removal(SOCKET sock, const iscsi_pdu_t *req,
                                                scsi_ctx_t *ctx)
{
    /* No-op: always allow removal. The Prevent field is in CDB byte 4 bits 1:0.
     * We don't actually prevent ejection since there's no physical media. */
    return scsi_send_response_good(sock, req, ctx, 0);
}

/* ============================================================
 * SYNCHRONIZE CACHE (0x35)
 * ============================================================ */

static int handle_sync_cache(SOCKET sock, const iscsi_pdu_t *req,
                              scsi_ctx_t *ctx)
{
    /* No-op for now — our writes go directly to the volume file */
    return scsi_send_response_good(sock, req, ctx, 0);
}

/* ============================================================
 * Main SCSI dispatch
 * ============================================================ */

int scsi_dispatch(SOCKET sock, const iscsi_pdu_t *req, scsi_ctx_t *ctx)
{
    const uint8_t *cdb = req->bhs.u.scsi_cmd.cdb;
    uint8_t opcode = cdb[0];

    /* Update expected command SN */
    uint32_t cmd_sn = ntohl(req->bhs.u.scsi_cmd.cmd_sn);
    ctx->exp_cmd_sn = cmd_sn + 1;
    ctx->max_cmd_sn = ctx->exp_cmd_sn + 31;  /* 32 outstanding commands */

    switch (opcode)
    {
    case SCSI_OP_TEST_UNIT_READY:
        return handle_test_unit_ready(sock, req, ctx);

    case SCSI_OP_REQUEST_SENSE:
        return handle_request_sense(sock, req, ctx);

    case SCSI_OP_INQUIRY:
        return handle_inquiry(sock, req, ctx);

    case SCSI_OP_MODE_SENSE_6:
    case SCSI_OP_MODE_SENSE_10:
        return handle_mode_sense(sock, req, ctx);

    case SCSI_OP_READ_CAPACITY_10:
        return handle_read_capacity_10(sock, req, ctx);

    case SCSI_OP_READ_CAPACITY_16:
    {
        /* Check service action */
        uint8_t sa = cdb[1] & 0x1F;
        if (sa == SCSI_SA_READ_CAPACITY_16)
            return handle_read_capacity_16(sock, req, ctx);
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_CDB);
    }

    case SCSI_OP_READ_10:
    case SCSI_OP_READ_16:
        return handle_read(sock, req, ctx);

    case SCSI_OP_WRITE_10:
    case SCSI_OP_WRITE_16:
        return handle_write(sock, req, ctx);

    case SCSI_OP_REPORT_LUNS:
        return handle_report_luns(sock, req, ctx);

    case SCSI_OP_PREVENT_ALLOW_MEDIUM_REMOVAL:
        return handle_prevent_allow_medium_removal(sock, req, ctx);

    case SCSI_OP_SYNC_CACHE_10:
        return handle_sync_cache(sock, req, ctx);

    default:
        fprintf(stderr, "[iSCSI] Unknown SCSI opcode 0x%02X\n", opcode);
        return scsi_send_check_condition(sock, req, ctx,
                   SCSI_SENSE_ILLEGAL_REQUEST, SCSI_ASC_INVALID_CDB);
    }
}

#endif /* _WIN32 */
