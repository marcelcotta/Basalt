/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

/*
 * Minimal iSCSI target server for Basalt.
 *
 * Implements RFC 7143 iSCSI for a single LUN backed by encrypted volume data.
 * Only handles the subset needed by the Windows iSCSI Initiator:
 *   - Login negotiation (SecurityNegotiation + OperationalNegotiation)
 *   - SCSI command dispatch (via iscsi_scsi.c)
 *   - R2T / Data-Out for writes
 *   - NOP-In/Out keepalive
 *   - Text request (SendTargets discovery)
 *   - Task management (abort)
 *   - Logout
 *
 * Architecture: WSAPoll-based event loop with wakeup socket for stop signal.
 * Max 2 concurrent connections (1 active + 1 reconnect overlap).
 */

#ifdef _WIN32

#include "iscsi_target.h"
#include "iscsi_pdu.h"
#include "iscsi_scsi.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

/* ============================================================
 * Server internal state
 * ============================================================ */

/* Session states */
#define SESS_STATE_FREE          0
#define SESS_STATE_LOGIN         1
#define SESS_STATE_FULL_FEATURE  2

typedef struct {
    SOCKET      sock;
    int         state;
    uint32_t    cmd_sn;
    uint32_t    exp_cmd_sn;
    uint32_t    max_cmd_sn;
    uint32_t    stat_sn;
    uint16_t    tsih;           /* Target Session Handle */
    uint8_t     isid[6];       /* Initiator Session ID (for reinstatement matching) */
    uint32_t    max_recv_data_seg_len;   /* Negotiated, initiator → target */
    uint32_t    max_send_data_seg_len;   /* Negotiated, target → initiator */
    uint32_t    max_burst_length;
    uint32_t    first_burst_length;
    int         initial_r2t;
    int         immediate_data;
    uint32_t    scsi_cmd_count; /* Number of SCSI commands processed */
    scsi_ctx_t  scsi;           /* SCSI command processor */
} iscsi_session_t;

#define MAX_SESSIONS 4

struct iscsi_server {
    iscsi_config_t   config;
    SOCKET           listen_sock;
    SOCKET           wakeup_send;   /* Send end of wakeup pair */
    SOCKET           wakeup_recv;   /* Recv end of wakeup pair */
    volatile int     running;
    iscsi_session_t  sessions[MAX_SESSIONS];
    uint16_t         next_tsih;
};

/* ============================================================
 * Wakeup socket pair (TCP loopback, since Windows lacks socketpair)
 * ============================================================ */

static int create_wakeup_pair(SOCKET *recv_sock, SOCKET *send_sock)
{
    SOCKET listener = INVALID_SOCKET;
    SOCKET s1 = INVALID_SOCKET, s2 = INVALID_SOCKET;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  /* Ephemeral port */

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        goto fail;

    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR)
        goto fail;

    if (listen(listener, 1) == SOCKET_ERROR)
        goto fail;

    s1 = socket(AF_INET, SOCK_STREAM, 0);
    if (s1 == INVALID_SOCKET)
        goto fail;

    if (connect(s1, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
        goto fail;

    s2 = accept(listener, NULL, NULL);
    if (s2 == INVALID_SOCKET)
        goto fail;

    closesocket(listener);
    *send_sock = s1;
    *recv_sock = s2;
    return 0;

fail:
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (s1 != INVALID_SOCKET) closesocket(s1);
    if (s2 != INVALID_SOCKET) closesocket(s2);
    return -1;
}

/* ============================================================
 * Login negotiation
 * ============================================================ */

/* Context for collecting login parameters */
typedef struct {
    iscsi_session_t *sess;
    const iscsi_server_t *srv;
    uint8_t *resp_buf;
    uint32_t resp_buf_size;
    uint32_t resp_len;
    int       got_initiator_name;
    int       got_session_type;
    int       is_discovery;
} login_ctx_t;

static void login_kv_handler(const char *key, const char *value, void *opaque)
{
    login_ctx_t *lctx = (login_ctx_t *)opaque;

    if (strcmp(key, "InitiatorName") == 0)
    {
        lctx->got_initiator_name = 1;
    }
    else if (strcmp(key, "SessionType") == 0)
    {
        lctx->is_discovery = (strcmp(value, "Discovery") == 0);
        lctx->got_session_type = 1;
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "SessionType", value);
    }
    else if (strcmp(key, "TargetName") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "TargetName", value);
        /* RFC 7143 §13.9: target MUST provide TargetPortalGroupTag at login */
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "TargetPortalGroupTag", "1");
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "TargetAlias", "Basalt");
    }
    else if (strcmp(key, "AuthMethod") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "AuthMethod", "None");
    }
    else if (strcmp(key, "HeaderDigest") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "HeaderDigest", "None");
    }
    else if (strcmp(key, "DataDigest") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "DataDigest", "None");
    }
    else if (strcmp(key, "MaxRecvDataSegmentLength") == 0)
    {
        /* This is the initiator's max recv — becomes our max send */
        uint32_t v = (uint32_t)atoi(value);
        if (v > 0)
            lctx->sess->max_send_data_seg_len = v;
        /* Respond with our max recv */
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "MaxRecvDataSegmentLength", "262144");
        lctx->sess->max_recv_data_seg_len = 262144;
    }
    else if (strcmp(key, "InitialR2T") == 0)
    {
        /* We require InitialR2T=Yes to simplify write path */
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "InitialR2T", "Yes");
        lctx->sess->initial_r2t = 1;
    }
    else if (strcmp(key, "ImmediateData") == 0)
    {
        /* Disable immediate data to simplify write path */
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "ImmediateData", "No");
        lctx->sess->immediate_data = 0;
    }
    else if (strcmp(key, "MaxBurstLength") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "MaxBurstLength", "262144");
        lctx->sess->max_burst_length = 262144;
    }
    else if (strcmp(key, "FirstBurstLength") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "FirstBurstLength", "65536");
        lctx->sess->first_burst_length = 65536;
    }
    else if (strcmp(key, "MaxConnections") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "MaxConnections", "1");
    }
    else if (strcmp(key, "MaxOutstandingR2T") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "MaxOutstandingR2T", "1");
    }
    else if (strcmp(key, "ErrorRecoveryLevel") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "ErrorRecoveryLevel", "0");
    }
    else if (strcmp(key, "DefaultTime2Wait") == 0)
    {
        /* Give 2 seconds between reconnects to reduce session cycling */
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "DefaultTime2Wait", "2");
    }
    else if (strcmp(key, "DefaultTime2Retain") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "DefaultTime2Retain", "0");
    }
    else if (strcmp(key, "DataPDUInOrder") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "DataPDUInOrder", "Yes");
    }
    else if (strcmp(key, "DataSequenceInOrder") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "DataSequenceInOrder", "Yes");
    }
    else if (strcmp(key, "OFMarker") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "OFMarker", "No");
    }
    else if (strcmp(key, "IFMarker") == 0)
    {
        lctx->resp_len = iscsi_kv_append(lctx->resp_buf, lctx->resp_buf_size,
                                          lctx->resp_len, "IFMarker", "No");
    }
    /* Ignore unknown keys silently */
}

static int handle_login(iscsi_server_t *srv, iscsi_session_t *sess,
                         const iscsi_pdu_t *req)
{
    uint8_t csg = (req->bhs.flags & ISCSI_LOGIN_CSG_MASK) >> 2;
    uint8_t nsg = req->bhs.flags & ISCSI_LOGIN_NSG_MASK;
    int transit = (req->bhs.flags & ISCSI_FLAG_LOGIN_TRANSIT) != 0;

    /* Extract ISID (bytes 8-13) and TSIH (bytes 14-15) from request */
    uint16_t req_tsih;
    memcpy(&req_tsih, req->bhs.lun + 6, 2);
    req_tsih = ntohs(req_tsih);

    /* Login PDU logging suppressed — cycling is normal Windows Initiator behavior */

    /* RFC 7143 §5.3.5 — Session Reinstatement:
     * If the initiator sends TSIH=0 with the same ISID as an existing session,
     * the target MUST close the old session before establishing the new one.
     * Without this, the initiator sees the old session still alive and cycles. */
    if (req_tsih == 0 && csg == 0 /* first login PDU */)
    {
        const uint8_t *req_isid = req->bhs.lun;  /* bytes 8-13 */
        for (int i = 0; i < MAX_SESSIONS; i++)
        {
            iscsi_session_t *old = &srv->sessions[i];
            if (old == sess || old->sock == INVALID_SOCKET)
                continue;
            /* Match any session with the same ISID (LOGIN or FULL_FEATURE).
             * ISID is stored at TSIH assignment time (first login PDU). */
            if (old->tsih != 0 && memcmp(old->isid, req_isid, 6) == 0)
            {
                closesocket(old->sock);
                old->sock = INVALID_SOCKET;
                old->state = SESS_STATE_FREE;
            }
        }
    }

    /* Parse key-value pairs from data segment */
    uint8_t resp_buf[4096];
    login_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.sess = sess;
    lctx.srv = srv;
    lctx.resp_buf = resp_buf;
    lctx.resp_buf_size = sizeof(resp_buf);
    lctx.resp_len = 0;

    if (req->data && req->data_len > 0)
        iscsi_kv_parse(req->data, req->data_len, login_kv_handler, &lctx);

    /* Assign TSIH on first login and store ISID for reinstatement matching */
    if (sess->tsih == 0)
    {
        sess->tsih = srv->next_tsih++;
        if (srv->next_tsih == 0)
            srv->next_tsih = 1;
        memcpy(sess->isid, req->bhs.lun, 6);
    }

    /* Build Login Response */
    iscsi_pdu_t resp;
    iscsi_pdu_init(&resp);
    resp.bhs.opcode = ISCSI_OP_LOGIN_RESP;
    resp.bhs.init_task_tag = req->bhs.init_task_tag;

    /* Copy ISID (bytes 8-13) and TSIH (bytes 14-15) from LUN field area.
     * Per RFC 7143 §11.12/§11.13, Login Request/Response have ISID at
     * bytes 8-13 and TSIH at bytes 14-15 (same position as LUN in other PDUs). */
    memcpy(resp.bhs.lun, req->bhs.lun, 6);  /* Copy ISID from request bytes 8-13 */
    {
        uint16_t tsih_net = htons(sess->tsih);
        memcpy(resp.bhs.lun + 6, &tsih_net, 2);  /* Set TSIH at bytes 14-15 */
    }

    /* Sequence numbers */
    sess->stat_sn++;
    resp.bhs.u.login.cmd_sn_or_stat_sn = htonl(sess->stat_sn - 1);
    resp.bhs.u.login.exp_sn            = htonl(sess->exp_cmd_sn);
    resp.bhs.u.login.max_cmd_sn        = htonl(sess->max_cmd_sn);

    /* Version-max and Version-active (bytes 2-3 per RFC 7143 §11.13) */
    resp.bhs.rsvd2[0] = 0x00;  /* Version-max: 0x00 */
    resp.bhs.rsvd2[1] = 0x00;  /* Version-active: 0x00 */

    /* Status-Class and Status-Detail at bytes 36-37 (u.login.isid[0..1]) */
    resp.bhs.u.login.isid[0] = 0;  /* Status-Class: Success */
    resp.bhs.u.login.isid[1] = 0;  /* Status-Detail: 0 */

    /* Determine stage transitions */
    if (transit)
    {
        resp.bhs.flags = ISCSI_FLAG_LOGIN_TRANSIT;
        resp.bhs.flags |= (csg << 2) | nsg;

        if (nsg == ISCSI_LOGIN_STAGE_FULL)
        {
            sess->state = SESS_STATE_FULL_FEATURE;
            sess->scsi_cmd_count = 0;
            /* Initialize SCSI context */
            sess->scsi.stat_sn = sess->stat_sn;
            sess->scsi.exp_cmd_sn = sess->exp_cmd_sn;
            sess->scsi.max_cmd_sn = sess->max_cmd_sn;
            sess->scsi.max_recv_data_seg_len = sess->max_send_data_seg_len;
            sess->scsi.io.read_sectors  = srv->config.read_sectors;
            sess->scsi.io.write_sectors = srv->config.write_sectors;
            sess->scsi.io.get_volume_size  = srv->config.get_volume_size;
            sess->scsi.io.get_sector_size  = srv->config.get_sector_size;
            sess->scsi.io.ctx      = srv->config.ctx;
            sess->scsi.io.readonly = srv->config.readonly;
        }
    }
    else
    {
        resp.bhs.flags = (csg << 2) | nsg;
    }

    /* Attach response key-value data */
    if (lctx.resp_len > 0)
    {
        resp.data = (uint8_t *)malloc(lctx.resp_len);
        if (resp.data)
        {
            memcpy(resp.data, resp_buf, lctx.resp_len);
            resp.data_len = lctx.resp_len;
            iscsi_set_data_seg_len(&resp.bhs, lctx.resp_len);
        }
    }

    /* (Login Response debug removed — Status=0/0 confirmed working) */

    int rc = iscsi_pdu_write(sess->sock, &resp);
    if (resp.data) free(resp.data);
    return rc;
}

/* ============================================================
 * Text Request (SendTargets discovery)
 * ============================================================ */

static int handle_text_request(iscsi_server_t *srv, iscsi_session_t *sess,
                                const iscsi_pdu_t *req)
{
    /* Text Request — SendTargets discovery (no logging, happens frequently) */

    uint8_t resp_buf[1024];
    uint32_t resp_len = 0;

    /* Check if this is a SendTargets request */
    if (req->data && req->data_len > 0)
    {
        /* Always respond with our single target */
        resp_len = iscsi_kv_append(resp_buf, sizeof(resp_buf), resp_len,
                                    "TargetName", srv->config.target_iqn);
        /* Target address */
        char addr_buf[64];
        snprintf(addr_buf, sizeof(addr_buf), "127.0.0.1:%u,1",
                 (unsigned)srv->config.port);
        resp_len = iscsi_kv_append(resp_buf, sizeof(resp_buf), resp_len,
                                    "TargetAddress", addr_buf);
    }

    iscsi_pdu_t resp;
    iscsi_pdu_init(&resp);
    resp.bhs.opcode = ISCSI_OP_TEXT_RESP;       /* 0x24 — no flags in opcode byte */
    resp.bhs.flags  = ISCSI_FLAG_FINAL;         /* F-bit in byte 1 per RFC 7143 §11.19 */
    resp.bhs.init_task_tag = req->bhs.init_task_tag;
    resp.bhs.u.text.tgt_xfer_tag = htonl(0xFFFFFFFF);

    /* Use the session's stat_sn for text response */
    uint32_t stat_sn = sess->stat_sn++;

    /* BHS bytes 24-27: StatSN, 28-31: ExpCmdSN */
    resp.bhs.u.text.cmd_sn = htonl(stat_sn);       /* StatSN (bytes 24-27) */
    resp.bhs.u.text.exp_stat_sn = htonl(sess->exp_cmd_sn);  /* ExpCmdSN (bytes 28-31) */

    /* MaxCmdSN at bytes 32-35 — store in rsvd area (offset 12 in text union) */
    {
        uint32_t max_cmd_sn_net = htonl(sess->max_cmd_sn);
        memcpy(resp.bhs.u.text.rsvd, &max_cmd_sn_net, 4);
    }

    if (resp_len > 0)
    {
        resp.data = (uint8_t *)malloc(resp_len);
        if (resp.data)
        {
            memcpy(resp.data, resp_buf, resp_len);
            resp.data_len = resp_len;
            iscsi_set_data_seg_len(&resp.bhs, resp_len);
        }
    }

    int rc = iscsi_pdu_write(sess->sock, &resp);
    if (resp.data) free(resp.data);
    return rc;
}

/* ============================================================
 * NOP-In response (to NOP-Out from initiator)
 * ============================================================ */

static int handle_nop_out(iscsi_session_t *sess, const iscsi_pdu_t *req)
{
    /* Only respond if InitiatorTaskTag != 0xFFFFFFFF (solicited NOP) */
    if (req->bhs.init_task_tag == htonl(0xFFFFFFFF))
        return 0;  /* Unsolicited NOP-Out, no response needed */

    iscsi_pdu_t resp;
    iscsi_pdu_init(&resp);
    resp.bhs.opcode = ISCSI_OP_NOP_IN;          /* 0x20 — no flags in opcode byte */
    resp.bhs.flags  = ISCSI_FLAG_FINAL;         /* F-bit in byte 1 per RFC 7143 */
    resp.bhs.init_task_tag = req->bhs.init_task_tag;
    resp.bhs.u.nop.tgt_xfer_tag = htonl(0xFFFFFFFF);
    resp.bhs.u.nop.cmd_sn = htonl(sess->stat_sn++);  /* StatSN */
    resp.bhs.u.nop.exp_stat_sn = htonl(sess->exp_cmd_sn);  /* ExpCmdSN */

    /* Echo any data from NOP-Out */
    if (req->data && req->data_len > 0)
    {
        resp.data = req->data;
        resp.data_len = req->data_len;
        iscsi_set_data_seg_len(&resp.bhs, req->data_len);
    }

    int rc = iscsi_pdu_write(sess->sock, &resp);
    resp.data = NULL;  /* Don't free — belongs to req */
    return rc;
}

/* ============================================================
 * Task Management Response
 * ============================================================ */

static int handle_task_mgmt(iscsi_session_t *sess, const iscsi_pdu_t *req)
{
    iscsi_pdu_t resp;
    iscsi_pdu_init(&resp);
    resp.bhs.opcode = ISCSI_OP_TASK_MGT_RESP;
    resp.bhs.flags  = ISCSI_FLAG_FINAL | ISCSI_TMF_RSP_COMPLETE;  /* F-bit + Function complete */
    resp.bhs.init_task_tag = req->bhs.init_task_tag;
    resp.bhs.u.task_mgmt_resp.stat_sn    = htonl(sess->stat_sn++);
    resp.bhs.u.task_mgmt_resp.exp_cmd_sn = htonl(sess->exp_cmd_sn);
    resp.bhs.u.task_mgmt_resp.max_cmd_sn = htonl(sess->max_cmd_sn);

    return iscsi_pdu_write(sess->sock, &resp);
}

/* ============================================================
 * Logout Response
 * ============================================================ */

static int handle_logout(iscsi_session_t *sess, const iscsi_pdu_t *req)
{
    iscsi_pdu_t resp;
    iscsi_pdu_init(&resp);
    resp.bhs.opcode = ISCSI_OP_LOGOUT_RESP;
    resp.bhs.flags  = ISCSI_FLAG_FINAL;  /* F-bit in byte 1 + Response=0 (closed successfully) */
    resp.bhs.init_task_tag = req->bhs.init_task_tag;
    resp.bhs.u.logout.cmd_sn_or_stat_sn = htonl(sess->stat_sn++);
    resp.bhs.u.logout.exp_sn = htonl(sess->exp_cmd_sn);

    int rc = iscsi_pdu_write(sess->sock, &resp);

    sess->state = SESS_STATE_FREE;
    return rc;
}

/* ============================================================
 * SCSI Command — handle writes with R2T/Data-Out
 * ============================================================ */

static int handle_scsi_cmd(iscsi_server_t *srv, iscsi_session_t *sess,
                            iscsi_pdu_t *req)
{
    uint8_t flags = req->bhs.flags;
    int is_write = (flags & ISCSI_FLAG_CMD_WRITE) != 0;

    sess->scsi_cmd_count++;

    /* Sync SCSI context sequence numbers */
    sess->scsi.stat_sn = sess->stat_sn;
    sess->scsi.exp_cmd_sn = sess->exp_cmd_sn;
    sess->scsi.max_cmd_sn = sess->max_cmd_sn;

    if (is_write)
    {
        uint32_t exp_xfer_len = ntohl(req->bhs.u.scsi_cmd.exp_data_xfer_len);
        if (exp_xfer_len == 0)
        {
            /* Zero-length write — just dispatch */
            int rc = scsi_dispatch(sess->sock, req, &sess->scsi);
            sess->stat_sn = sess->scsi.stat_sn;
            return rc;
        }

        /* Send R2T to request write data */
        iscsi_pdu_t r2t;
        iscsi_pdu_init(&r2t);
        r2t.bhs.opcode = ISCSI_OP_R2T;
        r2t.bhs.flags  = ISCSI_FLAG_FINAL;  /* F-bit in byte 1 per RFC 7143 */
        r2t.bhs.init_task_tag = req->bhs.init_task_tag;
        r2t.bhs.u.r2t.tgt_xfer_tag        = req->bhs.init_task_tag;  /* Use ITT as TTT */
        r2t.bhs.u.r2t.stat_sn             = htonl(sess->stat_sn);
        r2t.bhs.u.r2t.exp_cmd_sn          = htonl(sess->exp_cmd_sn);
        r2t.bhs.u.r2t.max_cmd_sn          = htonl(sess->max_cmd_sn);
        r2t.bhs.u.r2t.r2t_sn              = htonl(0);
        r2t.bhs.u.r2t.buffer_offset       = htonl(0);
        r2t.bhs.u.r2t.desired_data_xfer_len = htonl(exp_xfer_len);

        /* Copy LUN from request */
        memcpy(r2t.bhs.lun, req->bhs.lun, 8);

        if (iscsi_pdu_write(sess->sock, &r2t) != 0)
            return -1;

        /* Accumulate Data-Out PDUs */
        uint8_t *write_buf = (uint8_t *)malloc(exp_xfer_len);
        if (!write_buf)
            return -1;

        uint32_t received = 0;
        while (received < exp_xfer_len)
        {
            iscsi_pdu_t data_out;
            if (iscsi_pdu_read(sess->sock, &data_out) != 0)
            {
                free(write_buf);
                return -1;
            }

            uint8_t op = data_out.bhs.opcode & ISCSI_OPCODE_MASK;
            if (op != ISCSI_OP_DATA_OUT)
            {
                fprintf(stderr, "[iSCSI] Expected Data-Out, got opcode 0x%02X\n", op);
                iscsi_pdu_free(&data_out);
                free(write_buf);
                return -1;
            }

            uint32_t buf_offset = ntohl(data_out.bhs.u.data_out.buffer_offset);
            uint32_t data_len = data_out.data_len;

            if (buf_offset + data_len <= exp_xfer_len && data_out.data)
            {
                memcpy(write_buf + buf_offset, data_out.data, data_len);
                received += data_len;
            }

            iscsi_pdu_free(&data_out);
        }

        /* Attach write data to request and dispatch */
        req->data = write_buf;
        req->data_len = exp_xfer_len;

        int rc = scsi_dispatch(sess->sock, req, &sess->scsi);
        sess->stat_sn = sess->scsi.stat_sn;

        free(write_buf);
        req->data = NULL;
        req->data_len = 0;
        return rc;
    }
    else
    {
        /* Read or no-data command — dispatch directly */
        int rc = scsi_dispatch(sess->sock, req, &sess->scsi);
        sess->stat_sn = sess->scsi.stat_sn;
        return rc;
    }
}

/* ============================================================
 * Session PDU processor
 * ============================================================ */

static int process_session_pdu(iscsi_server_t *srv, iscsi_session_t *sess)
{
    iscsi_pdu_t pdu;
    if (iscsi_pdu_read(sess->sock, &pdu) != 0)
        return -1;  /* Connection lost — silently clean up */

    uint8_t opcode = pdu.bhs.opcode & ISCSI_OPCODE_MASK;
    int rc = 0;

    /* Update expected CmdSN based on opcode-specific field */
    if (opcode == ISCSI_OP_SCSI_CMD)
    {
        uint32_t cmd_sn = ntohl(pdu.bhs.u.scsi_cmd.cmd_sn);
        if (cmd_sn == sess->exp_cmd_sn)
            sess->exp_cmd_sn = cmd_sn + 1;
        sess->max_cmd_sn = sess->exp_cmd_sn + 31;
    }

    switch (opcode)
    {
    case ISCSI_OP_LOGIN_REQ:
        rc = handle_login(srv, sess, &pdu);
        break;

    case ISCSI_OP_TEXT_REQ:
        rc = handle_text_request(srv, sess, &pdu);
        break;

    case ISCSI_OP_SCSI_CMD:
        if (sess->state != SESS_STATE_FULL_FEATURE)
        {
            fprintf(stderr, "[iSCSI] SCSI command before login complete\n");
            rc = -1;
        }
        else
        {
            rc = handle_scsi_cmd(srv, sess, &pdu);
        }
        break;

    case ISCSI_OP_NOP_OUT:
        rc = handle_nop_out(sess, &pdu);
        break;

    case ISCSI_OP_TASK_MGT_REQ:
        rc = handle_task_mgmt(sess, &pdu);
        break;

    case ISCSI_OP_LOGOUT_REQ:
        rc = handle_logout(sess, &pdu);
        break;

    case ISCSI_OP_DATA_OUT:
        /* Unexpected — should be consumed by handle_scsi_cmd's R2T loop */
        fprintf(stderr, "[iSCSI] Unexpected Data-Out PDU\n");
        break;

    default:
        fprintf(stderr, "[iSCSI] Unknown opcode 0x%02X\n", opcode);
        /* Send Reject PDU */
        {
            iscsi_pdu_t reject;
            iscsi_pdu_init(&reject);
            reject.bhs.opcode = ISCSI_OP_REJECT;
            reject.bhs.flags  = ISCSI_FLAG_FINAL | 0x04;  /* F-bit + Reason: command not supported */
            reject.bhs.init_task_tag = htonl(0xFFFFFFFF);

            /* Include original BHS as data */
            reject.data = (uint8_t *)&pdu.bhs;
            reject.data_len = 48;
            iscsi_set_data_seg_len(&reject.bhs, 48);

            iscsi_pdu_write(sess->sock, &reject);
            reject.data = NULL;
        }
        break;
    }

    iscsi_pdu_free(&pdu);
    return rc;
}

/* ============================================================
 * Server create/run/stop/destroy
 * ============================================================ */

iscsi_server_t *iscsi_server_create(const iscsi_config_t *config)
{
    if (!config || !config->read_sectors || !config->get_volume_size)
        return NULL;

    iscsi_server_t *srv = (iscsi_server_t *)calloc(1, sizeof(*srv));
    if (!srv)
        return NULL;

    srv->config = *config;
    srv->listen_sock = INVALID_SOCKET;
    srv->wakeup_send = INVALID_SOCKET;
    srv->wakeup_recv = INVALID_SOCKET;
    srv->next_tsih = 1;

    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        srv->sessions[i].sock = INVALID_SOCKET;
        srv->sessions[i].state = SESS_STATE_FREE;
        srv->sessions[i].max_recv_data_seg_len = 8192;
        srv->sessions[i].max_send_data_seg_len = 262144;
        srv->sessions[i].max_burst_length = 262144;
        srv->sessions[i].first_burst_length = 65536;
        srv->sessions[i].initial_r2t = 1;
        srv->sessions[i].immediate_data = 0;
        srv->sessions[i].exp_cmd_sn = 1;
        srv->sessions[i].max_cmd_sn = 32;
    }

    return srv;
}

int iscsi_server_run(iscsi_server_t *srv)
{
    if (!srv)
        return -1;

    /* Create wakeup socket pair */
    if (create_wakeup_pair(&srv->wakeup_recv, &srv->wakeup_send) != 0)
    {
        fprintf(stderr, "[iSCSI] Failed to create wakeup socket pair\n");
        return -1;
    }

    /* Create listening socket */
    srv->listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv->listen_sock == INVALID_SOCKET)
    {
        fprintf(stderr, "[iSCSI] Failed to create listen socket\n");
        return -1;
    }

    /* Allow port reuse */
    int opt = 1;
    setsockopt(srv->listen_sock, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&opt, sizeof(opt));

    /* Bind to 127.0.0.1 only */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(srv->config.port);

    if (bind(srv->listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        fprintf(stderr, "[iSCSI] Failed to bind to 127.0.0.1:%u (error %d)\n",
                (unsigned)srv->config.port, WSAGetLastError());
        closesocket(srv->listen_sock);
        srv->listen_sock = INVALID_SOCKET;
        return -1;
    }

    if (listen(srv->listen_sock, 4) == SOCKET_ERROR)
    {
        fprintf(stderr, "[iSCSI] Failed to listen (error %d)\n", WSAGetLastError());
        closesocket(srv->listen_sock);
        srv->listen_sock = INVALID_SOCKET;
        return -1;
    }

    fprintf(stderr, "[LamarckFUSE] iSCSI server listening on 127.0.0.1:%u\n",
            (unsigned)srv->config.port);
    srv->running = 1;

    /* Main event loop using WSAPoll */
    while (srv->running)
    {
        WSAPOLLFD fds[1 + MAX_SESSIONS + 1];  /* listen + sessions + wakeup */
        int nfds = 0;

        /* Wakeup socket */
        fds[nfds].fd = srv->wakeup_recv;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        int wakeup_idx = nfds++;

        /* Listen socket */
        fds[nfds].fd = srv->listen_sock;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        int listen_idx = nfds++;

        /* Active session sockets */
        int sess_idx[MAX_SESSIONS];
        for (int i = 0; i < MAX_SESSIONS; i++)
        {
            sess_idx[i] = -1;
            if (srv->sessions[i].sock != INVALID_SOCKET)
            {
                fds[nfds].fd = srv->sessions[i].sock;
                fds[nfds].events = POLLIN;
                fds[nfds].revents = 0;
                sess_idx[i] = nfds++;
            }
        }

        int ret = WSAPoll(fds, nfds, 5000);  /* 5s timeout for keepalive check */
        if (ret == SOCKET_ERROR)
        {
            if (!srv->running) break;
            fprintf(stderr, "[iSCSI] WSAPoll error %d\n", WSAGetLastError());
            continue;
        }

        if (ret == 0)
            continue;  /* Timeout — continue loop */

        /* Check wakeup socket */
        if (fds[wakeup_idx].revents & POLLIN)
        {
            char buf[1];
            recv(srv->wakeup_recv, buf, 1, 0);
            break;  /* Stop signal received */
        }

        /* Check for new connections */
        if (fds[listen_idx].revents & POLLIN)
        {
            struct sockaddr_in client_addr;
            int client_addr_len = sizeof(client_addr);
            SOCKET client = accept(srv->listen_sock,
                                    (struct sockaddr *)&client_addr, &client_addr_len);
            if (client != INVALID_SOCKET)
            {
                /* Find free session slot */
                int slot = -1;
                for (int i = 0; i < MAX_SESSIONS; i++)
                {
                    if (srv->sessions[i].sock == INVALID_SOCKET)
                    {
                        slot = i;
                        break;
                    }
                }

                /* No free slot — try to evict a non-FULL_FEATURE session.
                 * Never evict active sessions that are serving SCSI commands. */
                if (slot < 0)
                {
                    for (int i = 0; i < MAX_SESSIONS; i++)
                    {
                        if (srv->sessions[i].state != SESS_STATE_FULL_FEATURE)
                        {
                            slot = i;
                            break;
                        }
                    }
                    if (slot < 0)
                    {
                        /* All slots are FULL_FEATURE — reject new connection */
                        closesocket(client);
                        client = INVALID_SOCKET;
                    }
                    else
                    {
                        closesocket(srv->sessions[slot].sock);
                        srv->sessions[slot].sock = INVALID_SOCKET;
                        srv->sessions[slot].state = SESS_STATE_FREE;
                    }
                }

                if (client != INVALID_SOCKET && slot >= 0)
                {
                    srv->sessions[slot].sock = client;
                    srv->sessions[slot].state = SESS_STATE_LOGIN;
                    srv->sessions[slot].tsih = 0;
                    srv->sessions[slot].stat_sn = 1;
                    srv->sessions[slot].exp_cmd_sn = 1;
                    srv->sessions[slot].max_cmd_sn = 32;
                    srv->sessions[slot].max_recv_data_seg_len = 8192;
                    srv->sessions[slot].max_send_data_seg_len = 262144;

                    /* Disable Nagle for low latency */
                    int nodelay = 1;
                    setsockopt(client, IPPROTO_TCP, TCP_NODELAY,
                               (const char *)&nodelay, sizeof(nodelay));

                    /* Set socket recv/send timeout (30 seconds) */
                    DWORD timeout = 30000;
                    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                               (const char *)&timeout, sizeof(timeout));
                    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
                               (const char *)&timeout, sizeof(timeout));
                }
            }
        }

        /* Process session data */
        for (int i = 0; i < MAX_SESSIONS; i++)
        {
            if (sess_idx[i] < 0)
                continue;

            if (fds[sess_idx[i]].revents & (POLLIN | POLLERR | POLLHUP))
            {
                if (process_session_pdu(srv, &srv->sessions[i]) != 0 ||
                    srv->sessions[i].state == SESS_STATE_FREE)
                {
                    closesocket(srv->sessions[i].sock);
                    srv->sessions[i].sock = INVALID_SOCKET;
                    srv->sessions[i].state = SESS_STATE_FREE;
                }
            }
        }
    }

    /* Cleanup */
    for (int i = 0; i < MAX_SESSIONS; i++)
    {
        if (srv->sessions[i].sock != INVALID_SOCKET)
        {
            closesocket(srv->sessions[i].sock);
            srv->sessions[i].sock = INVALID_SOCKET;
        }
    }

    if (srv->listen_sock != INVALID_SOCKET)
    {
        closesocket(srv->listen_sock);
        srv->listen_sock = INVALID_SOCKET;
    }

    fprintf(stderr, "[iSCSI] Server stopped\n");
    return 0;
}

void iscsi_server_stop(iscsi_server_t *srv)
{
    if (!srv)
        return;

    srv->running = 0;

    /* Wake up the event loop */
    if (srv->wakeup_send != INVALID_SOCKET)
    {
        char c = 'x';
        send(srv->wakeup_send, &c, 1, 0);
    }
}

void iscsi_server_destroy(iscsi_server_t *srv)
{
    if (!srv)
        return;

    if (srv->wakeup_send != INVALID_SOCKET)
        closesocket(srv->wakeup_send);
    if (srv->wakeup_recv != INVALID_SOCKET)
        closesocket(srv->wakeup_recv);

    free(srv);
}

#endif /* _WIN32 */
