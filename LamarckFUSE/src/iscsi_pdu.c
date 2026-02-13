/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

/*
 * iSCSI PDU read/write and key-value parsing for Basalt's userspace iSCSI target.
 * Reference: RFC 7143
 */

#ifdef _WIN32

#include "iscsi_pdu.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================
 * Socket I/O helpers — guaranteed full read/write
 * ============================================================ */

/*
 * Read exactly 'len' bytes from socket.
 * Returns 0 on success, -1 on error or disconnect.
 */
static int sock_read_full(SOCKET sock, void *buf, int len)
{
    char *p = (char *)buf;
    int remaining = len;

    while (remaining > 0)
    {
        int n = recv(sock, p, remaining, 0);
        if (n <= 0)
            return -1;  /* Connection lost or reset — caller handles cleanup */
        p += n;
        remaining -= n;
    }
    return 0;
}

/*
 * Write exactly 'len' bytes to socket.
 * Returns 0 on success, -1 on error.
 */
static int sock_write_full(SOCKET sock, const void *buf, int len)
{
    const char *p = (const char *)buf;
    int remaining = len;

    while (remaining > 0)
    {
        int n = send(sock, p, remaining, 0);
        if (n <= 0)
            return -1;
        p += n;
        remaining -= n;
    }
    return 0;
}

/* ============================================================
 * PDU lifecycle
 * ============================================================ */

void iscsi_pdu_init(iscsi_pdu_t *pdu)
{
    memset(pdu, 0, sizeof(*pdu));
}

void iscsi_pdu_free(iscsi_pdu_t *pdu)
{
    if (pdu->data)
    {
        free(pdu->data);
        pdu->data = NULL;
    }
    pdu->data_len = 0;
}

/* ============================================================
 * PDU Read — reads BHS + data segment from socket
 * ============================================================ */

int iscsi_pdu_read(SOCKET sock, iscsi_pdu_t *pdu)
{
    iscsi_pdu_init(pdu);

    /* Read the 48-byte Basic Header Segment */
    if (sock_read_full(sock, &pdu->bhs, 48) != 0)
        return -1;

    /* Extract data segment length */
    uint32_t data_len = iscsi_get_data_seg_len(&pdu->bhs);
    uint32_t ahs_len = (uint32_t)pdu->bhs.total_ahs_len * 4;

    /* Skip AHS if present (we don't use it) */
    if (ahs_len > 0)
    {
        uint8_t *ahs_buf = (uint8_t *)malloc(iscsi_pad4(ahs_len));
        if (!ahs_buf)
            return -1;
        if (sock_read_full(sock, ahs_buf, (int)iscsi_pad4(ahs_len)) != 0)
        {
            free(ahs_buf);
            return -1;
        }
        free(ahs_buf);
    }

    /* Read data segment (with padding) */
    if (data_len > 0)
    {
        uint32_t padded_len = iscsi_pad4(data_len);

        /* Sanity check: max 16 MB data segment */
        if (padded_len > 16 * 1024 * 1024)
            return -1;

        pdu->data = (uint8_t *)malloc(padded_len);
        if (!pdu->data)
            return -1;

        if (sock_read_full(sock, pdu->data, (int)padded_len) != 0)
        {
            free(pdu->data);
            pdu->data = NULL;
            return -1;
        }

        pdu->data_len = data_len;
    }

    return 0;
}

/* ============================================================
 * PDU Write — writes BHS + data segment to socket
 * ============================================================ */

int iscsi_pdu_write(SOCKET sock, const iscsi_pdu_t *pdu)
{
    /* Write the 48-byte BHS */
    if (sock_write_full(sock, &pdu->bhs, 48) != 0)
        return -1;

    /* Write data segment (with padding) if present */
    uint32_t data_len = iscsi_get_data_seg_len(&pdu->bhs);
    if (data_len > 0 && pdu->data)
    {
        uint32_t padded_len = iscsi_pad4(data_len);

        /* Write actual data */
        if (sock_write_full(sock, pdu->data, (int)data_len) != 0)
            return -1;

        /* Write padding zeros */
        uint32_t pad_bytes = padded_len - data_len;
        if (pad_bytes > 0)
        {
            uint8_t zeros[4] = {0, 0, 0, 0};
            if (sock_write_full(sock, zeros, (int)pad_bytes) != 0)
                return -1;
        }
    }

    return 0;
}

/* ============================================================
 * Key-Value parsing for Login/Text PDU data segments
 * Format: "key=value\0key=value\0..."
 * ============================================================ */

void iscsi_kv_parse(const uint8_t *data, uint32_t len,
                    iscsi_kv_callback_t cb, void *ctx)
{
    if (!data || len == 0 || !cb)
        return;

    const char *p = (const char *)data;
    const char *end = p + len;

    while (p < end)
    {
        /* Find end of this key=value string (NUL terminated) */
        const char *str_end = (const char *)memchr(p, '\0', (size_t)(end - p));
        if (!str_end)
            str_end = end;

        /* Find '=' separator */
        const char *eq = (const char *)memchr(p, '=', (size_t)(str_end - p));
        if (eq)
        {
            /* We need mutable copies for the callback */
            size_t key_len = (size_t)(eq - p);
            size_t val_len = (size_t)(str_end - eq - 1);

            /* Use stack buffers for reasonable sizes */
            char key_buf[256];
            char val_buf[1024];

            if (key_len < sizeof(key_buf) && val_len < sizeof(val_buf))
            {
                memcpy(key_buf, p, key_len);
                key_buf[key_len] = '\0';
                memcpy(val_buf, eq + 1, val_len);
                val_buf[val_len] = '\0';

                cb(key_buf, val_buf, ctx);
            }
        }

        /* Move past NUL terminator */
        if (str_end < end)
            p = str_end + 1;
        else
            break;
    }
}

uint32_t iscsi_kv_append(uint8_t *buf, uint32_t buf_size, uint32_t offset,
                         const char *key, const char *value)
{
    if (!buf || !key || !value)
        return 0;

    size_t key_len = strlen(key);
    size_t val_len = strlen(value);
    uint32_t needed = (uint32_t)(key_len + 1 + val_len + 1);  /* key=value\0 */

    if (offset + needed > buf_size)
        return 0;

    memcpy(buf + offset, key, key_len);
    buf[offset + key_len] = '=';
    memcpy(buf + offset + key_len + 1, value, val_len);
    buf[offset + key_len + 1 + val_len] = '\0';

    return offset + needed;
}

#endif /* _WIN32 */
