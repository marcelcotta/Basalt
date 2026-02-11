/*
 * LamarckFUSE — NFSv4 COMPOUND dispatcher and operation handlers
 *
 * Translates NFSv4 operations into FUSE callback invocations.
 * Adapted from DarwinFUSE for cross-platform (Windows + POSIX).
 *
 * Changes from DarwinFUSE:
 * - Uses platform_compat.h for struct stat, S_IS* macros, arc4random
 * - Uses lamarckfuse_internal.h instead of darwinfuse_internal.h
 * - arc4random_buf() replaced with individual arc4random() calls
 * - struct stat → struct fuse_stat (platform_compat.h maps to native on POSIX)
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#include "nfs4_ops.h"
#include "nfs4_xdr.h"
#include "lamarckfuse_internal.h"
#include "fuse_context.h"

#include <fuse.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#endif

/* ---- arc4random_buf helper ---- */

/*
 * DarwinFUSE uses arc4random_buf() which doesn't exist on Windows.
 * We provide a portable version using arc4random() (which platform_compat.h
 * maps to BCryptGenRandom on Windows).
 */
static void lfuse_random_bytes(void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len >= 4) {
        uint32_t r = arc4random();
        memcpy(p, &r, 4);
        p += 4;
        len -= 4;
    }
    if (len > 0) {
        uint32_t r = arc4random();
        memcpy(p, &r, len);
    }
}

/* Redirect arc4random_buf calls */
#define arc4random_buf lfuse_random_bytes

/* ---- Filehandle helpers ---- */

static void fh_set(uint8_t *fh, uint32_t *fh_len, uint32_t id)
{
    uint32_t net = htonl(id);
    memcpy(fh, &net, 4);
    *fh_len = DFUSE_FH_LEN;
}

static uint32_t fh_get_id(const uint8_t *fh, uint32_t fh_len)
{
    if (fh_len != DFUSE_FH_LEN) return 0;
    uint32_t net;
    memcpy(&net, fh, 4);
    return ntohl(net);
}

static const char *fh_to_path(const lamarckfuse_config_t *config,
                               const uint8_t *fh, uint32_t fh_len)
{
    uint32_t id = fh_get_id(fh, fh_len);
    switch (id) {
    case DFUSE_FH_ROOT:    return "/";
    case DFUSE_FH_VOLUME:  return config->volume_path;
    case DFUSE_FH_CONTROL: return config->control_path;
    default:               return NULL;
    }
}

static uint32_t name_to_fh_id(const lamarckfuse_config_t *config, const char *name)
{
    const char *vol_name = config->volume_path + 1;
    const char *ctl_name = config->control_path + 1;

    if (strcmp(name, vol_name) == 0)
        return DFUSE_FH_VOLUME;
    if (strcmp(name, ctl_name) == 0)
        return DFUSE_FH_CONTROL;
    return 0;
}

/* ---- Attribute bitmap helpers ---- */

static const uint32_t supported_bitmap[2] = {
    /* Word 0 */
    (1u << FATTR4_SUPPORTED_ATTRS) |
    (1u << FATTR4_TYPE) |
    (1u << FATTR4_FH_EXPIRE_TYPE) |
    (1u << FATTR4_CHANGE) |
    (1u << FATTR4_SIZE) |
    (1u << FATTR4_LINK_SUPPORT) |
    (1u << FATTR4_SYMLINK_SUPPORT) |
    (1u << FATTR4_NAMED_ATTR) |
    (1u << FATTR4_FSID) |
    (1u << FATTR4_UNIQUE_HANDLES) |
    (1u << FATTR4_LEASE_TIME) |
    (1u << FATTR4_RDATTR_ERROR) |
    (1u << FATTR4_FILEHANDLE) |
    (1u << FATTR4_FILEID) |
    (1u << FATTR4_MAXFILESIZE) |
    (1u << FATTR4_MAXLINK) |
    (1u << FATTR4_MAXNAME) |
    (1u << FATTR4_MAXREAD) |
    (1u << FATTR4_MAXWRITE),

    /* Word 1 (bits 32+) */
    (1u << (FATTR4_MODE - 32)) |
    (1u << (FATTR4_NUMLINKS - 32)) |
    (1u << (FATTR4_OWNER - 32)) |
    (1u << (FATTR4_OWNER_GROUP - 32)) |
    (1u << (FATTR4_RAWDEV - 32)) |
    (1u << (FATTR4_SPACE_USED - 32)) |
    (1u << (FATTR4_TIME_ACCESS - 32)) |
    (1u << (FATTR4_TIME_METADATA - 32)) |
    (1u << (FATTR4_TIME_MODIFY - 32)) |
    (1u << (FATTR4_MOUNTED_ON_FILEID - 32))
};

static void decode_bitmap(xdr_buf_t *xdr, uint32_t *bitmap, int *nwords)
{
    *nwords = (int)xdr_decode_uint32(xdr);
    for (int i = 0; i < *nwords && i < 2; i++)
        bitmap[i] = xdr_decode_uint32(xdr);
    for (int i = 2; i < *nwords; i++)
        xdr_decode_uint32(xdr);
    if (*nwords > 2) *nwords = 2;
}

static inline int bitmap_isset(const uint32_t *bitmap, int nwords, int bit)
{
    int word = bit / 32;
    if (word >= nwords) return 0;
    return (bitmap[word] >> (bit % 32)) & 1;
}

/*
 * Encode fattr4 for a given stat result.
 * Uses struct fuse_stat (== struct stat on POSIX, custom struct on Windows).
 */
static void encode_fattr4(xdr_buf_t *xdr,
                           const struct fuse_stat *st,
                           const uint32_t *req_bitmap, int req_nwords,
                           const uint8_t *fh, uint32_t fh_len)
{
    uint32_t eff[2] = {0, 0};
    int eff_nwords = req_nwords < 2 ? req_nwords : 2;
    for (int i = 0; i < eff_nwords; i++)
        eff[i] = req_bitmap[i] & supported_bitmap[i];

    int enc_nwords = 0;
    if (eff[1]) enc_nwords = 2;
    else if (eff[0]) enc_nwords = 1;

    xdr_encode_uint32(xdr, (uint32_t)enc_nwords);
    for (int i = 0; i < enc_nwords; i++)
        xdr_encode_uint32(xdr, eff[i]);

    uint8_t attr_buf[4096];
    xdr_buf_t attr;
    xdr_init(&attr, attr_buf, sizeof(attr_buf));

    #define ATTR_SET(bit) bitmap_isset(eff, 2, (bit))

    /* Word 0 attributes */

    if (ATTR_SET(FATTR4_SUPPORTED_ATTRS)) {
        xdr_encode_uint32(&attr, 2);
        xdr_encode_uint32(&attr, supported_bitmap[0]);
        xdr_encode_uint32(&attr, supported_bitmap[1]);
    }

    if (ATTR_SET(FATTR4_TYPE)) {
        uint32_t nfs_type;
        if (S_ISDIR(st->st_mode))       nfs_type = NF4DIR;
        else if (S_ISREG(st->st_mode))  nfs_type = NF4REG;
        else if (S_ISLNK(st->st_mode))  nfs_type = NF4LNK;
        else if (S_ISBLK(st->st_mode))  nfs_type = NF4BLK;
        else if (S_ISCHR(st->st_mode))  nfs_type = NF4CHR;
        else if (S_ISFIFO(st->st_mode)) nfs_type = NF4FIFO;
        else if (S_ISSOCK(st->st_mode)) nfs_type = NF4SOCK;
        else                             nfs_type = NF4REG;
        xdr_encode_uint32(&attr, nfs_type);
    }

    if (ATTR_SET(FATTR4_FH_EXPIRE_TYPE)) {
        xdr_encode_uint32(&attr, FH4_PERSISTENT);
    }

    if (ATTR_SET(FATTR4_CHANGE)) {
        uint64_t change = (uint64_t)st->st_mtime * 1000000000ULL;
#ifdef __APPLE__
        change += (uint64_t)st->st_mtimespec.tv_nsec;
#endif
        xdr_encode_uint64(&attr, change);
    }

    if (ATTR_SET(FATTR4_SIZE)) {
        xdr_encode_uint64(&attr, (uint64_t)st->st_size);
    }

    if (ATTR_SET(FATTR4_LINK_SUPPORT)) {
        xdr_encode_bool(&attr, 0);
    }

    if (ATTR_SET(FATTR4_SYMLINK_SUPPORT)) {
        xdr_encode_bool(&attr, 0);
    }

    if (ATTR_SET(FATTR4_NAMED_ATTR)) {
        xdr_encode_bool(&attr, 0);
    }

    if (ATTR_SET(FATTR4_FSID)) {
        xdr_encode_uint64(&attr, 0);
        xdr_encode_uint64(&attr, 1);
    }

    if (ATTR_SET(FATTR4_UNIQUE_HANDLES)) {
        xdr_encode_bool(&attr, 1);
    }

    if (ATTR_SET(FATTR4_LEASE_TIME)) {
        xdr_encode_uint32(&attr, 90);
    }

    if (ATTR_SET(FATTR4_RDATTR_ERROR)) {
        xdr_encode_uint32(&attr, NFS4_OK);
    }

    if (ATTR_SET(FATTR4_FILEHANDLE)) {
        xdr_encode_opaque(&attr, fh, fh_len);
    }

    if (ATTR_SET(FATTR4_FILEID)) {
        xdr_encode_uint64(&attr, (uint64_t)fh_get_id(fh, fh_len));
    }

    if (ATTR_SET(FATTR4_MAXFILESIZE)) {
        xdr_encode_uint64(&attr, 0x7FFFFFFFFFFFFFFFULL);
    }

    if (ATTR_SET(FATTR4_MAXLINK)) {
        xdr_encode_uint32(&attr, 1);
    }

    if (ATTR_SET(FATTR4_MAXNAME)) {
        xdr_encode_uint32(&attr, 255);
    }

    if (ATTR_SET(FATTR4_MAXREAD)) {
        xdr_encode_uint64(&attr, 65536);
    }

    if (ATTR_SET(FATTR4_MAXWRITE)) {
        xdr_encode_uint64(&attr, 65536);
    }

    /* Word 1 attributes */

    if (ATTR_SET(FATTR4_MODE)) {
        xdr_encode_uint32(&attr, st->st_mode & 07777);
    }

    if (ATTR_SET(FATTR4_NUMLINKS)) {
        xdr_encode_uint32(&attr, (uint32_t)st->st_nlink);
    }

    if (ATTR_SET(FATTR4_OWNER)) {
        char owner_str[32];
        snprintf(owner_str, sizeof(owner_str), "%u", (unsigned)st->st_uid);
        xdr_encode_string(&attr, owner_str);
    }

    if (ATTR_SET(FATTR4_OWNER_GROUP)) {
        char group_str[32];
        snprintf(group_str, sizeof(group_str), "%u", (unsigned)st->st_gid);
        xdr_encode_string(&attr, group_str);
    }

    if (ATTR_SET(FATTR4_RAWDEV)) {
        xdr_encode_uint32(&attr, 0);
        xdr_encode_uint32(&attr, 0);
    }

    if (ATTR_SET(FATTR4_SPACE_USED)) {
        xdr_encode_uint64(&attr, (uint64_t)st->st_size);
    }

    if (ATTR_SET(FATTR4_TIME_ACCESS)) {
        xdr_encode_int64(&attr, (int64_t)st->st_atime);
        xdr_encode_uint32(&attr, 0);
    }

    if (ATTR_SET(FATTR4_TIME_METADATA)) {
        xdr_encode_int64(&attr, (int64_t)st->st_ctime);
        xdr_encode_uint32(&attr, 0);
    }

    if (ATTR_SET(FATTR4_TIME_MODIFY)) {
        xdr_encode_int64(&attr, (int64_t)st->st_mtime);
        xdr_encode_uint32(&attr, 0);
    }

    if (ATTR_SET(FATTR4_MOUNTED_ON_FILEID)) {
        xdr_encode_uint64(&attr, (uint64_t)fh_get_id(fh, fh_len));
    }

    #undef ATTR_SET

    xdr_encode_opaque(xdr, attr_buf, (uint32_t)xdr_getpos(&attr));
}

/* ---- Individual operation handlers ---- */

static uint32_t handle_putrootfh(const lamarckfuse_config_t *config,
                                  nfs4_conn_state_t *conn,
                                  xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)req;
    fh_set(conn->current_fh, &conn->current_fh_len, DFUSE_FH_ROOT);
    return NFS4_OK;
}

static uint32_t handle_putfh(const lamarckfuse_config_t *config,
                              nfs4_conn_state_t *conn,
                              xdr_buf_t *req, xdr_buf_t *rep)
{
    uint8_t fh[128];
    uint32_t fh_len = xdr_decode_opaque(req, fh, sizeof(fh));
    if (req->error) return NFS4ERR_BADHANDLE;

    uint32_t id = fh_get_id(fh, fh_len);
    if (id < DFUSE_FH_ROOT || id > DFUSE_FH_CONTROL)
        return NFS4ERR_BADHANDLE;

    memcpy(conn->current_fh, fh, fh_len);
    conn->current_fh_len = fh_len;
    return NFS4_OK;
}

static uint32_t handle_getfh(const lamarckfuse_config_t *config,
                              nfs4_conn_state_t *conn,
                              xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)req;
    if (conn->current_fh_len == 0)
        return NFS4ERR_NOENT;
    xdr_encode_opaque(rep, conn->current_fh, conn->current_fh_len);
    return NFS4_OK;
}

static uint32_t handle_savefh(const lamarckfuse_config_t *config,
                               nfs4_conn_state_t *conn,
                               xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)req; (void)rep;
    memcpy(conn->saved_fh, conn->current_fh, conn->current_fh_len);
    conn->saved_fh_len = conn->current_fh_len;
    return NFS4_OK;
}

static uint32_t handle_restorefh(const lamarckfuse_config_t *config,
                                  nfs4_conn_state_t *conn,
                                  xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)req; (void)rep;
    if (conn->saved_fh_len == 0)
        return NFS4ERR_RESTOREFH;
    memcpy(conn->current_fh, conn->saved_fh, conn->saved_fh_len);
    conn->current_fh_len = conn->saved_fh_len;
    return NFS4_OK;
}

static uint32_t handle_lookup(const lamarckfuse_config_t *config,
                               nfs4_conn_state_t *conn,
                               xdr_buf_t *req, xdr_buf_t *rep)
{
    if (fh_get_id(conn->current_fh, conn->current_fh_len) != DFUSE_FH_ROOT)
        return NFS4ERR_NOTDIR;

    char name[256];
    xdr_decode_string(req, name, sizeof(name));
    if (req->error) return NFS4ERR_INVAL;

    LFUSE_LOG("  LOOKUP name='%s' (vol='%s' ctl='%s')",
              name, config->volume_path, config->control_path);

    uint32_t id = name_to_fh_id(config, name);
    if (id == 0) {
        LFUSE_LOG("  LOOKUP '%s' -> NOENT", name);
        return NFS4ERR_NOENT;
    }

    fh_set(conn->current_fh, &conn->current_fh_len, id);
    return NFS4_OK;
}

static uint32_t handle_getattr(const lamarckfuse_config_t *config,
                                nfs4_conn_state_t *conn,
                                xdr_buf_t *req, xdr_buf_t *rep)
{
    uint32_t req_bitmap[2] = {0, 0};
    int req_nwords = 0;
    decode_bitmap(req, req_bitmap, &req_nwords);
    if (req->error) return NFS4ERR_INVAL;

    const char *path = fh_to_path(config, conn->current_fh, conn->current_fh_len);
    if (!path) return NFS4ERR_BADHANDLE;

    struct fuse_stat st;
    memset(&st, 0, sizeof(st));

    if (config->ops->getattr) {
        int rc = config->ops->getattr(path, (struct stat *)&st);
        if (rc != 0) return NFS4ERR_IO;
    } else {
        return NFS4ERR_IO;
    }

    encode_fattr4(rep, &st, req_bitmap, req_nwords,
                  conn->current_fh, conn->current_fh_len);
    return NFS4_OK;
}

static uint32_t handle_setattr(const lamarckfuse_config_t *config,
                                nfs4_conn_state_t *conn,
                                xdr_buf_t *req, xdr_buf_t *rep)
{
    xdr_decode_uint32(req);
    xdr_skip(req, 12);

    uint32_t bitmap[2] = {0, 0};
    int nwords = 0;
    decode_bitmap(req, bitmap, &nwords);
    xdr_skip_opaque(req);

    xdr_encode_uint32(rep, 0);
    return NFS4_OK;
}

static uint32_t handle_access(const lamarckfuse_config_t *config,
                               nfs4_conn_state_t *conn,
                               xdr_buf_t *req, xdr_buf_t *rep)
{
    uint32_t requested = xdr_decode_uint32(req);
    if (req->error) return NFS4ERR_INVAL;

    const char *path = fh_to_path(config, conn->current_fh, conn->current_fh_len);
    if (!path) return NFS4ERR_BADHANDLE;

    uint32_t granted = requested;

    if (config->ops->access) {
        int mask = 0;
        if (requested & ACCESS4_READ)    mask |= R_OK;
        if (requested & ACCESS4_MODIFY)  mask |= W_OK;
        if (requested & ACCESS4_EXECUTE) mask |= X_OK;

        int rc = config->ops->access(path, mask);
        if (rc != 0)
            granted = 0;
    }

    xdr_encode_uint32(rep, requested);
    xdr_encode_uint32(rep, granted);
    return NFS4_OK;
}

/* ---- READDIR ---- */

#define MAX_READDIR_ENTRIES 32

typedef struct {
    char     name[256];
    uint64_t cookie;
} readdir_entry_t;

typedef struct {
    readdir_entry_t entries[MAX_READDIR_ENTRIES];
    int count;
} readdir_collector_t;

static int readdir_filler(void *buf, const char *name,
                           const struct stat *stbuf, off_t off)
{
    readdir_collector_t *col = (readdir_collector_t *)buf;
    if (col->count >= MAX_READDIR_ENTRIES) return 1;

    readdir_entry_t *e = &col->entries[col->count];
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    e->cookie = (uint64_t)(col->count + 1);
    col->count++;
    return 0;
}

static uint32_t handle_readdir(const lamarckfuse_config_t *config,
                                nfs4_conn_state_t *conn,
                                xdr_buf_t *req, xdr_buf_t *rep)
{
    if (fh_get_id(conn->current_fh, conn->current_fh_len) != DFUSE_FH_ROOT)
        return NFS4ERR_NOTDIR;

    uint64_t cookie      = xdr_decode_uint64(req);
    uint8_t cookieverf[8];
    xdr_decode_opaque_fixed(req, cookieverf, 8);
    uint32_t dircount    = xdr_decode_uint32(req);
    uint32_t maxcount    = xdr_decode_uint32(req);

    uint32_t attr_bitmap[2] = {0, 0};
    int attr_nwords = 0;
    decode_bitmap(req, attr_bitmap, &attr_nwords);
    if (req->error) return NFS4ERR_INVAL;

    (void)dircount;
    (void)maxcount;

    readdir_collector_t collector;
    memset(&collector, 0, sizeof(collector));

    if (config->ops->readdir) {
        struct fuse_file_info fi;
        memset(&fi, 0, sizeof(fi));
        config->ops->readdir("/", &collector, readdir_filler, 0, &fi);
    }

    uint8_t reply_verf[8] = {0};
    xdr_encode_opaque_fixed(rep, reply_verf, 8);

    for (int i = 0; i < collector.count; i++) {
        readdir_entry_t *e = &collector.entries[i];
        if (e->cookie <= cookie) continue;

        if (strcmp(e->name, ".") == 0 || strcmp(e->name, "..") == 0)
            continue;

        xdr_encode_bool(rep, 1);
        xdr_encode_uint64(rep, e->cookie);
        xdr_encode_string(rep, e->name);

        char path[512];
        snprintf(path, sizeof(path), "/%s", e->name);

        struct fuse_stat st;
        memset(&st, 0, sizeof(st));
        if (config->ops->getattr)
            config->ops->getattr(path, (struct stat *)&st);

        uint32_t eid = name_to_fh_id(config, e->name);
        uint8_t efh[4];
        uint32_t efh_len = 0;
        if (eid)
            fh_set(efh, &efh_len, eid);

        encode_fattr4(rep, &st, attr_bitmap, attr_nwords, efh, efh_len);
    }

    xdr_encode_bool(rep, 0);
    xdr_encode_bool(rep, 1);

    return NFS4_OK;
}

/* ---- OPEN ---- */

static uint32_t handle_open(const lamarckfuse_config_t *config,
                             nfs4_conn_state_t *conn,
                             xdr_buf_t *req, xdr_buf_t *rep)
{
    xdr_decode_uint32(req);
    uint32_t share_access  = xdr_decode_uint32(req);
    xdr_decode_uint32(req);

    xdr_decode_uint64(req);
    xdr_skip_opaque(req);

    uint32_t opentype = xdr_decode_uint32(req);
    if (opentype == OPEN4_CREATE) {
        uint32_t createmode = xdr_decode_uint32(req);
        (void)createmode;
        uint32_t bm[2] = {0};
        int nw = 0;
        decode_bitmap(req, bm, &nw);
        xdr_skip_opaque(req);
    }

    uint32_t claim_type = xdr_decode_uint32(req);

    char filename[256] = {0};
    uint32_t target_fh_id = 0;

    if (claim_type == CLAIM_NULL) {
        xdr_decode_string(req, filename, sizeof(filename));

        if (fh_get_id(conn->current_fh, conn->current_fh_len) != DFUSE_FH_ROOT)
            return NFS4ERR_NOTDIR;

        target_fh_id = name_to_fh_id(config, filename);
        if (target_fh_id == 0)
            return NFS4ERR_NOENT;
    } else if (claim_type == CLAIM_FH) {
        target_fh_id = fh_get_id(conn->current_fh, conn->current_fh_len);
        if (target_fh_id == 0)
            return NFS4ERR_BADHANDLE;
    } else {
        return NFS4ERR_NOTSUPP;
    }

    if (req->error) return NFS4ERR_INVAL;

    const char *path = NULL;
    switch (target_fh_id) {
    case DFUSE_FH_VOLUME:  path = config->volume_path; break;
    case DFUSE_FH_CONTROL: path = config->control_path; break;
    default:               return NFS4ERR_ISDIR;
    }

    struct fuse_file_info fi;
    memset(&fi, 0, sizeof(fi));
    if (share_access & OPEN4_SHARE_ACCESS_WRITE)
        fi.flags = O_RDWR;
    else
        fi.flags = O_RDONLY;

    if (config->ops->open) {
        int rc = config->ops->open(path, &fi);
        if (rc != 0) return NFS4ERR_ACCESS;
    }

    nfs4_stateid_t sid;
    conn->open_seqid++;
    sid.seqid = conn->open_seqid;
    arc4random_buf(sid.other, sizeof(sid.other));

    if (conn->open_stateid_count < MAX_OPEN_STATEIDS) {
        conn->open_stateids[conn->open_stateid_count] = sid;
        conn->open_fh_ids[conn->open_stateid_count] = target_fh_id;
        conn->open_stateid_count++;
    }

    fh_set(conn->current_fh, &conn->current_fh_len, target_fh_id);

    xdr_encode_uint32(rep, sid.seqid);
    xdr_encode_opaque_fixed(rep, sid.other, 12);

    xdr_encode_bool(rep, 1);
    xdr_encode_uint64(rep, 0);
    xdr_encode_uint64(rep, 1);

    xdr_encode_uint32(rep, 0x00000004);

    xdr_encode_uint32(rep, 0);

    xdr_encode_uint32(rep, OPEN_DELEGATE_NONE);

    return NFS4_OK;
}

static uint32_t handle_open_confirm(const lamarckfuse_config_t *config,
                                     nfs4_conn_state_t *conn,
                                     xdr_buf_t *req, xdr_buf_t *rep)
{
    uint32_t sid_seqid = xdr_decode_uint32(req);
    uint8_t sid_other[12];
    xdr_decode_opaque_fixed(req, sid_other, 12);
    uint32_t seqid = xdr_decode_uint32(req);
    (void)sid_seqid;
    (void)seqid;

    for (int i = 0; i < conn->open_stateid_count; i++) {
        if (memcmp(conn->open_stateids[i].other, sid_other, 12) == 0) {
            conn->open_stateids[i].seqid++;
            xdr_encode_uint32(rep, conn->open_stateids[i].seqid);
            xdr_encode_opaque_fixed(rep, conn->open_stateids[i].other, 12);
            return NFS4_OK;
        }
    }

    return NFS4ERR_BAD_STATEID;
}

static uint32_t handle_close(const lamarckfuse_config_t *config,
                              nfs4_conn_state_t *conn,
                              xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config;

    uint32_t seqid = xdr_decode_uint32(req);
    (void)seqid;
    uint32_t sid_seqid = xdr_decode_uint32(req);
    uint8_t sid_other[12];
    xdr_decode_opaque_fixed(req, sid_other, 12);

    for (int i = 0; i < conn->open_stateid_count; i++) {
        if (memcmp(conn->open_stateids[i].other, sid_other, 12) == 0) {
            xdr_encode_uint32(rep, sid_seqid + 1);
            xdr_encode_opaque_fixed(rep, sid_other, 12);

            conn->open_stateid_count--;
            if (i < conn->open_stateid_count) {
                conn->open_stateids[i] = conn->open_stateids[conn->open_stateid_count];
                conn->open_fh_ids[i] = conn->open_fh_ids[conn->open_stateid_count];
            }
            return NFS4_OK;
        }
    }

    xdr_encode_uint32(rep, 0);
    uint8_t zero[12] = {0};
    xdr_encode_opaque_fixed(rep, zero, 12);
    return NFS4_OK;
}

static uint32_t handle_read(const lamarckfuse_config_t *config,
                             nfs4_conn_state_t *conn,
                             xdr_buf_t *req, xdr_buf_t *rep)
{
    xdr_decode_uint32(req);
    xdr_skip(req, 12);

    uint64_t offset = xdr_decode_uint64(req);
    uint32_t count  = xdr_decode_uint32(req);
    if (req->error) return NFS4ERR_INVAL;

    const char *path = fh_to_path(config, conn->current_fh, conn->current_fh_len);
    if (!path) return NFS4ERR_BADHANDLE;

    if (!config->ops->read)
        return NFS4ERR_NOTSUPP;

    if (count > 65536) count = 65536;
    uint8_t *buf = malloc(count);
    if (!buf) return NFS4ERR_SERVERFAULT;

    struct fuse_file_info fi;
    memset(&fi, 0, sizeof(fi));

    int n = config->ops->read(path, (char *)buf, count, (off_t)offset, &fi);
    if (n < 0) {
        LFUSE_LOG("  READ '%s' offset=%llu count=%u -> error %d",
                  path, (unsigned long long)offset, count, n);
        free(buf);
        return NFS4ERR_IO;
    }

    struct fuse_stat st;
    memset(&st, 0, sizeof(st));
    int eof = 0;
    if (config->ops->getattr) {
        config->ops->getattr(path, (struct stat *)&st);
        eof = ((uint64_t)offset + (uint64_t)n >= (uint64_t)st.st_size) ? 1 : 0;
    }

    xdr_encode_bool(rep, eof);
    xdr_encode_opaque(rep, buf, (uint32_t)n);

    free(buf);
    return NFS4_OK;
}

static uint32_t handle_write(const lamarckfuse_config_t *config,
                              nfs4_conn_state_t *conn,
                              xdr_buf_t *req, xdr_buf_t *rep)
{
    xdr_decode_uint32(req);
    xdr_skip(req, 12);

    uint64_t offset = xdr_decode_uint64(req);
    uint32_t stable = xdr_decode_uint32(req);
    (void)stable;

    uint32_t data_len_raw = xdr_decode_uint32(req);
    if (req->error || data_len_raw > LFUSE_XDR_MAXBUF)
        return NFS4ERR_INVAL;

    size_t padded = (data_len_raw + 3) & ~(size_t)3;
    if (xdr_remaining(req) < padded)
        return NFS4ERR_INVAL;

    uint8_t *data = req->data + req->pos;
    xdr_skip(req, padded);

    const char *path = fh_to_path(config, conn->current_fh, conn->current_fh_len);
    if (!path) return NFS4ERR_BADHANDLE;

    if (!config->ops->write)
        return NFS4ERR_ROFS;

    struct fuse_file_info fi;
    memset(&fi, 0, sizeof(fi));

    int n = config->ops->write(path, (const char *)data, data_len_raw,
                                (off_t)offset, &fi);
    if (n < 0)
        return NFS4ERR_IO;

    xdr_encode_uint32(rep, (uint32_t)n);
    xdr_encode_uint32(rep, FILE_SYNC4);

    uint8_t writeverf[8] = {'L','F','U','S','E','v','0','1'};
    xdr_encode_opaque_fixed(rep, writeverf, 8);

    return NFS4_OK;
}

static uint32_t handle_commit(const lamarckfuse_config_t *config,
                               nfs4_conn_state_t *conn,
                               xdr_buf_t *req, xdr_buf_t *rep)
{
    xdr_decode_uint64(req);
    xdr_decode_uint32(req);

    uint8_t writeverf[8] = {'L','F','U','S','E','v','0','1'};
    xdr_encode_opaque_fixed(rep, writeverf, 8);

    return NFS4_OK;
}

/* ---- Session management ---- */

static uint32_t handle_setclientid(const lamarckfuse_config_t *config,
                                    nfs4_conn_state_t *conn,
                                    xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config;

    uint8_t verifier[8];
    xdr_decode_opaque_fixed(req, verifier, 8);
    xdr_skip_opaque(req);
    xdr_decode_uint32(req);
    xdr_skip_string(req);
    xdr_skip_string(req);
    xdr_decode_uint32(req);

    if (req->error) return NFS4ERR_INVAL;

    conn->clientid = ((uint64_t)arc4random() << 32) | arc4random();
    memcpy(&conn->client_verifier, verifier, 8);
    conn->server_verifier = ((uint64_t)arc4random() << 32) | arc4random();
    conn->confirmed = 0;

    xdr_encode_uint64(rep, conn->clientid);
    uint8_t sv[8];
    memcpy(sv, &conn->server_verifier, 8);
    xdr_encode_opaque_fixed(rep, sv, 8);

    return NFS4_OK;
}

static uint32_t handle_setclientid_confirm(const lamarckfuse_config_t *config,
                                            nfs4_conn_state_t *conn,
                                            xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)rep;

    uint64_t clientid = xdr_decode_uint64(req);
    uint8_t verifier[8];
    xdr_decode_opaque_fixed(req, verifier, 8);

    if (clientid != conn->clientid)
        return NFS4ERR_STALE_CLIENTID;

    uint64_t v;
    memcpy(&v, verifier, 8);
    if (v != conn->server_verifier)
        return NFS4ERR_CLID_INUSE;

    conn->confirmed = 1;
    return NFS4_OK;
}

static uint32_t handle_renew(const lamarckfuse_config_t *config,
                              nfs4_conn_state_t *conn,
                              xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)rep;

    uint64_t clientid = xdr_decode_uint64(req);
    if (clientid != conn->clientid)
        return NFS4ERR_STALE_CLIENTID;

    return NFS4_OK;
}

static uint32_t handle_lock(const lamarckfuse_config_t *config,
                             nfs4_conn_state_t *conn,
                             xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config;

    uint32_t locktype = xdr_decode_uint32(req);
    uint32_t reclaim  = xdr_decode_uint32(req);
    (void)locktype; (void)reclaim;
    xdr_decode_uint64(req);
    xdr_decode_uint64(req);

    uint32_t new_lock_owner = xdr_decode_uint32(req);
    if (new_lock_owner) {
        xdr_decode_uint32(req);
        xdr_decode_uint32(req);
        xdr_skip(req, 12);
        xdr_decode_uint32(req);
        xdr_decode_uint64(req);
        xdr_skip_opaque(req);
    } else {
        xdr_decode_uint32(req);
        xdr_skip(req, 12);
        xdr_decode_uint32(req);
    }
    if (req->error) return NFS4ERR_INVAL;

    xdr_encode_uint32(rep, 1);
    uint8_t zero[12] = {0};
    zero[0] = 0x4C;
    xdr_encode_opaque_fixed(rep, zero, 12);

    return NFS4_OK;
}

static uint32_t handle_lockt(const lamarckfuse_config_t *config,
                              nfs4_conn_state_t *conn,
                              xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)conn; (void)rep;

    xdr_decode_uint32(req);
    xdr_decode_uint64(req);
    xdr_decode_uint64(req);
    xdr_decode_uint64(req);
    xdr_skip_opaque(req);

    return NFS4_OK;
}

static uint32_t handle_locku(const lamarckfuse_config_t *config,
                              nfs4_conn_state_t *conn,
                              xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)conn;

    xdr_decode_uint32(req);
    xdr_decode_uint32(req);
    xdr_decode_uint32(req);
    xdr_skip(req, 12);
    xdr_decode_uint64(req);
    xdr_decode_uint64(req);
    if (req->error) return NFS4ERR_INVAL;

    xdr_encode_uint32(rep, 2);
    uint8_t zero[12] = {0};
    zero[0] = 0x4C;
    xdr_encode_opaque_fixed(rep, zero, 12);

    return NFS4_OK;
}

static uint32_t handle_release_lockowner(const lamarckfuse_config_t *config,
                                          nfs4_conn_state_t *conn,
                                          xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)conn; (void)rep;
    xdr_decode_uint64(req);
    xdr_skip_opaque(req);
    return NFS4_OK;
}

static uint32_t handle_secinfo(const lamarckfuse_config_t *config,
                                nfs4_conn_state_t *conn,
                                xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)conn;

    char name[256];
    xdr_decode_string(req, name, sizeof(name));

    xdr_encode_uint32(rep, 1);
    xdr_encode_uint32(rep, AUTH_SYS);
    return NFS4_OK;
}

static uint32_t handle_verify(const lamarckfuse_config_t *config,
                               nfs4_conn_state_t *conn,
                               xdr_buf_t *req, xdr_buf_t *rep)
{
    (void)config; (void)conn; (void)rep;
    uint32_t bm[2] = {0};
    int nw = 0;
    decode_bitmap(req, bm, &nw);
    xdr_skip_opaque(req);
    return NFS4_OK;
}

/* ---- COMPOUND Dispatcher ---- */

int nfs4_dispatch_compound(const lamarckfuse_config_t *config,
                            nfs4_conn_state_t *conn,
                            xdr_buf_t *request,
                            xdr_buf_t *reply)
{
    char tag[256] = {0};
    xdr_decode_string(request, tag, sizeof(tag));

    uint32_t minorversion = xdr_decode_uint32(request);
    uint32_t numops = xdr_decode_uint32(request);

    if (request->error) {
        LFUSE_ERR("Failed to decode COMPOUND header");
        return -1;
    }

    if (minorversion != 0) {
        xdr_encode_uint32(reply, NFS4ERR_MINOR_VERS_MISMATCH);
        xdr_encode_string(reply, tag);
        xdr_encode_uint32(reply, 0);
        return 0;
    }

    size_t status_pos = xdr_getpos(reply);
    xdr_encode_uint32(reply, NFS4_OK);
    xdr_encode_string(reply, tag);
    size_t numres_pos = xdr_getpos(reply);
    xdr_encode_uint32(reply, 0);

    uint32_t overall_status = NFS4_OK;
    uint32_t completed_ops = 0;

    for (uint32_t i = 0; i < numops; i++) {
        uint32_t opnum = xdr_decode_uint32(request);
        if (request->error) break;

        LFUSE_LOG("  op[%u] = %u", i, opnum);

        xdr_encode_uint32(reply, opnum);

        size_t op_status_pos = xdr_getpos(reply);
        xdr_encode_uint32(reply, NFS4_OK);

        uint32_t status;
        switch (opnum) {
        case OP_PUTROOTFH:
            status = handle_putrootfh(config, conn, request, reply);
            break;
        case OP_PUTFH:
            status = handle_putfh(config, conn, request, reply);
            break;
        case OP_GETFH:
            status = handle_getfh(config, conn, request, reply);
            break;
        case OP_SAVEFH:
            status = handle_savefh(config, conn, request, reply);
            break;
        case OP_RESTOREFH:
            status = handle_restorefh(config, conn, request, reply);
            break;
        case OP_LOOKUP:
            status = handle_lookup(config, conn, request, reply);
            break;
        case OP_GETATTR:
            status = handle_getattr(config, conn, request, reply);
            break;
        case OP_SETATTR:
            status = handle_setattr(config, conn, request, reply);
            break;
        case OP_ACCESS:
            status = handle_access(config, conn, request, reply);
            break;
        case OP_READDIR:
            status = handle_readdir(config, conn, request, reply);
            break;
        case OP_OPEN:
            status = handle_open(config, conn, request, reply);
            break;
        case OP_OPEN_CONFIRM:
            status = handle_open_confirm(config, conn, request, reply);
            break;
        case OP_CLOSE:
            status = handle_close(config, conn, request, reply);
            break;
        case OP_READ:
            status = handle_read(config, conn, request, reply);
            break;
        case OP_WRITE:
            status = handle_write(config, conn, request, reply);
            break;
        case OP_COMMIT:
            status = handle_commit(config, conn, request, reply);
            break;
        case OP_SETCLIENTID:
            status = handle_setclientid(config, conn, request, reply);
            break;
        case OP_SETCLIENTID_CONFIRM:
            status = handle_setclientid_confirm(config, conn, request, reply);
            break;
        case OP_RENEW:
            status = handle_renew(config, conn, request, reply);
            break;
        case OP_LOCK:
            status = handle_lock(config, conn, request, reply);
            break;
        case OP_LOCKT:
            status = handle_lockt(config, conn, request, reply);
            break;
        case OP_LOCKU:
            status = handle_locku(config, conn, request, reply);
            break;
        case OP_RELEASE_LOCKOWNER:
            status = handle_release_lockowner(config, conn, request, reply);
            break;
        case OP_SECINFO:
            status = handle_secinfo(config, conn, request, reply);
            break;
        case OP_VERIFY:
        case OP_NVERIFY:
            status = handle_verify(config, conn, request, reply);
            break;
        default:
            LFUSE_LOG("  unsupported op %u", opnum);
            status = NFS4ERR_NOTSUPP;
            break;
        }

        size_t saved_pos = xdr_getpos(reply);
        xdr_setpos(reply, op_status_pos);
        xdr_encode_uint32(reply, status);
        xdr_setpos(reply, saved_pos);

        completed_ops++;

        if (status != NFS4_OK) {
            overall_status = status;
            LFUSE_LOG("  op[%u]=%u failed with status %u", i, opnum, status);
            break;
        }
    }

    size_t end_pos = xdr_getpos(reply);

    xdr_setpos(reply, status_pos);
    xdr_encode_uint32(reply, overall_status);

    xdr_setpos(reply, numres_pos);
    xdr_encode_uint32(reply, completed_ops);

    xdr_setpos(reply, end_pos);

    return reply->error ? -1 : 0;
}
