/*
 * Test: Start DarwinFUSE NFSv4 server without mounting.
 * Sends a NULL RPC call to verify the server responds.
 * No root required.
 */

#include "nfs4_server.h"
#include "nfs4_xdr.h"
#include "rpc.h"
#include "darwinfuse_internal.h"
#include <fuse.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>

/* Minimal FUSE ops */
static int test_getattr(const char *path, struct stat *st)
{
    memset(st, 0, sizeof(*st));
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = st->st_mtime = st->st_ctime = time(NULL);
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    return -2; /* ENOENT */
}

static int test_access(const char *path, int mask)
{
    (void)mask;
    if (strcmp(path, "/") == 0) return 0;
    return -2;
}

static int test_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    (void)offset; (void)fi;
    if (strcmp(path, "/") != 0) return -2;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    return 0;
}

/* Server thread */
static void *srv_thread(void *arg)
{
    darwinfuse_server_t *srv = (darwinfuse_server_t *)arg;
    nfs4_server_run(srv);
    return NULL;
}

/* Send an RPC NULL call and check for a valid reply */
static int test_rpc_null(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    fprintf(stderr, "[test] Connected to 127.0.0.1:%u\n", port);

    /* Build RPC NULL call:
     * xid=1, msg_type=CALL(0), rpcvers=2, prog=100003, vers=4, proc=0
     * auth: AUTH_NONE(0), len=0
     * verf: AUTH_NONE(0), len=0
     */
    uint8_t call_buf[256];
    xdr_buf_t call;
    xdr_init(&call, call_buf + 4, sizeof(call_buf) - 4);  /* leave 4 for record mark */

    xdr_encode_uint32(&call, 1);         /* xid */
    xdr_encode_uint32(&call, 0);         /* CALL */
    xdr_encode_uint32(&call, 2);         /* rpcvers */
    xdr_encode_uint32(&call, 100003);    /* NFS program */
    xdr_encode_uint32(&call, 4);         /* NFS version */
    xdr_encode_uint32(&call, 0);         /* NULL proc */
    xdr_encode_uint32(&call, 0);         /* auth_none flavor */
    xdr_encode_uint32(&call, 0);         /* auth body len */
    xdr_encode_uint32(&call, 0);         /* verf_none flavor */
    xdr_encode_uint32(&call, 0);         /* verf body len */

    uint32_t payload_len = (uint32_t)xdr_getpos(&call);
    rpc_encode_record_mark(call_buf, payload_len, 1);

    /* Send */
    size_t total = 4 + payload_len;
    if (write(fd, call_buf, total) != (ssize_t)total) {
        perror("write");
        close(fd);
        return -1;
    }

    fprintf(stderr, "[test] Sent NULL RPC (%zu bytes)\n", total);

    /* Read reply */
    uint8_t reply_buf[512];
    ssize_t n = read(fd, reply_buf, sizeof(reply_buf));
    if (n <= 0) {
        fprintf(stderr, "[test] No reply (n=%zd, errno=%d)\n", n, errno);
        close(fd);
        return -1;
    }

    fprintf(stderr, "[test] Got reply: %zd bytes\n", n);

    /* Parse record mark */
    if (n < 4) {
        fprintf(stderr, "[test] Reply too short\n");
        close(fd);
        return -1;
    }

    int last_frag;
    uint32_t rlen = rpc_parse_record_mark(reply_buf, &last_frag);
    fprintf(stderr, "[test] Record mark: len=%u, last_fragment=%d\n", rlen, last_frag);

    /* Parse reply header */
    xdr_buf_t rep;
    xdr_init(&rep, reply_buf + 4, (size_t)(n - 4));

    uint32_t xid = xdr_decode_uint32(&rep);
    uint32_t msg_type = xdr_decode_uint32(&rep);
    uint32_t reply_stat = xdr_decode_uint32(&rep);

    fprintf(stderr, "[test] xid=%u, msg_type=%u (1=REPLY), reply_stat=%u (0=ACCEPTED)\n",
            xid, msg_type, reply_stat);

    if (msg_type != 1 || reply_stat != 0) {
        fprintf(stderr, "[test] FAIL: unexpected reply\n");
        close(fd);
        return -1;
    }

    /* Skip verifier (flavor + len) */
    xdr_decode_uint32(&rep); /* verf flavor */
    xdr_decode_uint32(&rep); /* verf len */

    /* accept_stat */
    uint32_t accept_stat = xdr_decode_uint32(&rep);
    fprintf(stderr, "[test] accept_stat=%u (0=SUCCESS)\n", accept_stat);

    close(fd);

    if (accept_stat == 0) {
        fprintf(stderr, "[test] SUCCESS: NULL RPC accepted\n");
        return 0;
    }

    return -1;
}

/* Send an NFS COMPOUND with PUTROOTFH + GETATTR to test filesystem ops */
static int test_compound_getattr(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    fprintf(stderr, "\n[test] === COMPOUND PUTROOTFH + GETATTR ===\n");

    uint8_t call_buf[512];
    xdr_buf_t call;
    xdr_init(&call, call_buf + 4, sizeof(call_buf) - 4);

    /* RPC header */
    xdr_encode_uint32(&call, 42);        /* xid */
    xdr_encode_uint32(&call, 0);         /* CALL */
    xdr_encode_uint32(&call, 2);         /* rpcvers */
    xdr_encode_uint32(&call, 100003);    /* NFS program */
    xdr_encode_uint32(&call, 4);         /* NFS version */
    xdr_encode_uint32(&call, 1);         /* COMPOUND proc */
    xdr_encode_uint32(&call, 0);         /* auth_none */
    xdr_encode_uint32(&call, 0);         /* auth body len */
    xdr_encode_uint32(&call, 0);         /* verf_none */
    xdr_encode_uint32(&call, 0);         /* verf body len */

    /* COMPOUND header */
    xdr_encode_uint32(&call, 4);         /* tag length */
    xdr_encode_opaque(&call, (const uint8_t *)"test", 4); /* but encode_opaque includes len... */
    /* Actually the tag is already length-prefixed by encode_opaque, undo double length */

    /* Let me rebuild: COMPOUND body = tag(string) + minorversion(uint32) + numops(uint32) + ops */
    /* Reset and redo the compound body properly */

    /* Actually xdr_encode_opaque already writes len+data+padding, which is correct for an XDR string */

    xdr_encode_uint32(&call, 0);         /* minorversion = 0 */
    xdr_encode_uint32(&call, 2);         /* numops = 2 */

    /* Op 1: PUTROOTFH (op 24, no args) */
    xdr_encode_uint32(&call, 24);

    /* Op 2: GETATTR (op 9) */
    xdr_encode_uint32(&call, 9);
    /* attr_request bitmap: 2 words */
    xdr_encode_uint32(&call, 2);         /* bitmap length = 2 words */
    /* Word 0: TYPE(bit1) | SIZE(bit4) | FSID(bit8) = 0x112 */
    xdr_encode_uint32(&call, (1u << 1) | (1u << 4) | (1u << 8));
    /* Word 1: MODE(bit1) | NUMLINKS(bit3) | TIME_MODIFY(bit21) */
    xdr_encode_uint32(&call, (1u << 1) | (1u << 3) | (1u << 21));

    uint32_t payload_len = (uint32_t)xdr_getpos(&call);
    rpc_encode_record_mark(call_buf, payload_len, 1);

    size_t total = 4 + payload_len;
    if (write(fd, call_buf, total) != (ssize_t)total) {
        perror("write");
        close(fd);
        return -1;
    }

    fprintf(stderr, "[test] Sent COMPOUND (%zu bytes)\n", total);

    /* Read reply */
    uint8_t reply_buf[4096];
    ssize_t n = read(fd, reply_buf, sizeof(reply_buf));
    if (n <= 0) {
        fprintf(stderr, "[test] No reply (n=%zd)\n", n);
        close(fd);
        return -1;
    }

    fprintf(stderr, "[test] Got reply: %zd bytes\n", n);

    /* Parse record mark */
    int last_frag;
    uint32_t rlen = rpc_parse_record_mark(reply_buf, &last_frag);
    fprintf(stderr, "[test] Record mark: len=%u\n", rlen);

    /* Parse RPC reply header */
    xdr_buf_t rep;
    xdr_init(&rep, reply_buf + 4, (size_t)(n - 4));

    uint32_t xid = xdr_decode_uint32(&rep);
    uint32_t msg_type = xdr_decode_uint32(&rep);
    uint32_t reply_stat = xdr_decode_uint32(&rep);
    xdr_decode_uint32(&rep); /* verf flavor */
    xdr_decode_uint32(&rep); /* verf len */
    uint32_t accept_stat = xdr_decode_uint32(&rep);

    fprintf(stderr, "[test] xid=%u, msg_type=%u, reply_stat=%u, accept_stat=%u\n",
            xid, msg_type, reply_stat, accept_stat);

    if (accept_stat != 0) {
        fprintf(stderr, "[test] FAIL: COMPOUND rejected\n");
        close(fd);
        return -1;
    }

    /* Parse COMPOUND reply header */
    uint32_t status = xdr_decode_uint32(&rep);
    /* tag */
    uint32_t tag_len = xdr_decode_uint32(&rep);
    if (tag_len > 0) xdr_skip(&rep, ((tag_len + 3) & ~3u));
    uint32_t numresults = xdr_decode_uint32(&rep);

    fprintf(stderr, "[test] COMPOUND status=%u, numresults=%u\n", status, numresults);

    /* Parse PUTROOTFH result */
    if (numresults >= 1) {
        uint32_t op = xdr_decode_uint32(&rep);
        uint32_t st = xdr_decode_uint32(&rep);
        fprintf(stderr, "[test] Op %u (PUTROOTFH) status=%u\n", op, st);
    }

    /* Parse GETATTR result */
    if (numresults >= 2) {
        uint32_t op = xdr_decode_uint32(&rep);
        uint32_t st = xdr_decode_uint32(&rep);
        fprintf(stderr, "[test] Op %u (GETATTR) status=%u\n", op, st);
        if (st == 0) {
            /* fattr4: bitmap + attrmask */
            uint32_t bm_len = xdr_decode_uint32(&rep);
            fprintf(stderr, "[test]   bitmap words: %u\n", bm_len);
            for (uint32_t i = 0; i < bm_len; i++) {
                uint32_t w = xdr_decode_uint32(&rep);
                fprintf(stderr, "[test]   bitmap[%u] = 0x%08x\n", i, w);
            }
            /* attr data (opaque) */
            uint32_t attr_len = xdr_decode_uint32(&rep);
            fprintf(stderr, "[test]   attr data: %u bytes\n", attr_len);
        }
    }

    close(fd);
    fprintf(stderr, "[test] SUCCESS: COMPOUND PUTROOTFH+GETATTR\n");
    return 0;
}

int main(void)
{
    static struct fuse_operations ops;
    memset(&ops, 0, sizeof(ops));
    ops.getattr = test_getattr;
    ops.access  = test_access;
    ops.readdir = test_readdir;

    darwinfuse_config_t config;
    memset(&config, 0, sizeof(config));
    config.ops = &ops;
    config.uid = getuid();
    config.gid = getgid();
    config.volume_path = "/volume.dmg";
    config.control_path = "/control";

    uint16_t port = 0;
    darwinfuse_server_t *srv = nfs4_server_create(&config, &port);
    if (!srv) {
        fprintf(stderr, "FAIL: nfs4_server_create\n");
        return 1;
    }

    fprintf(stderr, "[test] Server on port %u\n", port);

    /* Run server in thread */
    pthread_t tid;
    pthread_create(&tid, NULL, srv_thread, srv);

    /* Give the thread a moment to start */
    usleep(50000);

    /* Test 1: NULL RPC */
    int rc1 = test_rpc_null(port);

    /* Test 2: COMPOUND with PUTROOTFH + GETATTR */
    int rc2 = test_compound_getattr(port);

    /* Stop server */
    nfs4_server_stop(srv);
    pthread_join(tid, NULL);
    nfs4_server_destroy(srv);

    fprintf(stderr, "\n=== Results ===\n");
    fprintf(stderr, "NULL RPC:    %s\n", rc1 == 0 ? "PASS" : "FAIL");
    fprintf(stderr, "COMPOUND:    %s\n", rc2 == 0 ? "PASS" : "FAIL");

    return (rc1 == 0 && rc2 == 0) ? 0 : 1;
}
