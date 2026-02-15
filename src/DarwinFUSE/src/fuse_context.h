/*
 * DarwinFUSE — internal fuse context management
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef DARWINFUSE_FUSE_CONTEXT_H
#define DARWINFUSE_FUSE_CONTEXT_H

#include <sys/types.h>

/*
 * Set the thread-local FUSE context uid/gid.
 * Called by nfs4_ops.c before invoking any FUSE callback,
 * using the uid/gid extracted from the ONC RPC AUTH_SYS credentials.
 */
void darwinfuse_set_context(uid_t uid, gid_t gid);

#endif /* DARWINFUSE_FUSE_CONTEXT_H */
