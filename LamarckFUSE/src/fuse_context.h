/*
 * LamarckFUSE — internal fuse context management (Windows-only)
 *
 * Adapted from DarwinFUSE: uses platform_compat.h for uid_t/gid_t.
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef LAMARCKFUSE_FUSE_CONTEXT_H
#define LAMARCKFUSE_FUSE_CONTEXT_H

#include "platform_compat.h"  /* uid_t, gid_t */

/*
 * Set the thread-local FUSE context uid/gid.
 * Called before invoking any FUSE callback.
 */
void lamarckfuse_set_context(uid_t uid, gid_t gid);

/* DarwinFUSE compatibility alias */
#define darwinfuse_set_context lamarckfuse_set_context

#endif /* LAMARCKFUSE_FUSE_CONTEXT_H */
