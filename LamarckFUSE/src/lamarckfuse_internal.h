/*
 * LamarckFUSE — internal shared definitions (Windows-only)
 *
 * Windows adaptation of DarwinFUSE's darwinfuse_internal.h.
 * Same constants, adapted logging paths and macros.
 *
 * On macOS/Linux, DarwinFUSE is used instead (separate directory).
 *
 * Copyright (c) 2025 Basalt contributors. All rights reserved.
 * Licensed under the MIT License.
 */

#ifndef LAMARCKFUSE_INTERNAL_H
#define LAMARCKFUSE_INTERNAL_H

#include "platform_compat.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ---------- Logging ---------- */

/*
 * On Windows, log to %TEMP%\lamarckfuse.log.
 * We use a helper to get the path since getenv isn't async-signal-safe
 * (but that doesn't matter on Windows — no signals).
 */
static inline const char *lfuse_log_path(void)
{
    static char path[MAX_PATH] = {0};
    if (path[0] == '\0') {
        const char *tmp = getenv("TEMP");
        if (!tmp) tmp = getenv("TMP");
        if (!tmp) tmp = "C:\\Windows\\Temp";
        snprintf(path, sizeof(path), "%s\\lamarckfuse.log", tmp);
    }
    return path;
}

#define LFUSE_LOG(fmt, ...) do { \
    FILE *_f = fopen(lfuse_log_path(), "a"); \
    if (_f) { fprintf(_f, "[LamarckFUSE] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[LamarckFUSE] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define LFUSE_ERR(fmt, ...) do { \
    FILE *_f = fopen(lfuse_log_path(), "a"); \
    if (_f) { fprintf(_f, "[LamarckFUSE ERROR] " fmt "\n", ##__VA_ARGS__); fclose(_f); } \
    fprintf(stderr, "[LamarckFUSE ERROR] " fmt "\n", ##__VA_ARGS__); \
} while (0)

#endif /* LAMARCKFUSE_INTERNAL_H */
