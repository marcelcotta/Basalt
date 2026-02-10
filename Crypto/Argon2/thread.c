/*
 * Argon2 threading — adapted for Basalt.
 * Original: https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache License 2.0
 */

#include "thread.h"

int argon2_thread_create(argon2_thread_handle_t *handle,
                         argon2_thread_func_t func, void *args) {
    if (handle == NULL) {
        return -1;
    }
    return pthread_create(handle, NULL, func, args);
}

int argon2_thread_join(argon2_thread_handle_t handle) {
    return pthread_join(handle, NULL);
}
