/*
 * Argon2 threading — adapted for Basalt.
 * Original: https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache License 2.0
 */

#ifndef ARGON2_THREAD_H
#define ARGON2_THREAD_H

#if defined(__cplusplus)
extern "C" {
#endif

/* Use pthreads on macOS/Unix */
#include <pthread.h>

typedef pthread_t argon2_thread_handle_t;
typedef void *argon2_thread_return_t;
typedef void *(*argon2_thread_func_t)(void *);

int argon2_thread_create(argon2_thread_handle_t *handle,
                         argon2_thread_func_t func, void *args);
int argon2_thread_join(argon2_thread_handle_t handle);

#if defined(__cplusplus)
}
#endif

#endif /* ARGON2_THREAD_H */
