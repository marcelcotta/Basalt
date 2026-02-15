/*
 * Blake2b implementation helpers — adapted for Basalt.
 * Original: https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache License 2.0
 */

#ifndef ARGON2_BLAKE2_IMPL_H
#define ARGON2_BLAKE2_IMPL_H

#include <stdint.h>
#include <string.h>

static inline uint32_t load32(const void *src) {
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

static inline uint64_t load64(const void *src) {
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

static inline void store32(void *dst, uint32_t w) { memcpy(dst, &w, sizeof w); }

static inline void store64(void *dst, uint64_t w) { memcpy(dst, &w, sizeof w); }

static inline uint64_t rotr64(const uint64_t w, const unsigned c) {
    return (w >> c) | (w << (64 - c));
}

#endif /* ARGON2_BLAKE2_IMPL_H */
