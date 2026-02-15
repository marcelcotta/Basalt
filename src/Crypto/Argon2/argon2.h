/*
 * Argon2 reference implementation — adapted for Basalt (TrueCrypt macOS port).
 *
 * Original source: https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache License 2.0
 *
 * Only Argon2id is used; Argon2i/Argon2d entry points are omitted.
 */

#ifndef ARGON2_H
#define ARGON2_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Argon2 input parameter restrictions */
#define ARGON2_MIN_LANES UINT32_C(1)
#define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)
#define ARGON2_MIN_THREADS UINT32_C(1)
#define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)
#define ARGON2_SYNC_POINTS UINT32_C(4)
#define ARGON2_MIN_OUTLEN UINT32_C(4)
#define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS)
#define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARGON2_MAX_MEMORY_BITS 32
#define ARGON2_MAX_MEMORY ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)
#define ARGON2_MIN_TIME UINT32_C(1)
#define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_AD_LENGTH UINT32_C(0)
#define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_SECRET UINT32_C(0)
#define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)

#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8)
#define ARGON2_OWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 16)
#define ARGON2_HWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 32)
#define ARGON2_512BIT_WORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 64)
#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH 72

/* Argon2 type */
typedef enum Argon2_type {
    Argon2_d = 0,
    Argon2_i = 1,
    Argon2_id = 2
} argon2_type;

/* Argon2 version */
typedef enum Argon2_version {
    ARGON2_VERSION_10 = 0x10,
    ARGON2_VERSION_13 = 0x13,
    ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

/* Error codes */
typedef enum Argon2_ErrorCodes {
    ARGON2_OK = 0,

    ARGON2_OUTPUT_PTR_NULL = -1,

    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,

    ARGON2_PWD_TOO_SHORT = -4,
    ARGON2_PWD_TOO_LONG = -5,

    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,

    ARGON2_AD_TOO_SHORT = -8,
    ARGON2_AD_TOO_LONG = -9,

    ARGON2_SECRET_TOO_SHORT = -10,
    ARGON2_SECRET_TOO_LONG = -11,

    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,

    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,

    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,

    ARGON2_PWD_PTR_MISMATCH = -18,
    ARGON2_SALT_PTR_MISMATCH = -19,
    ARGON2_SECRET_PTR_MISMATCH = -20,
    ARGON2_AD_PTR_MISMATCH = -21,

    ARGON2_MEMORY_ALLOCATION_ERROR = -22,

    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,

    ARGON2_OUT_PTR_MISMATCH = -27,

    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,

    ARGON2_MISSING_ARGS = -30,

    ARGON2_ENCODING_FAIL = -31,

    ARGON2_DECODING_FAIL = -32,

    ARGON2_THREAD_FAIL = -33,

    ARGON2_DECODING_LENGTH_FAIL = -34,

    ARGON2_VERIFY_MISMATCH = -35
} argon2_error_codes;

/* Context: primary Argon2 inputs */
typedef struct Argon2_Context {
    uint8_t *out;    /* output array */
    uint32_t outlen; /* digest length */

    uint8_t *pwd;    /* password array */
    uint32_t pwdlen; /* password length */

    uint8_t *salt;    /* salt array */
    uint32_t saltlen; /* salt length */

    uint8_t *secret;    /* key array (optional) */
    uint32_t secretlen; /* key length */

    uint8_t *ad;    /* associated data array (optional) */
    uint32_t adlen; /* associated data length */

    uint32_t t_cost;  /* number of passes */
    uint32_t m_cost;  /* amount of memory requested (KB) */
    uint32_t lanes;   /* number of lanes */
    uint32_t threads; /* maximum number of threads */

    argon2_version version; /* version number */

    int (*allocate_cbk)(uint8_t **memory, size_t bytes_to_allocate);
    void (*free_cbk)(uint8_t *memory, size_t bytes_to_allocate);

    uint32_t flags; /* array of bool options */
} argon2_context;

/* Flag to determine if we should wipe password after use */
#define ARGON2_DEFAULT_FLAGS UINT32_C(0)
#define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
#define ARGON2_FLAG_CLEAR_SECRET (UINT32_C(1) << 1)

/**
 * Raw hash function — produces tag of given length.
 * @param t_cost   Number of iterations
 * @param m_cost   Memory usage in kibibytes
 * @param parallelism   Number of threads and lanes
 * @param pwd   Pointer to password
 * @param pwdlen   Password size in bytes
 * @param salt   Pointer to salt
 * @param saltlen   Salt size in bytes
 * @param hash   Buffer for the hash
 * @param hashlen   Desired length of the hash in bytes
 * @return ARGON2_OK on success, error code otherwise
 */
int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash,
                      const size_t hashlen);

/**
 * Main Argon2 function — called by the type-specific entry points.
 */
int argon2_ctx(argon2_context *context, argon2_type type);

/**
 * Return error message for the given error code.
 */
const char *argon2_error_message(int error_code);

#if defined(__cplusplus)
}
#endif

#endif /* ARGON2_H */
