/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Argon2Kdf.h"
#include "Crypto/Argon2/argon2.h"

/*
 * Hardcoded Argon2id parameters (correct security posture — no configuration).
 *
 * Standard:  m=512 MB, t=4, p=4  — fast on any macOS 14 capable Mac
 * Maximum:   m=1 GB,   t=4, p=8  — for high-value data, leverages 8+ cores
 */
#define ARGON2ID_STD_M_COST   524288    /* 512 MB */
#define ARGON2ID_STD_T_COST   4
#define ARGON2ID_STD_P        4

#define ARGON2ID_MAX_M_COST   1048576   /* 1 GB */
#define ARGON2ID_MAX_T_COST   4
#define ARGON2ID_MAX_P        8

int derive_key_argon2id (char *pwd, int pwd_len,
                         char *salt, int salt_len,
                         char *dk, int dklen)
{
    return argon2id_hash_raw (
        ARGON2ID_STD_T_COST,
        ARGON2ID_STD_M_COST,
        ARGON2ID_STD_P,
        pwd, (size_t) pwd_len,
        salt, (size_t) salt_len,
        dk, (size_t) dklen
    );
}

int derive_key_argon2id_max (char *pwd, int pwd_len,
                              char *salt, int salt_len,
                              char *dk, int dklen)
{
    return argon2id_hash_raw (
        ARGON2ID_MAX_T_COST,
        ARGON2ID_MAX_M_COST,
        ARGON2ID_MAX_P,
        pwd, (size_t) pwd_len,
        salt, (size_t) salt_len,
        dk, (size_t) dklen
    );
}

int derive_key_argon2id_test (char *pwd, int pwd_len,
                              char *salt, int salt_len,
                              uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                              char *dk, int dklen)
{
    return argon2id_hash_raw (
        t_cost, m_cost, parallelism,
        pwd, (size_t) pwd_len,
        salt, (size_t) salt_len,
        dk, (size_t) dklen
    );
}
