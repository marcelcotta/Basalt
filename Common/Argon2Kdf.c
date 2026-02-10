/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "Argon2Kdf.h"
#include "Crypto/Argon2/argon2.h"

/*
 * Hardcoded Argon2id parameters (correct security posture — no configuration):
 *   m_cost = 262144 KiB (256 MB)
 *   t_cost = 3 passes
 *   parallelism = 4 lanes/threads
 */
#define ARGON2ID_M_COST  262144
#define ARGON2ID_T_COST  3
#define ARGON2ID_P        4

int derive_key_argon2id (char *pwd, int pwd_len,
                         char *salt, int salt_len,
                         char *dk, int dklen)
{
    return argon2id_hash_raw (
        ARGON2ID_T_COST,
        ARGON2ID_M_COST,
        ARGON2ID_P,
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
