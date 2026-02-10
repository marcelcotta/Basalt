/*
 Copyright (c) 2024 TrueCrypt macOS Port. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Common_Argon2Kdf
#define TC_HEADER_Common_Argon2Kdf

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Derive key using Argon2id with hardcoded parameters:
 *   m_cost = 262144 (256 MB), t_cost = 3, parallelism = 4
 *
 * Returns 0 on success, Argon2 error code on failure (e.g., out of memory).
 * On failure, the output buffer is zeroed.
 */
int derive_key_argon2id (char *pwd, int pwd_len,
                         char *salt, int salt_len,
                         char *dk, int dklen);

/*
 * Test-only variant with caller-specified parameters.
 * Used by self-tests with reduced memory to keep test time short.
 */
int derive_key_argon2id_test (char *pwd, int pwd_len,
                              char *salt, int salt_len,
                              uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                              char *dk, int dklen);

#if defined(__cplusplus)
}
#endif

#endif /* TC_HEADER_Common_Argon2Kdf */
