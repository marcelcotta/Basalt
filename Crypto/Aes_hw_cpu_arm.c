/*
 ARM hardware AES acceleration using ARMv8 Cryptographic Extensions.

 Drop-in replacement for Aes_hw_cpu.asm (x86 AES-NI) on Apple Silicon.
 Uses ARM NEON intrinsics: vaeseq_u8, vaesdq_u8, vaesmcq_u8, vaesimcq_u8.

 Important: ARM AESE performs XOR-then-SubBytes-then-ShiftRows (AddRoundKey
 is implicit at the beginning), unlike x86 AESENC which does it at the end.
 The round loop structure accounts for this difference.

 Key schedule format is identical to the software implementation:
   aes_encrypt_ctx: 60 x uint32 round keys + 4-byte info (inf.b[0] = rounds*16)
   aes_decrypt_ctx: same layout, with AES_REV_DKS (reversed key order)
*/

#include "Common/Tcdefs.h"

#if defined(__aarch64__) && (defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES))

#include <arm_neon.h>
#include "Aes.h"

/* Number of AES rounds for AES-256 */
#define AES256_ROUNDS 14

/* Load a round key from the key schedule at given round index */
static inline uint8x16_t load_round_key (const uint32_t *ks, int round)
{
	return vreinterpretq_u8_u32 (vld1q_u32 (ks + round * 4));
}

byte is_aes_hw_cpu_supported (void)
{
	/* Apple Silicon always supports ARMv8 Crypto Extensions */
	return 1;
}

void aes_hw_cpu_enable_sse (void)
{
	/* No-op on ARM (SSE is x86-specific) */
}

void aes_hw_cpu_encrypt (const byte *ks, byte *data)
{
	const uint32_t *rk = (const uint32_t *) ks;
	/* Number of rounds from context: inf.b[0] / 16 */
	int rounds = ((const byte *) ks)[sizeof(aes_encrypt_ctx) - 4] / 16;
	if (rounds == 0) rounds = AES256_ROUNDS;

	uint8x16_t state = vld1q_u8 (data);

	/* ARM AESE: state = ShiftRows(SubBytes(state XOR round_key))
	   So we pass round key 0 to first AESE, key 1 to second, etc.
	   After AESE we apply MixColumns for all rounds except the last. */

	state = vaeseq_u8 (state, load_round_key (rk, 0));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 1));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 2));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 3));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 4));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 5));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 6));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 7));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 8));
	state = vaesmcq_u8 (state);

	state = vaeseq_u8 (state, load_round_key (rk, 9));
	if (rounds > 10) {
		state = vaesmcq_u8 (state);

		state = vaeseq_u8 (state, load_round_key (rk, 10));
		state = vaesmcq_u8 (state);

		state = vaeseq_u8 (state, load_round_key (rk, 11));
		if (rounds > 12) {
			state = vaesmcq_u8 (state);

			state = vaeseq_u8 (state, load_round_key (rk, 12));
			state = vaesmcq_u8 (state);

			state = vaeseq_u8 (state, load_round_key (rk, 13));
		}
	}

	/* Final XOR with last round key (AESE already did SubBytes+ShiftRows) */
	state = veorq_u8 (state, load_round_key (rk, rounds));

	vst1q_u8 (data, state);
}

void aes_hw_cpu_decrypt (const byte *ks, byte *data)
{
	const uint32_t *rk = (const uint32_t *) ks;
	/* Number of rounds from context: inf.b[0] / 16 */
	int rounds = ((const byte *) ks)[sizeof(aes_decrypt_ctx) - 4] / 16;
	if (rounds == 0) rounds = AES256_ROUNDS;

	uint8x16_t state = vld1q_u8 (data);

	/*
	 * AES_REV_DKS is defined in TrueCrypt, meaning decryption keys are stored
	 * in reverse order. So rk[0] is the last round key, rk[rounds] is the first.
	 * ARM AESD: state = InvShiftRows(InvSubBytes(state XOR round_key))
	 */

	state = vaesdq_u8 (state, load_round_key (rk, 0));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 1));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 2));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 3));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 4));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 5));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 6));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 7));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 8));
	state = vaesimcq_u8 (state);

	state = vaesdq_u8 (state, load_round_key (rk, 9));
	if (rounds > 10) {
		state = vaesimcq_u8 (state);

		state = vaesdq_u8 (state, load_round_key (rk, 10));
		state = vaesimcq_u8 (state);

		state = vaesdq_u8 (state, load_round_key (rk, 11));
		if (rounds > 12) {
			state = vaesimcq_u8 (state);

			state = vaesdq_u8 (state, load_round_key (rk, 12));
			state = vaesimcq_u8 (state);

			state = vaesdq_u8 (state, load_round_key (rk, 13));
		}
	}

	/* Final XOR with last round key */
	state = veorq_u8 (state, load_round_key (rk, rounds));

	vst1q_u8 (data, state);
}

void aes_hw_cpu_encrypt_32_blocks (const byte *ks, byte *data)
{
	int i;
	for (i = 0; i < 32; i++)
	{
		aes_hw_cpu_encrypt (ks, data);
		data += 16;
	}
}

void aes_hw_cpu_decrypt_32_blocks (const byte *ks, byte *data)
{
	int i;
	for (i = 0; i < 32; i++)
	{
		aes_hw_cpu_decrypt (ks, data);
		data += 16;
	}
}

#endif /* __aarch64__ && (__ARM_FEATURE_CRYPTO || __ARM_FEATURE_AES) */
