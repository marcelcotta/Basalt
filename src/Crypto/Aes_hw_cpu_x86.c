/*
 x86-64 hardware AES acceleration using AES-NI compiler intrinsics.
 Drop-in replacement for Aes_hw_cpu.asm when the assembler modules are not
 built (NOASM=1, as used for universal macOS builds), mirroring
 Aes_hw_cpu_arm.c on Apple Silicon.

 The functions are compiled for the "aes" target only; callers reach them
 solely after is_aes_hw_cpu_supported() confirmed CPU support at run time.

 Key schedule format is identical to the software implementation:
   aes_encrypt_ctx: round keys + 4-byte info (inf.b[0] = rounds*16)
   aes_decrypt_ctx: same layout, with AES_REV_DKS (reversed key order, middle
                    round keys in InvMixColumns form), as expected by AESDEC.
*/

#include "Common/Tcdefs.h"

#if defined(__x86_64__) && !defined(TC_ARCH_X64)

#include <cpuid.h>
#include <wmmintrin.h>
#include "Aes.h"
#include "Aes_hw_cpu.h"

#define AES256_ROUNDS 14
#define AES_NI_TARGET __attribute__((target("aes,sse2")))

byte is_aes_hw_cpu_supported (void)
{
	unsigned int eax, ebx, ecx, edx;

	if (!__get_cpuid (1, &eax, &ebx, &ecx, &edx))
		return 0;

	return (ecx & bit_AES) ? 1 : 0;
}

void aes_hw_cpu_enable_sse (void)
{
	/* SSE is always enabled on x86-64 */
}

static inline int get_rounds (const byte *ks, size_t ctxSize)
{
	/* Number of rounds from context: inf.b[0] / 16 */
	int rounds = ks[ctxSize - 4] / 16;
	return rounds == 0 ? AES256_ROUNDS : rounds;
}

AES_NI_TARGET static inline __m128i load_round_key (const byte *ks, int round)
{
	return _mm_loadu_si128 ((const __m128i *) (ks + round * 16));
}

AES_NI_TARGET void aes_hw_cpu_encrypt (const byte *ks, byte *data)
{
	int rounds = get_rounds (ks, sizeof (aes_encrypt_ctx));
	__m128i state = _mm_loadu_si128 ((const __m128i *) data);
	int r;

	state = _mm_xor_si128 (state, load_round_key (ks, 0));

	for (r = 1; r < rounds; r++)
		state = _mm_aesenc_si128 (state, load_round_key (ks, r));

	state = _mm_aesenclast_si128 (state, load_round_key (ks, rounds));
	_mm_storeu_si128 ((__m128i *) data, state);
}

AES_NI_TARGET void aes_hw_cpu_decrypt (const byte *ks, byte *data)
{
	int rounds = get_rounds (ks, sizeof (aes_decrypt_ctx));
	__m128i state = _mm_loadu_si128 ((const __m128i *) data);
	int r;

	state = _mm_xor_si128 (state, load_round_key (ks, 0));

	for (r = 1; r < rounds; r++)
		state = _mm_aesdec_si128 (state, load_round_key (ks, r));

	state = _mm_aesdeclast_si128 (state, load_round_key (ks, rounds));
	_mm_storeu_si128 ((__m128i *) data, state);
}

/* Four independent blocks per iteration hide the AES instruction latency. */

AES_NI_TARGET void aes_hw_cpu_encrypt_32_blocks (const byte *ks, byte *data)
{
	int rounds = get_rounds (ks, sizeof (aes_encrypt_ctx));
	int i, r;

	for (i = 0; i < 32; i += 4, data += 64)
	{
		__m128i k = load_round_key (ks, 0);
		__m128i s0 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data +  0)), k);
		__m128i s1 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data + 16)), k);
		__m128i s2 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data + 32)), k);
		__m128i s3 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data + 48)), k);

		for (r = 1; r < rounds; r++)
		{
			k = load_round_key (ks, r);
			s0 = _mm_aesenc_si128 (s0, k);
			s1 = _mm_aesenc_si128 (s1, k);
			s2 = _mm_aesenc_si128 (s2, k);
			s3 = _mm_aesenc_si128 (s3, k);
		}

		k = load_round_key (ks, rounds);
		_mm_storeu_si128 ((__m128i *) (data +  0), _mm_aesenclast_si128 (s0, k));
		_mm_storeu_si128 ((__m128i *) (data + 16), _mm_aesenclast_si128 (s1, k));
		_mm_storeu_si128 ((__m128i *) (data + 32), _mm_aesenclast_si128 (s2, k));
		_mm_storeu_si128 ((__m128i *) (data + 48), _mm_aesenclast_si128 (s3, k));
	}
}

AES_NI_TARGET void aes_hw_cpu_decrypt_32_blocks (const byte *ks, byte *data)
{
	int rounds = get_rounds (ks, sizeof (aes_decrypt_ctx));
	int i, r;

	for (i = 0; i < 32; i += 4, data += 64)
	{
		__m128i k = load_round_key (ks, 0);
		__m128i s0 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data +  0)), k);
		__m128i s1 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data + 16)), k);
		__m128i s2 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data + 32)), k);
		__m128i s3 = _mm_xor_si128 (_mm_loadu_si128 ((const __m128i *) (data + 48)), k);

		for (r = 1; r < rounds; r++)
		{
			k = load_round_key (ks, r);
			s0 = _mm_aesdec_si128 (s0, k);
			s1 = _mm_aesdec_si128 (s1, k);
			s2 = _mm_aesdec_si128 (s2, k);
			s3 = _mm_aesdec_si128 (s3, k);
		}

		k = load_round_key (ks, rounds);
		_mm_storeu_si128 ((__m128i *) (data +  0), _mm_aesdeclast_si128 (s0, k));
		_mm_storeu_si128 ((__m128i *) (data + 16), _mm_aesdeclast_si128 (s1, k));
		_mm_storeu_si128 ((__m128i *) (data + 32), _mm_aesdeclast_si128 (s2, k));
		_mm_storeu_si128 ((__m128i *) (data + 48), _mm_aesdeclast_si128 (s3, k));
	}
}

#endif /* __x86_64__ && !TC_ARCH_X64 */
