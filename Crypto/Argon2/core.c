/*
 * Argon2 core — adapted for Basalt.
 * Original: https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache License 2.0
 *
 * Modification: clear_internal_memory uses memset_s (Basalt security standard).
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "core.h"
#include "blake2.h"
#include "blake2-impl.h"
#include "thread.h"

/* Securely wipe memory — uses memset_s where available (Basalt standard) */
void clear_internal_memory(void *v, size_t n) {
    if (v) {
#if defined(__STDC_LIB_EXT1__) || defined(__APPLE__)
        memset_s(v, n, 0, n);
#else
        volatile unsigned char *p = (volatile unsigned char *)v;
        while (n--) *p++ = 0;
#endif
    }
}

void init_block_value(block *b, uint8_t in) { memset(b->v, in, sizeof(b->v)); }

void copy_block(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

void xor_block(block *dst, const block *src) {
    int i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] ^= src->v[i];
    }
}

static void load_block(block *dst, const void *input) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        dst->v[i] = load64((const uint8_t *)input + i * sizeof(dst->v[i]));
    }
}

static void store_block(void *output, const block *src) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}

int allocate_memory(const argon2_context *context, uint8_t **memory,
                    size_t num, size_t size) {
    size_t memory_size = num * size;
    if (memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    /* Check for multiplication overflow */
    if (size != 0 && memory_size / size != num) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    if (context->allocate_cbk) {
        (context->allocate_cbk)(memory, memory_size);
    } else {
        *memory = (uint8_t *)malloc(memory_size);
    }

    if (*memory == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    return ARGON2_OK;
}

void free_memory(const argon2_context *context, uint8_t *memory,
                 size_t num, size_t size) {
    size_t memory_size = num * size;
    clear_internal_memory(memory, memory_size);
    if (context->free_cbk) {
        (context->free_cbk)(memory, memory_size);
    } else {
        free(memory);
    }
}

int validate_inputs(const argon2_context *context) {
    if (NULL == context) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (NULL == context->out) {
        return ARGON2_OUTPUT_PTR_NULL;
    }

    /* Validate output length */
    if (ARGON2_MIN_OUTLEN > context->outlen) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    if (ARGON2_MAX_OUTLEN < context->outlen) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    /* Validate password length */
    if (NULL == context->pwd) {
        if (0 != context->pwdlen) {
            return ARGON2_PWD_PTR_MISMATCH;
        }
    }

    if (ARGON2_MAX_PWD_LENGTH < context->pwdlen) {
        return ARGON2_PWD_TOO_LONG;
    }

    /* Validate salt */
    if (NULL == context->salt) {
        if (0 != context->saltlen) {
            return ARGON2_SALT_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_SALT_LENGTH > context->saltlen) {
            return ARGON2_SALT_TOO_SHORT;
        }
        if (ARGON2_MAX_SALT_LENGTH < context->saltlen) {
            return ARGON2_SALT_TOO_LONG;
        }
    }

    /* Validate secret */
    if (NULL == context->secret) {
        if (0 != context->secretlen) {
            return ARGON2_SECRET_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_SECRET > context->secretlen) {
            return ARGON2_SECRET_TOO_SHORT;
        }
        if (ARGON2_MAX_SECRET < context->secretlen) {
            return ARGON2_SECRET_TOO_LONG;
        }
    }

    /* Validate associated data */
    if (NULL == context->ad) {
        if (0 != context->adlen) {
            return ARGON2_AD_PTR_MISMATCH;
        }
    } else {
        if (ARGON2_MIN_AD_LENGTH > context->adlen) {
            return ARGON2_AD_TOO_SHORT;
        }
        if (ARGON2_MAX_AD_LENGTH < context->adlen) {
            return ARGON2_AD_TOO_LONG;
        }
    }

    /* Validate memory cost */
    if (ARGON2_MIN_MEMORY > context->m_cost) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }

    if (ARGON2_MAX_MEMORY < context->m_cost) {
        return ARGON2_MEMORY_TOO_MUCH;
    }

    if (context->m_cost < 8 * context->lanes) {
        return ARGON2_MEMORY_TOO_LITTLE;
    }

    /* Validate time cost */
    if (ARGON2_MIN_TIME > context->t_cost) {
        return ARGON2_TIME_TOO_SMALL;
    }

    if (ARGON2_MAX_TIME < context->t_cost) {
        return ARGON2_TIME_TOO_LARGE;
    }

    /* Validate lanes */
    if (ARGON2_MIN_LANES > context->lanes) {
        return ARGON2_LANES_TOO_FEW;
    }

    if (ARGON2_MAX_LANES < context->lanes) {
        return ARGON2_LANES_TOO_MANY;
    }

    /* Validate threads */
    if (ARGON2_MIN_THREADS > context->threads) {
        return ARGON2_THREADS_TOO_FEW;
    }

    if (ARGON2_MAX_THREADS < context->threads) {
        return ARGON2_THREADS_TOO_MANY;
    }

    return ARGON2_OK;
}

void fill_block(const block *prev_block, const block *ref_block,
                block *next_block, int with_xor) {
    block blockR, tmp;
    unsigned i;

    copy_block(&blockR, ref_block);
    xor_block(&blockR, prev_block);
    copy_block(&tmp, &blockR);
    /* Now blockR = ref_block XOR prev_block */

    /* Apply Blake2 on columns of 64-bit words: (0,1,...,15), then
       (16,17,..31)... finally (112,...127) */
    for (i = 0; i < 8; ++i) {
        /* Operate on 16 uint64's = 128 bytes at a time */
        uint64_t *v = &blockR.v[16 * i];
        /* Blake2b round function */
        #define BLAMKA_G(a, b, c, d)                                            \
        do {                                                                    \
            a = a + b + 2 * ((uint64_t)(uint32_t)a) * ((uint64_t)(uint32_t)b);  \
            d = rotr64(d ^ a, 32);                                              \
            c = c + d + 2 * ((uint64_t)(uint32_t)c) * ((uint64_t)(uint32_t)d);  \
            b = rotr64(b ^ c, 24);                                              \
            a = a + b + 2 * ((uint64_t)(uint32_t)a) * ((uint64_t)(uint32_t)b);  \
            d = rotr64(d ^ a, 16);                                              \
            c = c + d + 2 * ((uint64_t)(uint32_t)c) * ((uint64_t)(uint32_t)d);  \
            b = rotr64(b ^ c, 63);                                              \
        } while ((void)0, 0)

        BLAMKA_G(v[0], v[4], v[8],  v[12]);
        BLAMKA_G(v[1], v[5], v[9],  v[13]);
        BLAMKA_G(v[2], v[6], v[10], v[14]);
        BLAMKA_G(v[3], v[7], v[11], v[15]);
        BLAMKA_G(v[0], v[5], v[10], v[15]);
        BLAMKA_G(v[1], v[6], v[11], v[12]);
        BLAMKA_G(v[2], v[7], v[8],  v[13]);
        BLAMKA_G(v[3], v[4], v[9],  v[14]);
    }

    /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113),
       then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
    for (i = 0; i < 8; ++i) {
        /* Rearranged to operate on rows */
        uint64_t *v0 = &blockR.v[2 * i];
        uint64_t *v1 = &blockR.v[2 * i + 16];
        uint64_t *v2 = &blockR.v[2 * i + 32];
        uint64_t *v3 = &blockR.v[2 * i + 48];
        uint64_t *v4 = &blockR.v[2 * i + 64];
        uint64_t *v5 = &blockR.v[2 * i + 80];
        uint64_t *v6 = &blockR.v[2 * i + 96];
        uint64_t *v7 = &blockR.v[2 * i + 112];

        BLAMKA_G(*v0, *v2, *v4, *v6);
        BLAMKA_G(*(v0+1), *(v2+1), *(v4+1), *(v6+1));
        BLAMKA_G(*v1, *v3, *v5, *v7);
        BLAMKA_G(*(v1+1), *(v3+1), *(v5+1), *(v7+1));
        BLAMKA_G(*v0, *(v2+1), *v5, *(v6+1));
        BLAMKA_G(*(v0+1), *v3, *(v5+1), *v7);
        BLAMKA_G(*v1, *(v3+1), *v4, *(v7+1));
        BLAMKA_G(*(v1+1), *v2, *(v4+1), *v6);

        #undef BLAMKA_G
    }

    copy_block(next_block, &tmp);
    xor_block(next_block, &blockR);
}

void initial_hash(uint8_t *blockhash, argon2_context *context,
                  argon2_type type) {
    blake2b_state BlakeHash;
    uint8_t value[sizeof(uint32_t)];

    if (NULL == context || NULL == blockhash) {
        return;
    }

    blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);

    store32(&value, context->lanes);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->outlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->m_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->t_cost);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->version);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, (uint32_t)type);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->pwdlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->pwd != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->pwd,
                       context->pwdlen);

        if (context->flags & ARGON2_FLAG_CLEAR_PASSWORD) {
            clear_internal_memory(context->pwd, context->pwdlen);
            context->pwdlen = 0;
        }
    }

    store32(&value, context->saltlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->salt != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->salt,
                       context->saltlen);
    }

    store32(&value, context->secretlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->secret != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->secret,
                       context->secretlen);

        if (context->flags & ARGON2_FLAG_CLEAR_SECRET) {
            clear_internal_memory(context->secret, context->secretlen);
            context->secretlen = 0;
        }
    }

    store32(&value, context->adlen);
    blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->ad != NULL) {
        blake2b_update(&BlakeHash, (const uint8_t *)context->ad,
                       context->adlen);
    }

    blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

static void fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance) {
    uint32_t l;
    /* Make the first and second block in each lane as G(H0||0||i) or
       G(H0||1||i) */
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    for (l = 0; l < instance->lanes; ++l) {
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 0],
                   blockhash_bytes);

        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash,
                     ARGON2_PREHASH_SEED_LENGTH);
        load_block(&instance->memory[l * instance->lane_length + 1],
                   blockhash_bytes);
    }
    clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
}

int initialize(argon2_instance_t *instance, argon2_context *context) {
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    int result = ARGON2_OK;

    if (instance == NULL || context == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    instance->context_ptr = context;

    /* 1. Memory allocation */
    result = allocate_memory(context, (uint8_t **)&(instance->memory),
                             instance->memory_blocks, sizeof(block));

    if (result != ARGON2_OK) {
        return result;
    }

    /* 2. Initial hashing */
    /* H_0 + 8 extra bytes to produce the first blocks */
    initial_hash(blockhash, context, instance->type);
    /* 3. Creating first blocks, filling them with G(H0||0) or G(H0||1) */
    fill_first_blocks(blockhash, instance);
    clear_internal_memory(blockhash, ARGON2_PREHASH_SEED_LENGTH);

    return ARGON2_OK;
}

void finalize(const argon2_context *context, argon2_instance_t *instance) {
    if (context != NULL && instance != NULL) {
        block blockhash;
        uint32_t l;
        uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];

        copy_block(&blockhash, &instance->memory[instance->lane_length - 1]);

        /* XOR the last blocks */
        for (l = 1; l < instance->lanes; ++l) {
            uint32_t last_block_in_lane =
                l * instance->lane_length + (instance->lane_length - 1);
            xor_block(&blockhash, &instance->memory[last_block_in_lane]);
        }

        /* Hash the result */
        store_block(blockhash_bytes, &blockhash);
        blake2b_long(context->out, context->outlen, blockhash_bytes,
                     ARGON2_BLOCK_SIZE);
        /* Wipe */
        clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
        clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);

        /* Wipe memory area */
        free_memory(context, (uint8_t *)instance->memory,
                    instance->memory_blocks, sizeof(block));
    }
}

uint32_t index_alpha(const argon2_instance_t *instance,
                     const argon2_position_t *position, uint32_t pseudo_rand,
                     int same_lane) {
    /*
     * 0..(" area size" - 1) are available.
     * area size depends on position in pass.
     */
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (0 == position->pass) {
        /* First pass */
        if (0 == position->slice) {
            /* First slice */
            reference_area_size =
                position->index - 1; /* all done blocks are available */
        } else {
            if (same_lane) {
                /* The same lane => add current segment */
                reference_area_size =
                    position->slice * instance->segment_length +
                    position->index - 1;
            } else {
                reference_area_size =
                    position->slice * instance->segment_length +
                    ((position->index == 0) ? (-1) : 0);
            }
        }
    } else {
        /* Second pass or later */
        if (same_lane) {
            reference_area_size =
                instance->lane_length -
                instance->segment_length + position->index - 1;
        } else {
            reference_area_size =
                instance->lane_length -
                instance->segment_length +
                ((position->index == 0) ? (-1) : 0);
        }
    }

    /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
     * relative position */
    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 -
                        (reference_area_size * relative_position >> 32);

    /* 1.2.5 Computing starting position */
    start_position = 0;

    if (0 != position->pass) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0
                             : (position->slice + 1) * instance->segment_length;
    }

    /* 1.2.6. Computing absolute position */
    absolute_position = (start_position + relative_position) %
                        instance->lane_length; /* absolute position */
    return absolute_position;
}

/* Data for threaded fill_segment */
typedef struct {
    argon2_instance_t *instance_ptr;
    argon2_position_t pos;
} fill_segment_data;

static argon2_thread_return_t fill_segment_thr_wrapper(void *arg) {
    fill_segment_data *fsd = (fill_segment_data *)arg;
    fill_segment(fsd->instance_ptr, fsd->pos);
    return 0;
}

int fill_memory_blocks(argon2_instance_t *instance) {
    uint32_t r, s;

    if (instance == NULL || instance->lanes == 0) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    for (r = 0; r < instance->passes; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
            uint32_t l;

            /* 2. Calling threads */
            if (instance->threads > 1) {
                argon2_thread_handle_t *thread =
                    (argon2_thread_handle_t *)malloc(
                        instance->lanes * sizeof(argon2_thread_handle_t));
                fill_segment_data *thr_data =
                    (fill_segment_data *)malloc(
                        instance->lanes * sizeof(fill_segment_data));

                if (thread == NULL || thr_data == NULL) {
                    if (thread) free(thread);
                    if (thr_data) free(thr_data);
                    return ARGON2_MEMORY_ALLOCATION_ERROR;
                }

                for (l = 0; l < instance->lanes; ++l) {
                    argon2_position_t position;
                    position.pass = r;
                    position.lane = l;
                    position.slice = (uint8_t)s;
                    position.index = 0;

                    thr_data[l].instance_ptr = instance;
                    thr_data[l].pos = position;

                    if (argon2_thread_create(&thread[l],
                                             &fill_segment_thr_wrapper,
                                             (void *)&thr_data[l])) {
                        /* Fallback to sequential if thread creation fails */
                        for ( ; l < instance->lanes; ++l) {
                            thr_data[l].instance_ptr = instance;
                            position.lane = l;
                            thr_data[l].pos = position;
                            fill_segment(instance, position);
                        }
                        break;
                    }
                }

                for (l = 0; l < instance->lanes; ++l) {
                    argon2_thread_join(thread[l]);
                }

                free(thread);
                free(thr_data);
            } else {
                /* Single-threaded */
                for (l = 0; l < instance->lanes; ++l) {
                    argon2_position_t position;
                    position.pass = r;
                    position.lane = l;
                    position.slice = (uint8_t)s;
                    position.index = 0;
                    fill_segment(instance, position);
                }
            }
        }
    }
    return ARGON2_OK;
}
