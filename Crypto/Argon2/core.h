/*
 * Argon2 core — adapted for Basalt.
 * Original: https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache License 2.0
 */

#ifndef ARGON2_CORE_H
#define ARGON2_CORE_H

#include "argon2.h"

#define ARGON2_CORE_H_DEF

/*
 * Argon2 memory block (1024 bytes = 128 uint64's)
 */
typedef struct block_ { uint64_t v[ARGON2_QWORDS_IN_BLOCK]; } block;

/*
 * Argon2 instance: memory + parameters
 */
typedef struct Argon2_instance_t {
    block *memory;           /* Memory pointer */
    uint32_t version;
    uint32_t passes;         /* Number of passes */
    uint32_t memory_blocks;  /* Number of blocks in memory */
    uint32_t segment_length; /* Blocks per segment */
    uint32_t lane_length;    /* Blocks per lane */
    uint32_t lanes;          /* Number of lanes */
    uint32_t threads;        /* Number of threads */
    argon2_type type;
    int print_internals;     /* Whether to print internals */
    argon2_context *context_ptr; /* Points to original context */
} argon2_instance_t;

/*
 * Argon2 position: current state of filling
 */
typedef struct Argon2_position_t {
    uint32_t pass;
    uint32_t lane;
    uint8_t slice;
    uint32_t index;
} argon2_position_t;

/* Context validation */
int validate_inputs(const argon2_context *context);

/* Fills a memory block */
void fill_block(const block *prev_block, const block *ref_block,
                block *next_block, int with_xor);

/* Initialize Argon2 */
int initialize(argon2_instance_t *instance, argon2_context *context);

/* Finalize: compute output tag */
void finalize(const argon2_context *context, argon2_instance_t *instance);

/* Run the filling passes */
int fill_memory_blocks(argon2_instance_t *instance);

/* Fill a single segment */
void fill_segment(const argon2_instance_t *instance,
                  argon2_position_t position);

/* Return the index of a reference block */
uint32_t index_alpha(const argon2_instance_t *instance,
                     const argon2_position_t *position, uint32_t pseudo_rand,
                     int same_lane);

/* Block utility functions */
void init_block_value(block *b, uint8_t in);
void copy_block(block *dst, const block *src);
void xor_block(block *dst, const block *src);

/* Wipe internal memory securely */
void clear_internal_memory(void *v, size_t n);

/* Initial hash from H_0 */
void initial_hash(uint8_t *blockhash, argon2_context *context,
                  argon2_type type);

/* Allocate memory for the instance */
int allocate_memory(const argon2_context *context, uint8_t **memory,
                    size_t num, size_t size);

/* Free memory */
void free_memory(const argon2_context *context, uint8_t *memory,
                 size_t num, size_t size);

#endif /* ARGON2_CORE_H */
