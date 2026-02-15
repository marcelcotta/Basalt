/*
 * Argon2 reference fill segment — adapted for Basalt.
 * Original: https://github.com/P-H-C/phc-winner-argon2
 * License: CC0 1.0 Universal / Apache License 2.0
 *
 * This is the portable reference implementation (no SSE/NEON).
 * It works on both arm64 and x86_64.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "argon2.h"
#include "core.h"
#include "blake2.h"
#include "blake2-impl.h"

/*
 * Function generates new block by applying BlaMka over ref and prev blocks.
 * On first pass: next = compress(prev, ref)
 * On subsequent passes: next = next XOR compress(prev, ref)
 */
static void fill_block_ref(const block *prev_block, const block *ref_block,
                           block *next_block, int with_xor) {
    fill_block(prev_block, ref_block, next_block, with_xor);
}

static void next_addresses(block *address_block, block *input_block,
                           const block *zero_block) {
    input_block->v[6]++;
    fill_block(zero_block, input_block, address_block, 0);
    fill_block(zero_block, address_block, address_block, 0);
}

void fill_segment(const argon2_instance_t *instance,
                  argon2_position_t position) {
    block *ref_block = NULL, *curr_block = NULL;
    block address_block, input_block, zero_block;
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index;
    uint32_t i;
    int data_independent_addressing;

    if (instance == NULL) {
        return;
    }

    data_independent_addressing =
        (instance->type == Argon2_i) ||
        (instance->type == Argon2_id && (position.pass == 0) &&
         (position.slice < ARGON2_SYNC_POINTS / 2));

    if (data_independent_addressing) {
        init_block_value(&zero_block, 0);
        init_block_value(&input_block, 0);

        input_block.v[0] = position.pass;
        input_block.v[1] = position.lane;
        input_block.v[2] = position.slice;
        input_block.v[3] = instance->memory_blocks;
        input_block.v[4] = instance->passes;
        input_block.v[5] = instance->type;
    }

    starting_index = 0;

    if ((0 == position.pass) && (0 == position.slice)) {
        starting_index = 2; /* we have already generated the first two blocks */
        /* Don't forget to generate the first block of addresses if necessary */
        if (data_independent_addressing) {
            next_addresses(&address_block, &input_block, &zero_block);
        }
    }

    /* Offset of the current block */
    curr_offset = position.lane * instance->lane_length +
                  position.slice * instance->segment_length + starting_index;

    if (0 == curr_offset % instance->lane_length) {
        /* Last block in this lane */
        prev_offset = curr_offset + instance->lane_length - 1;
    } else {
        /* Previous block */
        prev_offset = curr_offset - 1;
    }

    for (i = starting_index; i < instance->segment_length; ++i,
         ++curr_offset, ++prev_offset) {
        /* 1.1 Rotating prev_offset if needed */
        if (curr_offset % instance->lane_length == 1) {
            prev_offset = curr_offset - 1;
        }

        /* 1.2 Computing the index of the reference block */
        /* 1.2.1 Taking pseudo-random value from the previous block */
        if (data_independent_addressing) {
            if (i % ARGON2_QWORDS_IN_BLOCK == 0) {
                next_addresses(&address_block, &input_block, &zero_block);
            }
            pseudo_rand = address_block.v[i % ARGON2_QWORDS_IN_BLOCK];
        } else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        /* 1.2.2 Computing the lane of the reference block */
        ref_lane = ((pseudo_rand >> 32)) % instance->lanes;

        if ((position.pass == 0) && (position.slice == 0)) {
            /* Can not reference other lanes yet */
            ref_lane = position.lane;
        }

        /* 1.2.3 Computing the number of possible reference block within the
         * lane. */
        position.index = i;
        ref_index = index_alpha(instance, &position, (uint32_t)pseudo_rand,
                                ref_lane == position.lane);

        /* 2 Creating a new block */
        ref_block = instance->memory +
                    instance->lane_length * ref_lane + ref_index;
        curr_block = instance->memory + curr_offset;

        if (0 == position.pass) {
            fill_block_ref(instance->memory + prev_offset, ref_block,
                           curr_block, 0);
        } else {
            fill_block_ref(instance->memory + prev_offset, ref_block,
                           curr_block, 1);
        }
    }
}
