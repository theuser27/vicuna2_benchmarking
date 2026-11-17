#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <riscv_vector.h>

#ifndef __riscv_zvkned
    #error "Compile this file with Zvkned enabled (e.g. -march=rv32imv_zvkned)"
#endif

void aes128_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16]);
void aes256_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32]);
void aes128_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16]);
void aes256_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32]);

void aes128_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16],
                               const uint8_t iv[16]);
void aes256_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32],
                               const uint8_t iv[16]);
void aes128_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16],
                               const uint8_t iv[16]);
void aes256_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32],
                               const uint8_t iv[16]);

#define ZVKNED_NAKED __attribute__((naked, noinline, used, aligned(4)))
#define UNUSED __attribute__((unused))

// inline assembly functions adapted from 
// https://github.com/riscv/riscv-crypto/blob/9cb90879050f68de8ba0b2f8bc34bec599ac8025/doc/vector/code-samples/zvkned.s


inline ZVKNED_NAKED void zvkned_aes128_expand_key(uint8_t dest_key[176] UNUSED, const uint8_t key[16] UNUSED)
{
    __asm__ volatile (
        // 4: number of 4B elements (4B*4 = 16B = 128b)
        // e32: vector of 32b/4B elements
        // m1: LMUL=4  (allows for VLEN=32)
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // x0 is not written, we known the number of vector elements, 4.
        "vsetivli x0, 4, e32, m4, ta, ma\n\t"   // Vectors of 8b

        // Note that this version interleaves the key schedule instructions
        // and storing the resulting round keys, while always using the same
        // vector register. Depending on micro-architecture (latencies,
        // in order vs. out of order, renaming limits, etc), it could
        // be beneficial to use more registers push stores further from
        // the key schedule logic.

        // Load user key from `key`, all 16B at once
        "vle32.v v4, (a1)\n\t"
        // v4 contains the evolving key state during expansion.

        // Initial word, copy the input key.
        "vse32.v v4, (a0)\n\t"  // w[0,3] expanded word (== input key)
        // Round 1
        "vaeskf1.vi v4, v4, 1\n\t"
        // Move dest by 128b (4 * 32b  words)
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"  // Round 1 expanded key
        // Round 2
        "vaeskf1.vi v4, v4, 2\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 3
        "vaeskf1.vi v4, v4, 3\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 4
        "vaeskf1.vi v4, v4, 4\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 5
        "vaeskf1.vi v4, v4, 5\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 6
        "vaeskf1.vi v4, v4, 6\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 7
        "vaeskf1.vi v4, v4, 7\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 8
        "vaeskf1.vi v4, v4, 8\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 9
        "vaeskf1.vi v4, v4, 9\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"
        // Round 10
        "vaeskf1.vi v4, v4, 10\n\t"
        "add a0, a0, 16\n\t"
        "vse32.v v4, (a0)\n\t"

        "ret\n\t"
    );
}

inline ZVKNED_NAKED void zvkned_aes256_expand_key(uint8_t dest_key[240] UNUSED, const uint8_t key[32] UNUSED)
{
    __asm__ __volatile__ (
        // 4: number of 4B elements (4B*4 = 16B = 128b)
        // e32: vector of 32b/4B elements
        // m1: LMUL=4  (allows for VLEN=32)
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // x0 is not written, we known the number of vector elements, 2.
        "vsetivli x0, 4, e32, m4, ta, ma\n\t"   // Vectors of 4B

        // Load user key from `key`, all 16B at once
        "vle32.v v4, (a1)\n\t"
        "addi a1, a1, 16\n\t"
        "vle32.v v8, (a1)\n\t"
        "addi a1, a1, 16\n\t"

        // v4 and v8 contain the evolving key state during expansion,
        // alternating holding key[i] and key[i-1] as inputs to vaeskf.

        // For the initial 2 4-words, we copy the input key.
        // Round 0 expanded key, w[0, 3] (== input key LO).
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 1 expanded key, w[4, 7] (== input key HI)
        "vse32.v v8, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 2 expanded key, w[8, 13].
        "vaeskf2.vi v4, v8, 2\n\t"
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 3 expanded key, w[12, 15].
        "vaeskf2.vi v8, v4, 3\n\t"
        "vse32.v v8, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 4 expanded key, w[16, 19].
        "vaeskf2.vi v4, v8, 4\n\t"
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 5 expanded key, w[20, 23].
        "vaeskf2.vi v8, v4, 5\n\t"
        "vse32.v v8, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 6 expanded key, w[24, 27].
        "vaeskf2.vi v4, v8, 6\n\t"
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 7 expanded key, w[28, 31].
        "vaeskf2.vi v8, v4, 7\n\t"
        "vse32.v v8, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 8 expanded key, w[32, 35].
        "vaeskf2.vi v4, v8, 8\n\t"
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 9 expanded key, w[36, 39].
        "vaeskf2.vi v8, v4, 9\n\t"
        "vse32.v v8, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 10 expanded key, w[40, 43].
        "vaeskf2.vi v4, v8, 10\n\t"
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 11 expanded key, w[44, 47].
        "vaeskf2.vi v8, v4, 11\n\t"
        "vse32.v v8, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 12 expanded key, w[48, 51].
        "vaeskf2.vi v4, v8, 12\n\t"
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 13 expanded key, w[52, 55].
        "vaeskf2.vi v8, v4, 13\n\t"
        "vse32.v v8, (a0)\n\t"
        "add a0, a0, 16\n\t"
        // Round 14 expanded key, w[56, 59].
        "vaeskf2.vi v4, v8, 14\n\t"
        "vse32.v v4, (a0)\n\t"
        "add a0, a0, 16\n\t"

        "ret\n\t"
    );
}

inline ZVKNED_NAKED size_t zvkned_aes128_encode_vs_lmul1(void *dest UNUSED, 
    const void *src UNUSED, size_t n UNUSED, const uint8_t *round_keys UNUSED)
{
    __asm__ __volatile__ (
        // a2 on input is number of bytes of the plaintext. We round it down
        // to a multiple of 16 bytes (128b), keep that in t0 that we return.
        "andi t0, a2, -16\n\t"  // 0xFF0 in two's complement, clear low 4 bits.
        "beqz t0, 2f\n\t"  // Early exit in the "0 bytes to process" case
        // t3 <- t0 / 4, number of remaining 4B elements
        "srli t3, t0, 2\n\t"

        // We load the 11 round keys into 11 vector registers, v10-v20,
        // with the 16B (4x32b) round keys present in the first 4x32b
        // element group of those vectors.
        "vsetivli x0, 4, e32, m1, ta, ma\n\t"
        "vle32.v v10, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v11, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v12, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v13, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v14, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v15, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v16, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v17, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v18, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v19, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v20, (a3)\n\t"

    "1:\n\t"
        // t3: number of remaining 4B elements (which is a multiple of 4)
        // e32: vector of 32/4B elements
        // m1: LMUL=1
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // t2 receives the number of 4B elements in the vector
        "vsetvli t2, t3, e32, m1, ta, ma\n\t"   // Vectors of 4B

        // Load plain text from `src`, a full vector of 4B elements at a time.
        "vle32.v v1, (a1)\n\t"

        // Initial AddRoundKey
        "vaesz.vs v1, v10\n\t"   // with round key w[ 0, 4]
        // Middle rounds, vaesem performs
        // SubBytes+ShiftRows+MixColumns+AddRoundKey
        "vaesem.vs v1, v11\n\t"  // with round key w[ 4, 7]
        "vaesem.vs v1, v12\n\t"  // with round key w[ 8,11]
        "vaesem.vs v1, v13\n\t"  // with round key w[12,15]
        "vaesem.vs v1, v14\n\t"  // with round key w[16,19]
        "vaesem.vs v1, v15\n\t"  // with round key w[20,23]
        "vaesem.vs v1, v16\n\t"  // with round key w[24,27]
        "vaesem.vs v1, v17\n\t"  // with round key w[28,31]
        "vaesem.vs v1, v18\n\t"  // with round key w[32,35]
        "vaesem.vs v1, v19\n\t"  // with round key w[36,39]
        // Final round, vaesef does
        // SubBytes+ShiftRows+AddRoundKey,
        // i.e., the same as vaesem except that MixColumns is not missing.
        "vaesef.vs v1, v20\n\t"  // with round key w[40,43]

        // Store cypher test
        // a0 is the destination (updated)
        "vse32.v v1, (a0)\n\t"

        // t2 contains the number of 32b/4B elements processed
        "sub t3, t3, t2\n\t"              // Decrement count (4B elements)

        // Scale by 4 to get number of bytes
        "slli t2, t2, 2\n\t"              // t2 (#bytes) <- t2 (#4B) * 4
        "add a1, a1, t2\n\t"              // Increment source address (bytes)
        "add a0, a0, t2\n\t"              // Increment target address (bytes)

        "bnez t3, 1b\n\t"                 // Continue the loop?

        // Return the number of bytes actually processed
    "2:\n\t"
        "mv a0, t0\n\t"  // 'n' bytes result, computed on entry.
        "ret\n\t"
    );
}

inline ZVKNED_NAKED size_t zvkned_aes128_encode_vs_lmul2(void *dest UNUSED, 
    const void *src UNUSED, size_t n UNUSED, const uint8_t *round_keys UNUSED)
{
    __asm__ __volatile__ (
        // a2 on input is number of bytes of the plaintext. We round it down
        // to a multiple of 16 bytes (128b), keep that in t0 that we return.
        "andi t0, a2, -16\n\t"  // 0xFF0 in two's complement, clear low 4 bits.
        "beqz t0, 2f\n\t"  // Early exit in the "0 bytes to process" case
        // t3 <- t0 / 4, number of remaining 4B elements
        "srli t3, t0, 2\n\t"

        // We load the 11 round keys into 11 vector register groups,
        // v2-v22 (v2, v4, v6, ..., v22, 11 groups), with the 16B (4 words)
        // with the 16B (4x32b) round keys present in the first 4x32b
        // element group of those vectors.
        "vsetivli x0, 4, e32, m2, ta, ma\n\t"
        "vle32.v v2, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v4, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v6, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v8, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v10, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v12, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v14, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v16, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v18, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v20, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v22, (a3)\n\t"

    "1:\n\t"
        // t3: number of remaining 4B elements (which is 4*k)
        // e32: vector of 32b/4B elements
        // m2: LMUL=2
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // t2 receives the number of 4B elements in the vector
        "vsetvli t2, t3, e32, m2, ta, ma\n\t"   // Vectors of 8b

        // Load plain text from `src`.
        "vle32.v v0, (a1)\n\t"

        // Initial AddRoundKey
        "vaesz.vs  v0,  v2\n\t"   // with round key w[ 0, 4]
        // Middle rounds, vaesem performs
        // SubBytes+ShiftRows+MixColumns+AddRoundKey
        "vaesem.vs v0,  v4\n\t"  // with round key w[ 4, 7]
        "vaesem.vs v0,  v6\n\t"  // with round key w[ 8,11]
        "vaesem.vs v0,  v8\n\t"  // with round key w[12,15]
        "vaesem.vs v0, v10\n\t"  // with round key w[16,19]
        "vaesem.vs v0, v12\n\t"  // with round key w[20,23]
        "vaesem.vs v0, v14\n\t"  // with round key w[24,27]
        "vaesem.vs v0, v16\n\t"  // with round key w[28,31]
        "vaesem.vs v0, v18\n\t"  // with round key w[32,35]
        "vaesem.vs v0, v20\n\t"  // with round key w[36,39]
        // Final round, vaesef does
        // SubBytes+ShiftRows+AddRoundKey,
        // i.e., the same as vaesem except that MixColumns is not missing.
        "vaesef.vs v0, v22\n\t"  // with round key w[40,43]

        // Store cypher test
        // a0 is the destination (updated)
        "vse32.v v0, (a0)\n\t"

        // t2 contains the number of 32b/4B elements processed
        "sub t3, t3, t2\n\t"              // Decrement count (4B elements)

        // Scale by 4 to get number of bytes
        "slli t2, t2, 2\n\t"              // t2 (#bytes) <- t2 (#4B) * 4
        "add a1, a1, t2\n\t"              // Increment source address (bytes)
        "add a0, a0, t2\n\t"              // Increment target address (bytes)

        "bnez t3, 1b\n\t"                 // Continue the loop?

        // Return the number of bytes actually processed
    "2:\n\t"
        "mv a0, t0\n\t\n\t"  // 'n' bytes result, computed on entry.

        "ret\n\t"
    );
}

inline ZVKNED_NAKED size_t zvkned_aes128_decode_vs_lmul1(void *dest UNUSED, 
    const void *src UNUSED, size_t n UNUSED, const uint8_t *round_keys UNUSED)
{
    __asm__ __volatile__ (
        // a2 on input is number of bytes of the plaintext. We round it down
        // to a multiple of 16 bytes (128b), keep that in t0 that we return.
        "andi t0, a2, -16\n\t"  // 0xFF0 in two's complement, clear low 4 bits.
        "beqz t0, 2f\n\t"  // Early exit in the "0 bytes to process" case
        // t3 <- t0 / 4, number of remaining 4B elements
        "srli t3, t0, 2\n\t"

        // We load the 11 round keys into 11 vector registers, v10-v20,
        // with the 16B (4x32b) round keys present in the first 4x32b
        // element group of those vectors.
        // We use only even registers to enable the "lmul2" variant to use
        // the same code, with only the vset[i]vli changed.
        "vsetivli t2, 4, e32, m1, ta, ma\n\t"
        "vle32.v v2, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v4, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v6, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v8, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v10, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v12, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v14, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v16, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v18, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v20, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v22, (a3)\n\t"

    "1:\n\t"
        // t3: number of remaining 4B elements (which is 4*k)
        // e32: vector of 64b/8B elements
        // m1: LMUL=1
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // t2 receives the number of 8B elements in the vector
        "vsetvli t2, t3, e32, m1, ta, ma\n\t"   // Vectors of 4B

        // v1 contains the text, from cipher to clear,
        // v10-v20 contain the 11 per-round keys.

        // Load cipher text from `src`, one vector full at a time.
        "vle32.v v0, (a1)\n\t"

        // Initial round, AddRoundKey
        "vaesz.vs v0, v22\n\t"  // with round key w[43,47]
        // Middle rounds, vaesdm performs
        // InvShiftRows+InvSubBytes+AddRoundKey+InvMixColumns.
        "vaesdm.vs v0, v20\n\t"  // with round key w[36,39]
        "vaesdm.vs v0, v18\n\t"  // with round key w[32,35]
        "vaesdm.vs v0, v16\n\t"  // with round key w[28,31]
        "vaesdm.vs v0, v14\n\t"  // with round key w[24,27]
        "vaesdm.vs v0, v12\n\t"  // with round key w[20,23]
        "vaesdm.vs v0, v10\n\t"  // with round key w[16,19]
        "vaesdm.vs v0, v8\n\t"  // with round key w[12,15]
        "vaesdm.vs v0, v6\n\t"  // with round key w[ 8,11]
        "vaesdm.vs v0, v4\n\t"  // with round key w[ 4, 7]
        // Final round, vaesdf performs
        // InvShiftRows+InvSubBytes+AddRoundKey,
        // i.e., the same as vaesdm except that InvMixColumns is missing.
        "vaesdf.vs v0, v2\n\t"  // with round key w[ 0, 4]

        // Store clear test
        // a0 is the destination (updated)
        "vse32.v v0, (a0)\n\t"

        // t2 contains the number of 32b/4B elements processed
        "sub t3, t3, t2\n\t"  // Decrement count (4B elements)

        // Scale by 4 to get number of bytes
        "slli t2, t2, 2\n\t"  // t2 (#bytes) <- t2 (#4B) * 4
        "add a1, a1, t2\n\t"  // Increment source address (bytes)
        "add a0, a0, t2\n\t"  // Increment target address (bytes)

        "bnez t3, 1b\n\t"     // Loop if text remains.

        // Return the number of bytes actually processed
    "2:\n\t"
        "mv a0, t0\n\t"  // 'n' bytes result, computed on entry.
        "ret\n\t"
    );
}

inline ZVKNED_NAKED size_t zvkned_aes128_decode_vs_lmul2(void *dest UNUSED, 
    const void *src UNUSED, size_t n UNUSED, const uint8_t *round_keys UNUSED)
{
    __asm__ __volatile__ (
        // a2 on input is number of bytes of the plaintext. We round it down
        // to a multiple of 16 bytes (128b), keep that in t0 that we return.
        "andi t0, a2, -16\n\t"  // 0xFF0 in two's complement, clear low 4 bits.
        "beqz t0, 2f\n\t"  // Early exit in the "0 bytes to process" case
        // t3 <- t0 / 4, number of remaining 4B elements
        "srli t3, t0, 2\n\t"

        // We load the 11 round keys into 11 vector register groups, v2-v22,
        // with the 16B (4x32b) round keys present in the first 4x32b
        // element group of those vectors.
        "vsetivli t2, 4, e32, m2, ta, ma\n\t"
        "vle32.v v2, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v4, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v6, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v8, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v10, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v12, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v14, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v16, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v18, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v20, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v22, (a3)\n\t"

    "1:\n\t"
        // t3: number of remaining 4B elements (which is 4*k)
        // e32: vector of 64b/8B elements
        // m2: LMUL=2
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // t2 receives the number of 8B elements in the vector
        "vsetvli t2, t3, e32, m2, ta, ma\n\t"   // Vectors of 4B

        // v1 contains the text, from cipher to clear,
        // v10-v20 contain the 11 per-round keys.

        // Load cipher text from `src`, one vector full at a time.
        "vle32.v v0, (a1)\n\t"

        // Initial round, AddRoundKey
        "vaesz.vs v0, v22\n\t"  // with round key w[43,47]
        // Middle rounds, vaesdm performs
        // InvShiftRows+InvSubBytes+AddRoundKey+InvMixColumns.
        "vaesdm.vs v0, v20\n\t"  // with round key w[36,39]
        "vaesdm.vs v0, v18\n\t"  // with round key w[32,35]
        "vaesdm.vs v0, v16\n\t"  // with round key w[28,31]
        "vaesdm.vs v0, v14\n\t"  // with round key w[24,27]
        "vaesdm.vs v0, v12\n\t"  // with round key w[20,23]
        "vaesdm.vs v0, v10\n\t"  // with round key w[16,19]
        "vaesdm.vs v0, v8\n\t"  // with round key w[12,15]
        "vaesdm.vs v0, v6\n\t"  // with round key w[ 8,11]
        "vaesdm.vs v0, v4\n\t"  // with round key w[ 4, 7]
        // Final round, vaesdf performs
        // InvShiftRows+InvSubBytes+AddRoundKey,
        // i.e., the same as vaesdm except that InvMixColumns is missing.
        "vaesdf.vs v0, v2\n\t"  // with round key w[ 0, 4]

        // Store clear test
        // a0 is the destination (updated)
        "vse32.v v0, (a0)\n\t"

        // t2 contains the number of 32b/4B elements processed
        "sub t3, t3, t2\n\t"  // Decrement count (4B elements)

        // Scale by 4 to get number of bytes
        "slli t2, t2, 2\n\t"  // t2 (#bytes) <- t2 (#4B) * 4
        "add a1, a1, t2\n\t"  // Increment source address (bytes)
        "add a0, a0, t2\n\t"  // Increment target address (bytes)

        "bnez t3, 1b\n\t"     // Loop if text remains.

        // Return the number of bytes actually processed
    "2:\n\t"
        "mv a0, t0\n\t"  // 'n' bytes result, computed on entry.
        "ret\n\t"
    );
}

inline ZVKNED_NAKED size_t zvkned_aes256_encode_vs_lmul1(void *dest UNUSED, 
    const void *src UNUSED, size_t n UNUSED, const uint8_t *round_keys UNUSED)
{
    __asm__ __volatile__ (
        // a2 on input is number of bytes of the plaintext. We round it down
        // to a multiple of 16 bytes (128b), keep that in t0 that we return.
        "andi t0, a2, -16\n\t"  // 0xFF0 in two's complement, clear low 4 bits.
        "beqz t0, 2f\n\t"  // Early exit in the "0 bytes to process" case
        // t3 <- t0 / 4, number of remaining 4B elements
        "srli t3, t0, 2\n\t"

        // We load the 15 round keys into 15 vector registers, v10-v24,
        // with the 16B (4x32b) round keys present in the first 4x32b
        // element group of those vectors.
        "vsetivli x0, 4, e32, m1, ta, ma\n\t"
        "vle32.v v10, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v11, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v12, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v13, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v14, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v15, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v16, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v17, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v18, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v19, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v20, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v21, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v22, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v23, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v24, (a3)\n\t"

    "1:\n\t"
        // t3: number of remaining 4B elements (which is a multiple of 4)
        // e32: vector of 32b/4B elements
        // m1: LMUL=1
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // t2 receives the number of 8B elements in the vector
        "vsetvli t2, t3, e32, m1, ta, ma\n\t"   // Vectors of 4B

        // v0 contains the text (from clear to cipher)
        // Load plain text from `src`, 4B(*4) at a time
        "vle32.v v0, (a1)\n\t"

        // Round 0, Initial AddRoundKey of w[0, 3]
        "vaesz.vs v0, v10\n\t"
        // vaesem does SubBytes+ShiftRows+MixColumns+AddRoundKey of w[4*round .. 4*round+3]
        "vaesem.vs v0, v11\n\t"  // v11 contains round 1 key, w[4, 7]
        "vaesem.vs v0, v12\n\t"
        "vaesem.vs v0, v13\n\t"
        "vaesem.vs v0, v14\n\t"
        "vaesem.vs v0, v15\n\t"
        "vaesem.vs v0, v16\n\t"
        "vaesem.vs v0, v17\n\t"
        "vaesem.vs v0, v18\n\t"
        "vaesem.vs v0, v19\n\t"
        "vaesem.vs v0, v20\n\t"
        "vaesem.vs v0, v21\n\t"
        "vaesem.vs v0, v22\n\t"
        "vaesem.vs v0, v23\n\t"
        // Final round
        // vaesef does SubBytes+ShiftRows+AddRoundKey of w[56,59]
        // (same as vaesem except that MixColumns is not performed)
        "vaesef.vs v0, v24\n\t"

        // Store cypher test
        // a0 is the destination (updated)
        "vse32.v v0, (a0)\n\t"
        // ret // Test a single write

        // t2 contains the number of 32b/4B elements processed
        "sub t3, t3, t2\n\t"              // Decrement count (4B elements)

        // Scale by 8 to get number of bytes
        "slli t2, t2, 2\n\t"              // t2 (#bytes) <- t2 (#4B) * 4
        "add a1, a1, t2\n\t"              // Increment source address (bytes)
        "add a0, a0, t2\n\t"              // Increment target address (bytes)

        "bnez t3, 1b\n\t"                 // Continue the loop?

        // Return the number of bytes actually processed
    "2:\n\t"
        "mv a0, t0\n\t"  // 'n' bytes result, computed on entry.
        "ret\n\t"
    );
}

inline ZVKNED_NAKED size_t zvkned_aes256_decode_vs_lmul1(void *dest UNUSED, 
    const void *src UNUSED, size_t n UNUSED, const uint8_t *round_keys UNUSED)
{
    __asm__ __volatile__ (
        // a2 on input is number of bytes of the plaintext. We round it down
        // to a multiple of 16 bytes (128b), keep that in t0 that we return.
        "andi t0, a2, -16\n\t"  // 0xFF0 in two's complement, clear low 4 bits.
        "beqz t0, 2f\n\t"  // Early exit in the "0 bytes to process" case
        // t3 <- t0 / 4, number of remaining 4B elements
        "srli t3, t0, 2\n\t"

        // We load the 15 round keys into 15 vector registers at even indices,
        // v2-v30, with the 16B (4x32b) round keys present in the first 4x32b
        // element group of those vectors.
        "vsetivli x0, 4, e32, m1, ta, ma\n\t"
        "vle32.v v2, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v4, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v6, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v8, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v10, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v12, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v14, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v16, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v18, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v20, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v22, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v24, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v26, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v28, (a3)\n\t"
        "addi a3, a3, 16\n\t"
        "vle32.v v30, (a3)\n\t"

    "1:\n\t"
        // t3: number of remaining 4B elements (which is even)
        // e32: vector of 32b/4B elements
        // m1: LMUL=1
        // ta: tail agnostic (don't care about those elements)
        // ma: mask agnostic (don't care about those elements)
        // t2 receives the number of 8B elements in the vector
        "vsetvli t2, t3, e32, m1, ta, ma\n\t"   // Vectors of 4B

        // v1 will contain the text, from cipher to clear,
        // v10-v24 contain the 15 per-round keys.

        // Load cipher text from `src`, 8B(*2) at a time
        "vle32.v v0, (a1)\n\t"

        // Initial round, AddRoundKey
        "vaesz.vs v0, v30\n\t"   // with round key w[56,59]
        // Middle rounds, vaesdm performs
        // InvShiftRows+InvSubBytes+AddRoundKey+InvMixColumns.
        "vaesdm.vs v0, v28\n\t"  // with round key w[52,55]
        "vaesdm.vs v0, v26\n\t"  // with round key w[48,51]
        "vaesdm.vs v0, v24\n\t"  // with round key w[44,47]
        "vaesdm.vs v0, v22\n\t"  // with round key w[40,43]
        "vaesdm.vs v0, v20\n\t"  // with round key w[36,39]
        "vaesdm.vs v0, v18\n\t"  // with round key w[32,35]
        "vaesdm.vs v0, v16\n\t"  // with round key w[28,31]
        "vaesdm.vs v0, v14\n\t"  // with round key w[24,27]
        "vaesdm.vs v0, v12\n\t"  // with round key w[20,23]
        "vaesdm.vs v0, v10\n\t"  // with round key w[16,19]
        "vaesdm.vs v0, v8\n\t"   // with round key w[12,15]
        "vaesdm.vs v0, v6\n\t"   // with round key w[ 8,11]
        "vaesdm.vs v0, v4\n\t"   // with round key w[ 4, 7]
        // Final round, vaesdf performs
        // InvShiftRows+InvSubBytes+AddRoundKey,
        // i.e., the same as vaesdm except that InvMixColumns is missing.
        "vaesdf.vs v0, v2\n\t"  // with round key w[ 0, 4]

        // Store clear test
        // a0 is the destination (updated)
        "vse32.v v0, (a0)\n\t"
        // ret // Test a single write

        // t2 contains the number of 32b/4B elements processed
        "sub t3, t3, t2\n\t"              // Decrement count (4B elements)

        // Scale by 8 to get number of bytes
        "slli t2, t2, 2\n\t"              // t2 (#bytes) <- t2 (#4B) * 4
        "add a1, a1, t2\n\t"              // Increment source address (bytes)
        "add a0, a0, t2\n\t"              // Increment target address (bytes)

        "bnez t3, 1b\n\t"                 // Continue the loop?

        // Return the number of bytes actually processed
    "2:\n\t"
        "mv a0, t0\n\t"  // 'n' bytes result, computed on entry.
        "ret\n\t"
    );
}


inline void aes128_ecb_encrypt_zvkned(const uint8_t *input, 
    uint8_t *output, size_t n, const uint8_t key[16])
{
    alignas(16) uint8_t round_keys[176];
    if (n == 0)
        return;
    zvkned_aes128_expand_key(round_keys, key);
    zvkned_aes128_encode_vs_lmul1(output, input, n, round_keys);
}

inline void aes256_ecb_encrypt_zvkned(const uint8_t *input, 
    uint8_t *output, size_t n, const uint8_t key[32])
{
    alignas(16) uint8_t round_keys[240];
    if (n == 0)
        return;
    zvkned_aes256_expand_key(round_keys, key);
    zvkned_aes256_encode_vs_lmul1(output, input, n, round_keys);
}

inline void aes128_ecb_decrypt_zvkned(const uint8_t *input, 
    uint8_t *output, size_t n, const uint8_t key[16])
{
    alignas(16) uint8_t round_keys[176];
    if (n == 0)
        return;
    zvkned_aes128_expand_key(round_keys, key);
    zvkned_aes128_decode_vs_lmul1(output, input, n, round_keys);
}

inline void aes256_ecb_decrypt_zvkned(const uint8_t *input, 
    uint8_t *output, size_t n, const uint8_t key[32])
{
    alignas(16) uint8_t round_keys[240];
    if (n == 0)
        return;
    zvkned_aes256_expand_key(round_keys, key);
    zvkned_aes256_decode_vs_lmul1(output, input, n, round_keys);
}

inline void aes128_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
    size_t n, const uint8_t key[16], const uint8_t iv[16])
{
    if (n == 0)
        return;
    assert(n % 16 == 0);

    alignas(16) uint8_t round_keys[176];
    zvkned_aes128_expand_key(round_keys, key);

    alignas(16) uint8_t chain[16];
    memcpy(chain, iv, 16);

    for (size_t i = 0; i < n; i += 16)
    {
        // XOR plaintext with previous ciphertext
        for (size_t j = 0; j < 16; ++j)
            chain[j] ^= input[i + j];

        // Encrypt one block using the existing ECB function
        zvkned_aes128_encode_vs_lmul1(output + i, chain, 16, round_keys);

        // Current ciphertext becomes the next chaining value
        memcpy(chain, output + i, 16);
    }
}

inline void aes256_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
    size_t n, const uint8_t key[32], const uint8_t iv[16])
{
    if (n == 0)
        return;
    assert(n % 16 == 0);

    alignas(16) uint8_t round_keys[240];
    zvkned_aes256_expand_key(round_keys, key);
    
    alignas(16) uint8_t chain[16];
    memcpy(chain, iv, 16);

    for (size_t i = 0; i < n; i += 16)
    {
        // XOR plaintext with previous ciphertext
        for (size_t j = 0; j < 16; ++j)
            chain[j] ^= input[i + j];

        // Encrypt one block using the existing ECB function
        zvkned_aes256_encode_vs_lmul1(output + i, chain, 16, round_keys);

        // Current ciphertext becomes the next chaining value
        memcpy(chain, output + i, 16);
    }
}

inline void aes128_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
    size_t n, const uint8_t key[16], const uint8_t iv[16])
{
    if (n == 0)
        return;
    assert(n % 16 == 0);

    alignas(16) uint8_t round_keys[176];
    zvkned_aes128_expand_key(round_keys, key);

    if (output != input)
    {
        // Decrypt all blocks in parallel
        zvkned_aes128_decode_vs_lmul1(output, input, n, round_keys);

        // XOR with IV
        for (size_t j = 0; j < 16; ++j)
            output[j] ^= iv[j];

        // XOR with previous ciphertext blocks
        for (size_t i = 16; i < n; i += 16)
            for (size_t j = 0; j < 16; ++j)
                output[i + j] ^= input[i + j - 16];

        return;
    }

    // In-place decryption: process one block at a time
    // Save the previous ciphertext before overwriting the current block
    uint8_t chain[16];
    uint8_t ciphertext[16];

    memcpy(chain, iv, 16);

    for (size_t i = 0; i < n; i += 16)
    {
        memcpy(ciphertext, input + i, 16);

        zvkned_aes128_decode_vs_lmul1(output + i, ciphertext, 16, round_keys);
        for (size_t j = 0; j < 16; ++j)
            output[i + j] ^= chain[j];

        memcpy(chain, ciphertext, 16);
    }
}

inline void aes256_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
    size_t n, const uint8_t key[32], const uint8_t iv[16])
{
    if (n == 0)
        return;
    assert(n % 16 == 0);

    alignas(16) uint8_t round_keys[240];
    zvkned_aes256_expand_key(round_keys, key);

    if (output != input)
    {
        // Decrypt all blocks in parallel
        zvkned_aes256_decode_vs_lmul1(output, input, n, round_keys);

        // XOR with IV
        for (size_t j = 0; j < 16; ++j)
            output[j] ^= iv[j];

        // XOR with previous ciphertext blocks
        for (size_t i = 16; i < n; i += 16)
            for (size_t j = 0; j < 16; ++j)
                output[i + j] ^= input[i + j - 16];

        return;
    }

    // In-place decryption: process one block at a time
    // Save the previous ciphertext before overwriting the current block
    uint8_t chain[16];
    uint8_t ciphertext[16];

    memcpy(chain, iv, 16);

    for (size_t i = 0; i < n; i += 16)
    {
        memcpy(ciphertext, input + i, 16);

        zvkned_aes256_decode_vs_lmul1(output + i, ciphertext, 16, round_keys);
        for (size_t j = 0; j < 16; ++j)
            output[i + j] ^= chain[j];

        memcpy(chain, ciphertext, 16);
    }
}
