#pragma once

#include <stddef.h>
#include <stdint.h>

void aes128_ecb_encrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[16]);
void aes192_ecb_encrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[24]);
void aes256_ecb_encrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[32]);
void aes128_ecb_decrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[16]);
void aes192_ecb_decrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[24]);
void aes256_ecb_decrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[32]);

void aes128_cbc_encrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[16],
                            const uint8_t iv[16]);
void aes192_cbc_encrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[24],
                            const uint8_t iv[16]);
void aes256_cbc_encrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[32],
                            const uint8_t iv[16]);
void aes128_cbc_decrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[16],
                            const uint8_t iv[16]);
void aes192_cbc_decrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[24],
                            const uint8_t iv[16]);
void aes256_cbc_decrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t key[32],
                            const uint8_t iv[16]);

#ifndef __riscv_vector
#error "Compile this file with vector extension enabled (e.g. -march=rv32imv)"
#endif

#include <riscv_vector.h>
#include <string.h>

/* Standard AES S-box. */
static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Inverse AES S-box, used by the vector decryption path. */
static const uint8_t aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static uint8_t aes_xtime_scalar(uint8_t x)
{
    return (uint8_t)((uint8_t)(x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u));
}

// TODO: probably optimise key expansion, while making it safe from timing sidechannels
/*
 * Expand a 128-, 192-, or 256-bit AES key.
 * Returns Nr (10, 12, or 14). round_keys has room for 15 round keys.
 * This scalar key expansion is kept shared across all six APIs.
 */
static unsigned aes_expand_key(const uint8_t *key, unsigned nk,
                               uint8_t round_keys[240])
{
    const unsigned nr = nk + 6;
    const unsigned key_bytes = nk * 4;
    const unsigned total_bytes = 16 * (nr + 1);
    uint8_t rcon = 1;

    memcpy(round_keys, key, key_bytes);

    for (unsigned generated = key_bytes; generated < total_bytes; generated += 4) {
        uint8_t t[4];
        t[0] = round_keys[generated - 4];
        t[1] = round_keys[generated - 3];
        t[2] = round_keys[generated - 2];
        t[3] = round_keys[generated - 1];

        if ((generated % key_bytes) == 0) {
            const uint8_t first = t[0];
            t[0] = (uint8_t)(aes_sbox[t[1]] ^ rcon);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[first];
            rcon = aes_xtime_scalar(rcon);
        } else if (nk == 8 && (generated % key_bytes) == 16) {
            t[0] = aes_sbox[t[0]];
            t[1] = aes_sbox[t[1]];
            t[2] = aes_sbox[t[2]];
            t[3] = aes_sbox[t[3]];
        }

        for (unsigned j = 0; j < 4; ++j)
            round_keys[generated + j] =
                (uint8_t)(round_keys[generated - key_bytes + j] ^ t[j]);
    }

    return nr;
}

/* Vectorized SubBytes via two 128-entry vector-register lookup tables. */
static inline vuint8m8_t aes_subbytes_rvv(
    vuint8m8_t x, vuint8m8_t sbox_lo, vuint8m8_t sbox_hi, size_t vl)
{
    vuint8m8_t index = __riscv_vand_vx_u8m8(x, 0x7f, vl);
    vuint8m8_t lo = __riscv_vrgather_vv_u8m8(sbox_lo, index, vl);
    vuint8m8_t hi = __riscv_vrgather_vv_u8m8(sbox_hi, index, vl);

    /* Build 0x00 or 0xff per byte depending on the input's high bit. */
    vuint8m8_t top_bit = __riscv_vsrl_vx_u8m8(x, 7, vl);
    vuint8m8_t zero = __riscv_vmv_v_x_u8m8(0, vl);
    vuint8m8_t mask = __riscv_vsub_vv_u8m8(zero, top_bit, vl);
    vuint8m8_t diff = __riscv_vxor_vv_u8m8(lo, hi, vl);
    diff = __riscv_vand_vv_u8m8(diff, mask, vl);
    return __riscv_vxor_vv_u8m8(lo, diff, vl);
}

/* Vectorized MixColumns. Index vectors select neighbouring rows in the SAME column. */
static inline vuint8m8_t aes_mixcolumns_rvv(
    vuint8m8_t x, vuint8m8_t idx1, vuint8m8_t idx2,
    vuint8m8_t idx3, size_t vl)
{
    vuint8m8_t a1 = __riscv_vrgather_vv_u8m8(x, idx1, vl);
    vuint8m8_t a2 = __riscv_vrgather_vv_u8m8(x, idx2, vl);
    vuint8m8_t a3 = __riscv_vrgather_vv_u8m8(x, idx3, vl);

    vuint8m8_t t = __riscv_vxor_vv_u8m8(x, a1, vl);
    t = __riscv_vxor_vv_u8m8(t, a2, vl);
    t = __riscv_vxor_vv_u8m8(t, a3, vl);

    vuint8m8_t pair = __riscv_vxor_vv_u8m8(x, a1, vl);
    vuint8m8_t high = __riscv_vsrl_vx_u8m8(pair, 7, vl);
    vuint8m8_t reduction = __riscv_vmul_vx_u8m8(high, 0x1b, vl);
    vuint8m8_t doubled = __riscv_vsll_vx_u8m8(pair, 1, vl);
    vuint8m8_t xtime = __riscv_vxor_vv_u8m8(doubled, reduction, vl);

    vuint8m8_t result = __riscv_vxor_vv_u8m8(x, t, vl);
    return __riscv_vxor_vv_u8m8(result, xtime, vl);
}

/*
 * Shared RVV AES encryption core.
 * iv == NULL selects ECB. Otherwise CBC is processed one block at a time,
 * because each CBC ciphertext depends on the previous ciphertext.
 */
static void aes_encrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t round_keys[240],
                            unsigned nr, const uint8_t *iv)
{
    if (nblocks == 0)
        return;

    size_t max_vl = __riscv_vsetvlmax_e8m8();
    // vrgather's SEW=8 indices are 8-bit, therefore we can't go above this
    if (max_vl > 256)
        max_vl = 256;
    // because we're using m8 our length is effectively a byte count
    // therefore rounding to multiples of 16 produces multiples of an AES block
    max_vl &= ~(size_t)15;

    // Each batch restarts at byte index zero, so these indices repeat by block.
    uint8_t idx_rep[256];
    uint8_t idx_shift[256];
    uint8_t idx1[256];
    uint8_t idx2[256];
    uint8_t idx3[256];
    static const uint8_t shift_perm[16] = {
        0, 5,10,15, 4, 9,14, 3, 8,13, 2, 7,12, 1, 6,11
    };

    // TODO: optimise this
    for (size_t i = 0; i < max_vl; ++i) {
        idx_rep[i] = (uint8_t)(i & 15u);
        idx_shift[i] = (uint8_t)((i & ~(size_t)15) | shift_perm[i & 15u]);
        idx1[i] = (uint8_t)((i & ~(size_t)3) | ((i + 1u) & 3u));
        idx2[i] = (uint8_t)((i & ~(size_t)3) | ((i + 2u) & 3u));
        idx3[i] = (uint8_t)((i & ~(size_t)3) | ((i + 3u) & 3u));
    }

    // Only indices 0..127 are used from each table vector.
    vuint8m8_t sbox_lo = __riscv_vle8_v_u8m8(aes_sbox, 128);
    vuint8m8_t sbox_hi = __riscv_vle8_v_u8m8(aes_sbox + 128, 128);

    uint8_t chain[16];
    if (iv != NULL)
        memcpy(chain, iv, sizeof chain);

    while (nblocks != 0) {
        size_t blocks;
        if (iv != NULL) {
            blocks = 1; // CBC encryption is serial.
        } else {
            blocks = nblocks;
            if (blocks > max_vl / 16)
                blocks = max_vl / 16;
        }

        const size_t vl = __riscv_vsetvl_e8m8(blocks * 16);
        vuint8m8_t vrep = __riscv_vle8_v_u8m8(idx_rep, vl);
        vuint8m8_t vshift = __riscv_vle8_v_u8m8(idx_shift, vl);
        vuint8m8_t vnext1 = __riscv_vle8_v_u8m8(idx1, vl);
        vuint8m8_t vnext2 = __riscv_vle8_v_u8m8(idx2, vl);
        vuint8m8_t vnext3 = __riscv_vle8_v_u8m8(idx3, vl);

        vuint8m8_t state = __riscv_vle8_v_u8m8(input, vl);
        if (iv != NULL) {
            vuint8m8_t vchain = __riscv_vle8_v_u8m8(chain, 16);
            state = __riscv_vxor_vv_u8m8(state, vchain, vl);
        }

        // Initial AddRoundKey.
        vuint8m8_t rk = __riscv_vle8_v_u8m8(round_keys, 16);
        vuint8m8_t repeated_key = __riscv_vrgather_vv_u8m8(rk, vrep, vl);
        state = __riscv_vxor_vv_u8m8(state, repeated_key, vl);

        // Rounds 1 .. Nr-1: SubBytes, ShiftRows, MixColumns, AddRoundKey.
        for (unsigned round = 1; round < nr; ++round) {
            state = aes_subbytes_rvv(state, sbox_lo, sbox_hi, vl);
            state = __riscv_vrgather_vv_u8m8(state, vshift, vl);

            state = aes_mixcolumns_rvv(state, vnext1, vnext2, vnext3, vl);

            rk = __riscv_vle8_v_u8m8(round_keys + round * 16, 16);
            repeated_key = __riscv_vrgather_vv_u8m8(rk, vrep, vl);
            state = __riscv_vxor_vv_u8m8(state, repeated_key, vl);
        }

        // Repeating one last time without MixColumns
        state = aes_subbytes_rvv(state, sbox_lo, sbox_hi, vl);
        state = __riscv_vrgather_vv_u8m8(state, vshift, vl);

        rk = __riscv_vle8_v_u8m8(round_keys + nr * 16, 16);
        repeated_key = __riscv_vrgather_vv_u8m8(rk, vrep, vl);
        state = __riscv_vxor_vv_u8m8(state, repeated_key, vl);

        __riscv_vse8_v_u8m8(output, state, vl);

        if (iv != NULL)
            memcpy(chain, output, 16); // ciphertext becomes next chain

        input += blocks * 16;
        output += blocks * 16;
        nblocks -= blocks;
    }
}

// Vectorized inverse SubBytes using the inverse S-box in vector registers.
static inline vuint8m8_t aes_inv_subbytes_rvv(
    vuint8m8_t x, vuint8m8_t sbox_lo, vuint8m8_t sbox_hi, size_t vl)
{
    vuint8m8_t index = __riscv_vand_vx_u8m8(x, 0x7f, vl);
    vuint8m8_t lo = __riscv_vrgather_vv_u8m8(sbox_lo, index, vl);
    vuint8m8_t hi = __riscv_vrgather_vv_u8m8(sbox_hi, index, vl);
    vuint8m8_t top_bit = __riscv_vsrl_vx_u8m8(x, 7, vl);
    vuint8m8_t zero = __riscv_vmv_v_x_u8m8(0, vl);
    vuint8m8_t mask = __riscv_vsub_vv_u8m8(zero, top_bit, vl);
    vuint8m8_t diff = __riscv_vxor_vv_u8m8(lo, hi, vl);
    diff = __riscv_vand_vv_u8m8(diff, mask, vl);
    return __riscv_vxor_vv_u8m8(lo, diff, vl);
}

static inline vuint8m8_t aes_xtime_rvv(vuint8m8_t x, size_t vl)
{
    vuint8m8_t high = __riscv_vsrl_vx_u8m8(x, 7, vl);
    vuint8m8_t reduction = __riscv_vmul_vx_u8m8(high, 0x1b, vl);
    vuint8m8_t doubled = __riscv_vsll_vx_u8m8(x, 1, vl);
    return __riscv_vxor_vv_u8m8(doubled, reduction, vl);
}

/*
 * Inverse MixColumns identity:
 *   InvMixColumns(x) = MixColumns(x XOR 4*(x XOR rotate_rows(x,2))).
 * Multiplication by four is two applications of xtime. The existing
 * forward MixColumns helper then performs the final MixColumns transform.
 */
static inline vuint8m8_t aes_inv_mixcolumns_rvv(
    vuint8m8_t x, vuint8m8_t idx1, vuint8m8_t idx2,
    vuint8m8_t idx3, size_t vl)
{
    vuint8m8_t opposite = __riscv_vrgather_vv_u8m8(x, idx2, vl);
    vuint8m8_t diff = __riscv_vxor_vv_u8m8(x, opposite, vl);
    diff = aes_xtime_rvv(diff, vl);
    diff = aes_xtime_rvv(diff, vl);
    x = __riscv_vxor_vv_u8m8(x, diff, vl);
    return aes_mixcolumns_rvv(x, idx1, idx2, idx3, vl);
}

/*
 * Shared RVV AES decryption core. iv == NULL selects ECB; non-NULL selects
 * CBC decryption. CBC decryption is batched because D_K(C[i]) is independent
 * across blocks; each result is XORed with its previous ciphertext block.
 */
static void aes_decrypt_rvv(const uint8_t *input, uint8_t *output,
                            size_t nblocks, const uint8_t round_keys[240],
                            unsigned nr, const uint8_t *iv)
{
    if (nblocks == 0)
        return;

    size_t max_vl = __riscv_vsetvlmax_e8m8();
    if (max_vl > 256)
        max_vl = 256;
    max_vl &= ~(size_t)15;

    uint8_t idx_rep[256];
    uint8_t idx_invshift[256];
    uint8_t idx1[256], idx2[256], idx3[256];
    static const uint8_t invshift_perm[16] = {
         0,13,10, 7, 4, 1,14,11, 8, 5, 2,15,12, 9, 6, 3
    };

    for (size_t i = 0; i < max_vl; ++i) {
        idx_rep[i] = (uint8_t)(i & 15u);
        idx_invshift[i] = (uint8_t)((i & ~(size_t)15) | invshift_perm[i & 15u]);
        idx1[i] = (uint8_t)((i & ~(size_t)3) | ((i + 1u) & 3u));
        idx2[i] = (uint8_t)((i & ~(size_t)3) | ((i + 2u) & 3u));
        idx3[i] = (uint8_t)((i & ~(size_t)3) | ((i + 3u) & 3u));
    }

    vuint8m8_t sbox_lo = __riscv_vle8_v_u8m8(aes_inv_sbox, 128);
    vuint8m8_t sbox_hi = __riscv_vle8_v_u8m8(aes_inv_sbox + 128, 128);

    uint8_t chain[16];
    if (iv != NULL)
        memcpy(chain, iv, sizeof chain);

    while (nblocks != 0) {
        size_t blocks = nblocks;
        if (blocks > max_vl / 16)
            blocks = max_vl / 16;

        const size_t vl = __riscv_vsetvl_e8m8(blocks * 16);
        vuint8m8_t vrep = __riscv_vle8_v_u8m8(idx_rep, vl);
        vuint8m8_t vinvshift = __riscv_vle8_v_u8m8(idx_invshift, vl);
        vuint8m8_t vnext1 = __riscv_vle8_v_u8m8(idx1, vl);
        vuint8m8_t vnext2 = __riscv_vle8_v_u8m8(idx2, vl);
        vuint8m8_t vnext3 = __riscv_vle8_v_u8m8(idx3, vl);

        // CBC decryption can decrypt a whole batch in parallel. Save the
        // final ciphertext for the next batch and build C[i-1] for each
        // plaintext block before an in-place store can overwrite ciphertext.
        uint8_t saved_ciphertext[16];
        uint8_t previous_ciphertext[256];
        if (iv != NULL) {
            memcpy(saved_ciphertext, input + (blocks - 1u) * 16u, 16);
            memcpy(previous_ciphertext, chain, 16);
            if (blocks > 1)
                memcpy(previous_ciphertext + 16, input, (blocks - 1u) * 16u);
        }
        vuint8m8_t state = __riscv_vle8_v_u8m8(input, vl);

        // Initial AddRoundKey uses the last encryption round key.
        vuint8m8_t rk = __riscv_vle8_v_u8m8(round_keys + nr * 16u, 16);
        vuint8m8_t repeated_key = __riscv_vrgather_vv_u8m8(rk, vrep, vl);
        state = __riscv_vxor_vv_u8m8(state, repeated_key, vl);

        // Inverse middle rounds, using encryption round keys in reverse.
        for (unsigned round = nr - 1; round > 0; --round) {
            state = __riscv_vrgather_vv_u8m8(state, vinvshift, vl);
            state = aes_inv_subbytes_rvv(state, sbox_lo, sbox_hi, vl);

            rk = __riscv_vle8_v_u8m8(round_keys + round * 16u, 16);
            repeated_key = __riscv_vrgather_vv_u8m8(rk, vrep, vl);
            state = __riscv_vxor_vv_u8m8(state, repeated_key, vl);
            state = aes_inv_mixcolumns_rvv(state, vnext1, vnext2, vnext3, vl);
        }

        // Final inverse round omits InvMixColumns and uses round key zero.
        state = __riscv_vrgather_vv_u8m8(state, vinvshift, vl);
        state = aes_inv_subbytes_rvv(state, sbox_lo, sbox_hi, vl);
        rk = __riscv_vle8_v_u8m8(round_keys, 16);
        repeated_key = __riscv_vrgather_vv_u8m8(rk, vrep, vl);
        state = __riscv_vxor_vv_u8m8(state, repeated_key, vl);

        if (iv != NULL) {
            vuint8m8_t vprevious =
                __riscv_vle8_v_u8m8(previous_ciphertext, vl);
            state = __riscv_vxor_vv_u8m8(state, vprevious, vl);
        }
        __riscv_vse8_v_u8m8(output, state, vl);

        if (iv != NULL)
            memcpy(chain, saved_ciphertext, 16);

        input += blocks * 16;
        output += blocks * 16;
        nblocks -= blocks;
    }
}

#define DEFINE_AES_MODE_FUNCS(bits, nk, keylen)                                      \
    void aes##bits##_ecb_encrypt_rvv(const uint8_t *input, uint8_t *output,          \
                                     size_t nblocks, const uint8_t key[keylen])      \
    {                                                                                 \
        if (nblocks == 0) return;                                                      \
        uint8_t round_keys[240];                                                       \
        unsigned nr = aes_expand_key(key, nk, round_keys);                             \
        aes_encrypt_rvv(input, output, nblocks, round_keys, nr, NULL);                 \
    }                                                                                 \
    void aes##bits##_cbc_encrypt_rvv(const uint8_t *input, uint8_t *output,           \
                                     size_t nblocks, const uint8_t key[keylen],       \
                                     const uint8_t iv[16])                            \
    {                                                                                 \
        if (nblocks == 0) return;                                                      \
        uint8_t round_keys[240];                                                       \
        unsigned nr = aes_expand_key(key, nk, round_keys);                             \
        aes_encrypt_rvv(input, output, nblocks, round_keys, nr, iv);                  \
    }

DEFINE_AES_MODE_FUNCS(128, 4, 16)
DEFINE_AES_MODE_FUNCS(192, 6, 24)
DEFINE_AES_MODE_FUNCS(256, 8, 32)

#define DEFINE_AES_DECRYPT_FUNCS(bits, nk, keylen)                                  \
    void aes##bits##_ecb_decrypt_rvv(const uint8_t *input, uint8_t *output,          \
                                     size_t nblocks, const uint8_t key[keylen])      \
    {                                                                                 \
        if (nblocks == 0) return;                                                      \
        uint8_t round_keys[240];                                                       \
        unsigned nr = aes_expand_key(key, nk, round_keys);                             \
        aes_decrypt_rvv(input, output, nblocks, round_keys, nr, NULL);                 \
    }                                                                                 \
    void aes##bits##_cbc_decrypt_rvv(const uint8_t *input, uint8_t *output,           \
                                     size_t nblocks, const uint8_t key[keylen],       \
                                     const uint8_t iv[16])                            \
    {                                                                                 \
        if (nblocks == 0) return;                                                      \
        uint8_t round_keys[240];                                                       \
        unsigned nr = aes_expand_key(key, nk, round_keys);                             \
        aes_decrypt_rvv(input, output, nblocks, round_keys, nr, iv);                  \
    }

DEFINE_AES_DECRYPT_FUNCS(128, 4, 16)
DEFINE_AES_DECRYPT_FUNCS(192, 6, 24)
DEFINE_AES_DECRYPT_FUNCS(256, 8, 32)

#undef DEFINE_AES_DECRYPT_FUNCS
#undef DEFINE_AES_MODE_FUNCS