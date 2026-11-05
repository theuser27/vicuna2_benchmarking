/*
 * AES-128/192/256 ECB and CBC encryption for RVV + Zvkned.
 *
 * ECB API:
 *   aes128_ecb_encrypt_zvkned(in, out, nblocks, key16);
 *   aes192_ecb_encrypt_zvkned(in, out, nblocks, key24);
 *   aes256_ecb_encrypt_zvkned(in, out, nblocks, key32);
 * CBC API has the same arguments plus a 16-byte IV at the end.
 *
 * Build with a toolchain implementing the ratified RVV and Zvkned C
 * intrinsics, e.g. -march=rv32imv_zvkned -mabi=ilp32.
 *
 * Encrypts nblocks complete 16-byte blocks; no padding is added. Exact
 * in-place operation (input == output) is supported; partial overlap is not.
 * CBC copies the IV at entry and encrypts blocks serially because of chaining.
 *
 * Encryption rounds use vaesz.vs, vaesem.vs, and vaesef.vs intrinsics. AES-128
 * and AES-256 key schedules use vaeskf1.vi and vaeskf2.vi; AES-192 has no
 * dedicated Zvkned key-schedule instruction and uses a table-free software
 * schedule.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* Encrypt or decrypt nblocks complete 16-byte AES-ECB blocks. No padding is added.
 * Exact in-place operation (input == output) is supported; partial overlap
 * is not supported. This implementation requires RVV + Zvkned at runtime.
 */
void aes128_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16]);
void aes192_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24]);
void aes256_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32]);
void aes128_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16]);
void aes192_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24]);
void aes256_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32]);


/* Encrypt or decrypt nblocks complete 16-byte AES-CBC blocks. No padding is added.
 * iv is the 16-byte CBC initialization vector. The IV is copied at entry;
 * exact in-place input/output is supported, partial overlap is not.
 * CBC blocks in a single message are inherently serial due to chaining.
 */
void aes128_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16],
                               const uint8_t iv[16]);
void aes192_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24],
                               const uint8_t iv[16]);
void aes256_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32],
                               const uint8_t iv[16]);
void aes128_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16],
                               const uint8_t iv[16]);
void aes192_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24],
                               const uint8_t iv[16]);
void aes256_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32],
                               const uint8_t iv[16]);

#include <riscv_vector.h>

#ifndef __riscv_zvkned
#error "Compile this file with Zvkned enabled (e.g. -march=rv32imv_zvkned)"
#endif

/* Constant-time GF(2^8) multiplication, polynomial x^8+x^4+x^3+x+1. */
static uint8_t aes_gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (unsigned i = 0; i < 8; ++i) {
        const uint8_t b_mask = (uint8_t)(0u - (unsigned)(b & 1u));
        const uint8_t hi_mask = (uint8_t)(0u - (unsigned)(a >> 7));
        p ^= (uint8_t)(a & b_mask);
        a = (uint8_t)((uint8_t)(a << 1) ^ (uint8_t)(0x1bu & hi_mask));
        b >>= 1;
    }
    return p;
}

static uint8_t aes_rotl8(uint8_t x, unsigned n)
{
    return (uint8_t)(((unsigned)x << n) | ((unsigned)x >> (8u - n)));
}

/* AES S-box without secret-indexed memory accesses. */
static uint8_t aes_sbox_ct(uint8_t x)
{
    const uint8_t x2   = aes_gf_mul(x, x);
    const uint8_t x4   = aes_gf_mul(x2, x2);
    const uint8_t x8   = aes_gf_mul(x4, x4);
    const uint8_t x16  = aes_gf_mul(x8, x8);
    const uint8_t x32  = aes_gf_mul(x16, x16);
    const uint8_t x64  = aes_gf_mul(x32, x32);
    const uint8_t x128 = aes_gf_mul(x64, x64);
    uint8_t inv = aes_gf_mul(x128, x64); /* x^192 */
    inv = aes_gf_mul(inv, x32);          /* x^224 */
    inv = aes_gf_mul(inv, x16);          /* x^240 */
    inv = aes_gf_mul(inv, x8);           /* x^248 */
    inv = aes_gf_mul(inv, x4);           /* x^252 */
    inv = aes_gf_mul(inv, x2);           /* x^254; zero maps to zero */

    return (uint8_t)(inv ^ aes_rotl8(inv, 1) ^ aes_rotl8(inv, 2) ^
                     aes_rotl8(inv, 3) ^ aes_rotl8(inv, 4) ^ 0x63u);
}

/* Constant-time software AES key expansion. Used for AES-192. */
static unsigned aes_expand_key_software(const uint8_t *key,
                                        unsigned key_bytes,
                                        uint8_t round_keys[15][16])
{
    const unsigned nk = key_bytes / 4u;
    const unsigned nr = nk + 6u;
    const unsigned total_words = 4u * (nr + 1u);
    uint8_t *rk = &round_keys[0][0];
    uint8_t rcon = 1;

    for (unsigned i = 0; i < key_bytes; ++i)
        rk[i] = key[i];

    for (unsigned i = nk; i < total_words; ++i) {
        uint8_t t[4];
        for (unsigned j = 0; j < 4; ++j)
            t[j] = rk[4u * (i - 1u) + j];

        if ((i % nk) == 0) {
            const uint8_t first = t[0];
            t[0] = (uint8_t)(aes_sbox_ct(t[1]) ^ rcon);
            t[1] = aes_sbox_ct(t[2]);
            t[2] = aes_sbox_ct(t[3]);
            t[3] = aes_sbox_ct(first);
            rcon = (uint8_t)((rcon << 1) ^
                             ((rcon & 0x80u) ? 0x1bu : 0u));
        } else if (nk > 6u && (i % nk) == 4u) {
            for (unsigned j = 0; j < 4; ++j)
                t[j] = aes_sbox_ct(t[j]);
        }

        for (unsigned j = 0; j < 4; ++j)
            rk[4u * i + j] = (uint8_t)(rk[4u * (i - nk) + j] ^ t[j]);
    }

    return nr;
}

/* Load one 128-bit key into the low element group of a vector register. */
static inline vuint32m1_t aes_load_round_key(const uint8_t *key)
{
    vuint8m1_t bytes = __riscv_vle8_v_u8m1(key, 16);
    return __riscv_vreinterpret_v_u8m1_u32m1(bytes);
}

static inline void aes_store_round_key(uint8_t out[16], vuint32m1_t key)
{
    vuint8m1_t bytes = __riscv_vreinterpret_v_u32m1_u8m1(key);
    __riscv_vse8_v_u8m1(out, bytes, 16);
}

/* AES-128 key expansion with the Zvkned vaeskf1.vi instruction. */
static void aes_expand_key_128_zvkned(const uint8_t key[16],
                                      uint8_t round_keys[15][16])
{
    vuint32m1_t current = aes_load_round_key(key);
    for (unsigned i = 0; i < 16; ++i)
        round_keys[0][i] = key[i];

    /* The round number is an instruction immediate, so these are unrolled. */
#define AES128_KS_STEP(R) do {                                      \
        current = __riscv_vaeskf1_vi_u32m1(current, R, 4);           \
        aes_store_round_key(round_keys[(R)], current);               \
    } while (0)
    AES128_KS_STEP(1);
    AES128_KS_STEP(2);
    AES128_KS_STEP(3);
    AES128_KS_STEP(4);
    AES128_KS_STEP(5);
    AES128_KS_STEP(6);
    AES128_KS_STEP(7);
    AES128_KS_STEP(8);
    AES128_KS_STEP(9);
    AES128_KS_STEP(10);
#undef AES128_KS_STEP
}

/* AES-256 key expansion with vaeskf2.vi. Rounds 2..14 generate K2..K14. */
static void aes_expand_key_256_zvkned(const uint8_t key[32],
                                      uint8_t round_keys[15][16])
{
    vuint32m1_t previous = aes_load_round_key(key);
    vuint32m1_t current = aes_load_round_key(key + 16);
    vuint32m1_t next;

    for (unsigned i = 0; i < 16; ++i) {
        round_keys[0][i] = key[i];
        round_keys[1][i] = key[16 + i];
    }

    /* vaeskf2.vi uses vd as the previous key and vs2 as the current key. */
#define AES256_KS_STEP(R) do {                                      \
        next = __riscv_vaeskf2_vi_u32m1(previous, current, R, 4);    \
        previous = current;                                         \
        current = next;                                              \
        aes_store_round_key(round_keys[(R)], current);               \
    } while (0)
    AES256_KS_STEP(2);
    AES256_KS_STEP(3);
    AES256_KS_STEP(4);
    AES256_KS_STEP(5);
    AES256_KS_STEP(6);
    AES256_KS_STEP(7);
    AES256_KS_STEP(8);
    AES256_KS_STEP(9);
    AES256_KS_STEP(10);
    AES256_KS_STEP(11);
    AES256_KS_STEP(12);
    AES256_KS_STEP(13);
    AES256_KS_STEP(14);
#undef AES256_KS_STEP
}

static void aes_ecb_encrypt_zvkned_core(const uint8_t *input,
                                        uint8_t *output,
                                        size_t nblocks,
                                        const uint8_t round_keys[15][16],
                                        unsigned nr)
{
    /* A 128-bit AES block is four e32 elements. m8 allows multiple blocks
       in one vector register group; max_blocks adapts to the hardware VLEN. */
    const size_t max_blocks = __riscv_vsetvlmax_e32m8() / 4u;

    while (nblocks != 0) {
        const size_t blocks = nblocks < max_blocks ? nblocks : max_blocks;
        const size_t vl_words = __riscv_vsetvl_e32m8(blocks * 4u);
        const size_t vl_bytes = vl_words * 4u;
        vuint8m8_t state_bytes = __riscv_vle8_v_u8m8(input, vl_bytes);
        vuint32m8_t state = __riscv_vreinterpret_v_u8m8_u32m8(state_bytes);
        vuint32m1_t rk;

        /* Round zero: AddRoundKey. One 128-bit key is shared across all blocks. */
        rk = aes_load_round_key(round_keys[0]);
        state = __riscv_vaesz_vs_u32m8_u32m1(state, rk, vl_words);

        /* Middle rounds include MixColumns. */
        for (unsigned round = 1; round < nr; ++round) {
            rk = aes_load_round_key(round_keys[round]);
            state = __riscv_vaesem_vs_u32m8_u32m1(state, rk, vl_words);
        }

        /* Final round omits MixColumns. */
        rk = aes_load_round_key(round_keys[nr]);
        state = __riscv_vaesef_vs_u32m8_u32m1(state, rk, vl_words);

        state_bytes = __riscv_vreinterpret_v_u32m8_u8m8(state);
        __riscv_vse8_v_u8m8(output, state_bytes, vl_bytes);

        input += blocks * 16u;
        output += blocks * 16u;
        nblocks -= blocks;
    }
}

void aes128_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0)
        return;
    aes_expand_key_128_zvkned(key, round_keys);
    aes_ecb_encrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 10);
}

void aes192_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0)
        return;
    (void)aes_expand_key_software(key, 24, round_keys);
    aes_ecb_encrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 12);
}

void aes256_ecb_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0)
        return;
    aes_expand_key_256_zvkned(key, round_keys);
    aes_ecb_encrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 14);
}


static void aes_ecb_decrypt_zvkned_core(const uint8_t *input,
                                        uint8_t *output,
                                        size_t nblocks,
                                        const uint8_t round_keys[15][16],
                                        unsigned nr);

void aes128_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0) return;
    aes_expand_key_128_zvkned(key, round_keys);
    aes_ecb_decrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 10);
}

void aes192_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0) return;
    (void)aes_expand_key_software(key, 24, round_keys);
    aes_ecb_decrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 12);
}

void aes256_ecb_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0) return;
    aes_expand_key_256_zvkned(key, round_keys);
    aes_ecb_decrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 14);
}


/*
 * Shared Zvkned AES decryption core. AES decryption starts with AddRoundKey
 * using the final encryption round key, then walks the encryption round keys
 * backwards through vaesdm, finishing with vaesdf and round key zero.
 */
static void aes_ecb_decrypt_zvkned_core(const uint8_t *input,
                                        uint8_t *output,
                                        size_t nblocks,
                                        const uint8_t round_keys[15][16],
                                        unsigned nr)
{
    const size_t max_blocks = __riscv_vsetvlmax_e32m8() / 4u;

    while (nblocks != 0) {
        const size_t blocks = nblocks < max_blocks ? nblocks : max_blocks;
        const size_t vl_words = __riscv_vsetvl_e32m8(blocks * 4u);
        const size_t vl_bytes = vl_words * 4u;
        vuint8m8_t state_bytes = __riscv_vle8_v_u8m8(input, vl_bytes);
        vuint32m8_t state = __riscv_vreinterpret_v_u8m8_u32m8(state_bytes);
        vuint32m1_t rk = aes_load_round_key(round_keys[nr]);

        /* Initial AddRoundKey with K[Nr]. */
        state = __riscv_vaesz_vs_u32m8_u32m1(state, rk, vl_words);

        /* Inverse middle rounds consume K[Nr-1] down to K[1]. */
        for (unsigned round = nr - 1; round > 0; --round) {
            rk = aes_load_round_key(round_keys[round]);
            state = __riscv_vaesdm_vs_u32m8_u32m1(state, rk, vl_words);
        }

        /* Final inverse round with K[0], without InvMixColumns. */
        rk = aes_load_round_key(round_keys[0]);
        state = __riscv_vaesdf_vs_u32m8_u32m1(state, rk, vl_words);

        state_bytes = __riscv_vreinterpret_v_u32m8_u8m8(state);
        __riscv_vse8_v_u8m8(output, state_bytes, vl_bytes);

        input += blocks * 16u;
        output += blocks * 16u;
        nblocks -= blocks;
    }
}

static void aes_cbc_decrypt_zvkned_core(const uint8_t *input,
                                        uint8_t *output,
                                        size_t nblocks,
                                        const uint8_t round_keys[15][16],
                                        unsigned nr,
                                        const uint8_t iv[16])
{
    uint8_t chain[16];
    memcpy(chain, iv, 16); /* Preserve IV if it aliases output. */

    size_t max_blocks = __riscv_vsetvlmax_e32m8() / 4u;
    if (max_blocks > 16u)
        max_blocks = 16u; /* Bound the scratch space to 256 bytes. */

    while (nblocks != 0) {
        const size_t blocks = nblocks < max_blocks ? nblocks : max_blocks;
        const size_t bytes = blocks * 16u;
        uint8_t ciphertext[256];
        uint8_t previous_ciphertext[256];

        /* Preserve this batch first, so exact in-place decryption is safe. */
        memcpy(ciphertext, input, bytes);
        memcpy(previous_ciphertext, chain, 16);
        if (blocks > 1u)
            memcpy(previous_ciphertext + 16, ciphertext, bytes - 16u);

        aes_ecb_decrypt_zvkned_core(ciphertext, output, blocks, round_keys, nr);
        for (size_t i = 0; i < bytes; ++i)
            output[i] ^= previous_ciphertext[i];

        /* Chain from the last input ciphertext, never from plaintext output. */
        memcpy(chain, ciphertext + bytes - 16u, 16);
        input += bytes;
        output += bytes;
        nblocks -= blocks;
    }
}

/*
 * CBC encryption core. CBC has a data dependency between consecutive blocks:
 * C[i] = AES_K(P[i] XOR C[i-1]), with C[-1] = IV. Consequently, blocks from
 * one CBC message cannot be encrypted in parallel as they are in ECB. Reuse
 * the Zvkned ECB core one block at a time; each AES block is still processed
 * by the vector AES instructions.
 */
static void aes_cbc_encrypt_zvkned_core(const uint8_t *input,
                                        uint8_t *output,
                                        size_t nblocks,
                                        const uint8_t round_keys[15][16],
                                        unsigned nr,
                                        const uint8_t iv[16])
{
    uint8_t chain[16];
    for (unsigned i = 0; i < 16; ++i)
        chain[i] = iv[i]; /* Copy IV before writing output; IV may alias output. */

    while (nblocks != 0) {
        uint8_t mixed[16];

        /* Save the XOR result before writing output, so exact in-place works. */
        for (unsigned i = 0; i < 16; ++i)
            mixed[i] = (uint8_t)(input[i] ^ chain[i]);

        aes_ecb_encrypt_zvkned_core(mixed, output, 1, round_keys, nr);

        /* The ciphertext of this block becomes the chaining value. */
        for (unsigned i = 0; i < 16; ++i)
            chain[i] = output[i];

        input += 16;
        output += 16;
        --nblocks;
    }
}

void aes128_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16],
                               const uint8_t iv[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0)
        return;
    aes_expand_key_128_zvkned(key, round_keys);
    aes_cbc_encrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 10, iv);
}

void aes192_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24],
                               const uint8_t iv[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0)
        return;
    (void)aes_expand_key_software(key, 24, round_keys);
    aes_cbc_encrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 12, iv);
}

void aes256_cbc_encrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32],
                               const uint8_t iv[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0)
        return;
    aes_expand_key_256_zvkned(key, round_keys);
    aes_cbc_encrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 14, iv);
}

void aes128_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[16],
                               const uint8_t iv[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0) return;
    aes_expand_key_128_zvkned(key, round_keys);
    aes_cbc_decrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 10, iv);
}

void aes192_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[24],
                               const uint8_t iv[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0) return;
    (void)aes_expand_key_software(key, 24, round_keys);
    aes_cbc_decrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 12, iv);
}

void aes256_cbc_decrypt_zvkned(const uint8_t *input, uint8_t *output,
                               size_t nblocks, const uint8_t key[32],
                               const uint8_t iv[16])
{
    uint8_t round_keys[15][16];
    if (nblocks == 0) return;
    aes_expand_key_256_zvkned(key, round_keys);
    aes_cbc_decrypt_zvkned_core(input, output, nblocks,
                                (const uint8_t (*)[16])round_keys, 14, iv);
}
