#include "des.h"

#define NUM_ROUNDS 16

// masks to select bits out of plaintext (based on IP rows)
const uint64_t IP_masks[8] = { 0x4040404040404040, 0x1010101010101010,
    0x0404040404040404, 0x0101010101010101, 0x8080808080808080,
    0x2020202020202020, 0x0808080808080808, 0x0202020202020202 };
const uint8_t IP_shifts[8] = { 6, 4, 2, 0, 7, 5, 3, 1 };

// Initial Permutation
uint64_t IP(const uint64_t x)
{
    uint64_t temp = 0, y = 0;

    // mask out wanted bits, shift them to a common location
    for(int i = 0; i < 8; i++)
    {
        temp = (x & IP_masks[i]) >> IP_shifts[i];
        for(int j = 0; j < 8; j++)
        {
            // build y from bits from temp
            y <<= 1;
            y |= (temp & 1);
            temp >>= 8;
        }
    }
    return y;
}

// Expansion Permutation
// returns E(u) in lower 48 bits of return value
uint64_t E_perm(const uint32_t u)
{
    uint64_t long_u = u;
    uint64_t out = (long_u & 1) << 47;
    out |= (long_u & 0xf8000000LL) << 15;
    out |= (long_u & 0x1f800000LL) << 13;
    out |= (long_u & 0x01f80000LL) << 11;
    out |= (long_u & 0x001f8000LL) << 9;
    out |= (long_u & 0x0001f800LL) << 7;
    out |= (long_u & 0x00001f80LL) << 5;
    out |= (long_u & 0x000001f8LL) << 3;
    out |= (long_u & 0x0000001fLL) << 1;
    out |= (long_u & 0x80000000LL) >> 31;
    return out;
}

// sboxes defined in an array pattern
const uint8_t sbox1[64] = { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0,
    7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13,
    6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3,
    14, 10, 0, 6, 13 };
const uint8_t sbox2[64] = { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5,
    10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10,
    4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12,
    0, 5, 14, 9 };
const uint8_t sbox3[64] = { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2,
    8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15,
    3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3,
    11, 5, 2, 12 };
const uint8_t sbox4[64] = { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4,
    15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12,
    11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11,
    12, 7, 2, 14 };
const uint8_t sbox5[64] = { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14,
    9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10,
    13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0,
    9, 10, 4, 5, 3 };
const uint8_t sbox6[64] = { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5,
    11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2,
    8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1,
    7, 6, 0, 8, 13 };
const uint8_t sbox7[64] = { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6,
    1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12,
    3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10 ,7, 9, 5, 0, 15,
    14, 2, 3, 12 };
const uint8_t sbox8[64] = { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12,
    7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12,
    14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0,
    3, 5, 6, 11 };

// takes an sbox number and an input and returns the substituted value
uint8_t sbox(const int sbox_number, const uint8_t x)
{
    // produce sbox index: b_1 b_6 b_2 b_3 b_4 b_5
    uint8_t s_index = (x & 0x20) | ((x & 1) << 4) | ((x & 0x1e) >> 1);
    switch(sbox_number)
    {
        case 1:
            return sbox1[s_index];
        case 2:
            return sbox2[s_index];
        case 3:
            return sbox3[s_index];
        case 4:
            return sbox4[s_index];
        case 5:
            return sbox5[s_index];
        case 6:
            return sbox6[s_index];
        case 7:
            return sbox7[s_index];
        default:
            return sbox8[s_index];
    }
}

// given 48 bit input, return 32 bit sbox substituted bit string
uint32_t sboxes(const uint64_t x)
{
    // mask out inputs
    uint8_t sb1_input = (x & 0xfc0000000000LL) >> 42;
    uint8_t sb2_input = (x & 0x03f000000000LL) >> 36;
    uint8_t sb3_input = (x & 0x000fc0000000LL) >> 30;
    uint8_t sb4_input = (x & 0x00003f000000LL) >> 24;
    uint8_t sb5_input = (x & 0x000000fc0000LL) >> 18;
    uint8_t sb6_input = (x & 0x00000003f000LL) >> 12;
    uint8_t sb7_input = (x & 0x000000000fc0LL) >> 6;
    uint8_t sb8_input = (x & 0x00000000003fLL);
    return  (sbox(1, sb1_input) << 28)
        |   (sbox(2, sb2_input) << 24)
        |   (sbox(3, sb3_input) << 20)
        |   (sbox(4, sb4_input) << 16)
        |   (sbox(5, sb5_input) << 12)
        |   (sbox(6, sb6_input) << 8)
        |   (sbox(7, sb7_input) << 4)
        |   sbox(8, sb8_input);
}

// returns the nth bit of 32-bit x
uint8_t get_nth_bit_32bit(const uint32_t x, const uint8_t n)
{
    uint8_t shift_amount = 32 - n;
    return (x & (1 << shift_amount)) >> shift_amount;
}

const uint8_t P_bits[32] = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5,
    18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

// does P permutation
uint32_t P_perm(const uint32_t x)
{
    uint32_t y = 0;
    // build output bit by bit
    for(int i = 0; i < 32; i++)
    {
        y <<= 1;
        y |= (get_nth_bit_32bit(x, P_bits[i]) & 1);
    }
    return y;
}

const uint64_t C_masks[4] = { 0x8080808080808080, 0x4040404040404040,
    0x2020202020202020, 0x10101010};
const int C_shifts[4] = { 7, 6, 5, 4};

// Key scheduler C key permutation
uint32_t C_perm(const uint64_t K)
{
    uint32_t out = 0;
    // build permutation in 8 bit chunks

    uint64_t temp = 0;
    for(int i = 0; i < 3; i++)
    {
        temp = (K & C_masks[i]) >> C_shifts[i];
        for(int j = 0; j < 8; j++)
        {
            out <<= 1;
            out |= temp & 1;
            temp >>= 8;
        }
    }
    temp = (K & C_masks[3]) >> C_shifts[3];
    for(int j = 0; j < 4; j++)
    {
        out <<= 1;
        out |= temp & 1;
        temp >>= 8;
    }
    return out;
}

const uint64_t D_masks[4] = { 0x0202020202020202, 0x0404040404040404,
    0x0808080808080808, 0x1010101000000000 };
const int D_shifts[4] = { 1, 2, 3, 36 };

// Key scheduler D key permutation
uint32_t D_perm(const uint64_t K)
{
    uint32_t out = 0;

    // build permutation in 8 bit chunks
    uint64_t temp = 0;
    for(int i = 0; i < 3; i++)
    {
        temp = (K & D_masks[i]) >> D_shifts[i];
        for(int j = 0; j < 8; j++)
        {
            out <<= 1;
            out |= temp & 1;
            temp >>= 8;
        }
    }
    temp = (K & D_masks[3]) >> D_shifts[3];
    for(int j = 0; j < 4; j++)
    {
        out <<= 1;
        out |= temp & 1;
        temp >>= 8;
    }
    return out;
}

const int L_shift_amounts[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2,
    1 };

// Left circular shift on 28-bit input X with round
uint32_t L_shift(const uint32_t X, const unsigned int round)
{
    if(L_shift_amounts[round - 1] == 1) // rotate 1
    {
        uint32_t temp = (X & 0x08000000) >> 27;
        return temp | ((X & 0x07FFFFFF) << 1);
    }
    else // rotate 2
    {
        uint32_t temp = (X & 0x0c000000) >> 26;
        return temp | ((X & 0x03FFFFFF) << 2);
    }
}

// returns the nth bit of 56-bit x
uint8_t get_nth_bit_56bit(const uint64_t x, const uint8_t n)
{
    uint8_t shift_amount = 56 - n;
    uint64_t masked_value = x & (1LL << shift_amount);
    uint64_t y = masked_value >> shift_amount;
    return y;
}

const uint8_t PC2_bits[48] = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23,
    19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51,
    45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

// does PC2 permutation on 56 bit input
uint64_t PC2(const uint64_t x)
{
    uint64_t y = 0;

    // build one bit at a time
    for(int i = 0; i < 48; i++)
    {
        y <<= 1;
        y |= (uint64_t) (get_nth_bit_56bit(x, PC2_bits[i]) & 1);
    }
    return y;
}

// returns the nth bit of 64-bit x
uint8_t get_nth_bit_64bit(const uint64_t x, const uint8_t n)
{
    uint8_t shift_amount = 64 - n;
    return (x & (1LL << shift_amount)) >> shift_amount;
}

const uint64_t inv_IP_bits[64] = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15,
     55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61,
     29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
     42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

// does inverse IP permutation
uint64_t inv_IP(const uint64_t x)
{
    uint64_t y = 0;

    // build result one bit at a time
    for(int i = 0; i < 64; i++)
    {
        y <<= 1;
        y |= (get_nth_bit_64bit(x, inv_IP_bits[i]) & 1);
    }
    return y;
}

// implements f function in Feistel structure
uint32_t f(const uint32_t R, const uint64_t K)
{
    uint64_t E_out = E_perm(R);
    uint64_t y = E_out ^ K;
    y = sboxes(y);
    return P_perm(y);
}

// encrypt function
// takes 64-bit plaintext and key
// returns 64-bit ciphertext
uint64_t des_encrypt(const uint64_t plaintext, const uint64_t key)
{
    // plaintext setup
    uint64_t u = IP(plaintext);
    uint32_t L, R, temp;
    L = (u & 0xFFFFFFFF00000000) >> 32;
    R = u & 0xFFFFFFFF;

    // key setup
    uint32_t C, D;
    uint64_t K;
    C = C_perm(key);
    D = D_perm(key);

    // rounds
    for(int i = 1; i <= NUM_ROUNDS; i++)
    {
        // create round key
        C = L_shift(C, i);
        D = L_shift(D, i);
        K = PC2(((uint64_t) C << 28) | (uint64_t) D);

        // do Feistel structure
        temp = R;
        R = f(R, K);
        R = L ^ R;
        L = temp;
    }
    // put last round output through inverse IP
    u = ((uint64_t) R << 32) | (uint64_t) L;
    u = inv_IP(u);
    return u;
}

// decrypt function
// takes 64-bit ciphertext and key
// returns 64-bit plaintext
uint64_t des_decrypt(const uint64_t ciphertext, const uint64_t key)
{
    uint64_t round_keys[NUM_ROUNDS];
    uint32_t L, R, temp;

    // generate round keys
    uint32_t C, D;
    C = C_perm(key);
    D = D_perm(key);

    for(int i = 1; i <= NUM_ROUNDS; i++)
    {
        // create round key
        C = L_shift(C, i);
        D = L_shift(D, i);
        round_keys[i - 1] = PC2(((uint64_t) C << 28) | (uint64_t) D);
    }

    // apply Initial permutation
    uint64_t u = IP(ciphertext);
    L = u & 0xFFFFFFFF;
    R = (u >> 32) & 0xFFFFFFFF;

    // rounds
    for(int i = NUM_ROUNDS; i >= 1; i--)
    {
        // do Feistel structure
        temp = R;
        R = L;
        L = temp ^ f(R, round_keys[i - 1]);
    }

    // produce plaintext
    uint64_t plaintext = inv_IP(((uint64_t) L << 32) | (uint64_t) R);
    return plaintext;
}
