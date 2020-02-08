#include "../des.hpp"
#include "../des_data.hpp"
#include "../des_key.hpp"

#pragma GCC optimize ("unroll-loops")

Des::Des(ui64 key) : sub_key() {
    keygen(key);
}

ui64 Des::encrypt(ui64 block) {
    return des(block, DesMode::ENCRYPT);
}

ui64 Des::decrypt(ui64 block) {
    return des(block, DesMode::DECRYPT);
}

ui64 Des::des(ui64 block, DesMode mode) {
    // applying initial permutation
    block = ip(block);

    // dividing T' into two 32-bit parts
    ui32 L = (ui32) (block >> 32u) & L64_MASK;
    ui32 R = (ui32) (block & L64_MASK);

    // 16 rounds
    for (ui8 i = 0; i < 16; i++) {
        ui32 F = static_cast<bool>(mode) ? f(R, sub_key[15 - i]) : f(R, sub_key[i]);
        feistel(L, R, F);
    }

    // swapping the two parts
    block = (((ui64) R) << 32u) | (ui64) L;
    // applying final permutation
    return fp(block);
}

void Des::keygen(ui64 key) {
    // initial key schedule calculation
    ui64 permuted_choice_1 = 0; // 56 bits
    for (char i : PC1) {
        permuted_choice_1 <<= 1u;
        permuted_choice_1 |= (key >> (64u - i)) & LB64_MASK;
    }

    // 28 bits
    ui32 C = (ui32) ((permuted_choice_1 >> 28u) & L64_MASK);
    ui32 D = (ui32) (permuted_choice_1 & L64_MASK);

    // Calculation of the 16 keys
    for (ui8 i = 0; i < 16; i++) {
        // key schedule, shifting Ci and Di
        for (ui8 j = 0; j < ITERATION_SHIFT[i]; j++) {
            C = (L32_MASK & (C << 1u)) | (LB32_MASK & (C >> 27u));
            D = (L32_MASK & (D << 1u)) | (LB32_MASK & (D >> 27u));
        }

        ui64 permuted_choice_2 = (((ui64) C) << 28u) | (ui64) D;

        sub_key[i] = 0; // 48 bits (2*24)
        for (char j : PC2) {
            sub_key[i] <<= 1u;
            sub_key[i] |= (permuted_choice_2 >> (56u - j)) & LB64_MASK;
        }
    }
}

// initial permutation
ui64 Des::ip(ui64 block) {
    ui64 result = 0;
    for (char i : IP) {
        result <<= 1u;
        result |= (block >> (64u - i)) & LB64_MASK;
    }
    return result;
}

// inverse initial permutation
ui64 Des::fp(ui64 block) {
    ui64 result = 0;
    for (char i : FP) {
        result <<= 1u;
        result |= (block >> (64u - i)) & LB64_MASK;
    }
    return result;
}

void Des::feistel(ui32 &L, ui32 &R, ui32 F) {
    ui32 temp = R;
    R = L ^ F;
    L = temp;
}

// f(R,k) function
ui32 Des::f(ui32 R, ui64 k) {
    // applying expansion permutation and returning 48-bit data
    ui64 s_input = 0;
    for (char i : EXPANSION) {
        s_input <<= 1u;
        s_input |= (ui64) ((R >> (32u - i)) & LB32_MASK);
    }

    // XORing expanded Ri with Ki, the round key
    s_input = s_input ^ k;

    // applying S-Boxes function and returning 32-bit data
    ui32 s_output = 0;
    for (ui8 i = 0; i < 8; i++) {
        // Outer bits
        unsigned char row = (char) ((s_input & (0x0000840000000000u >> 6u * i)) >> (42u - 6u * i));
        row = (row >> 4u) | (row & 0x01u);

        // Middle 4 bits of input
        unsigned char column = (char) ((s_input & (0x0000780000000000u >> 6u * i)) >> (43u - 6u * i));

        s_output <<= 4u;
        s_output |= (ui32) (SBOX[i][16u * row + column] & 0x0fu);
    }

    // applying the round permutation
    ui32 f_result = 0;
    for (char i : PBOX) {
        f_result <<= 1u;
        f_result |= (s_output >> (32u - i)) & LB32_MASK;
    }

    return f_result;
}