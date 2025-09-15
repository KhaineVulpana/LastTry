#ifndef CHACHA20_H
#define CHACHA20_H

#include <vector>
#include <cstdint>
#include <algorithm>

inline uint32_t rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

inline void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

inline void chacha20Block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16];
    state[0] = 0x61707865; // "expa"
    state[1] = 0x3320646e; // "nd 3"
    state[2] = 0x79622d32; // "2-by"
    state[3] = 0x6b206574; // "te k"
    for (int i = 0; i < 8; ++i) {
        state[4 + i] =
            (uint32_t)key[i * 4] |
            ((uint32_t)key[i * 4 + 1] << 8) |
            ((uint32_t)key[i * 4 + 2] << 16) |
            ((uint32_t)key[i * 4 + 3] << 24);
    }
    state[12] = counter;
    state[13] = (uint32_t)nonce[0] | ((uint32_t)nonce[1] << 8) |
                ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    state[14] = (uint32_t)nonce[4] | ((uint32_t)nonce[5] << 8) |
                ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    state[15] = (uint32_t)nonce[8] | ((uint32_t)nonce[9] << 8) |
                ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);

    uint32_t working[16];
    for (int i = 0; i < 16; ++i) working[i] = state[i];

    for (int i = 0; i < 10; ++i) {
        quarterRound(working[0], working[4], working[8], working[12]);
        quarterRound(working[1], working[5], working[9], working[13]);
        quarterRound(working[2], working[6], working[10], working[14]);
        quarterRound(working[3], working[7], working[11], working[15]);
        quarterRound(working[0], working[5], working[10], working[15]);
        quarterRound(working[1], working[6], working[11], working[12]);
        quarterRound(working[2], working[7], working[8], working[13]);
        quarterRound(working[3], working[4], working[9], working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t result = working[i] + state[i];
        out[4 * i] = result & 0xFF;
        out[4 * i + 1] = (result >> 8) & 0xFF;
        out[4 * i + 2] = (result >> 16) & 0xFF;
        out[4 * i + 3] = (result >> 24) & 0xFF;
    }
}

inline std::vector<uint8_t> chacha20Encrypt(const std::vector<uint8_t>& data, uint64_t counter, const uint8_t nonce[12]) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    std::vector<uint8_t> out(data.size());
    uint32_t block_counter = static_cast<uint32_t>(counter);
    size_t offset = 0;
    while (offset < data.size()) {
        uint8_t block[64];
        chacha20Block(key, nonce, block_counter, block);
        size_t block_len = std::min<size_t>(64, data.size() - offset);
        for (size_t i = 0; i < block_len; ++i) {
            out[offset + i] = data[offset + i] ^ block[i];
        }
        offset += block_len;
        ++block_counter;
    }
    return out;
}

inline std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data, uint64_t counter, const uint8_t nonce[12]) {
    return chacha20Encrypt(data, counter, nonce);
}

inline std::vector<uint8_t> decryptData(const std::vector<uint8_t>& data, uint64_t counter, const uint8_t nonce[12]) {
    return chacha20Encrypt(data, counter, nonce); // symmetric stream cipher
}

#endif // CHACHA20_H
