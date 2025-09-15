#ifndef XOR_CIPHER_H
#define XOR_CIPHER_H

#include <vector>
#include <cstdint>
#include <string>

// Simple XOR-based cipher for demonstration purposes only
inline std::vector<uint8_t> xorCipher(const std::vector<uint8_t>& data) {
    static const std::string key = "0123456789ABCDEF0123456789ABCDEF"; // 32-byte shared key
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        out[i] = data[i] ^ static_cast<uint8_t>(key[i % key.size()]);
    }
    return out;
}

inline std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data) {
    return xorCipher(data);
}

inline std::vector<uint8_t> decryptData(const std::vector<uint8_t>& data) {
    return xorCipher(data); // XOR is symmetric
}

#endif // XOR_CIPHER_H
