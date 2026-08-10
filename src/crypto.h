#pragma once

#include <cstddef>
#include <string>

namespace crypto {

constexpr unsigned int kKeyLen = 32;  // AES-256
constexpr unsigned int kIvLen = 12;   // GCM recommended nonce size
constexpr unsigned int kTagLen = 16;  // GCM auth tag
constexpr unsigned int kSaltLen = 16;

std::string base64_encode(const unsigned char* data, size_t len);
std::string base64_decode(const std::string& in, bool& ok);

void random_bytes(unsigned char* buf, size_t len);

std::string derive_key(const std::string& password, const std::string& salt,
                       unsigned int iterations);

struct EncryptedBlob {
    std::string iv;          // raw kIvLen bytes
    std::string tag;         // raw kTagLen bytes
    std::string ciphertext;  // raw bytes
};

EncryptedBlob encrypt(const std::string& key, const std::string& plaintext);
bool decrypt(const std::string& key, const EncryptedBlob& blob,
             std::string& plaintext);

}  // namespace crypto
