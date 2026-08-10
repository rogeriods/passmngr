#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>

namespace crypto {

std::string base64_encode(const unsigned char* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    std::string out(out_len + 1, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), data,
                                  static_cast<int>(len));
    out.resize(static_cast<size_t>(written));
    return out;
}

std::string base64_decode(const std::string& in, bool& ok) {
    size_t pad = 0;
    for (char c : in) {
        if (c == '=') {
            ++pad;
        } else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/')) {
            ok = false;
            return {};
        }
    }
    std::string out(3 * (in.size() / 4) + 3, '\0');
    int written = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                                  reinterpret_cast<const unsigned char*>(in.data()),
                                  static_cast<int>(in.size()));
    if (written < 0) {
        ok = false;
        return {};
    }
    written -= static_cast<int>(pad);
    if (written < 0) {
        ok = false;
        return {};
    }
    out.resize(static_cast<size_t>(written));
    ok = true;
    return out;
}

void random_bytes(unsigned char* buf, size_t len) {
    if (RAND_bytes(buf, static_cast<int>(len)) != 1) {
        throw std::runtime_error("failed to obtain random bytes");
    }
}

std::string derive_key(const std::string& password, const std::string& salt,
                       unsigned int iterations) {
    std::string key(kKeyLen, '\0');
    int rc = PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                               reinterpret_cast<const unsigned char*>(salt.data()),
                               static_cast<int>(salt.size()),
                               static_cast<int>(iterations), EVP_sha256(), kKeyLen,
                               reinterpret_cast<unsigned char*>(&key[0]));
    if (rc != 1) {
        throw std::runtime_error("key derivation failed");
    }
    return key;
}

EncryptedBlob encrypt(const std::string& key, const std::string& plaintext) {
    EncryptedBlob blob;
    blob.iv.assign(kIvLen, '\0');
    random_bytes(reinterpret_cast<unsigned char*>(&blob.iv[0]), kIvLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("failed to create cipher context");

    blob.ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    int final_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           reinterpret_cast<const unsigned char*>(blob.iv.data())) != 1 ||
        EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&blob.ciphertext[0]),
                          &out_len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&blob.ciphertext[0]) + out_len,
                            &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("encryption failed");
    }
    blob.ciphertext.resize(static_cast<size_t>(out_len + final_len));

    blob.tag.assign(kTagLen, '\0');
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, &blob.tag[0]) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("failed to obtain authentication tag");
    }
    EVP_CIPHER_CTX_free(ctx);
    return blob;
}

bool decrypt(const std::string& key, const EncryptedBlob& blob,
             std::string& plaintext) {
    if (blob.iv.size() != kIvLen || blob.tag.size() != kTagLen) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    plaintext.resize(blob.ciphertext.size());
    int out_len = 0;
    int final_len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                 reinterpret_cast<const unsigned char*>(key.data()),
                                 reinterpret_cast<const unsigned char*>(blob.iv.data())) == 1 &&
              EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &out_len,
                                reinterpret_cast<const unsigned char*>(blob.ciphertext.data()),
                                static_cast<int>(blob.ciphertext.size())) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen,
                                  const_cast<char*>(blob.tag.data())) == 1 &&
              EVP_DecryptFinal_ex(ctx,
                                  reinterpret_cast<unsigned char*>(&plaintext[0]) + out_len,
                                  &final_len) == 1;
    plaintext.resize(static_cast<size_t>(out_len + final_len));
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

}  // namespace crypto
