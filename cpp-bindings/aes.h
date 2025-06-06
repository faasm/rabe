#pragma once

#ifndef __faasm
#include <cstddef>
#include <cstdint>
#endif
#include <string>
#include <vector>

#define TLESS_AES256GCM_NONCE_SIZE 12
#define TLESS_AES256GCM_AUTH_SIZE 16
#define TLESS_SHA256_HASH_SIZE 32

extern "C" {
void aes256gcm_encrypt(const uint8_t *keyPtr, size_t keySize,
                       const uint8_t *noncePtr, size_t nonceSize,
                       const uint8_t *plainTextPtr, size_t plainTextSize,
                       uint8_t *cipherTextPtr, size_t cipherTextSize);

void aes256gcm_decrypt(const uint8_t *keyPtr, size_t keySize,
                       const uint8_t *noncePtr, size_t nonceSize,
                       const uint8_t *cipherTextPtr, size_t cipherTextSize,
                       uint8_t *plainTextPtr, size_t plainTextSize);

void sha256_digest(const uint8_t *dataPtr, size_t dataLen,
                   const uint8_t *hashPtr);
}

namespace accless::aes256gcm {
std::vector<uint8_t> encrypt(std::vector<uint8_t> key,
                             std::vector<uint8_t> nonce,
                             std::vector<uint8_t> plainText);

std::vector<uint8_t> decrypt(std::vector<uint8_t> key,
                             std::vector<uint8_t> nonce,
                             std::vector<uint8_t> cipherText);
} // namespace accless::aes256gcm

namespace accless::sha256 {
std::vector<uint8_t> hash(const std::vector<uint8_t> &data);
std::vector<uint8_t> hash(const std::string &data);
} // namespace accless::sha256
