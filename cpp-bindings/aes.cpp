#include "aes.h"

#include <iostream>
#include <string>
#include <vector>

namespace accless::aes256gcm {
std::vector<uint8_t> encrypt(std::vector<uint8_t> key,
                             std::vector<uint8_t> nonce,
                             std::vector<uint8_t> plainText)
{
    size_t cipherTextSize = TLESS_AES256GCM_AUTH_SIZE + TLESS_AES256GCM_NONCE_SIZE + plainText.size();
    std::vector<uint8_t> cipherText(cipherTextSize);

    aes256gcm_encrypt(
        key.data(),
        key.size(),
        nonce.data(),
        nonce.size(),
        plainText.data(),
        plainText.size(),
        cipherText.data(),
        cipherText.size());

    return cipherText;
}

std::vector<uint8_t> decrypt(std::vector<uint8_t> key,
                             std::vector<uint8_t> nonce,
                             std::vector<uint8_t> cipherText)
{
    size_t plainTextSize = cipherText.size() - TLESS_AES256GCM_AUTH_SIZE;
    std::vector<uint8_t> plainText(plainTextSize);

    aes256gcm_decrypt(
        key.data(),
        key.size(),
        nonce.data(),
        nonce.size(),
        cipherText.data(),
        cipherText.size(),
        plainText.data(),
        plainText.size());

    return plainText;
}
}

namespace accless::sha256 {
std::vector<uint8_t> hash(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> hashedData(TLESS_SHA256_HASH_SIZE);

    sha256_digest(data.data(), data.size(), hashedData.data());

    return hashedData;
}

std::vector<uint8_t> hash(const std::string& data)
{
    std::vector<uint8_t> hashedData(TLESS_SHA256_HASH_SIZE);

    sha256_digest((uint8_t*) data.c_str(), data.size(), hashedData.data());

    return hashedData;
}
}
