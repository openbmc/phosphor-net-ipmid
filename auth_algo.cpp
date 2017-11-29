#include "auth_algo.hpp"
#include "integrity_algo.hpp"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <iostream>

namespace cipher
{

namespace rakp_auth
{

std::vector<uint8_t> AlgoSHA1::generateHMAC(
        const UserKey& userKey,
        const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), userKey.data(), userKey.size(), input.data(),
             input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate HMAC failed\n";
        output.resize(0);
    }

    return output;
}

std::vector<uint8_t> AlgoSHA1::generateICV(
        const std::vector<uint8_t>& sik,
        const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), sik.data(), sik.size(),
             input.data(), input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate Session Integrity Key failed\n";
        output.resize(0);
    }
    output.resize(integrity::AlgoSHA1::SHA1_96_AUTHCODE_LENGTH);

    return output;
}

std::vector<uint8_t> AlgoSHA256::generateHMAC(
        const UserKey& userKey,
        const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha256(), userKey.data(), userKey.size(), input.data(),
             input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate HMAC_SHA256 failed\n";
        output.resize(0);
    }

    return output;
}

std::vector<uint8_t> AlgoSHA256::generateICV(
        const std::vector<uint8_t>& sik,
        const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha256(), sik.data(), sik.size(),
             input.data(), input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate HMAC_SHA256_128 Integrity Check Value failed\n";
        output.resize(0);
    }
    output.resize(integrity::AlgoSHA256::SHA256_128_AUTHCODE_LENGTH);

    return output;
}

} // namespace auth

} // namespace cipher
