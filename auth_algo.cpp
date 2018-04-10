#include "auth_algo.hpp"

#include <experimental/filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace cipher
{

namespace rakp_auth
{

void Interface::loadPassword()
{
    static constexpr auto pwdFileName = "/etc/ipmipwd";
    std::ifstream pwdFile;
    pwdFile.open(pwdFileName, std::ifstream::binary);
    if (!pwdFile.is_open())
    {
        return;
    }

    std::error_code ec;
    auto pwdLength = std::experimental::filesystem::file_size(pwdFileName, ec);
    userKey.fill(0);

    pwdFile.read(reinterpret_cast<char *>(userKey.data()), pwdLength);
    pwdFile.close();
}

std::vector<uint8_t> AlgoSHA1::generateHMAC(
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
        const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), sessionIntegrityKey.data(), SHA_DIGEST_LENGTH,
             input.data(), input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate Session Integrity Key failed\n";
        output.resize(0);
    }
    output.resize(integrityCheckValueLength);

    return output;
}

std::vector<uint8_t> AlgoSHA256::generateHMAC(
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
        const std::vector<uint8_t>& input) const
{
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha256(),
             sessionIntegrityKey.data(), sessionIntegrityKey.size(),
             input.data(), input.size(), output.data(), &mdLen) == NULL)
    {
        std::cerr << "Generate HMAC_SHA256_128 Integrity Check Value failed\n";
        output.resize(0);
    }
    output.resize(integrityCheckValueLength);

    return output;
}

} // namespace auth

} // namespace cipher
