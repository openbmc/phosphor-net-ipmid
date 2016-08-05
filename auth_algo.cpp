#include "auth_algo.hpp"

#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace cipher
{
namespace auth
{
std::vector<uint8_t> RAKPAlgoSHA1::generateHMAC(std::vector<uint8_t>& input)
{
    std::vector<uint8_t> output;
    output.resize(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    HMAC(EVP_sha1(), userKey.data(), userKey.size(), input.data(), input.size(),
         output.data(), &mdLen);

    output.resize(mdLen);
    return output;
}

std::vector<uint8_t> RAKPAlgoSHA1::generateICV(std::vector<uint8_t>& input)
{
    std::vector<uint8_t> output;
    output.resize(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    HMAC(EVP_sha1(), sessionIntegrityKey.data(), SHA_DIGEST_LENGTH, input.data(),
         input.size(), output.data(), &mdLen);

    output.resize(mdLen);
    return output;
}

} // namespace auth

} // namespace cipher
