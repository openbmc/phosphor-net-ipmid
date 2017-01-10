#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "integrity_algo.hpp"
#include "message_parsers.hpp"

namespace cipher
{

namespace integrity
{

Interface::Interface(const Buffer& sik, const Key& addKey, size_t authLength)
{
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(), sik.data(), sik.size(), addKey.data(),
             addKey.size(), key1.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating Key1 for integrity "
                                 "algorithm failed");
    }

    authCodeLength = authLength;
}

bool AlgoSHA1::verifyIntegrityData(const Buffer& packet,
                                   const size_t packetLen,
                                   Buffer::const_iterator integrityData) const
{
    Buffer output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(),
             key1.data(), key1.size(),
             packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
             packetLen - message::parser::RMCP_SESSION_HEADER_SIZE,
             output.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating integrity data for verification "
                                 "failed");
    }

    // HMAC generates Message Digest to the size of SHA_DIGEST_LENGTH, the
    // AuthCode field length is based on the integrity algorithm. So we are
    // interested only in the AuthCode field length of the generated Message
    // digest.
    output.resize(authCodeLength);

    return (std::equal(output.begin(), output.end(), integrityData));
}

Buffer AlgoSHA1::generateIntegrityData(const Buffer& packet) const
{
    Buffer output(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;

    if (HMAC(EVP_sha1(),
             key1.data(), key1.size(),
             packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
             packet.size() - message::parser::RMCP_SESSION_HEADER_SIZE,
             output.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating integrity data for response "
                                 "failed");
    }

    return output;
}

}// namespace integrity

}// namespace cipher
