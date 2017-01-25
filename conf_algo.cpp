#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <numeric>
#include "conf_algo.hpp"
#include "message_parsers.hpp"

namespace cipher
{

namespace conf
{

Interface::Interface(const buffer& sik, const key& addKey)
{
    unsigned int mdLen = 0;

    // Generated K2 for the confidentiality algorithm with the additional key
    // keyed with SIK.
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), addKey.data(),
             addKey.size(), K2.data(), &mdLen) == NULL)
    {
        throw std::runtime_error("Generating K2 for confidentiality algorithm"
                                 "failed");
    }
}

constexpr key AlgoAES128::const2;

constexpr std::array<uint8_t, AlgoAES128::AESCBC128BlockSize - 1>
        AlgoAES128::confPadBytes;

buffer AlgoAES128::decryptPayload(const buffer& packet,
                                  const size_t sessHeaderLen,
                                  const size_t payloadLen) const
{

}

buffer AlgoAES128::encryptPayload(buffer& payload)
{

}

buffer AlgoAES128::decryptData(const uint8_t* iv,
                               const uint8_t* input,
                               const int inputLen) const
{

}

buffer AlgoAES128::encryptData(const uint8_t* input, const int inputLen) const
{

}

}// namespace integrity

}// namespace cipher


