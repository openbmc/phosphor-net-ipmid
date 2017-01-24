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

}// namespace integrity

}// namespace cipher


