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
    auto plainPayload = decryptData(packet.data() + sessHeaderLen,
            packet.data() + sessHeaderLen + AESCBC128ConfHeader,
            payloadLen - AESCBC128ConfHeader);

    auto confPadLength = plainPayload.back();

    auto plainPayloadLen = plainPayload.size() - confPadLength - 1;

    // Additional check if the confidentiality pad bytes are as expected
    if(!std::equal(plainPayload.begin() + plainPayloadLen,
                   plainPayload.begin() + plainPayloadLen + confPadLength,
                   confPadBytes.begin()))
    {
        throw std::runtime_error("Confidentiality pad bytes check failed");
    }

    plainPayload.resize(plainPayloadLen);

    return plainPayload;
}

buffer AlgoAES128::encryptPayload(buffer& payload)
{

}

buffer AlgoAES128::decryptData(const uint8_t* iv,
                               const uint8_t* input,
                               const int inputLen) const
{
    EVP_CIPHER_CTX ctx;

    // Initializes Cipher context
    EVP_CIPHER_CTX_init(&ctx);

    /*
     * EVP_DecryptInit_ex sets up cipher context ctx for encryption with type
     * AES-CBC-128. ctx must be initialized before calling this function. K2 is
     * the symmetric key used and iv is the initialization vector used.
     */
    EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, K2.data(), iv);

    /*
     * EVP_CIPHER_CTX_set_padding() enables or disables padding. If the pad
     * parameter is zero then no padding is performed. This function always
     * returns 1.
     */
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    buffer output(inputLen + AESCBC128BlockSize);

    int outputLen = 0;

    /*
     * If padding is disabled then EVP_DecryptFinal_ex() will not encrypt any
     * more data and it will return an error if any data remains in a partial
     * block: that is if the total data length is not a multiple of the block
     * size. Since AES-CBC-128 encrypted payload format adds padding bytes and
     * ensures that payload is a multiple of block size, we are not making the
     * call to  EVP_DecryptFinal_ex().
     */
    if (!EVP_DecryptUpdate(&ctx, output.data(), &outputLen, input, inputLen))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    output.resize(outputLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    return output;
}

buffer AlgoAES128::encryptData(const uint8_t* input, const int inputLen) const
{

}

}// namespace conf

}// namespace cipher


