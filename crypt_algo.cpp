#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <algorithm>
#include <numeric>
#include "crypt_algo.hpp"
#include "message_parsers.hpp"

namespace cipher
{

namespace crypt
{

Interface::Interface(const buffer& sik, const key& addKey)
{
    unsigned int mdLen = 0;

    // Generated K2 for the confidentiality algorithm with the additional key
    // keyed with SIK.
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), addKey.data(),
             addKey.size(), k2.data(), &mdLen) == NULL)
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
    auto plainPayload = decryptData(
            packet.data() + sessHeaderLen,
            packet.data() + sessHeaderLen + AESCBC128ConfHeader,
            payloadLen - AESCBC128ConfHeader);

    /*
     * The confidentiality pad length is the last byte in the payload, it would
     * tell the number of pad bytes in the payload. We added a condition, so
     * that buffer overrun does't happen.
     */
    auto confPadLength = plainPayload.back();
    auto padLength = std::min(plainPayload.size() -1,
            static_cast<size_t>(confPadLength));

    auto plainPayloadLen = plainPayload.size() - padLength - 1;

    // Additional check if the confidentiality pad bytes are as expected
    if(!std::equal(plainPayload.begin() + plainPayloadLen,
                   plainPayload.begin() + plainPayloadLen + padLength,
                   confPadBytes.begin()))
    {
        throw std::runtime_error("Confidentiality pad bytes check failed");
    }

    plainPayload.resize(plainPayloadLen);

    return plainPayload;
}

buffer AlgoAES128::encryptPayload(buffer& payload) const
{
    auto payloadLen = payload.size();

    /*
     * The following logic calculates the number of padding bytes to be added to
     * the payload data. This would ensure that the length is a multiple of the
     * block size of algorithm being used. For the AES algorithm, the block size
     * is 16 bytes.
     */
    auto paddingLen = AESCBC128BlockSize - ((payloadLen + 1) & 0xF);

    /*
     * The additional field is for the Confidentiality Pad Length field. For the
     * AES algorithm, this number will range from 0 to 15 bytes. This field is
     * mandatory.
     */
    payload.resize(payloadLen + paddingLen + 1);

    /*
     * If no Confidentiality Pad bytes are required, the Confidentiality Pad
     * Length field is set to 00h. If present, the value of the first byte of
     * Confidentiality Pad shall be one (01h) and all subsequent bytes shall
     * have a monotonically increasing value (e.g., 02h, 03h, 04h, etc).
     */
    if (0 != paddingLen)
    {
        std::iota(payload.begin() + payloadLen,
                  payload.begin() + payloadLen + paddingLen,
                  1);
    }

    payload.back() = paddingLen;

    return encryptData(payload.data(), payload.size());
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
    if (!EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, k2.data(), iv))
    {
        throw std::runtime_error("EVP_DecryptInit_ex failed for type "
                                 "AES-CBC-128");
    }

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
    buffer output(inputLen + AESCBC128BlockSize);

    // Generate the initialization vector
    if (!RAND_bytes(output.data(), AESCBC128ConfHeader))
    {
        throw std::runtime_error("RAND_bytes failed");
    }

    EVP_CIPHER_CTX ctx;

    // Initializes Cipher context
    EVP_CIPHER_CTX_init(&ctx);

    /*
     * EVP_EncryptInit_ex sets up cipher context ctx for encryption with type
     * AES-CBC-128. ctx must be initialized before calling this function. K2 is
     * the symmetric key used and iv is the initialization vector used.
     */
    if (!EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, k2.data(),
                            output.data()))
    {
        throw std::runtime_error("EVP_EncryptInit_ex failed for type "
                                 "AES-CBC-128");
    }

    /*
     * EVP_CIPHER_CTX_set_padding() enables or disables padding. If the pad
     * parameter is zero then no padding is performed. This function always
     * returns 1.
     */
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    int outputLen = 0;

    /*
     * If padding is disabled then EVP_EncryptFinal_ex() will not encrypt any
     * more data and it will return an error if any data remains in a partial
     * block: that is if the total data length is not a multiple of the block
     * size. Since we are adding padding bytes and ensures that payload is a
     * multiple of block size, we are not making the call to
     * EVP_DecryptFinal_ex()
     */
    if (!EVP_EncryptUpdate(&ctx,
                           output.data() + AESCBC128ConfHeader,
                           &outputLen,
                           input, inputLen))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed for type "
                                 "AES-CBC-128");
    }

    output.resize(AESCBC128ConfHeader + outputLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    return output;
}

}// namespace crypt

}// namespace cipher


