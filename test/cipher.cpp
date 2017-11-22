#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include "crypt_algo.hpp"
#include "integrity_algo.hpp"
#include "message_parsers.hpp"
#include "rmcp.hpp"
#include <gtest/gtest.h>

TEST(IntegrityAlgo, HMAC_SHA1_96_GenerateIntegrityDataCheck)
{
    /*
     * Step-1 Generate Integrity Data for the packet, using the implemented API
     */
    // Packet = RMCP Session Header (4 bytes) + Packet (8 bytes)
    std::vector<uint8_t> packet = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16, 17, 18, 19, 20 };

    auto algoPtr = std::make_unique<cipher::integrity::AlgoSHA1>(sik);

    ASSERT_EQ(true, (algoPtr != NULL));

    // Generate the Integrity Data
    auto response = algoPtr->generateIntegrityData(packet);

    EXPECT_EQ(true, (response.size() ==
                    cipher::integrity::AlgoSHA1::SHA1_96_AUTHCODE_LENGTH));

    /*
     * Step-2 Generate Integrity data using OpenSSL SHA1 algorithm
     */
    std::vector<uint8_t> K1(SHA_DIGEST_LENGTH);
    constexpr rmcp::Const_n const1 = { 0x01, 0x01, 0x01, 0x01, 0x01,
                                       0x01, 0x01, 0x01, 0x01, 0x01,
                                       0x01, 0x01, 0x01, 0x01, 0x01,
                                       0x01, 0x01, 0x01, 0x01, 0x01
                                     };

    // Generated K1 for the integrity algorithm with the additional key keyed
    // with SIK.
    unsigned int mdLen = 0;
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), const1.data(),
             const1.size(), K1.data(), &mdLen) == NULL)
    {
        FAIL() << "Generating Key1 failed";
    }

    mdLen = 0;
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    size_t length = packet.size() - message::parser::RMCP_SESSION_HEADER_SIZE;

    if (HMAC(EVP_sha1(), K1.data(), K1.size(),
             packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
             length,
             output.data(), &mdLen) == NULL)
    {
        FAIL() << "Generating integrity data failed";
    }

    output.resize(cipher::integrity::AlgoSHA1::SHA1_96_AUTHCODE_LENGTH);

    /*
     * Step-3 Check if the integrity data we generated using the implemented API
     * matches with one generated by OpenSSL SHA1 algorithm.
     */
    auto check = std::equal(output.begin(), output.end(), response.begin());
    EXPECT_EQ(true, check);
}

TEST(IntegrityAlgo, HMAC_SHA1_96_VerifyIntegrityDataPass)
{
    /*
     * Step-1 Generate Integrity data using OpenSSL SHA1 algorithm
     */

    // Packet = RMCP Session Header (4 bytes) + Packet (8 bytes)
    std::vector<uint8_t> packet = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16, 17, 18, 19, 20 };

    std::vector<uint8_t> K1(SHA_DIGEST_LENGTH);
    constexpr rmcp::Const_n const1 = { 0x01, 0x01, 0x01, 0x01, 0x01,
                                       0x01, 0x01, 0x01, 0x01, 0x01,
                                       0x01, 0x01, 0x01, 0x01, 0x01,
                                       0x01, 0x01, 0x01, 0x01, 0x01
                                     };

    // Generated K1 for the integrity algorithm with the additional key keyed
    // with SIK.
    unsigned int mdLen = 0;
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), const1.data(),
             const1.size(), K1.data(), &mdLen) == NULL)
    {
        FAIL() << "Generating Key1 failed";
    }

    mdLen = 0;
    std::vector<uint8_t> output(SHA_DIGEST_LENGTH);
    size_t length = packet.size() - message::parser::RMCP_SESSION_HEADER_SIZE;

    if (HMAC(EVP_sha1(), K1.data(), K1.size(),
             packet.data() + message::parser::RMCP_SESSION_HEADER_SIZE,
             length,
             output.data(), &mdLen) == NULL)
    {
        FAIL() << "Generating integrity data failed";
    }

    output.resize(cipher::integrity::AlgoSHA1::SHA1_96_AUTHCODE_LENGTH);

    /*
     * Step-2 Insert the integrity data into the packet
     */
    auto packetSize = packet.size();
    packet.insert(packet.end(), output.begin(), output.end());

     // Point to the integrity data in the packet
     auto integrityIter = packet.cbegin();
     std::advance(integrityIter, packetSize);

     /*
      * Step-3 Invoke the verifyIntegrityData API and validate the response
      */

     auto algoPtr = std::make_unique<cipher::integrity::AlgoSHA1>(sik);
     ASSERT_EQ(true, (algoPtr != NULL));

     auto check = algoPtr->verifyIntegrityData(
             packet,
             packetSize - message::parser::RMCP_SESSION_HEADER_SIZE,
             integrityIter);

     EXPECT_EQ(true, check);
}

TEST(IntegrityAlgo, HMAC_SHA1_96_VerifyIntegrityDataFail)
{
    /*
     * Step-1 Add hardcoded Integrity data to the packet
     */

    // Packet = RMCP Session Header (4 bytes) + Packet (8 bytes)
    std::vector<uint8_t> packet = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    std::vector<uint8_t> integrity = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    packet.insert(packet.end(), integrity.begin(), integrity.end());

    // Point to the integrity data in the packet
    auto integrityIter = packet.cbegin();
    std::advance(integrityIter, packet.size());

    /*
     * Step-2 Invoke the verifyIntegrityData API and validate the response
     */

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16, 17, 18, 19, 20 };

    auto algoPtr = std::make_unique<cipher::integrity::AlgoSHA1>(sik);

    ASSERT_EQ(true, (algoPtr != NULL));


    // Verify the Integrity Data
    auto check = algoPtr->verifyIntegrityData(
            packet,
            packet.size() - message::parser::RMCP_SESSION_HEADER_SIZE,
            integrityIter);

    EXPECT_EQ(false, check);
}

TEST(CryptAlgo, AES_CBC_128_EncryptPayloadValidate)
{
    /*
     * Step-1 Generate the encrypted data using the implemented API for
     * AES-CBC-128
     */
    std::vector<uint8_t> payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16, 17, 18, 19, 20 };

    /*
     * Step-2 Decrypt the encrypted payload using OpenSSL EVP_aes_128_cbc()
     * implementation
     */

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    std::vector<uint8_t> k2(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;
    constexpr rmcp::Const_n const1 = { 0x02, 0x02, 0x02, 0x02, 0x02,
                                       0x02, 0x02, 0x02, 0x02, 0x02,
                                       0x02, 0x02, 0x02, 0x02, 0x02,
                                       0x02, 0x02, 0x02, 0x02, 0x02
                                     };

    // Generated K2 for the confidentiality algorithm with the additional key
    // keyed with SIK.
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), const1.data(),
             const1.size(), k2.data(), &mdLen) == NULL)
    {
        FAIL() << "Generating K2 for confidentiality algorithm failed";
    }

    auto cryptPtr = std::make_unique<cipher::crypt::AlgoAES128>(k2);

    ASSERT_EQ(true, (cryptPtr != NULL));

    auto cipher = cryptPtr->encryptPayload(payload);

    if (!EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, k2.data(),
                            cipher.data()))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        FAIL() << "EVP_DecryptInit_ex failed for type AES-CBC-128";
    }

    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    std::vector<uint8_t> output(
            cipher.size() + cipher::crypt::AlgoAES128::AESCBC128BlockSize);
    int outputLen = 0;

    if (!EVP_DecryptUpdate(&ctx, output.data(), &outputLen,
                           cipher.data() +
                           cipher::crypt::AlgoAES128::AESCBC128ConfHeader,
                           cipher.size() -
                           cipher::crypt::AlgoAES128::AESCBC128ConfHeader))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        FAIL() << "EVP_DecryptUpdate failed";
    }

    output.resize(outputLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    /*
     * Step -3 Check if the plain payload matches with the decrypted one
     */
    auto check = std::equal(payload.begin(), payload.end(), output.begin());
    EXPECT_EQ(true, check);
}

TEST(CryptAlgo, AES_CBC_128_DecryptPayloadValidate)
{
    /*
     * Step-1 Encrypt the payload using OpenSSL EVP_aes_128_cbc()
     * implementation
     */

    std::vector<uint8_t> payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                     13, 14, 15, 16};
    payload.resize(payload.size() + 1);
    payload.back() = 0;

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16, 17, 18, 19, 20 };
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    std::vector<uint8_t> k2(SHA_DIGEST_LENGTH);
    unsigned int mdLen = 0;
    constexpr rmcp::Const_n const1 = { 0x02, 0x02, 0x02, 0x02, 0x02,
                                       0x02, 0x02, 0x02, 0x02, 0x02,
                                       0x02, 0x02, 0x02, 0x02, 0x02,
                                       0x02, 0x02, 0x02, 0x02, 0x02
                                     };
    std::vector<uint8_t> output(
            payload.size() + cipher::crypt::AlgoAES128::AESCBC128BlockSize);

    if (!RAND_bytes(output.data(),
                    cipher::crypt::AlgoAES128::AESCBC128ConfHeader))
    {
        FAIL() << "RAND_bytes failed";
    }

    // Generated K2 for the confidentiality algorithm with the additional key
    // keyed with SIK.
    if (HMAC(EVP_sha1(), sik.data(), sik.size(), const1.data(),
             const1.size(), k2.data(), &mdLen) == NULL)
    {
        FAIL() << "Generating K2 for confidentiality algorithm failed";
    }

    if (!EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, k2.data(),
                            output.data()))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        FAIL() << "EVP_EncryptInit_ex failed for type AES-CBC-128";
    }

    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    int outputLen = 0;

    if (!EVP_EncryptUpdate(&ctx,
                           output.data() +
                           cipher::crypt::AlgoAES128::AESCBC128ConfHeader,
                           &outputLen,
                           payload.data(),
                           payload.size()))
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        FAIL() << "EVP_EncryptUpdate failed";
    }

    output.resize(cipher::crypt::AlgoAES128::AESCBC128ConfHeader + outputLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    /*
     * Step-2 Decrypt the encrypted payload using the implemented API for
     * AES-CBC-128
     */

    auto cryptPtr = std::make_unique<cipher::crypt::AlgoAES128>(k2);

    ASSERT_EQ(true, (cryptPtr != NULL));

    auto plain = cryptPtr->decryptPayload(output, 0, output.size());

    /*
     * Step -3 Check if the plain payload matches with the decrypted one
     */
    auto check = std::equal(payload.begin(), payload.end(), plain.begin());
    EXPECT_EQ(true, check);
}
