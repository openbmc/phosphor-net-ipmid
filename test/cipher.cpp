#include <iostream>
#include <vector>
#include "crypt_algo.hpp"
#include "integrity_algo.hpp"
#include "message_parsers.hpp"
#include <gtest/gtest.h>

TEST(IntegrityAlgo, HMAC_SHA1_96)
{
    const size_t packetLen = 8;

    // Packet = RMCP Session Header (4 bytes) + Packet (8 bytes)
    std::vector<uint8_t> packet = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16};

    auto algoPtr = std::make_unique<cipher::integrity::AlgoSHA1>(sik);

    ASSERT_EQ(true, (algoPtr != NULL));

    // Generate the Integrity Data
    auto response = algoPtr->generateIntegrityData(packet);

    EXPECT_EQ(true, (response.size() ==
                    cipher::integrity::AlgoSHA1::SHA1_96_AUTHCODE_LENGTH));

    // Insert the Integrity Data inside the packet
    packet.insert(packet.end(), response.begin(), response.end());

    // Point to the integrity data in the packet
    auto integrityIter = packet.cbegin();
    std::advance(integrityIter, message::parser::RMCP_SESSION_HEADER_SIZE +
                 packetLen);

    // Verify the Integrity Data
    auto check = algoPtr->verifyIntegrityData(packet, packetLen, integrityIter);

    EXPECT_EQ(true, check);
}

TEST(CryptAlgo, AES_CBC_128)
{
    // Payload (12 bytes)
    std::vector<uint8_t> payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    auto payloadLen = payload.size();

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16};

    auto cryptPtr = std::make_unique<cipher::crypt::AlgoAES128>(sik);

    ASSERT_EQ(true, (cryptPtr != NULL));

    // Generate the Encrypted Payload
    auto cipher = cryptPtr->encryptPayload(payload);

    auto blockSize = cipher::crypt::AlgoAES128::AESCBC128BlockSize;
    auto headersize = cipher::crypt::AlgoAES128::AESCBC128ConfHeader;

    auto cipherExpectedLen = ((payloadLen/blockSize) + 1) * blockSize;
    cipherExpectedLen += headersize;

    // Validate the size of the Cipher
    EXPECT_EQ(true, (cipher.size() == cipherExpectedLen));

    // Decrypt the encrypted payload
    auto plain = cryptPtr->decryptPayload(cipher, 0, cipher.size());

    EXPECT_EQ(true, (payloadLen == plain.size()));

    // Check if the payload and the encrypted one matches
    auto check = std::equal(plain.begin(), plain.end(), payload.begin());

    EXPECT_EQ(true, check);
}
