#include <iostream>
#include <vector>
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

    // Generate the Integrity Data
    auto response = algoPtr->generateIntegrityData(packet);

    // Insert the Integrity Data inside the packet
    packet.insert(packet.end(), response.begin(), response.end());

    // Point to the integrity data in the packet
    auto integrityIter = packet.cbegin();
    std::advance(integrityIter, message::parser::RMCP_SESSION_HEADER_SIZE +
                 packetLen);

    // Verify the Integrity Data
    auto check = algoPtr->verifyIntegrityData(packet, packetLen, integrityIter);

    EXPECT_EQ(1, check);
}

TEST(ConfAlgo, AES_CBC_128)
{
    // Payload (12 bytes)
    std::vector<uint8_t> payload = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // Hardcoded Session Integrity Key
    std::vector<uint8_t> sik = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                 13, 14, 15, 16};

    auto confPtr = std::make_unique<cipher::conf::AlgoAES128>(sik);

    // Generate the Encrypted Payload
    auto cipher = confPtr->encryptPayload(payload);

    // Decrypt the encrypted payload
    auto plain = confPtr->decryptPayload(cipher, 0, cipher.size());

    // Check if the payload and the encrypted one matches
    auto check = std::equal(plain.begin(), plain.end(), payload.begin());

    EXPECT_EQ(1, check);
}
