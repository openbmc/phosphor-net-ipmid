#include "integrity_algo.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <iostream>
#include <string>

#include "message_parsers.hpp"
#include "session.hpp"

namespace cipher
{
namespace integrity
{
void AlgoNone::generateIntegrityData(cipher::Keys*
                                     i_sessionSlot,
                                     IpmiMessage* i_message)
{
}

bool AlgoNone::verifyIntegrityData(cipher::Keys* i_sessionSlot,
                                   IpmiMessage* i_message)
{
    return true;
}

void Ipmi_GenerateIntegrityCode(uint8_t* i_buffer, uint16_t i_len,
                                uint8_t* o_buffer,
                                uint32_t& o_len, cipher::Keys* i_sessionSlot)
{
    if (!i_sessionSlot || i_buffer == nullptr)
    {
        return;
    }

    uint8_t k1_buffer[SHA_DIGEST_LENGTH];
    uint32_t k1_length = 0;
    uint32_t gen_len = 0;

    uint8_t l_sik_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_sik_hmacBuflen = sizeof(l_sik_hmacBuffer);

    std::copy(i_sessionSlot->sessionIntegrityKey.begin(),
              i_sessionSlot->sessionIntegrityKey.end(), l_sik_hmacBuffer);
    l_sik_hmacBuflen =  i_sessionSlot->sessionIntegrityKey.size();

    uint8_t CONST_1[] =  {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                          0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
                         };

    HMAC(EVP_sha1(), l_sik_hmacBuffer, l_sik_hmacBuflen, CONST_1, 20, k1_buffer,
         &k1_length);

    HMAC(EVP_sha1(), k1_buffer, k1_length, i_buffer, i_len, o_buffer, &gen_len);

    o_len = gen_len;
}

void AlgoHmacSha1_96::generateIntegrityData(
    cipher::Keys* i_sessionSlot,
    IpmiMessage* i_message)
{
    auto  l_hdr = reinterpret_cast<Ipmi20Parser::SessionHeader_t*>
                  (i_message->getPacket());

    l_hdr->payloadType = (l_hdr->payloadType | 0x40);

    auto l_pOutgoingPacket = i_message->getPacket();
    auto l_lanMsgLength = i_message->getPacketLength();

    uint8_t generated_authcode[SHA_DIGEST_LENGTH] = {};
    uint32_t gen_auth_len = 0;

    Ipmi_GenerateIntegrityCode(l_pOutgoingPacket + 4,  //Skip RMCP Hdr
                               l_lanMsgLength - 4, generated_authcode, gen_auth_len, i_sessionSlot);

    uint8_t* l_intgData = new uint8_t[gen_auth_len];
    memcpy(l_intgData, generated_authcode, gen_auth_len);
    i_message->setIntegrityData(l_intgData, true);
    i_message->setIntegrityDataLength(12);
    return;
}

bool AlgoHmacSha1_96::verifyIntegrityData(cipher::Keys*
        i_sessionSlot,
        IpmiMessage* i_message)
{
    if (! i_message->getIsPacketAuthenticated())
    {
        return true;
    }

    const uint32_t IPMI_SESSION_HEADER_AUTH_TYPE_OFFSET = 4;
    const uint32_t IPMI_SESSION_TRAILER_SIZE = 2;
    const uint32_t IPMI_SESSION_HEADER_SIZE = 12;

    bool l_valid = false;

    uint8_t generated_authcode[SHA_DIGEST_LENGTH] = {};
    uint32_t gen_auth_len = 0;

    uint8_t* l_pReceivedMsg = i_message->getPacket();

    uint32_t l_RcvMsgLength = i_message->getPayloadLength();
    l_RcvMsgLength += IPMI_SESSION_HEADER_SIZE;
    l_RcvMsgLength += (4 - ((i_message->getPayloadLength() + 2) % 4)); // Pad bytes
    l_RcvMsgLength += IPMI_SESSION_TRAILER_SIZE;

    Ipmi_GenerateIntegrityCode(l_pReceivedMsg +
                               IPMI_SESSION_HEADER_AUTH_TYPE_OFFSET,
                               l_RcvMsgLength, generated_authcode, gen_auth_len, i_sessionSlot);

    uint8_t* bmc_authcode = i_message->getIntegrityData();

    int value = memcmp(bmc_authcode, generated_authcode, 12);
    if (value == 0)
    {
        l_valid = true;
    }
    else
    {
        std::cerr << "E> IPMI Packet Integrity Verification failed\n";
        l_valid = false;
    }

    return l_valid;
}

}// namespace integrity

}// namespace cipher
