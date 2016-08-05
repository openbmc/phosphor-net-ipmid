#pragma once

#include "cipher.hpp"

namespace cipher
{
namespace auth
{
class AlgoInterface : public CipherAlgorithm
{
    public:
        enum AuthenticationAlgorithms
        {
            RAKP_NONE = 0,
            RAKP_HMAC_SHA1,
            RAKP_INVALID = 0xFF,
        };

        AlgoInterface() = default;
        virtual ~AlgoInterface() = default;
        AlgoInterface(const AlgoInterface&) = delete;
        AlgoInterface& operator=(const AlgoInterface&) = delete;
        AlgoInterface(AlgoInterface&&) = delete;
        AlgoInterface& operator=(AlgoInterface&&) = delete;

        virtual void generateKeyExchangeAuthCode_RAKP2(Keys* i_sessionSlot,
                const uint8_t* i_input, uint32_t i_inputLength,
                uint8_t* o_key, uint32_t& o_keyLength) = 0;

        virtual bool verifyKeyExchangeAuthCode_RAKP3(Keys* i_sessionSlot,
                uint8_t* i_key,
                uint32_t i_keyLength) = 0;

        virtual void generateSessionIntegrityKey_RAKP3(Keys* i_sessionSlot) = 0;

        virtual void generateIntegrityCheckValue_RAKP4(Keys* i_sessionSlot,
                uint8_t*& o_key,
                uint32_t& o_keyLength) = 0;
};

class AlgoNone : public AlgoInterface
{
    public:
        AlgoNone() = default;
        ~AlgoNone() = default;
        AlgoNone(const AlgoNone&) = delete;
        AlgoNone& operator=(const AlgoNone&) = delete;
        AlgoNone(AlgoNone&&) = delete;
        AlgoNone& operator=(AlgoNone&&) = delete;

        virtual void generateKeyExchangeAuthCode_RAKP2(Keys* i_sessionSlot,
                const uint8_t* i_input, uint32_t i_inputLength,
                uint8_t* o_key, uint32_t& o_keyLength);

        virtual bool verifyKeyExchangeAuthCode_RAKP3(Keys* i_sessionSlot,
                uint8_t* i_key,
                uint32_t i_keyLength);

        virtual void generateSessionIntegrityKey_RAKP3(Keys* i_sessionSlot);

        virtual void generateIntegrityCheckValue_RAKP4(Keys* i_sessionSlot,
                uint8_t*& o_key,
                uint32_t& o_keyLength);
};

}// namespace auth

}// namespace cipher

