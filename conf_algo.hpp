#pragma once

#include "cipher.hpp"
#include "message.hpp"

namespace cipher
{
namespace conf
{
class AlgoInterface : public CipherAlgorithm
{
    public:
        enum ConfidentialityAlgorithms
        {
            CONFIDENTIALITY_NONE,
            CONFIDENTIALITY_AES_CBC_128,
            CONFIDENTIALITY_INVALID = 0xFF,
        };

        AlgoInterface() = default;
        virtual ~AlgoInterface() = default;
        AlgoInterface(const AlgoInterface&) = delete;
        AlgoInterface& operator=(const AlgoInterface&) = delete;
        AlgoInterface(AlgoInterface&&) = delete;
        AlgoInterface& operator=(AlgoInterface&&) = delete;

        virtual void encryptData(Keys* i_sessionSlot, IpmiMessage* i_message) = 0;

        virtual void decryptData(Keys* i_sessionSlot, IpmiMessage* i_message) = 0;
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

        virtual void encryptData(Keys* i_sessionSlot, IpmiMessage* i_message);

        virtual void decryptData(Keys* i_sessionSlot, IpmiMessage* i_message);
};

class AlgoAesCbc128 : public AlgoInterface
{
    public:
        AlgoAesCbc128() = default;
        ~AlgoAesCbc128() = default;
        AlgoAesCbc128(const AlgoAesCbc128&) = delete;
        AlgoAesCbc128& operator=(const AlgoAesCbc128&) = delete;
        AlgoAesCbc128(AlgoAesCbc128&&) = delete;
        AlgoAesCbc128& operator=(AlgoAesCbc128&&) = delete;

        virtual void encryptData(Keys* i_sessionSlot, IpmiMessage* i_message);

        virtual void decryptData(Keys* i_sessionSlot, IpmiMessage* i_message);
};

} // namespace conf

} // namespace cipher
