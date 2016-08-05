#pragma once

#include "cipher.hpp"
#include "message.hpp"

namespace cipher
{
namespace integrity
{
class AlgoInterface : public CipherAlgorithm
{
    public:
        enum IntegtrityAlgorithms
        {
            INTEGRITY_NONE = 0,
            INTEGRITY_HMAC_SHA1_96,
            INTEGRITY_INVALID = 0xFF,
        };

        AlgoInterface() = default;
        virtual ~AlgoInterface() = default;
        AlgoInterface(const AlgoInterface&) = delete;
        AlgoInterface& operator=(const AlgoInterface&) = delete;
        AlgoInterface(AlgoInterface&&) = delete;
        AlgoInterface& operator=(AlgoInterface&&) = delete;

        virtual void generateIntegrityData(Keys* i_sessionSlot,
                                           IpmiMessage* i_message) = 0;

        virtual bool verifyIntegrityData(Keys* i_sessionSlot,
                                         IpmiMessage* i_message) = 0;
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

        virtual void generateIntegrityData(Keys* i_sessionSlot,
                                           IpmiMessage* i_message);

        virtual bool verifyIntegrityData(Keys* i_sessionSlot,
                                         IpmiMessage* i_message);
};

class AlgoHmacSha1_96 : public AlgoInterface
{
    public:
        AlgoHmacSha1_96() = default;
        ~AlgoHmacSha1_96() = default;
        AlgoHmacSha1_96(const AlgoHmacSha1_96&) = delete;
        AlgoHmacSha1_96& operator=(const AlgoHmacSha1_96&) = delete;
        AlgoHmacSha1_96(AlgoHmacSha1_96&&) = delete;
        AlgoHmacSha1_96& operator=(AlgoHmacSha1_96&&) = delete;

        virtual void generateIntegrityData(Keys* i_sessionSlot,
                                           IpmiMessage* i_message);

        virtual bool verifyIntegrityData(Keys* i_sessionSlot,
                                         IpmiMessage* i_message);
};

}// namespace integrity

}// namespace cipher
