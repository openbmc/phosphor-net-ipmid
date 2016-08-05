#pragma once

#include <openssl/sha.h>

#include <memory>
#include <vector>

#include "message.hpp"

struct SessionKeys
{
    static constexpr size_t IPMI_USER_NAME_MAX_LENGTH = 16;
    static constexpr size_t IPMI_USER_KEY_MAX_LENGTH = 20;
    static constexpr size_t IPMI_BMC_RANDOM_NUMBER_LEN = 16;
    static constexpr size_t IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN = 16;
    static constexpr size_t IPMI_SESSION_INTEGRITY_KEY_LENGTH = SHA_DIGEST_LENGTH;

    std::vector<uint8_t> userName;
    std::vector<uint8_t> userKey;
    std::vector<uint8_t> bmcRandomNum;
    std::vector<uint8_t> rcRandomNum;
    std::vector<uint8_t> sessionIntegrityKey;
};

class CipherAlgorithm
{
    public:

        virtual ~CipherAlgorithm() = default;

        bool getState()
        {
            return enabled;
        }

        bool setState(bool i_enable)
        {
            enabled = i_enable;
            return enabled;
        }

        uint8_t getRequested()
        {
            return requested;
        }

        uint8_t setRequested(uint8_t i_algoIndex)
        {
            requested = i_algoIndex;
            return requested;
        }

        uint8_t getApplied()
        {
            return applied;
        }

        uint8_t setApplied(uint8_t i_algoIndex)
        {
            applied = i_algoIndex;
            return applied;
        }

    protected:
        CipherAlgorithm(): enabled(false), requested(0), applied(0) {};

        bool enabled;
        uint8_t requested;
        uint8_t applied;
};

//Cipher Algorithm Base Class
class AuthAlgoInterface : public CipherAlgorithm
{
    public:
        enum AuthenticationAlgorithms
        {
            IPMI_RAKP_NONE = 0,
            IPMI_RAKP_HMAC_SHA1,
            IPMI_RAKP_INVALID = 0xFF,
        };

        AuthAlgoInterface() = default;
        virtual ~AuthAlgoInterface() = default;

        virtual void generateKeyExchangeAuthCode_RAKP2(SessionKeys* i_sessionSlot,
                const uint8_t* i_input, uint32_t i_inputLength,
                uint8_t* o_key, uint32_t& o_keyLength) = 0;

        virtual bool verifyKeyExchangeAuthCode_RAKP3(SessionKeys* i_sessionSlot,
                uint8_t* i_key,
                uint32_t i_keyLength) = 0;

        virtual void generateSessionIntegrityKey_RAKP3(SessionKeys* i_sessionSlot) = 0;

        virtual void generateIntegrityCheckValue_RAKP4(SessionKeys* i_sessionSlot,
                uint8_t*& o_key,
                uint32_t& o_keyLength) = 0;
};

class IntegrityAlgoInterface : public CipherAlgorithm
{
    public:
        enum IntegtrityAlgorithms
        {
            IPMI_INTEGRITY_NONE = 0,
            IPMI_INTEGRITY_HMAC_SHA1_96,
            IPMI_INTEGRITY_INVALID = 0xFF,
        };

        IntegrityAlgoInterface() = default;
        virtual ~IntegrityAlgoInterface() = default;

        virtual void generateIntegrityData(SessionKeys* i_sessionSlot,
                                           IpmiMessage* i_message) = 0;

        virtual bool verifyIntegrityData(SessionKeys* i_sessionSlot,
                                         IpmiMessage* i_message) = 0;
};

class ConfidentialityAlgoInterface : public CipherAlgorithm
{
    public:
        enum ConfidentialityAlgorithms
        {
            IPMI_CONFIDENTIALITY_NONE,
            IPMI_CONFIDENTIALITY_AES_CBC_128,
            IPMI_CONFIDENTIALITY_INVALID = 0xFF,
        };

        ConfidentialityAlgoInterface() = default;
        virtual ~ConfidentialityAlgoInterface() = default;

        virtual void encryptData(SessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message) = 0;

        virtual void decryptData(SessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message) = 0;
};

class UserAuthInterface
{
    public:
        enum AuthenticationMethod
        {
            IPMI_AUTH_METHOD_STATIC_PASS_KEY = 0,
            IPMI_AUTH_METHOD_UNSUPPORTED = 0xFF,
        };

        UserAuthInterface() = delete;
        virtual ~UserAuthInterface() = default;

        UserAuthInterface(AuthenticationMethod i_authMethod) : authMethod(
                i_authMethod) {};

        virtual AuthenticationMethod getAuthMethod()
        {
            return authMethod;
        }

        virtual bool AuthenticateUser(uint8_t* i_userName, uint32_t i_userNameLen,
                                      uint8_t* o_key,
                                      uint32_t& o_keyLen, uint8_t& io_privilegeLevel) = 0;

    protected:
        AuthenticationMethod authMethod;
};

using CipherSuite = std::tuple<SessionKeys, std::unique_ptr<AuthAlgoInterface>,
      std::unique_ptr<IntegrityAlgoInterface>,
      std::unique_ptr<ConfidentialityAlgoInterface>,
      std::unique_ptr<UserAuthInterface>>;

