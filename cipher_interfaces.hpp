#pragma once

#include <openssl/sha.h>

#include <memory>

#include "message.hpp"

class IpmiSessionKeys
{
    public:
        static constexpr size_t IPMI_USER_NAME_MAX_LENGTH = 16;
        static constexpr size_t IPMI_USER_KEY_MAX_LENGTH = 20;
        static constexpr size_t IPMI_BMC_RANDOM_NUMBER_LEN = 16;
        static constexpr size_t IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN = 16;
        static constexpr size_t IPMI_SESSION_INTEGRITY_KEY_LENGTH = SHA_DIGEST_LENGTH;
        static constexpr size_t IPMI_SESSION_K1_KEY_LENGTH = SHA_DIGEST_LENGTH;
        static constexpr size_t IPMI_SESSION_K2_KEY_LENGTH = SHA_DIGEST_LENGTH;


        IpmiSessionKeys();

        ~IpmiSessionKeys() = default;

        void getUserName(void* o_toBuffer, uint8_t& io_size);

        void setUserName(const void* i_buffer, uint8_t i_size);

        void getUserKey(void* o_toBuffer, uint32_t& io_size);

        void setUserKey(const void* i_buffer, uint32_t i_size);

        void getBmcRandomNum(void* o_toBuffer, uint32_t& io_size);

        void setBmcRandomNum(const void* i_buffer, uint32_t i_size);

        void getRcRandomNum(void* o_toBuffer, uint32_t& io_size);

        void setRcRandomNum(const void* i_buffer, uint32_t i_size);

        void getSIK(void* o_toBuffer, uint32_t& io_size);

        void setSIK(const void* i_buffer, uint32_t i_size);

        void getK1(void* o_toBuffer, uint32_t& io_size);

        void setK1(const void* i_buffer, uint32_t i_size);

        void getK2(void* o_toBuffer, uint32_t& io_size);

        void setK2(const void* i_buffer, uint32_t i_size);

    private:
        // User Name
        uint32_t userNameLength;
        uint8_t userName[IPMI_USER_NAME_MAX_LENGTH];

        // User Key
        uint32_t userKeyLength;
        uint8_t userKey[IPMI_USER_KEY_MAX_LENGTH];

        // Session Random Numbers
        uint32_t bmcRandomNumLength;
        uint8_t bmcRandomNum[IPMI_BMC_RANDOM_NUMBER_LEN];
        uint32_t rcRandomNumLength;
        uint8_t rcRandomNum[IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN];

        // Session Integrity Key (SIK)
        uint32_t sessionIntegrityKeyLength;
        uint8_t sessionIntegrityKey[IPMI_SESSION_INTEGRITY_KEY_LENGTH];

        // K1 <used in Integrity Algorithm>
        uint32_t sessionKeyLength_k1;
        uint8_t sessionKey_k1[IPMI_SESSION_K1_KEY_LENGTH];

        // K2 <used in Confidentiality Algorithm>
        uint32_t sessionKeyLength_k2;
        uint8_t sessionKey_k2[IPMI_SESSION_K2_KEY_LENGTH];
};

class IpmiCipherAlgorithm
{
    public:

        virtual ~IpmiCipherAlgorithm() = default;

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
        IpmiCipherAlgorithm();

        bool enabled;
        uint8_t requested;
        uint8_t applied;
};

//Cipher Algorithm Base Classes
class IpmiAuthenticationAlgoInterface : public IpmiCipherAlgorithm
{
    public:
        enum IpmiAuthenticationAlgorithms
        {
            IPMI_RAKP_NONE = 0,
            IPMI_RAKP_HMAC_SHA1,
            IPMI_RAKP_INVALID = 0xFF,
        };

        IpmiAuthenticationAlgoInterface() = default;
        virtual ~IpmiAuthenticationAlgoInterface() = default;

        virtual void generateKeyExchangeAuthCode_RAKP2(IpmiSessionKeys* i_sessionSlot,
                const uint8_t* i_input, uint32_t i_inputLength,
                uint8_t* o_key, uint32_t& o_keyLength) = 0;

        virtual bool verifyKeyExchangeAuthCode_RAKP3(IpmiSessionKeys* i_sessionSlot,
                uint8_t* i_key,
                uint32_t i_keyLength) = 0;

        virtual void generateSessionIntegrityKey_RAKP3(IpmiSessionKeys* i_sessionSlot) =
            0;

        virtual void generateIntegrityCheckValue_RAKP4(IpmiSessionKeys* i_sessionSlot,
                uint8_t*& o_key,
                uint32_t& o_keyLength) = 0;
};

class IpmiIntegrityAlgoInterface : public IpmiCipherAlgorithm
{
    public:
        enum IpmiIntegtrityAlgorithms
        {
            IPMI_INTEGRITY_NONE = 0,
            IPMI_INTEGRITY_HMAC_SHA1_96,
            IPMI_INTEGRITY_INVALID = 0xFF,
        };

        IpmiIntegrityAlgoInterface() = default;
        virtual ~IpmiIntegrityAlgoInterface() = default;

        virtual void generateIntegrityData(IpmiSessionKeys* i_sessionSlot,
                                           IpmiMessage* i_message) = 0;

        virtual bool verifyIntegrityData(IpmiSessionKeys* i_sessionSlot,
                                         IpmiMessage* i_message) = 0;
};

class IpmiConfidentialityAlgoInterface : public IpmiCipherAlgorithm
{
    public:
        enum IpmiConfidentialityAlgorithms
        {
            IPMI_CONFIDENTIALITY_NONE,
            IPMI_CONFIDENTIALITY_AES_CBC_128,
            IPMI_CONFIDENTIALITY_INVALID = 0xFF,
        };

        IpmiConfidentialityAlgoInterface() = default;
        virtual ~IpmiConfidentialityAlgoInterface() = default;

        virtual void encryptData(IpmiSessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message) = 0;

        virtual void decryptData(IpmiSessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message) = 0;
};

class IpmiUserAuthenticationInterface
{
    public:
        enum IpmiAuthenticationMethod
        {
            IPMI_AUTH_METHOD_STATIC_PASS_KEY = 0,
            IPMI_AUTH_METHOD_PASSWORD_FILE = 1,
            IPMI_AUTH_METHOD_UNSUPPORTED = 0xFF,
        };

        IpmiUserAuthenticationInterface() = delete;
        virtual ~IpmiUserAuthenticationInterface() = default;

        IpmiUserAuthenticationInterface(IpmiAuthenticationMethod i_authMethod);

        virtual IpmiAuthenticationMethod getAuthMethod();

        virtual bool AuthenticateUser(uint8_t* i_userName, uint32_t i_userNameLen,
                                      uint8_t* o_key,
                                      uint32_t& o_keyLen, uint8_t& io_privilegeLevel) = 0;

    protected:
        IpmiAuthenticationMethod authMethod;
};

class IpmiSessionCipherSuite
{
    public:
        IpmiSessionCipherSuite();

        virtual ~IpmiSessionCipherSuite() = default;

        IpmiSessionKeys& getSessionKeys();

        IpmiAuthenticationAlgoInterface* getAuthCipher();

        IpmiIntegrityAlgoInterface* getIntegrityCipher();

        IpmiConfidentialityAlgoInterface* getConfidentialityCipher();

        IpmiUserAuthenticationInterface* getUserAuthInterface();

        IpmiAuthenticationAlgoInterface* setAuthCipher(
            std::unique_ptr<IpmiAuthenticationAlgoInterface> i_algo);

        IpmiIntegrityAlgoInterface* setIntegrityCipher(
            std::unique_ptr<IpmiIntegrityAlgoInterface> i_algo);

        IpmiConfidentialityAlgoInterface* setConfidentialityCipher(
            std::unique_ptr<IpmiConfidentialityAlgoInterface> i_algo);

        IpmiUserAuthenticationInterface* setUserAuthInterface(
            std::unique_ptr<IpmiUserAuthenticationInterface> i_intf);

    private:
        IpmiSessionKeys iv_sessionKeys;
        std::unique_ptr<IpmiAuthenticationAlgoInterface> iv_pAuthenticationAlgo;
        std::unique_ptr<IpmiIntegrityAlgoInterface> iv_pIntegrityAlgo;
        std::unique_ptr<IpmiConfidentialityAlgoInterface> iv_pConfidentialityAlgo;
        std::unique_ptr<IpmiUserAuthenticationInterface> iv_userAuthInterface;
};

