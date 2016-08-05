#pragma once

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "message.hpp"

class IpmiSessionKeys
{
    public:
        enum IpmiSessionKeysDefines
        {
            IPMI_USER_NAME_MAX_LENGTH = 16,
            IPMI_USER_KEY_MAX_LENGTH = 20,
            IPMI_BMC_RANDOM_NUMBER_LEN = 16,
            IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN = 16,
            IPMI_SESSION_INTEGRITY_KEY_LENGTH = SHA_DIGEST_LENGTH,
            IPMI_SESSION_K1_KEY_LENGTH = SHA_DIGEST_LENGTH,
            IPMI_SESSION_K2_KEY_LENGTH = SHA_DIGEST_LENGTH,
        };

        IpmiSessionKeys();

        ~IpmiSessionKeys();

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
        enum IpmiCipherAlgoType
        {
            IPMI_CIPHER_ALGO_TYPE_AUTHENTICATION,
            IPMI_CIPHER_ALGO_TYPE_INTEGRITY,
            IPMI_CIPHER_ALGO_TYPE_CONFIDENTIALITY,
        };

        virtual ~IpmiCipherAlgorithm();

        bool getState();

        bool setState(bool i_enable);

        uint8_t getRequested();

        uint8_t setRequested(uint8_t i_algoIndex);

        uint8_t getApplied();

        uint8_t setApplied(uint8_t i_algoIndex);

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

        IpmiAuthenticationAlgoInterface();

        virtual ~IpmiAuthenticationAlgoInterface();

        virtual void generateKeyExchangeAuthCode_RAKP2(IpmiSessionKeys* i_sessionSlot,
                const uint8_t* i_input, uint32_t i_inputLength,
                uint8_t* o_key, uint32_t& o_keyLength) = 0;

        virtual bool verifyKeyExchangeAuthCode_RAKP3(IpmiSessionKeys* i_sessionSlot,
                uint8_t* i_key,
                uint32_t i_keyLength) = 0;

        virtual void generateSessionIntegrityKey_RAKP3(IpmiSessionKeys* i_sessionSlot) = 0;

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

        IpmiIntegrityAlgoInterface();

        virtual ~IpmiIntegrityAlgoInterface();

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

        IpmiConfidentialityAlgoInterface();

        virtual ~IpmiConfidentialityAlgoInterface();

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

        IpmiUserAuthenticationInterface(IpmiAuthenticationMethod i_authMethod);

        virtual ~IpmiUserAuthenticationInterface();

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

        virtual ~IpmiSessionCipherSuite();

        IpmiSessionKeys& getSessionKeys();

        IpmiAuthenticationAlgoInterface* getAuthCipher();

        IpmiIntegrityAlgoInterface* getIntegrityCipher();

        IpmiConfidentialityAlgoInterface* getConfidentialityCipher();

        IpmiAuthenticationAlgoInterface* setAuthCipher(IpmiAuthenticationAlgoInterface* i_algo);

        IpmiIntegrityAlgoInterface* setIntegrityCipher(IpmiIntegrityAlgoInterface* i_algo);

        IpmiConfidentialityAlgoInterface* setConfidentialityCipher(
            IpmiConfidentialityAlgoInterface* i_algo);

        IpmiUserAuthenticationInterface* getUserAuthInterface();

        IpmiUserAuthenticationInterface* setUserAuthInterface(
            IpmiUserAuthenticationInterface* i_intf);

    private:
        IpmiSessionKeys iv_sessionKeys;
        IpmiAuthenticationAlgoInterface* iv_pAuthenticationAlgo;
        IpmiIntegrityAlgoInterface* iv_pIntegrityAlgo;
        IpmiConfidentialityAlgoInterface* iv_pConfidentialityAlgo;
        IpmiUserAuthenticationInterface* iv_userAuthInterface;
};

