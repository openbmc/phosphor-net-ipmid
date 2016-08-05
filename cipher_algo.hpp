#pragma once

#include "cipher.hpp"

class AuthAlgoNone : public AuthAlgoInterface
{
    public:
        AuthAlgoNone();

        virtual ~AuthAlgoNone();

        virtual void generateKeyExchangeAuthCode_RAKP2(SessionKeys* i_sessionSlot,
                const uint8_t* i_input, uint32_t i_inputLength,
                uint8_t* o_key, uint32_t& o_keyLength);

        virtual bool verifyKeyExchangeAuthCode_RAKP3(SessionKeys* i_sessionSlot,
                uint8_t* i_key,
                uint32_t i_keyLength);

        virtual void generateSessionIntegrityKey_RAKP3(SessionKeys* i_sessionSlot);

        virtual void generateIntegrityCheckValue_RAKP4(SessionKeys* i_sessionSlot,
                uint8_t*& o_key,
                uint32_t& o_keyLength);
};

class IntegrityAlgoNone : public IntegrityAlgoInterface
{
    public:
        IntegrityAlgoNone();

        virtual ~IntegrityAlgoNone();

        virtual void generateIntegrityData(SessionKeys* i_sessionSlot,
                                           IpmiMessage* i_message);

        virtual bool verifyIntegrityData(SessionKeys* i_sessionSlot,
                                         IpmiMessage* i_message);
};

class IntegrityAlgoHmacSha1_96 : public IntegrityAlgoInterface
{
    public:
        IntegrityAlgoHmacSha1_96();

        virtual ~IntegrityAlgoHmacSha1_96();

        virtual void generateIntegrityData(SessionKeys* i_sessionSlot,
                                           IpmiMessage* i_message);

        virtual bool verifyIntegrityData(SessionKeys* i_sessionSlot,
                                         IpmiMessage* i_message);
};

class IpmiConfidentialityAlgoNone : public ConfidentialityAlgoInterface
{
    public:
        IpmiConfidentialityAlgoNone();

        virtual ~IpmiConfidentialityAlgoNone();

        virtual void encryptData(SessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message);

        virtual void decryptData(SessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message);
};

class IpmiConfidentialityAlgoAesCbc128 : public
    ConfidentialityAlgoInterface
{
    public:
        IpmiConfidentialityAlgoAesCbc128();

        virtual ~IpmiConfidentialityAlgoAesCbc128();

        virtual void encryptData(SessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message);

        virtual void decryptData(SessionKeys* i_sessionSlot,
                                 IpmiMessage* i_message);
};

class IpmiUnsupportedPasswordAuthentication : public
    UserAuthInterface
{
    public:
        IpmiUnsupportedPasswordAuthentication();

        virtual ~IpmiUnsupportedPasswordAuthentication();

        virtual bool AuthenticateUser(uint8_t* i_userName, uint32_t i_userNameLen,
                                      uint8_t* o_key,
                                      uint32_t& o_keyLen, uint8_t& io_privilegeLevel);
};

class IpmiStaticPasswordAuthentication : public UserAuthInterface
{
    public:
        IpmiStaticPasswordAuthentication();

        virtual ~IpmiStaticPasswordAuthentication();

        virtual bool AuthenticateUser(uint8_t* i_userName, uint32_t i_userNameLen,
                                      uint8_t* o_key,
                                      uint32_t& o_keyLen, uint8_t& io_privilegeLevel);
};


