#ifndef IPMICIPHERS_H_
#define IPMICIPHERS_H_

#include <ipmiCipherInterfaces.H>

class IpmiAuthenticationAlgoNone : public IpmiAuthenticationAlgoInterface {
 public:
  IpmiAuthenticationAlgoNone();

  virtual ~IpmiAuthenticationAlgoNone();

  virtual void generateKeyExchangeAuthCode_RAKP2(IpmiSessionKeys* i_sessionSlot,
                                                 const uint8_t* i_input, uint32_t i_inputLength,
                                                 uint8_t* o_key, uint32_t& o_keyLength);

  virtual bool verifyKeyExchangeAuthCode_RAKP3(IpmiSessionKeys* i_sessionSlot, uint8_t* i_key,
                                               uint32_t i_keyLength);

  virtual void generateSessionIntegrityKey_RAKP3(IpmiSessionKeys* i_sessionSlot);

  virtual void generateIntegrityCheckValue_RAKP4(IpmiSessionKeys* i_sessionSlot, uint8_t*& o_key,
                                                 uint32_t& o_keyLength);
};

class IpmiIntegrityAlgoNone : public IpmiIntegrityAlgoInterface {
 public:
  IpmiIntegrityAlgoNone();

  virtual ~IpmiIntegrityAlgoNone();

  virtual void generateIntegrityData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);

  virtual bool verifyIntegrityData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);
};

class IpmiIntegrityAlgoHmacSha1_96 : public IpmiIntegrityAlgoInterface {
 public:
  IpmiIntegrityAlgoHmacSha1_96();

  virtual ~IpmiIntegrityAlgoHmacSha1_96();

  virtual void generateIntegrityData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);

  virtual bool verifyIntegrityData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);
};

class IpmiConfidentialityAlgoNone : public IpmiConfidentialityAlgoInterface {
 public:
  IpmiConfidentialityAlgoNone();

  virtual ~IpmiConfidentialityAlgoNone();

  virtual void encryptData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);

  virtual void decryptData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);
};

class IpmiConfidentialityAlgoAesCbc128 : public IpmiConfidentialityAlgoInterface {
 public:
  IpmiConfidentialityAlgoAesCbc128();

  virtual ~IpmiConfidentialityAlgoAesCbc128();

  virtual void encryptData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);

  virtual void decryptData(IpmiSessionKeys* i_sessionSlot, IpmiMessage* i_message);
};

class IpmiUnsupportedPasswordAuthentication : public IpmiUserAuthenticationInterface {
 public:
  IpmiUnsupportedPasswordAuthentication();

  virtual ~IpmiUnsupportedPasswordAuthentication();

  virtual bool AuthenticateUser(uint8_t* i_userName, uint32_t i_userNameLen, uint8_t* o_key,
                                uint32_t& o_keyLen, uint8_t& io_privilegeLevel);
};

class IpmiStaticPasswordAuthentication : public IpmiUserAuthenticationInterface {
 public:
  IpmiStaticPasswordAuthentication();

  virtual ~IpmiStaticPasswordAuthentication();

  virtual bool AuthenticateUser(uint8_t* i_userName, uint32_t i_userNameLen, uint8_t* o_key,
                                uint32_t& o_keyLen, uint8_t& io_privilegeLevel);
};

class IpmiPasswordFileAuthentication : public IpmiUserAuthenticationInterface {
 public:
  IpmiPasswordFileAuthentication();

  virtual ~IpmiPasswordFileAuthentication();

  virtual bool AuthenticateUser(uint8_t* i_userName, uint32_t i_userNameLen, uint8_t* o_key,
                                uint32_t& o_keyLen, uint8_t& io_privilegeLevel);
};

#endif /* IPMICIPHERS_H_ */
