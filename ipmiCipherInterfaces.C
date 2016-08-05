#include <ipmiCipherInterfaces.H>

IpmiSessionKeys::IpmiSessionKeys()
    : iv_userNameLength(0),iv_userName(),iv_userKeyLength(0),iv_userKey(),
      iv_bmcRandomNumLength(0),iv_bmcRandomNum(),iv_rcRandomNumLength(0),iv_rcRandomNum(),
      iv_sessionIntegrityKeyLength(0),iv_sessionIntegrityKey(),iv_sessionKeyLength_k1(0),
      iv_sessionKey_k1(),iv_sessionKeyLength_k2(0),iv_sessionKey_k2() {}

IpmiSessionKeys::~IpmiSessionKeys() {}

void IpmiSessionKeys::getUserName(void* o_toBuffer, uint8_t&  i_size) {
  uint32_t l_size = (iv_userNameLength > i_size) ? i_size : iv_userNameLength;
  memcpy(o_toBuffer, iv_userName, l_size);
  i_size = l_size;
}

void IpmiSessionKeys::setUserName(const void* i_buffer, uint8_t i_size) {
  uint32_t l_size = (IPMI_USER_NAME_MAX_LENGTH > i_size) ? i_size : IPMI_USER_NAME_MAX_LENGTH;
  memcpy(iv_userName, i_buffer, l_size);
  iv_userNameLength = l_size;
}

void IpmiSessionKeys::getUserKey(void* o_toBuffer, uint32_t& i_size) {
  uint32_t l_size = (iv_userKeyLength > i_size) ? i_size : iv_userKeyLength;
  memcpy(o_toBuffer, iv_userKey, l_size);
  i_size = l_size;
}

void IpmiSessionKeys::setUserKey(const void* i_buffer, uint32_t i_size) {
  uint32_t l_size = (IPMI_USER_KEY_MAX_LENGTH > i_size) ? i_size : IPMI_USER_KEY_MAX_LENGTH;
  memcpy(iv_userKey, i_buffer, l_size);
  iv_userKeyLength = l_size;
}

void IpmiSessionKeys::getBmcRandomNum(void* o_toBuffer, uint32_t& i_size) {
  uint32_t l_size = (iv_bmcRandomNumLength > i_size) ? i_size : iv_bmcRandomNumLength;
  memcpy(o_toBuffer, iv_bmcRandomNum, l_size);
  i_size = l_size;
}

void IpmiSessionKeys::setBmcRandomNum(const void* i_buffer, uint32_t i_size) {
  uint32_t l_size = (IPMI_BMC_RANDOM_NUMBER_LEN > i_size)?i_size:IPMI_BMC_RANDOM_NUMBER_LEN;
  memcpy(iv_bmcRandomNum, i_buffer, l_size);
  iv_bmcRandomNumLength = l_size;
}

void IpmiSessionKeys::getRcRandomNum(void* o_toBuffer, uint32_t& i_size) {
  uint32_t l_size = (iv_rcRandomNumLength > i_size) ? i_size : iv_rcRandomNumLength;
  memcpy(o_toBuffer, iv_rcRandomNum, l_size);
  i_size = l_size;
}

void IpmiSessionKeys::setRcRandomNum(const void* i_buffer, uint32_t i_size) {
  uint32_t l_size = (IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN > i_size) ?
                    i_size : IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN;
  memcpy(iv_rcRandomNum,i_buffer,l_size);
  iv_rcRandomNumLength = l_size;
}

void IpmiSessionKeys::getSIK(void* o_toBuffer, uint32_t& i_size) {
  uint32_t l_size = (iv_sessionIntegrityKeyLength > i_size) ? i_size : iv_sessionIntegrityKeyLength;
  memcpy(o_toBuffer, iv_sessionIntegrityKey, l_size);
  i_size = l_size;
}

void IpmiSessionKeys::setSIK(const void* i_buffer, uint32_t i_size) {
  uint32_t l_size = (IPMI_SESSION_INTEGRITY_KEY_LENGTH > i_size) ?
                    i_size:IPMI_SESSION_INTEGRITY_KEY_LENGTH;
  memcpy(iv_sessionIntegrityKey, i_buffer, l_size);
  iv_sessionIntegrityKeyLength = l_size;
}

void IpmiSessionKeys::getK1(void* o_toBuffer, uint32_t& i_size) {
  uint32_t l_size = (iv_sessionKeyLength_k1 > i_size) ? i_size : iv_sessionKeyLength_k1;
  memcpy(o_toBuffer, iv_sessionKey_k1, l_size);
  i_size = l_size;
}

void IpmiSessionKeys::setK1(const void* i_buffer, uint32_t i_size) {
  uint32_t l_size = (IPMI_SESSION_K1_KEY_LENGTH > i_size) ? i_size : IPMI_SESSION_K1_KEY_LENGTH;
  memcpy(iv_sessionKey_k1, i_buffer, l_size);
  iv_sessionKeyLength_k1 = l_size;
}

void IpmiSessionKeys::getK2(void* o_toBuffer, uint32_t& i_size) {
  uint32_t l_size = (iv_sessionKeyLength_k2 > i_size) ? i_size : iv_sessionKeyLength_k2;
  memcpy(o_toBuffer, iv_sessionKey_k2, l_size);
  i_size = l_size;
}

void IpmiSessionKeys::setK2(const void* i_buffer, uint32_t i_size) {
    uint32_t l_size = (IPMI_SESSION_K2_KEY_LENGTH > i_size) ? i_size : IPMI_SESSION_K2_KEY_LENGTH;
    memcpy(iv_sessionKey_k2, i_buffer, l_size);
    iv_sessionKeyLength_k2 = l_size;
}

IpmiCipherAlgorithm::IpmiCipherAlgorithm() : iv_enabled(), iv_requested(), iv_applied() {}

IpmiCipherAlgorithm::~IpmiCipherAlgorithm() {}

bool IpmiCipherAlgorithm::getState() {
  return iv_enabled;
}

bool IpmiCipherAlgorithm::setState(bool i_enable) {
  iv_enabled = i_enable;
  return iv_enabled;
}

uint8_t IpmiCipherAlgorithm::getRequested() {
  return iv_requested;
}

uint8_t IpmiCipherAlgorithm::setRequested(uint8_t i_algoIndex) {
  iv_requested = i_algoIndex;
  return iv_requested;
}

uint8_t IpmiCipherAlgorithm::getApplied() {
  return iv_applied;
}

uint8_t IpmiCipherAlgorithm::setApplied(uint8_t i_algoIndex) {
  iv_applied = i_algoIndex;
  return iv_applied;
}

IpmiAuthenticationAlgoInterface::IpmiAuthenticationAlgoInterface() {}

IpmiAuthenticationAlgoInterface::~IpmiAuthenticationAlgoInterface() {}

IpmiIntegrityAlgoInterface::IpmiIntegrityAlgoInterface() {}

IpmiIntegrityAlgoInterface::~IpmiIntegrityAlgoInterface() {}

IpmiConfidentialityAlgoInterface::IpmiConfidentialityAlgoInterface() {}

IpmiConfidentialityAlgoInterface::~IpmiConfidentialityAlgoInterface() {}

IpmiUserAuthenticationInterface::IpmiUserAuthenticationInterface
    (IpmiAuthenticationMethod i_authMethod) : iv_authMethod(i_authMethod) {}

IpmiUserAuthenticationInterface::~IpmiUserAuthenticationInterface() {}

IpmiUserAuthenticationInterface::IpmiAuthenticationMethod
    IpmiUserAuthenticationInterface::getAuthMethod() {
  return iv_authMethod;
}

IpmiSessionCipherSuite::IpmiSessionCipherSuite()
    : iv_sessionKeys(),
      iv_pAuthenticationAlgo(nullptr),
      iv_pIntegrityAlgo(nullptr),
      iv_pConfidentialityAlgo(nullptr) {}

IpmiSessionCipherSuite::~IpmiSessionCipherSuite() {
  if (iv_pAuthenticationAlgo) {
    delete iv_pAuthenticationAlgo;
    iv_pAuthenticationAlgo = nullptr;
  }

  if (iv_pIntegrityAlgo) {
    delete iv_pIntegrityAlgo;
    iv_pIntegrityAlgo = nullptr;
  }

  if (iv_pConfidentialityAlgo) {
    delete iv_pConfidentialityAlgo;
    iv_pConfidentialityAlgo = nullptr;
  }

  if (iv_userAuthInterface) {
    delete iv_userAuthInterface;
    iv_userAuthInterface = nullptr;
  }
}

IpmiSessionKeys& IpmiSessionCipherSuite::getSessionKeys() {
  return iv_sessionKeys;
}


IpmiAuthenticationAlgoInterface* IpmiSessionCipherSuite::getAuthCipher() {
  return iv_pAuthenticationAlgo;
}

IpmiIntegrityAlgoInterface* IpmiSessionCipherSuite::getIntegrityCipher() {
  return iv_pIntegrityAlgo;
}

IpmiConfidentialityAlgoInterface* IpmiSessionCipherSuite::getConfidentialityCipher() {
  return iv_pConfidentialityAlgo;
}

IpmiAuthenticationAlgoInterface* IpmiSessionCipherSuite::setAuthCipher(
    IpmiAuthenticationAlgoInterface* i_algo) {
  iv_pAuthenticationAlgo = i_algo;
  return iv_pAuthenticationAlgo;
}

IpmiIntegrityAlgoInterface* IpmiSessionCipherSuite::setIntegrityCipher(
    IpmiIntegrityAlgoInterface* i_algo) {
  iv_pIntegrityAlgo = i_algo;
  return iv_pIntegrityAlgo;
}

IpmiConfidentialityAlgoInterface* IpmiSessionCipherSuite::setConfidentialityCipher(
    IpmiConfidentialityAlgoInterface* i_algo) {
  iv_pConfidentialityAlgo = i_algo;
  return iv_pConfidentialityAlgo;
}

IpmiUserAuthenticationInterface* IpmiSessionCipherSuite::getUserAuthInterface() {
  return iv_userAuthInterface;
}

IpmiUserAuthenticationInterface* IpmiSessionCipherSuite::setUserAuthInterface(
    IpmiUserAuthenticationInterface* i_intf) {
  iv_userAuthInterface = i_intf;
  return iv_userAuthInterface;
}
