#include "cipher_interfaces.hpp"

IpmiSessionKeys::IpmiSessionKeys()
    : userNameLength(0), userName(), userKeyLength(0), userKey(),
      bmcRandomNumLength(0), bmcRandomNum(), rcRandomNumLength(0),
      rcRandomNum(),
      sessionIntegrityKeyLength(0), sessionIntegrityKey(),
      sessionKeyLength_k1(0),
      sessionKey_k1(), sessionKeyLength_k2(0), sessionKey_k2() {}

IpmiSessionKeys::~IpmiSessionKeys() {}

void IpmiSessionKeys::getUserName(void* o_toBuffer, uint8_t& i_size)
{
    auto l_size = (userNameLength > i_size) ? i_size : userNameLength;
    memcpy(o_toBuffer, userName, l_size);
    i_size = l_size;
}

void IpmiSessionKeys::setUserName(const void* i_buffer, uint8_t i_size)
{
    auto l_size = (IPMI_USER_NAME_MAX_LENGTH > i_size) ? i_size :
                      IPMI_USER_NAME_MAX_LENGTH;
    memcpy(userName, i_buffer, l_size);
    userNameLength = l_size;
}

void IpmiSessionKeys::getUserKey(void* o_toBuffer, uint32_t& i_size)
{
    auto l_size = (userKeyLength > i_size) ? i_size : userKeyLength;
    memcpy(o_toBuffer, userKey, l_size);
    i_size = l_size;
}

void IpmiSessionKeys::setUserKey(const void* i_buffer, uint32_t i_size)
{
    auto l_size = (IPMI_USER_KEY_MAX_LENGTH > i_size) ? i_size :
                      IPMI_USER_KEY_MAX_LENGTH;
    memcpy(userKey, i_buffer, l_size);
    userKeyLength = l_size;
}

void IpmiSessionKeys::getBmcRandomNum(void* o_toBuffer, uint32_t& i_size)
{
    auto l_size = (bmcRandomNumLength > i_size) ? i_size :
                      bmcRandomNumLength;
    memcpy(o_toBuffer, bmcRandomNum, l_size);
    i_size = l_size;
}

void IpmiSessionKeys::setBmcRandomNum(const void* i_buffer, uint32_t i_size)
{
    auto l_size = (IPMI_BMC_RANDOM_NUMBER_LEN > i_size) ? i_size :
                      IPMI_BMC_RANDOM_NUMBER_LEN;
    memcpy(bmcRandomNum, i_buffer, l_size);
    bmcRandomNumLength = l_size;
}

void IpmiSessionKeys::getRcRandomNum(void* o_toBuffer, uint32_t& i_size)
{
    auto l_size = (rcRandomNumLength > i_size) ? i_size :
                      rcRandomNumLength;
    memcpy(o_toBuffer, rcRandomNum, l_size);
    i_size = l_size;
}

void IpmiSessionKeys::setRcRandomNum(const void* i_buffer, uint32_t i_size)
{
    auto l_size = (IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN > i_size) ?
                      i_size : IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN;
    memcpy(rcRandomNum, i_buffer, l_size);
    rcRandomNumLength = l_size;
}

void IpmiSessionKeys::getSIK(void* o_toBuffer, uint32_t& i_size)
{
    auto l_size = (sessionIntegrityKeyLength > i_size) ? i_size :
                      sessionIntegrityKeyLength;
    memcpy(o_toBuffer, sessionIntegrityKey, l_size);
    i_size = l_size;
}

void IpmiSessionKeys::setSIK(const void* i_buffer, uint32_t i_size)
{
    auto l_size = (IPMI_SESSION_INTEGRITY_KEY_LENGTH > i_size) ?
                      i_size : IPMI_SESSION_INTEGRITY_KEY_LENGTH;
    memcpy(sessionIntegrityKey, i_buffer, l_size);
    sessionIntegrityKeyLength = l_size;
}

void IpmiSessionKeys::getK1(void* o_toBuffer, uint32_t& i_size)
{
    auto l_size = (sessionKeyLength_k1 > i_size) ? i_size :
                      sessionKeyLength_k1;
    memcpy(o_toBuffer, sessionKey_k1, l_size);
    i_size = l_size;
}

void IpmiSessionKeys::setK1(const void* i_buffer, uint32_t i_size)
{
    auto l_size = (IPMI_SESSION_K1_KEY_LENGTH > i_size) ? i_size :
                      IPMI_SESSION_K1_KEY_LENGTH;
    memcpy(sessionKey_k1, i_buffer, l_size);
    sessionKeyLength_k1 = l_size;
}

void IpmiSessionKeys::getK2(void* o_toBuffer, uint32_t& i_size)
{
    auto l_size = (sessionKeyLength_k2 > i_size) ? i_size :
                      sessionKeyLength_k2;
    memcpy(o_toBuffer, sessionKey_k2, l_size);
    i_size = l_size;
}

void IpmiSessionKeys::setK2(const void* i_buffer, uint32_t i_size)
{
    auto l_size = (IPMI_SESSION_K2_KEY_LENGTH > i_size) ? i_size :
                      IPMI_SESSION_K2_KEY_LENGTH;
    memcpy(sessionKey_k2, i_buffer, l_size);
    sessionKeyLength_k2 = l_size;
}

IpmiCipherAlgorithm::IpmiCipherAlgorithm() : enabled(), requested(),
    applied() {}

IpmiCipherAlgorithm::~IpmiCipherAlgorithm() {}

bool IpmiCipherAlgorithm::getState()
{
    return enabled;
}

bool IpmiCipherAlgorithm::setState(bool i_enable)
{
    enabled = i_enable;
    return enabled;
}

uint8_t IpmiCipherAlgorithm::getRequested()
{
    return requested;
}

uint8_t IpmiCipherAlgorithm::setRequested(uint8_t i_algoIndex)
{
    requested = i_algoIndex;
    return requested;
}

uint8_t IpmiCipherAlgorithm::getApplied()
{
    return applied;
}

uint8_t IpmiCipherAlgorithm::setApplied(uint8_t i_algoIndex)
{
    applied = i_algoIndex;
    return applied;
}

IpmiAuthenticationAlgoInterface::IpmiAuthenticationAlgoInterface() {}

IpmiAuthenticationAlgoInterface::~IpmiAuthenticationAlgoInterface() {}

IpmiIntegrityAlgoInterface::IpmiIntegrityAlgoInterface() {}

IpmiIntegrityAlgoInterface::~IpmiIntegrityAlgoInterface() {}

IpmiConfidentialityAlgoInterface::IpmiConfidentialityAlgoInterface() {}

IpmiConfidentialityAlgoInterface::~IpmiConfidentialityAlgoInterface() {}

IpmiUserAuthenticationInterface::IpmiUserAuthenticationInterface
(IpmiAuthenticationMethod i_authMethod) : authMethod(i_authMethod) {}

IpmiUserAuthenticationInterface::~IpmiUserAuthenticationInterface() {}

IpmiUserAuthenticationInterface::IpmiAuthenticationMethod
IpmiUserAuthenticationInterface::getAuthMethod()
{
    return authMethod;
}

IpmiSessionCipherSuite::IpmiSessionCipherSuite()
    : iv_sessionKeys(),
      iv_pAuthenticationAlgo(nullptr),
      iv_pIntegrityAlgo(nullptr),
      iv_pConfidentialityAlgo(nullptr) {}

IpmiSessionCipherSuite::~IpmiSessionCipherSuite()
{
    if (iv_pAuthenticationAlgo)
    {
        delete iv_pAuthenticationAlgo;
        iv_pAuthenticationAlgo = nullptr;
    }

    if (iv_pIntegrityAlgo)
    {
        delete iv_pIntegrityAlgo;
        iv_pIntegrityAlgo = nullptr;
    }

    if (iv_pConfidentialityAlgo)
    {
        delete iv_pConfidentialityAlgo;
        iv_pConfidentialityAlgo = nullptr;
    }

    if (iv_userAuthInterface)
    {
        delete iv_userAuthInterface;
        iv_userAuthInterface = nullptr;
    }
}

IpmiSessionKeys& IpmiSessionCipherSuite::getSessionKeys()
{
    return iv_sessionKeys;
}


IpmiAuthenticationAlgoInterface* IpmiSessionCipherSuite::getAuthCipher()
{
    return iv_pAuthenticationAlgo;
}

IpmiIntegrityAlgoInterface* IpmiSessionCipherSuite::getIntegrityCipher()
{
    return iv_pIntegrityAlgo;
}

IpmiConfidentialityAlgoInterface*
IpmiSessionCipherSuite::getConfidentialityCipher()
{
    return iv_pConfidentialityAlgo;
}

IpmiAuthenticationAlgoInterface* IpmiSessionCipherSuite::setAuthCipher(
    IpmiAuthenticationAlgoInterface* i_algo)
{
    iv_pAuthenticationAlgo = i_algo;
    return iv_pAuthenticationAlgo;
}

IpmiIntegrityAlgoInterface* IpmiSessionCipherSuite::setIntegrityCipher(
    IpmiIntegrityAlgoInterface* i_algo)
{
    iv_pIntegrityAlgo = i_algo;
    return iv_pIntegrityAlgo;
}

IpmiConfidentialityAlgoInterface*
IpmiSessionCipherSuite::setConfidentialityCipher(
    IpmiConfidentialityAlgoInterface* i_algo)
{
    iv_pConfidentialityAlgo = i_algo;
    return iv_pConfidentialityAlgo;
}

IpmiUserAuthenticationInterface* IpmiSessionCipherSuite::getUserAuthInterface()
{
    return iv_userAuthInterface;
}

IpmiUserAuthenticationInterface* IpmiSessionCipherSuite::setUserAuthInterface(
    IpmiUserAuthenticationInterface* i_intf)
{
    iv_userAuthInterface = i_intf;
    return iv_userAuthInterface;
}
