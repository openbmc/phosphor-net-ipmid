#include "cipher_interfaces.hpp"

#include <utility>

IpmiSessionKeys::IpmiSessionKeys()
    : userNameLength(0), userName(), userKeyLength(0), userKey(),
      bmcRandomNumLength(0), bmcRandomNum(), rcRandomNumLength(0),
      rcRandomNum(),
      sessionIntegrityKeyLength(0), sessionIntegrityKey(),
      sessionKeyLength_k1(0),
      sessionKey_k1(), sessionKeyLength_k2(0), sessionKey_k2() {}

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

IpmiUserAuthenticationInterface::IpmiUserAuthenticationInterface
(IpmiAuthenticationMethod i_authMethod) : authMethod(i_authMethod) {}

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

IpmiSessionKeys& IpmiSessionCipherSuite::getSessionKeys()
{
    return iv_sessionKeys;
}

IpmiAuthenticationAlgoInterface* IpmiSessionCipherSuite::getAuthCipher()
{
    return iv_pAuthenticationAlgo.get();
}

IpmiIntegrityAlgoInterface* IpmiSessionCipherSuite::getIntegrityCipher()
{
    return iv_pIntegrityAlgo.get();
}

IpmiConfidentialityAlgoInterface*
IpmiSessionCipherSuite::getConfidentialityCipher()
{
    return iv_pConfidentialityAlgo.get();
}

IpmiAuthenticationAlgoInterface* IpmiSessionCipherSuite::setAuthCipher(
    std::unique_ptr<IpmiAuthenticationAlgoInterface> i_algo)
{
    iv_pAuthenticationAlgo = std::move(i_algo);
    return iv_pAuthenticationAlgo.get();
}

IpmiIntegrityAlgoInterface* IpmiSessionCipherSuite::setIntegrityCipher(
    std::unique_ptr<IpmiIntegrityAlgoInterface> i_algo)
{
    iv_pIntegrityAlgo = std::move(i_algo);
    return iv_pIntegrityAlgo.get();
}

IpmiConfidentialityAlgoInterface*
IpmiSessionCipherSuite::setConfidentialityCipher(
    std::unique_ptr<IpmiConfidentialityAlgoInterface> i_algo)
{
    iv_pConfidentialityAlgo = std::move(i_algo);
    return iv_pConfidentialityAlgo.get();
}

IpmiUserAuthenticationInterface* IpmiSessionCipherSuite::getUserAuthInterface()
{
    return iv_userAuthInterface.get();
}

IpmiUserAuthenticationInterface* IpmiSessionCipherSuite::setUserAuthInterface(
    std::unique_ptr<IpmiUserAuthenticationInterface> i_intf)
{
    iv_userAuthInterface = std::move(i_intf);
    return iv_userAuthInterface.get();
}
