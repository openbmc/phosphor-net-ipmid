#include "auth_algo.hpp"

#include <openssl/hmac.h>

#include <iostream>
#include <string>

namespace cipher
{
namespace auth
{
void AlgoNone::generateKeyExchangeAuthCode_RAKP2(
    Keys* i_sessionSlot,
    const uint8_t* i_input,
    uint32_t i_inputLength,
    uint8_t* o_key,
    uint32_t& o_keyLength)
{
    uint8_t l_key[Keys::USER_KEY_MAX_LENGTH] = {};
    uint32_t l_keyLength = Keys::USER_KEY_MAX_LENGTH;

    std::copy(i_sessionSlot->userKey.begin(), i_sessionSlot->userKey.end(), l_key);

    HMAC(EVP_sha1(), l_key, l_keyLength, i_input, i_inputLength, o_key,
         &o_keyLength);
}

bool AlgoNone::verifyKeyExchangeAuthCode_RAKP3(
    Keys* i_sessionKeys,
    uint8_t* i_key,
    uint32_t i_keyLength)
{
    return true;
}

void AlgoNone::generateSessionIntegrityKey_RAKP3(
    Keys* i_sessionSlot)
{
}

void AlgoNone::generateIntegrityCheckValue_RAKP4(
    Keys* i_sessionSlot,
    uint8_t*& o_key,
    uint32_t& o_keyLength)
{
}

} // namespace auth

} // namespace cipher
