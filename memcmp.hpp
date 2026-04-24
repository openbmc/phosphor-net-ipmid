#pragma once

#include <openssl/crypto.h>

#include <span>

template <typename T>
bool cryptoMemcmp(const std::span<T>& userData, const std::span<T>& secretData)
{
    size_t cmpLen = userData.size();
    // always compare exactly userData.size() bytes
    // which means if userData is longer than secretData, we just
    // compare userData against itself and then return false because
    // of size mismatch
    std::span<T> cmpData;
    if (userData.size() > secretData.size())
    {
        cmpData = userData;
    }
    else
    {
        cmpData = secretData;
    }
    bool dataMatch =
        (CRYPTO_memcmp(userData.data(), cmpData.data(), cmpLen) == 0);
    bool sameSize = (userData.size() == secretData.size());
    return dataMatch && sameSize;
}
