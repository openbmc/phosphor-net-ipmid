#pragma once

#include <openssl/crypto.h>

#include <span>

template <typename T>
bool crypto_memcmp(const std::span<T>& a, const std::span<T>& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
