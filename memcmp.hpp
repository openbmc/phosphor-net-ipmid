#pragma once

#include <openssl/crypto.h>

#include <algorithm>
#include <span>

template <typename T>
bool crypto_memcmp(const std::span<T>& a, const std::span<T>& b)
{
    size_t minSize = std::min(a.size(), b.size());
    bool dataMatch = (CRYPTO_memcmp(a.data(), b.data(), minSize) == 0);
    bool sameSize = (a.size() == b.size());
    return dataMatch && sameSize;
}
