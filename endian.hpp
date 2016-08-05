#pragma once

#include <endian.h>
#include <stdint.h>

namespace endian
{
namespace details
{
template <typename T>
struct convert
{
    static T to_ipmi(T) = delete;
    static T from_ipmi(T) = delete;
    static T to_network(T) = delete;
    static T from_network(T) = delete;
};

template<> struct convert<uint16_t>
{
    uint16_t to_ipmi(uint16_t i) { return htole16(i); };
    uint16_t from_ipmi(uint16_t i) { return le16toh(i); };
    uint16_t to_network(uint16_t i) { return htobe16(i); };
    uint16_t from_network(uint16_t i) { return be16toh(i); };
};

template<> struct convert<uint32_t>
{
    uint32_t to_ipmi(uint32_t i) { return htole32(i); };
    uint32_t from_ipmi(uint32_t i) { return le32toh(i); };
    uint32_t to_network(uint32_t i) { return htobe32(i); };
    uint32_t from_network(uint32_t i) { return be32toh(i); };
};
}

template<typename T> T to_ipmi(T i)
{
  details::convert<T> a;
  return a.to_ipmi(i);
}

template<typename T> T from_ipmi(T i)
{
  details::convert<T> a;
  return a.from_ipmi(i);
}

template<typename T> T to_network(T i)
{
  details::convert<T> a;
  return a.to_network(i);
}
template<typename T> T from_network(T i)
{
  details::convert<T> a;
  return a.from_network(i);
}
}
