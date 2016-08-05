#include "app_util.hpp"

namespace endian
{
    namespace details
    {
        template<> uint16_t convert<uint16_t>::from_ipmi(uint16_t i)
        {
            return le16toh(i);
        }
        template<> uint16_t convert<uint16_t>::to_ipmi(uint16_t i)
        {
            return htole16(i);
        }
        template<> uint16_t convert<uint16_t>::from_network(uint16_t i)
        {
            return ntohs(i);
        }
        template<> uint16_t convert<uint16_t>::to_network(uint16_t i)
        {
            return htons(i);
        }
        template<> uint32_t convert<uint32_t>::from_ipmi(uint32_t i)
        {
            return le32toh(i);
        }
        template<> uint32_t convert<uint32_t>::to_ipmi(uint32_t i)
        {
            return htole32(i);
        }
        template<> uint32_t convert<uint32_t>::from_network(uint32_t i)
        {
            return ntohl(i);
        }
        template<> uint32_t convert<uint32_t>::to_network(uint32_t i)
        {
            return htonl(i);
        }
    }
}
