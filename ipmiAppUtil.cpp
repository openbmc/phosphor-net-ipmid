#include <ipmiAppUtil.H>

PacketField16_t::PacketField16_t() : var(0)
{
    set(0);
}

PacketField16_t::PacketField16_t(uint16_t  i_val,
                                 ByteOrder i_byteOrder) : var(0)
{
    set(i_val, i_byteOrder);
}

PacketField16_t::~PacketField16_t() {}

uint16_t PacketField16_t::get(ByteOrder i_byteOrder)
{
    uint16_t l_var = 0;

    switch (i_byteOrder)
    {
        case IPMI: // If the HOST is Big Endian, use htole16
            l_var = var;
            break;

        case NETWORK:
            l_var = htons(var);
            break;

        default: //HOST order
            l_var = var;
            break;
    }

    return l_var;
}

void PacketField16_t::set(uint16_t i_val, ByteOrder i_byteOrder)
{
    switch (i_byteOrder)
    {
        case IPMI: // If the HOST is Big Endian, use le16toh
            var = i_val;
            break;

        case NETWORK:
            var = ntohs(i_val);
            break;

        default: //HOST order
            var = i_val;
            break;
    }
}

PacketField32_t::PacketField32_t() : var(0)
{
    set(0);
}

PacketField32_t::PacketField32_t(uint32_t  i_val,
                                 ByteOrder i_byteOrder) : var(0)
{
    set(i_val, i_byteOrder);
}

PacketField32_t::~PacketField32_t() {}

uint32_t PacketField32_t::get(ByteOrder i_byteOrder)
{
    uint32_t l_var = 0;

    switch (i_byteOrder)
    {
        case IPMI: // If the HOST is Big Endian, use htole32
            l_var = var;
            break;

        case NETWORK:
            l_var = htonl(var);
            break;

        default: //HOST order
            l_var = var;
            break;
    }

    return l_var;
}

void PacketField32_t::set(uint32_t i_val, ByteOrder i_byteOrder)
{
    switch (i_byteOrder)
    {
        case IPMI: // If the HOST is Big Endian, use le32toh
            var = i_val;
            break;

        case NETWORK:
            var = ntohl(i_val);
            break;

        default: //HOST order
            var = i_val;
            break;
    }
}
