#include <openssl/rand.h>
#include <ipmiAppUtil.H>


PacketField16_t::PacketField16_t()
:iv_var(0)
{
    set(0);
}

PacketField16_t::PacketField16_t(uint16_t  i_val,
                                 ByteOrder i_byteOrder)
:iv_var(0)
{
    set(i_val,i_byteOrder);
}

PacketField16_t::~PacketField16_t()
{

}

uint16_t PacketField16_t::get(ByteOrder i_byteOrder)
{
    uint16_t l_var = 0;

    switch(i_byteOrder)
    {
    case IPMI: // If the HOST is Big Endian, use htole16
        l_var = iv_var;
        break;

    case NETWORK:
        l_var = htons(iv_var);
        break;

    default: //HOST order
        l_var = iv_var;
        break;
    }

    return l_var;
}

void PacketField16_t::set(uint16_t  i_val,
                          ByteOrder i_byteOrder )
{
    switch(i_byteOrder)
    {
    case IPMI: // If the HOST is Big Endian, use le16toh
        iv_var = i_val;
        break;

    case NETWORK:
        iv_var = ntohs(i_val);
        break;

    default: //HOST order
        iv_var = i_val;
        break;
    }
}

PacketField32_t::PacketField32_t()
:iv_var(0)
{
    set(0);
}

PacketField32_t::PacketField32_t(uint32_t  i_val,
                                 ByteOrder i_byteOrder)
:iv_var(0)
{
    set(i_val,i_byteOrder);
}

PacketField32_t::~PacketField32_t()
{

}

uint32_t PacketField32_t::get(ByteOrder i_byteOrder)
{
    uint32_t l_var = 0;

    switch(i_byteOrder)
    {
    case IPMI: // If the HOST is Big Endian, use htole32
        l_var = iv_var;
        break;

    case NETWORK:
        l_var = htonl(iv_var);
        break;

    default: //HOST order
        l_var = iv_var;
        break;
    }

    return l_var;
}

void PacketField32_t::set(uint32_t  i_val,
                          ByteOrder i_byteOrder)
{
    switch(i_byteOrder)
    {
    case IPMI: // If the HOST is Big Endian, use le32toh
        iv_var = i_val;
        break;

    case NETWORK:
        iv_var = ntohl(i_val);
        break;

    default: //HOST order
        iv_var = i_val;
        break;
    }
}

/*# Function Specification
 *
 * @Overview:
 *  Generate specified number of random bytes.
 *
 * @Thread:  Daemon/Library
 *
 * @note NOTES:
 *  # None.
 */
void ipmiGenerateRandomBytes(uint8_t* i_buffer, uint32_t io_numBytes)
{
    RAND_bytes(i_buffer,io_numBytes);
}

