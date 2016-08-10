#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <string>

class IpmiSockChannelData
{
    public:

        struct SockAddr_t
        {
            union
            {
                sockaddr sockAddr;
                sockaddr_in in_addr;
            };
            size_t addrSize;
        };

        /**
         *  @brief Constructor
         *
         *  Initialize the IPMI socket channel object with the file descriptor
         *
         *  @param  i_fd
         *    File Socket Handle
         *
         *  @return None
         */
        IpmiSockChannelData(int i_fd);

        /**
         *  @brief Destructor
         *
         *  Close the file descriptor
         */
        ~IpmiSockChannelData();

        /**
         *  @brief Fetch the IP address of the remote client
         *
         *    Returns the IP address of the remote IPMI client which is connected to this channel
         *
         *  @return Pointer to a const char string which describes address of the remote system
         */
        const char* getRemoteAddress();

        /**
         *  @brief Fetch the port number of the remote client
         *
         *    Returns the communication port number of the remote IPMI client
         *
         *  @return Port number
         *
         */
        uint16_t getPort();

        /**
         *  @brief Peek into the UDP packet
         *
         *    Reads the given number of bytes from the channel but does not consume the data.
         *    herefore, a second read will return data
         *
         *  @param  o_Buffer
         *    Output Buffer.  The user's buffer must be large enough to hold the data.
         *
         *  @param  io_Bytes
         *    On input, the number of bytes requested.
         *    On output, the number of bytes successfully transfered.
         *    On error, the variable is set to zero.
         *
         *  @return Error upon read failure
         *
         *  @note The UDP protocol does not allow reading a datagram in chunks and therefore the data
         *        must be "peeked" to obtain header information which is then followed by a read of
         *        the whole datagram.
         */
        int Peek(void* o_Buffer, size_t& io_Bytes);

        /**
         *  @brief Read
         *
         *  Reads the given number of bytes from the channel and transfers them to the caller's buffer.
         *
         *  @param  o_Buffer
         *    Output Buffer. The user's buffer must be large enough to hold the data.
         *
         *  @param  io_Bytes
         *    On input, the number of bytes requested.
         *    On output, the number of bytes successfully transfered.
         *    On error, the variable is set to zero.
         *
         *  @return Error upon read failure
         */
        int Read(void* o_Buffer, size_t& io_Bytes);

        /**
         *  @brief Write
         *
         *  Writes the given number of bytes to the channel.
         *
         *  @param  i_Buffer
         *      Caller's data source for the write.
         *
         *  @param  io_Bytes
         *      On input, number of bytes to write
         *      On output, the number of bytes successfully transfered.
         *      On error, the variable is set to zero.
         *
         *  @return Error upon write failure
         */
        int Write(void* i_Buffer, size_t& io_Bytes);

        /**
         * @brief   Returns socket or file descriptor for the channel
         *
         * @return  OS_HANDLE type channel descriptor.
         *
         */
        int getHandle(void) const
        {
            return fd;
        };

        IpmiSockChannelData(const IpmiSockChannelData& right) = delete;

        IpmiSockChannelData& operator=(const IpmiSockChannelData& right) = delete;

    private:
        int fd;
        SockAddr_t iv_Address;
        std::string iv_AddrStr;

        int Read(void* o_Buffer, size_t& i_Len, int i_SockFlags);
};
