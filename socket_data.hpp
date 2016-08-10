#pragma once

#include <arpa/inet.h>
#include <unistd.h>

#include <string>
#include <vector>

/** @class SocketData
 *
 *  @brief Provides encapsulation for UDP socket operations like Read, Peek,
 *         Write, Remote peer's IP Address and Port.
 */
class SocketData
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
         * @brief Constructor
         *
         * Initialize the IPMI socket object with the socket descriptor
         *
         * @param  i_fd
         *    File Descriptor for the socket
         *
         * @return None
         */
        SocketData(int i_sockfd)
        {
            sockfd = i_sockfd;
        }

        /**
         * @brief Destructor
         *
         * Close the socket descriptor
         */
        ~SocketData()
        {
            if (sockfd != -1)
            {
                close(sockfd);
            }
        }

        /**
         * @brief Fetch the IP address of the remote peer
         *
         * Returns the IP address of the remote peer which is connected to this socket
         *
         * @return Pointer to the address of the remote peer
         */
        const char* getRemoteAddress();

        /**
         * @brief Fetch the port number of the remote peer
         *
         * Returns the port number of the remote peer
         *
         * @return Port number
         *
         */
        auto getPort()
        {
            return iv_Address.in_addr.sin_port;
        }

        /**
         * @brief Peeks at an incoming message.
         *
         * The data is treated as unread and the next recvfrom() function shall still
         * return this data.
         *
         *
         * @param  io_buffer
         *    Output Buffer. The vector must be large enough to hold the length to peek.
         *    On input the size of the vector would be the number of bytes requested.
         *    In case of success, the number of bytes read from the socket descriptor
         *    and in case of error, the size is set to 0.
         *
         * @return Error upon read failure
         *
         * @note The UDP protocol does not allow reading a datagram in chunks and therefore the
         *        data must be "peeked" to obtain header information which is then followed by a
         *        read of the whole datagram.
         */
        int Peek(std::vector<uint8_t>& io_buffer);

        /**
         * @brief Read the incoming message
         *
         * Reads the given number of bytes from the socket.
         *
         * @param  io_Buffer
         *    Output Buffer. The vector must be large enough to hold the data to be read.
         *    On input the size of the vector would be the number of bytes requested.
         *    In case of success, the number of bytes read from the socket descriptor
         *    and in case of error, the size is set to 0.
         *
         * @return Error upon read failure
         */
        int Read(std::vector<uint8_t>& io_buffer);

        /**
         *  @brief Write the outgoing message
         *
         *  Writes the given number of bytes to the channel.
         *
         *  @param  i_Buffer
         *      The buffer of data to write out on to the socket.
         *      On input the size of the vector would be the number of bytes to write.
         *      In case of success, the number of bytes successfully written to the
         *      socket descriptor and in case of error, the size is set to 0.
         *
         *  @return Error upon write failure
         */
        int Write(std::vector<uint8_t>& i_buffer);

        /**
         * @brief Returns file descriptor for the socket
         */
        auto getHandle(void) const
        {
            return sockfd;
        };

        SocketData(const SocketData& right) = delete;
        SocketData& operator=(const SocketData& right) = delete;
        SocketData(SocketData&&) = delete;
        SocketData& operator=(SocketData&&) = delete;

    private:
        int sockfd;
        SockAddr_t iv_Address;
        std::string iv_AddrStr;

        int Read(std::vector<uint8_t>& io_buffer, int i_SockFlags);
};
