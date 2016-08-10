#pragma once

#include <arpa/inet.h>
#include <unistd.h>

#include <string>
#include <vector>

/** @class SocketChannel
 *
 *  @brief Provides encapsulation for UDP socket operations like Read, Peek,
 *         Write, Remote peer's IP Address and Port.
 */
class SocketChannel
{
    public:

        struct SockAddr_t
        {
            union
            {
                sockaddr sockAddr;
                sockaddr_in inAddr;
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
        SocketChannel(int insockfd)
        {
            sockfd = insockfd;
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
            return address.inAddr.sin_port;
        }

        /**
         * @brief Read the incoming message
         *
         * Reads the given number of bytes from the socket.
         *
         * @param  outBuffer
         *    Output Buffer. The vector must be large enough to hold the data to be read.
         *    On input the size of the vector would be the number of bytes requested.
         *    In case of success, the number of bytes read from the socket descriptor
         *    and in case of error, the size is set to 0.
         *
         * @return Error upon read failure
         */
        int read(std::vector<uint8_t>& outBuffer);

        /**
         *  @brief Write the outgoing message
         *
         *  Writes the given number of bytes to the channel.
         *
         *  @param  inBuffer
         *      The buffer of data to write out on to the socket.
         *      On input the size of the vector would be the number of bytes to write.
         *      In case of success, the number of bytes successfully written to the
         *      socket descriptor and in case of error, the size is set to 0.
         *
         *  @return Error upon write failure
         */
        int write(std::vector<uint8_t>& inBuffer);

        /**
         * @brief Returns file descriptor for the socket
         */
        auto getHandle(void) const
        {
            return sockfd;
        };

        ~SocketChannel() = default;
        SocketChannel(const SocketChannel& right) = delete;
        SocketChannel& operator=(const SocketChannel& right) = delete;
        SocketChannel(SocketChannel&&) = delete;
        SocketChannel& operator=(SocketChannel&&) = delete;

    private:
        int sockfd;
        SockAddr_t address;
        std::string addressStr;
};
