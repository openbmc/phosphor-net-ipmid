#include "socket_channel.hpp"

#include <errno.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>

const char* SocketChannel::getRemoteAddress()
{
    char tmp[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &address.inAddr.sin_addr, tmp, sizeof(tmp));
    addressStr = tmp;
    return addressStr.c_str();
}

int SocketChannel::read(std::vector<uint8_t>& outBuffer)
{
    auto rc = 0;
    auto readSize = 0;
    size_t readDataLen = 0;

    if (ioctl(sockfd, FIONREAD, &readSize) < 0)
    {
        std::cerr << "E> SocketChannel::Read : ioctl failed with errno = " << errno;
        return -errno;
    }

    outBuffer.resize(readSize);
    auto bufferSize = outBuffer.size();
    auto outputPtr = outBuffer.data();

    address.addrSize = sizeof(address.inAddr);
    readDataLen = recvfrom(sockfd,               // File Descriptor
                           outputPtr ,           // Buffer
                           bufferSize,           // Bytes requested
                           0,                    // Flags
                           &address.sockAddr,    // Address
                           &address.addrSize);   // Address Length

    if (readDataLen > 0) // Data read from the socket
    {
        std::cout << "I> SocketChannel::Read : DataIn Fd[" << sockfd << "] Req[" <<
                  bufferSize << "] Recv[" << readDataLen << "]\n";
    }
    else if (readDataLen == 0) // Peer has performed an orderly shutdown
    {
        std::cerr << "E> SocketChannel::Read : Connection Closed Fd[" << sockfd <<
                  "]\n";
        outBuffer.resize(0);
        rc = -1;
    }
    else if (readDataLen < 0) // Error
    {
        std::cerr << "E> SocketChannel::Read : Receive Error Fd[" << sockfd << "]" <<
                  "errno = " << errno << "\n";
        outBuffer.resize(0);
        rc = -errno;
    }

    if (readDataLen < bufferSize)
    {
        std::cout << "I> SocketChannel::Read readDataLen less than requested : Req["
                  << bufferSize << "] Recv[" << readDataLen << "]\n";
    }

    // Resize the vector to the actual data read from the socket
    outBuffer.resize(readDataLen);
    return rc;
}

int SocketChannel::write(std::vector<uint8_t>& inBuffer)
{
    auto rc = 0;
    auto outputPtr = inBuffer.data();
    auto bufferSize = inBuffer.size();
    auto l_spuriousWakeup = false;
    int writeDataLen = 0;

    fd_set l_writeSet;
    FD_ZERO(&l_writeSet);
    FD_SET(sockfd, &l_writeSet);

    struct timeval l_tv;
    l_tv.tv_sec = 30;
    l_tv.tv_usec = 0;

    do
    {
        l_spuriousWakeup = false;

        rc = select((sockfd + 1), NULL, &l_writeSet, NULL, &l_tv);

        if (rc > 0)
        {
            if (FD_ISSET(sockfd, &l_writeSet))
            {
                address.addrSize = sizeof(address.inAddr);
                writeDataLen = sendto(sockfd,                  // File Descriptor
                                      outputPtr,               // Message
                                      bufferSize,              // Length
                                      MSG_NOSIGNAL,            // Flags
                                      &address.sockAddr,       // Destination Address
                                      address.addrSize);       // Address Length

                if (writeDataLen == -1)
                {
                    std::cerr << "SocketChannel::Write: Write failed\n";
                    inBuffer.resize(0);
                    rc = -errno;
                }
                else if (static_cast<size_t>(writeDataLen) < bufferSize)
                {
                    std::cerr << "SocketChannel::Write: Complete data not written to the socket\n";
                    inBuffer.resize(writeDataLen);
                }
            }
            else
            {
                // Spurious wake up
                std::cerr << "E> Spurious wake up on select (writeset)\n";
                l_spuriousWakeup = true;
            }
        }
        else
        {
            if (rc == 0)
            {
                // Timed out
                std::cerr << "E> We timed out on select call (writeset)\n";
            }
            else
            {
                // Error
                std::cerr << "E> select call (writeset) had an error : " << errno << "\n";
                rc  = -errno;
            }

        }
    }
    while (l_spuriousWakeup);

    return rc;
}
