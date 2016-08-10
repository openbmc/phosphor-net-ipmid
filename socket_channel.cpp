#include "socket_channel.hpp"

#include <errno.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>

namespace udpsocket
{

std::string& Channel::getRemoteAddress()
{
    char tmp[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &address.inAddr.sin_addr, tmp, sizeof(tmp));
    addressStr = tmp;
    return addressStr;
}

int Channel::read(std::vector<uint8_t>& outBuffer)
{
    auto rc = 0;
    auto readSize = 0;
    ssize_t readDataLen = 0;

    if (ioctl(sockfd, FIONREAD, &readSize) < 0)
    {
        std::cerr << "E> Channel::Read : ioctl failed with errno = " << errno;
        return -errno;
    }

    outBuffer.resize(readSize);
    auto bufferSize = outBuffer.size();
    auto outputPtr = outBuffer.data();

    address.addrSize = sizeof(address.inAddr);

    do
    {
        readDataLen = recvfrom(sockfd,               // File Descriptor
                               outputPtr ,           // Buffer
                               bufferSize,           // Bytes requested
                               0,                    // Flags
                               &address.sockAddr,    // Address
                               &address.addrSize);   // Address Length

        if (readDataLen > 0) // Data read from the socket
        {
            std::cout << "I> Channel::Read : DataIn Fd[" << sockfd << "] Req[" <<
                      bufferSize << "] Recv[" << readDataLen << "]\n";
        }
        else if (readDataLen == 0) // Peer has performed an orderly shutdown
        {
            std::cerr << "E> Channel::Read : Connection Closed Fd[" << sockfd <<
                      "]\n";
            outBuffer.resize(0);
            rc = -1;
        }
        else if ((readDataLen < 0) && (errno != EINTR)) // Error
        {
            std::cerr << "E> Channel::Read : Receive Error Fd[" << sockfd << "]" <<
                      "errno = " << errno << "\n";
            rc = -errno;
            outBuffer.resize(0);
        }

    }
    while ((readDataLen < 0) && (errno == EINTR));

    // Resize the vector to the actual data read from the socket
    outBuffer.resize(readDataLen);
    return rc;
}

int Channel::write(std::vector<uint8_t>& inBuffer)
{
    auto rc = 0;
    auto outputPtr = inBuffer.data();
    auto bufferSize = inBuffer.size();
    auto spuriousWakeup = false;
    ssize_t writeDataLen = 0;

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sockfd, &writeSet);

    do
    {
        spuriousWakeup = false;

        rc = select((sockfd + 1), NULL, &writeSet, NULL, &timeout);

        if (rc > 0)
        {
            if (FD_ISSET(sockfd, &writeSet))
            {
                address.addrSize = sizeof(address.inAddr);
                do
                {
                    writeDataLen = sendto(sockfd,                  // File Descriptor
                                          outputPtr,               // Message
                                          bufferSize,              // Length
                                          MSG_NOSIGNAL,            // Flags
                                          &address.sockAddr,       // Destination Address
                                          address.addrSize);       // Address Length

                    if ((writeDataLen == -1) && (errno != EINTR))
                    {
                        std::cerr << "Channel::Write: Write failed with errno:" << errno << "\n";
                        rc = -errno;
                        inBuffer.resize(0);
                    }
                    else if (static_cast<size_t>(writeDataLen) < bufferSize)
                    {
                        std::cerr << "Channel::Write: Complete data not written to the socket\n";
                        inBuffer.resize(writeDataLen);
                    }
                }
                while ((writeDataLen < 0) && (errno == EINTR));
            }
            else
            {
                // Spurious wake up
                std::cerr << "E> Spurious wake up on select (writeset)\n";
                spuriousWakeup = true;
            }
        }
        else
        {
            if (rc == 0)
            {
                // Timed out
                std::cerr << "E> We timed out on select call (writeset)\n";
                rc = -1;
            }
            else
            {
                // Error
                std::cerr << "E> select call (writeset) had an error : " << errno << "\n";
                rc  = -errno;
            }

        }
    }
    while (spuriousWakeup);

    return rc;
}

} // namespace udpsocket
