#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include "socket_data.hpp"

const char* SocketData::getRemoteAddress()
{
    char tmp[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &iv_Address.in_addr.sin_addr, tmp, sizeof(tmp));
    iv_AddrStr = tmp;
    return iv_AddrStr.c_str();
}

int SocketData::Peek(std::vector<uint8_t>& io_buffer)
{
    return Read(io_buffer, MSG_PEEK);
}

int SocketData::Read(std::vector<uint8_t>& io_buffer)
{
    return Read(io_buffer, 0);
}

int SocketData::Read(std::vector<uint8_t>& io_buffer, int i_sockFlags)
{
    auto rc = 0;
    auto outputPtr = io_buffer.data();
    auto bufferSize = io_buffer.size();
    size_t readDataLength = 0;

    // Check for invalid socket
    if (sockfd == -1)
    {
        std::cerr << "E> SocketData::Read : The File descriptor is invalid\n";
    }
    else
    {
        iv_Address.addrSize = sizeof(iv_Address.in_addr);
        readDataLength = recvfrom(sockfd,               // File Descriptor
                                  outputPtr ,           // Buffer
                                  bufferSize,           // Bytes requested
                                  i_sockFlags,          // Flags
                                  &iv_Address.sockAddr, // Address
                                  &iv_Address.addrSize);// Address Length

        if (readDataLength > 0) // Data read from the socket
        {
            std::cout << "I> SocketData::Read : DataIn Fd[" << sockfd << "] Req[" <<
                      bufferSize << "] Recv[" << readDataLength << "]\n";
        }
        else if (readDataLength == 0) // Peer has performed an orderly shutdown
        {
            std::cerr << "E> SocketData::Read : Connection Closed Fd[" << sockfd <<
                      "] Flags[" << std::hex << i_sockFlags << "]\n";
            io_buffer.resize(0);
            rc = -1;
        }
        else if (readDataLength < 0) // Error
        {
            std::cerr << "E> SocketData::Read : Receive Error Fd[" << sockfd <<
                      "] Flags[" << std::hex << i_sockFlags << "]\n";
            io_buffer.resize(0);
            rc = -1;
        }
    }

    if (readDataLength < bufferSize)
    {
        std::cout << "I> SocketData::Read readDataLength less than requested : Req[" <<
                  bufferSize << "] Recv[" << readDataLength << "]\n";
    }

    // Resize the vector size to the actual data read from the socket
    io_buffer.resize(readDataLength);
    return rc;
}

int SocketData::Write(std::vector<uint8_t>& i_buffer)
{
    auto rc = 0;
    auto outputPtr = i_buffer.data();
    auto bufferSize = i_buffer.size();
    int writeDataLength = 0;

    if (sockfd == -1)
    {
        std::cerr << "SocketData::Write: The File descriptor is invalid\n";
    }
    else
    {
        iv_Address.addrSize = sizeof(iv_Address.in_addr);
        writeDataLength = sendto(sockfd,                  // File Descriptor
                                 outputPtr,               // Message
                                 bufferSize,              // Length
                                 MSG_NOSIGNAL,            // Flags
                                 &iv_Address.sockAddr,    // Destination Address
                                 iv_Address.addrSize);    // Address Length

        if (writeDataLength == -1)
        {
            std::cerr << "SocketData::Write: Write failed\n";
            i_buffer.resize(0);
            rc = -1;
        }
        else if (static_cast<size_t>(writeDataLength) < bufferSize)
        {
            std::cerr << "SocketData::Write: Complete data not written to the socket\n";
            i_buffer.resize(writeDataLength);
        }
    }
    return rc;
}
