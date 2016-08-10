#include <ipmiSockChannelData.H>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>

IpmiSockChannelData::IpmiSockChannelData(int i_fd) {
  fd_ = i_fd;
}

IpmiSockChannelData::~IpmiSockChannelData() {
  if ( fd_ != -1) {
    close(fd_);
    fd_ = -1;
  }
}

const char* IpmiSockChannelData::getRemoteAddress() {
  char tmp[INET_ADDRSTRLEN] = { 0 };
  const char *l_rc = nullptr;
  inet_ntop(AF_INET, &iv_Address.in_addr.sin_addr, tmp, sizeof(tmp));
  iv_AddrStr = tmp;
  l_rc = iv_AddrStr.c_str();
  return l_rc;
}

uint16_t IpmiSockChannelData::getPort() {
  return iv_Address.in_addr.sin_port;
}

int IpmiSockChannelData::Peek(void * o_Buffer, size_t& io_Bytes) {
  return Read(o_Buffer, io_Bytes, MSG_PEEK);
}

int IpmiSockChannelData::Read(void * o_Buffer, size_t& io_Bytes) {
  return Read(o_Buffer, io_Bytes, 0);
}

int IpmiSockChannelData::Read(void * o_Buffer, size_t& io_Len, int i_SockFlags) {
    int l_rc = 0;
    uint8_t * l_pOutput = reinterpret_cast<uint8_t *> (o_Buffer);
    int l_urc = 0;
    size_t l_BytesReceived = 0;

    // Check for invalid socket
    if(fd_ == -1) {
      std::cerr<<"E> IpmiSockChannelData::Read : The File descriptor is invalid"<<std::endl;
    } else {
      // Determine flags & Blocking I/O
      i_SockFlags  |= MSG_NOSIGNAL;
      i_SockFlags |= MSG_WAITALL;

      // Read Loop
      do {
        iv_Address.addrSize = sizeof(iv_Address.in_addr);
        l_urc = recvfrom(
          fd_,                          // Socket
          l_pOutput + l_BytesReceived,    // Output buffer
          io_Len - l_BytesReceived,       // Bytes requested
          i_SockFlags,                    // Options
          &iv_Address.sockAddr,
          &iv_Address.addrSize );

        // Got some data
        if (l_urc > 0) {
          l_BytesReceived += l_urc;
          std::cout<<"I> IpmiSockChannelData::Read : DataIn Fd["<<fd_<<"] Req["<<io_Len<<"] Recv["
                   <<l_BytesReceived<<"]"<<std::endl;
        } else if (l_urc == 0) { // Was the connection closed?
          std::cerr<<"E> IpmiSockChannelData::Read : Connection Closed Fd["<<fd_<<"] Req["<<io_Len
                   <<"] Recv["<<l_BytesReceived<<"] Flags["<<std::hex<<i_SockFlags<<"]"<<std::endl;
          l_rc = -1;
        } else if (l_urc < 0) { // Error checking
            if (errno == EINTR) { // Interrupted
            std::cerr<<"E> IpmiSockChannelData::Read : Interrupt Fd["<<fd_<<"] Req["<<io_Len
                     <<"] Recv["<<l_BytesReceived<<"] Errno["<<errno<<"]"<<std::endl;
            continue;
            } else if ( errno == EHOSTDOWN ) { // Peer unreachable
              std::cerr<<"E> IpmiSockChannelData::Read : Peer unreachable Fd["<<fd_<<"] Req["
                       <<io_Len<<"] Recv["<<l_BytesReceived<<"] Flags["<<std::hex<<i_SockFlags<<"]"
                       <<std::endl;
              l_rc = -1;
              break;
            } else { // Hard fail
              std::cerr<<"E> IpmiSockChannelData::Read : Receive Error Fd["<<fd_<<"] Req["<<io_Len
                       <<"] Recv["<<l_BytesReceived<<"] Flags["<<std::hex<<i_SockFlags<<"]"
                       <<std::endl;
              l_BytesReceived = 0;
              l_rc = -1;
              break;
            }
        }
      } while (l_BytesReceived != io_Len);
    }
    // Bytes read
    io_Len = l_BytesReceived;
    return l_rc;
}

int IpmiSockChannelData::Write(void * i_Buffer, size_t & io_Bytes) {
  int l_rc = 0;
  int bytesSent = 0;

  if(fd_ == -1) {
    std::cerr<<"IpmiSockChannelData::Write: The File descriptor is invalid"<<std::endl;
  } else {
    do {
      iv_Address.addrSize = sizeof(iv_Address.in_addr);
      bytesSent = sendto(fd_, i_Buffer, io_Bytes, MSG_NOSIGNAL, &iv_Address.sockAddr,
                         iv_Address.addrSize);
      } while (bytesSent < 0 && errno == EINTR);

      if(bytesSent  == -1) {
        std::cerr<<"IpmiSockChannelData::Write: Write failed"<<std::endl;
        io_Bytes = 0;
      } else {
        io_Bytes = bytesSent;
      }
  }
  return l_rc;
}

