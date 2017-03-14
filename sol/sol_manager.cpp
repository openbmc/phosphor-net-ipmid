#include <sys/socket.h>
#include <sys/un.h>
#include <cmath>
#include <iostream>
#include "main.hpp"
#include "sol_context.hpp"
#include "sol_manager.hpp"

namespace sol
{

int Manager::initHostConsoleFd()
{
    struct sockaddr_un addr;
    int rc = 0;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!fd)
    {
        std::cerr<< "Can't open the Host Console socket\n";
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(&addr.sun_path, &CONSOLE_SOCKET_PATH, CONSOLE_SOCKET_PATH_LEN);

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc)
    {
        std::cerr<< "Can't connect to console server\n";
        close(fd);
        return -1;
    }

    return 0;
}

int Manager::writeConsoleSocket(const sol::buffer& input)
{
    auto inBuffer = input.data();
    auto inBufferSize = input.size();
    size_t pos = 0;
    ssize_t rc = 0;

    for (pos = 0; pos < inBufferSize; pos += rc)
    {
        rc = write(fd, inBuffer + pos, inBufferSize - pos);
        if (rc <= 0) {
            std::cerr<< "Write error\n";
            return -1;
        }
    }

    return 0;
}

} // namespace sol
