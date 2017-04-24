#include <sys/socket.h>
#include <sys/un.h>
#include <cmath>
#include <phosphor-logging/log.hpp>
#include "main.hpp"
#include "sol_context.hpp"
#include "sol_manager.hpp"

namespace sol
{

using namespace phosphor::logging;

void Manager::initHostConsoleFd()
{
    struct sockaddr_un addr;
    int rc = 0;
    int fd = 0;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        log<level::ERR>("Failed to open the host console socket",
                entry("ERRNO=%d", errno));
        throw std::runtime_error("Failed to open the host console socket");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(&addr.sun_path, &CONSOLE_SOCKET_PATH, CONSOLE_SOCKET_PATH_LEN);
    consoleFD = std::make_unique<CustomFD>(fd);
    auto& conFD = *(consoleFD.get());

    rc = connect(conFD(), (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0)
    {
        log<level::ERR>("Failed to connect to host console socket address",
                entry("ERRNO=%d", errno));
        consoleFD.reset();
        throw std::runtime_error("Failed to connect to console server");
    }
}

int Manager::writeConsoleSocket(const Buffer& input) const
{
    auto inBuffer = input.data();
    auto inBufferSize = input.size();
    size_t pos = 0;
    ssize_t rc = 0;
    int errVal = 0;
    auto& conFD = *(consoleFD.get());

    for (pos = 0; pos < inBufferSize; pos += rc)
    {
        rc = write(conFD(), inBuffer + pos, inBufferSize - pos);
        if (rc <= 0)
        {
            if (errno == EINTR)
            {
                log<level::INFO>(" Retrying to handle EINTR",
                        entry("ERRNO=%d", errno));
                rc = 0;
                continue;
            }
            else
            {
                errVal = errno;
                log<level::ERR>("Failed to write to host console socket",
                        entry("ERRNO=%d", errno));
                return -errVal;
            }
        }
    }

    return 0;
}

} // namespace sol
