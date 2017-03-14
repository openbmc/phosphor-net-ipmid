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

int Manager::initHostConsoleFd()
{
    struct sockaddr_un addr;
    int rc = 0;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        log<level::ERR>("Failed to open the host console socket",
                entry("errno = %d", errno));
        return -errno;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(&addr.sun_path, &CONSOLE_SOCKET_PATH, CONSOLE_SOCKET_PATH_LEN);

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0)
    {
        log<level::ERR>("Failed to connect to host console socket address",
                entry("errno = %d", errno));
        std::cerr<< "Can't connect to console server\n";
        close(fd);
        return -errno;
    }

    return rc;
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
        if (rc <= 0)
        {
            log<level::ERR>("Failed to write to host console socket",
                    entry("errno = %d", errno));
            return -errno;
        }
    }

    return 0;
}

void Manager::startSOLPayload(uint8_t payloadInstance, uint32_t sessionID)
{
    int rc = 0;

    if (payloadMap.size() == 0)
    {
        rc = initHostConsoleFd();

        if (rc < 0)
        {
            throw std::runtime_error("Initialising the host console socket "
                                     "failed");
        }

        // Register the fd in the sd_event_loop
        rc = std::get<eventloop::EventLoop&>(singletonPool).
                startConsolePayload(fd);
        if (rc < 0)
        {
            throw std::runtime_error("Registering the host console socket "
                                     "to sd_event_loop failed");
        }
    }

    // Create the SOL Context data for payload instance
    auto context = std::make_unique<Context>(
            accumulateInterval, retryCount, payloadInstance, sessionID);

    payloadMap.emplace(payloadInstance, std::move(context));


    /*
     * Start payload event instance
     *
     * Accumulate interval is in 5 ms(millis sec) increments, since
     * sd_event_add_time takes in micro secs, it is converted to micro secs.
     * The Retry interval is in 10 ms (milli secs) increments.
     */
    std::get<eventloop::EventLoop&>(singletonPool).startSOLPayloadInstance(
            payloadInstance,
            accumulateInterval * 5 * pow(10, 6),
            retryThreshold * 10 * pow(10, 6));
}

} // namespace sol
