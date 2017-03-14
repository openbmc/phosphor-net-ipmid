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

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0)
    {
        log<level::ERR>("Failed to connect to host console socket address",
                entry("ERRNO=%d", errno));
        throw std::runtime_error("Failed to connect to console server");
        close(fd);
    }
}

int Manager::writeConsoleSocket(const Buffer& input)
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

void Manager::startPayloadInstance(uint8_t payloadInstance, uint32_t sessionID)
{
    if (payloadMap.empty())
    {
        initHostConsoleFd();

        // Register the fd in the sd_event_loop
        std::get<eventloop::EventLoop&>(singletonPool).startHostConsole(fd);
    }

    // Create the SOL Context data for payload instance
    auto context = std::make_unique<Context>(
            accumulateInterval, retryCount, payloadInstance, sessionID);

    payloadMap.emplace(payloadInstance, std::move(context));

    /*
     * Start payload event instance
     *
     * Accumulate interval is in 5 ms(milli secs) increments, since
     * sd_event_add_time takes in micro secs, it is converted to micro secs.
     * The Retry interval is in 10 ms (milli secs) increments.
     */
    std::get<eventloop::EventLoop&>(singletonPool).startSOLPayloadInstance(
            payloadInstance,
            accumulateInterval * 5 * pow(10, 3),
            retryThreshold * 10 * pow(10, 3));
}

void Manager::stopPayloadInstance(uint8_t payloadInstance)
{
    auto iter = payloadMap.find(payloadInstance);
    if (iter == payloadMap.end())
    {
        throw std::runtime_error("SOL Payload instance not found ");
    }

    payloadMap.erase(iter);

    if (payloadMap.empty())
    {
        // Remove the host console decriptor from the sd_event_loop
        std::get<eventloop::EventLoop&>(singletonPool).stopHostConsole();
    }
}

} // namespace sol
