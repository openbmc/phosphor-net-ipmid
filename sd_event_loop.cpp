#include  <sys/ioctl.h>
#include <phosphor-logging/log.hpp>
#include "sd_event_loop.hpp"
#include "message_handler.hpp"
#include "main.hpp"
#include <systemd/sd-daemon.h>

namespace eventloop
{
using namespace phosphor::logging;

static int udp623Handler(EventSource es, int fd, uint32_t revents,
                         void* userdata)
{
    std::shared_ptr<udpsocket::Channel> channelPtr;
    struct timeval timeout;
    timeout.tv_sec = SELECT_CALL_TIMEOUT;
    timeout.tv_usec = 0;

    channelPtr.reset(new udpsocket::Channel(fd, timeout));

    // Initialize the Message Handler with the socket channel
    message::Handler msgHandler(channelPtr);

    // Read the incoming IPMI packet
    std::unique_ptr<message::Message> inMessage;
    try
    {
        inMessage = msgHandler.receive();
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Reading & Parsing the incoming IPMI message failed");
        log<level::ERR>(e.what());
        return 0;
    }

    // Execute the Command
    auto outMessage = msgHandler.executeCommand(*(inMessage.get()));
    if (outMessage == nullptr)
    {
        log<level::ERR>("Execution of IPMI command failed");
        return 0;
    }

    try
    {
        // Send the response IPMI Message
        msgHandler.send(*(outMessage.get()));
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Flattening & Sending the outgoing IPMI message "
                        "failed");
        log<level::ERR>(e.what());
    }

    return 0;
}

static int consoleInputHandler(EventSource es, int fd, uint32_t revents,
                               void* userdata)
{
    int readSize = 0;

    if (ioctl(fd, FIONREAD, &readSize) < 0)
    {
        log<level::ERR>("ioctl failed for FIONREAD:",
                entry("errno = %d", errno));
        return 0;
    }

    std::vector<uint8_t> buffer(readSize);
    auto bufferSize = buffer.size();
    ssize_t readDataLen = 0;

    readDataLen = read(fd, buffer.data(), bufferSize);

    // Update the Console Buffer with data read from the socket
    if (readDataLen > 0)
    {
        buffer.resize(readDataLen);
        std::get<sol::Manager&>(singletonPool).buffer.writeData(buffer);
    }
    else if (readDataLen == 0)
    {
        log<level::ERR>("Connection Closed for host console socket");
    }
    else if (readDataLen < 0) // Error
    {
        log<level::ERR>("Reading from host console socket failed:",
                entry("errno = %d", errno));
    }

    return 0;
}

int EventLoop::startEventLoop()
{
    int fd = -1, r;
    sigset_t ss;

    r = sd_event_default(&event);
    if (r < 0)
    {
        goto finish;
    }

    if (sigemptyset(&ss) < 0 || sigaddset(&ss, SIGTERM) < 0 ||
        sigaddset(&ss, SIGINT) < 0)
    {
        r = -errno;
        goto finish;
    }

    /* Block SIGTERM first, so that the event loop can handle it */
    if (sigprocmask(SIG_BLOCK, &ss, nullptr) < 0)
    {
        r = -errno;
        goto finish;
    }

    /* Let's make use of the default handler and "floating" reference features
     * of sd_event_add_signal() */
    r = sd_event_add_signal(event, nullptr, SIGTERM, nullptr, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    r = sd_event_add_signal(event, nullptr, SIGINT, nullptr, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    if (sd_listen_fds(0) != 1)
    {
        log<level::ERR>("No or too many file descriptors received");
        goto finish;
    }

    fd = SD_LISTEN_FDS_START;

    r = sd_event_add_io(event, &udpIPMI, fd, EPOLLIN, udp623Handler, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    r = sd_event_loop(event);

finish:
    udpIPMI = sd_event_source_unref(udpIPMI);
    event = sd_event_unref(event);

    if (fd >= 0)
    {
        (void) close(fd);
    }

    if (r < 0)
    {
        log<level::ERR>("Event Loop Failure:",
                entry("Failure: %s", strerror(-r)));
    }

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

int EventLoop::startConsolePayload(int fd)
{
    int rc = 0;

    if (fd && !hostConsole)
    {
        // Add the fd to the event loop for EPOLLIN
        rc = sd_event_add_io(
                event, &hostConsole, fd, EPOLLIN, consoleInputHandler, nullptr);

        if (rc < 0)
        {
            log<level::ERR>("Adding host console socket descriptor to the "
                            "sd_event_loop failed");
            return rc;
        }
    }
    else
    {
        log<level::ERR>("Invalid fd or host console descriptor is already"
                        "added to the event loop");
        rc = -1;
    }

    return rc;
}

} // namespace eventloop
