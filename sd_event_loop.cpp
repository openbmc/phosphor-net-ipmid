#include <sys/ioctl.h>
#include <systemd/sd-daemon.h>
#include <phosphor-logging/log.hpp>
#include "main.hpp"
#include "message_handler.hpp"
#include "sd_event_loop.hpp"

namespace eventloop
{
using namespace phosphor::logging;

static int udp623Handler(sd_event_source* es, int fd, uint32_t revents,
                         void* userdata)
{
    std::shared_ptr<udpsocket::Channel> channelPtr;
    struct timeval timeout;
    timeout.tv_sec = SELECT_CALL_TIMEOUT;
    timeout.tv_usec = 0;

    try
    {
        channelPtr.reset(new udpsocket::Channel(fd, timeout));

        // Initialize the Message Handler with the socket channel
        message::Handler msgHandler(channelPtr);


        std::unique_ptr<message::Message> inMessage;

        // Read the incoming IPMI packet
        inMessage = msgHandler.receive();
        if (inMessage == nullptr)
        {
            return 0;
        }

        // Execute the Command
        auto outMessage = msgHandler.executeCommand(*(inMessage.get()));
        if (outMessage == nullptr)
        {
            return 0;
        }

        // Send the response IPMI Message
        msgHandler.send(*(outMessage.get()));
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Executing the IPMI message failed");
        log<level::ERR>(e.what());
    }

    return 0;
}

int EventLoop::startEventLoop()
{
    int fd = -1;
    int r = 0;
    sigset_t ss;
    sd_event_source* source = nullptr;

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

    r = sd_event_add_io(event, &source, fd, EPOLLIN, udp623Handler, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    udpIPMI.reset(source);
    source = nullptr;

    r = sd_event_loop(event);

finish:
    event = sd_event_unref(event);

    if (fd >= 0)
    {
        (void) close(fd);
    }

    if (r < 0)
    {
        log<level::ERR>("Event Loop Failure:",
                entry("FAILURE=%s", strerror(-r)));
    }

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

} // namespace eventloop
