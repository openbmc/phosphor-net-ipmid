#include  <sys/ioctl.h>
#include <iostream>
#include "sd_event_loop.hpp"
#include "message_handler.hpp"
#include "main.hpp"
#include <systemd/sd-daemon.h>

namespace eventloop
{

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
        std::cerr << "Reading & Parsing the incoming IPMI message failed\n";
        std::cerr << e.what() << "\n";
        return 0;
    }

    // Execute the Command
    auto outMessage = msgHandler.executeCommand(*(inMessage.get()));
    if (outMessage == nullptr)
    {
        std::cerr << "Execution of IPMI command failed\n";
        return 0;
    }

    try
    {
        // Send the response IPMI Message
        msgHandler.send(*(outMessage.get()));
    }
    catch (std::exception& e)
    {
        std::cerr << "Flattening & Sending the outgoing IPMI message failed\n";
        std::cerr << e.what() << "\n";
    }

    return 0;
}

static int consoleInputHandler(EventSource es, int fd, uint32_t revents,
                               void* userdata)
{
    int readSize = 0;
    int rc = 0;

    if (ioctl(fd, FIONREAD, &readSize) < 0)
    {
        std::cerr << "E> ioctl failed with errno = " << errno;
        return 0;
    }

    std::vector<uint8_t> buffer(readSize);
    auto bufferSize = buffer.size();
    ssize_t readDataLen = 0;

    readDataLen = read(fd, buffer.data(), bufferSize);

    if (readDataLen > 0) // Data read from the socket
    {
        buffer.resize(readDataLen);
        std::get<sol::Manager&>(singletonPool).buffer.writeData(buffer);
    }
    else if (readDataLen == 0)
    {
        std::cerr << "Connection Closed \n";
        rc = -1;
    }
    else if (readDataLen < 0) // Error
    {
        rc = -errno;
        std::cerr << "Can't read from server "<< errno <<"\n";
    }

    return rc;
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
        fprintf(stderr, "No or too many file descriptors received.\n");
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
        fprintf(stderr, "Failure: %s\n", strerror(-r));
    }

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

int EventLoop::startConsolePayload(int fd)
{
    int rc = 0;

    if (!hostConsole)
    {
        // Add the fd to the event loop for EPOLLIN
        rc = sd_event_add_io(
                event, &hostConsole, fd, EPOLLIN, consoleInputHandler, nullptr);

        if (rc < 0)
        {
            std::cerr<<"Add file descriptor to the sd_event_loop failed\n";
            return rc;
        }
    }

    return 0;
}

int EventLoop::stopConsolePayload()
{
    int rc = 0;

    // Stop the fd from the eventloop
    if (hostConsole)
    {
        // Disable the Host Console Payload
        rc = sd_event_source_set_enabled(hostConsole, SD_EVENT_OFF);
        if (rc < 0)
        {
            std::cerr<<"Failed to disable the retry timer "<< rc << "\n";
            return rc;
        }
        sd_event_source_unref(hostConsole);
    }

    return 0;
}

} // namespace eventloop
