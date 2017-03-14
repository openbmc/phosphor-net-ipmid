#include  <sys/ioctl.h>
#include <iostream>
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

static int charAccTimerHandler(EventSource s, uint64_t usec,
                               void *userdata)
{
    auto instance = *(static_cast<uint8_t*>(userdata));

    auto bufferSize = std::get<sol::Manager&>(singletonPool).buffer.getSize();
    /*
     * If there is data to be sent in the Console Buffer, send it to RC
     */
    if(bufferSize > 0)
    {
        // Invoke API to send the outbound SOL data
    }
    else
    {
        std::get<eventloop::EventLoop&>(singletonPool).switchAccumulateTimer
                (instance, true);
    }

    return 0;
}

static int retryTimerHandler(EventSource s, uint64_t usec,
                             void *userdata)
{
    auto instance = *(static_cast<uint8_t*>(userdata));

    auto& context = std::get<sol::Manager&>(singletonPool).getSOLContext
                            (instance);

    if(context.decrementRetryCounter())
    {
        std::get<eventloop::EventLoop&>(singletonPool).switchRetryTimer
                (instance, true);
    }
    else
    {
        // Close the SOL payload instance and close the IPMI session.
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

int EventLoop::stopConsolePayload()
{
    int rc = 0;

    if (hostConsole)
    {
        // Disable the Host Console Payload
        rc = sd_event_source_set_enabled(hostConsole, SD_EVENT_OFF);
        if (rc < 0)
        {
            log<level::ERR>("Failed to disable the host console socket",
                    entry("rc = %d", rc));
            return rc;
        }
        sd_event_source_unref(hostConsole);
    }

    return rc;
}

int EventLoop::startSOLPayloadInstance(uint8_t payloadInst,
                                       uint64_t accumulateInterval,
                                       uint64_t retryInterval)
{
    uint8_t instance = payloadInst;
    EventSource accTimerSource = nullptr;
    EventSource retryTimerSource = nullptr;
    int rc = 0;
    uint64_t currentTime = 0;

    rc = sd_event_now(event, CLOCK_MONOTONIC, &currentTime);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get the current timestamp",
                entry("rc = %d", rc));
        return rc;
    }

    // Create character accumulate timer
    rc = sd_event_add_time(event,
                           &accTimerSource,
                           CLOCK_MONOTONIC,
                           currentTime + accumulateInterval,
                           0,
                           charAccTimerHandler,
                           static_cast<void *>(&instance));
    if (rc < 0)
    {
        log<level::ERR>("Failed to setup the accumulate timer",
                entry("rc = %d", rc));
        return rc;
    }

    // Create retry interval timer and add to the event loop
    rc = sd_event_add_time(event,
                           &retryTimerSource,
                           CLOCK_MONOTONIC,
                           currentTime + retryInterval,
                           0,
                           retryTimerHandler,
                           static_cast<void *>(&instance));
    if (rc < 0)
    {
        log<level::ERR>("Failed to setup the retry timer",
                entry("rc = %d", rc));
        return rc;
    }

    // Disable the Retry Interval Timer
    rc = sd_event_source_set_enabled(retryTimerSource, SD_EVENT_OFF);
    if (rc < 0)
    {
        log<level::ERR>("Failed to disable the retry timer",
                entry("rc = %d", rc));
        return rc;
    }

    payloadInfo.emplace(instance,
                        std::make_tuple(accTimerSource, accumulateInterval,
                                        retryTimerSource, retryInterval));

   return rc;
}

int EventLoop::stopSOLPayloadInstance(uint8_t payloadInst)
{
    auto iter = payloadInfo.find(payloadInst);
    if (iter == payloadInfo.end())
    {
        throw std::runtime_error("Payload instance not found ");
    }

    int rc = 0;

    /* Destroy the Character Accumulate Timer Event Source */
    rc = sd_event_source_set_enabled(std::get<0>(iter->second),
                                     SD_EVENT_OFF);
    if (rc < 0)
    {
        std::cerr<<"Failed to disable the retry timer "<< rc << "\n";
        return rc;
    }

    sd_event_source_unref(std::get<0>(iter->second));

    /* Destroy the Retry Interval Timer Event Source */
    rc = sd_event_source_set_enabled(std::get<2>(iter->second),
                                     SD_EVENT_OFF);
    if (rc < 0)
    {
        std::cerr<<"Failed to disable the retry timer "<< rc << "\n";
        return rc;
    }

    sd_event_source_unref(std::get<2>(iter->second));

    payloadInfo.erase(payloadInst);

    return rc;
}

int EventLoop::switchAccumulateTimer(uint8_t payloadInst, bool status)
{
    auto iter = payloadInfo.find(payloadInst);
    if (iter == payloadInfo.end())
    {
        throw std::runtime_error("SOL Payload instance not found");
    }

    int rc = 0;

    // Turn OFF the Character Accumulate Timer
    if(!status)
    {
        rc = sd_event_source_set_enabled(std::get<0>(iter->second),
                                         SD_EVENT_OFF);
        if (rc < 0)
        {
            log<level::ERR>("Failed to disable the character accumulate timer",
                    entry("rc = %d", rc));
            return rc;
        }
        else
        {
            return 0;
        }
    }

    // Turn ON the Character Accumulate Timer
    uint64_t currentTime = 0;
    rc = sd_event_now(event, CLOCK_MONOTONIC, &currentTime);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get the current timestamp",
                entry("rc = %d", rc));
        return rc;
    }

    rc = sd_event_source_set_time(std::get<0>(iter->second),
                                  currentTime + std::get<1>(iter->second));
    if (rc < 0)
    {
        log<level::ERR>("Failed to sd_event_source_set_time",
                entry("rc = %d", rc));
        return rc;
    }

    rc = sd_event_source_set_enabled(std::get<0>(iter->second),
                                     SD_EVENT_ONESHOT);
    if (rc < 0)
    {
        log<level::ERR>("Failed to enable the character accumulate timer",
                entry("rc = %d", rc));
        return rc;
    }

    return rc;
}

int EventLoop::switchRetryTimer(uint8_t payloadInst, bool status)
{
    auto iter = payloadInfo.find(payloadInst);
    if (iter == payloadInfo.end())
    {
        throw std::runtime_error("SOL Payload instance not found ");
    }

    int rc = 0;

    // Turn OFF the Retry Interval Timer
    if(!status)
    {
        rc = sd_event_source_set_enabled(std::get<2>(iter->second),
                                         SD_EVENT_OFF);
        if (rc < 0)
        {
            log<level::ERR>("Failed to disable the retry interval timer",
                    entry("rc = %d", rc));
        }
        else
        {
            return 0;
        }
    }

    // Turn ON the Character Accumulate Timer
    uint64_t currentTime = 0;
    rc = sd_event_now(event, CLOCK_MONOTONIC, &currentTime);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get the current timestamp",
                entry("rc = %d", rc));
        return rc;
    }

    rc = sd_event_source_set_time(std::get<2>(iter->second),
                                  currentTime + std::get<3>(iter->second));
    if (rc < 0)
    {
        log<level::ERR>("Failed to sd_event_source_set_time",
                entry("rc = %d", rc));
        return rc;
    }

    rc = sd_event_source_set_enabled(std::get<2>(iter->second),
                                     SD_EVENT_ONESHOT);
    if (rc < 0)
    {
        log<level::ERR>("Failed to enable the retry interval timer",
                entry("rc = %d", rc));
        return rc;
    }

    return rc;
}

} // namespace eventloop
