#include <sys/ioctl.h>
#include <systemd/sd-daemon.h>
#include <phosphor-logging/log.hpp>
#include "main.hpp"
#include "message_handler.hpp"
#include "sd_event_loop.hpp"

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

static int consoleInputHandler(EventSource es, int fd, uint32_t revents,
                               void* userdata)
{
    try
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

        // Update the Console buffer with data read from the socket
        if (readDataLen > 0)
        {
            buffer.resize(readDataLen);
            std::get<sol::Manager&>(singletonPool).dataBuffer.write(buffer);
        }
        else if (readDataLen == 0)
        {
            log<level::ERR>("Connection Closed for host console socket");
        }
        else if (readDataLen < 0) // Error
        {
            log<level::ERR>("Reading from host console socket failed:",
                    entry("ERRNO=%d", errno));
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
    }

    return 0;
}

static int charAccTimerHandler(EventSource s, uint64_t usec,
                               void *userdata)
{
    // The instance is hardcoded to 1, in the case of supporting multiple
    // payload instances we would need to populate it from userdata
    uint8_t instance = 1;
    int rc = 0;
    auto bufferSize = std::get<sol::Manager&>(singletonPool).dataBuffer.size();

    try
    {
        if(bufferSize > 0)
        {
            auto& context = std::get<sol::Manager&>(singletonPool).getContext
                    (instance);

            rc = context.sendOutboundPayload();

            if (rc == 0)
            {
                return 0;
            }
        }

        std::get<eventloop::EventLoop&>(singletonPool).switchTimer(
                instance, Timers::ACCUMULATE, true);
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
    }

    return 0;
}

static int retryTimerHandler(EventSource s, uint64_t usec,
                             void *userdata)
{
    // The instance is hardcoded to 1, in the case of supporting multiple
    // payload instances we would need to populate it from userdata
    uint8_t instance = 1;

    try
    {
        auto& context = std::get<sol::Manager&>(singletonPool).getContext
                (instance);

        if (context.retryCounter)
        {
            --context.retryCounter;
            std::get<eventloop::EventLoop&>(singletonPool).switchTimer
                    (instance, Timers::RETRY, true);
            context.resendPayload(false);
        }
        else
        {
            context.retryCounter = context.retryCountVal;
            context.resendPayload(true);
            std::get<eventloop::EventLoop&>(singletonPool).switchTimer
                    (instance, Timers::RETRY, false);
            std::get<eventloop::EventLoop&>(singletonPool).switchTimer
                    (instance, Timers::ACCUMULATE, true);
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
    }

    return 0;
}

int EventLoop::startEventLoop()
{
    int fd = -1;
    int r = 0;
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
                entry("FAILURE=%s", strerror(-r)));
    }

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

void EventLoop::startHostConsole(int fd)
{
    int rc = 0;

    if(!fd || hostConsole)
    {
        throw std::runtime_error("Console descriptor already added");
    }

    // Add the fd to the event loop for EPOLLIN
    rc = sd_event_add_io(
            event, &hostConsole, fd, EPOLLIN, consoleInputHandler, nullptr);

    if (rc < 0)
    {
        throw std::runtime_error("Failed to add socket descriptor");
    }
}

void EventLoop::stopHostConsole()
{
    int rc = 0;

    if (hostConsole)
    {
        // Disable the host console payload
        rc = sd_event_source_set_enabled(hostConsole, SD_EVENT_OFF);
        if (rc < 0)
        {
            log<level::ERR>("Failed to disable the host console socket",
                    entry("RC=%d", rc));
            throw std::runtime_error("Failed to disable socket descriptor");
        }
        sd_event_source_unref(hostConsole);
        hostConsole = nullptr;
    }
}

void EventLoop::startSOLPayloadInstance(uint8_t payloadInst,
                                        uint64_t accumulateInterval,
                                        uint64_t retryInterval)
{
    auto instance = payloadInst;
    EventSource accTimerSource = nullptr;
    EventSource retryTimerSource = nullptr;
    int rc = 0;
    uint64_t currentTime = 0;

    rc = sd_event_now(event, CLOCK_MONOTONIC, &currentTime);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get the current timestamp",
                entry("RC=%d", rc));
        throw std::runtime_error("Failed to get current timestamp");
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
                entry("RC = %d", rc));
        throw std::runtime_error("Failed to setup accumulate timer");
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
                entry("RC = %d", rc));
        throw std::runtime_error("Failed to setup retry timer");
    }

    // Enable the Character Accumulate Timer
    rc = sd_event_source_set_enabled(accTimerSource, SD_EVENT_ONESHOT);
    if (rc < 0)
    {
        log<level::ERR>("Failed to enable the accumulate timer",
                entry("rc = %d", rc));
        throw std::runtime_error("Failed to enable accumulate timer");
    }

    // Disable the Retry Interval Timer
    rc = sd_event_source_set_enabled(retryTimerSource, SD_EVENT_OFF);
    if (rc < 0)
    {
        log<level::ERR>("Failed to disable the retry timer",
                entry("RC = %d", rc));
        throw std::runtime_error("Failed to disable retry timer");
    }

    payloadInfo.emplace(instance,
                        std::make_tuple(accTimerSource, accumulateInterval,
                                        retryTimerSource, retryInterval));
}

void EventLoop::stopSOLPayloadInstance(uint8_t payloadInst)
{
    auto iter = payloadInfo.find(payloadInst);
    if (iter == payloadInfo.end())
    {
        log<level::ERR>("SOL Payload instance not found",
                entry("payloadInst=%d", payloadInst));
        throw std::runtime_error("SOL payload instance not found");
    }

    int rc = 0;

    /* Destroy the character accumulate timer event source */
    rc = sd_event_source_set_enabled(std::get<0>(iter->second),
                                     SD_EVENT_OFF);
    if (rc < 0)
    {
        log<level::ERR>("Failed to disable the character accumulate timer",
                entry("RC=%d", rc));
        payloadInfo.erase(payloadInst);
        throw std::runtime_error("Failed to disable accumulate timer");
    }
    sd_event_source_unref(std::get<0>(iter->second));

    /* Destroy the retry interval timer event source */
    rc = sd_event_source_set_enabled(std::get<2>(iter->second),
                                     SD_EVENT_OFF);
    if (rc < 0)
    {
        log<level::ERR>("Failed to disable the retry timer",
                entry("RC=%d", rc));
        payloadInfo.erase(payloadInst);
        throw std::runtime_error("Failed to disable retry timer");
    }
    sd_event_source_unref(std::get<2>(iter->second));

    payloadInfo.erase(payloadInst);
}

void EventLoop::switchTimer(uint8_t payloadInst,
                            Timers type,
                            bool status)
{
    auto iter = payloadInfo.find(payloadInst);
    if (iter == payloadInfo.end())
    {
        log<level::ERR>("SOL Payload instance not found",
                entry("payloadInst=%d", payloadInst));
        throw std::runtime_error("SOL Payload instance not found");
    }

    int rc = 0;
    EventSource source = nullptr;
    uint64_t interval = 0;

    if (type == Timers::ACCUMULATE)
    {
        source = std::get<0>(iter->second);
        interval = std::get<1>(iter->second);
    }
    else if (type == Timers::RETRY)
    {
        source = std::get<2>(iter->second);
        interval = std::get<3>(iter->second);
    }
    else
    {
        throw std::runtime_error("Unsupported timer type");
    }

    // Turn OFF the timer
    if (!status)
    {
        rc = sd_event_source_set_enabled(source, SD_EVENT_OFF);
        if (rc < 0)
        {
            log<level::ERR>("Failed to disable the timer", entry("RC=%d", rc));
            throw std::runtime_error("Failed to disable timer");
        }
        return;
    }

    // Turn ON the timer
    uint64_t currentTime = 0;
    rc = sd_event_now(event, CLOCK_MONOTONIC, &currentTime);
    if (rc < 0)
    {
        log<level::ERR>("Failed to get the current timestamp",
                entry("RC=%d", rc));
        throw std::runtime_error("Failed to get current timestamp");
    }

    rc = sd_event_source_set_time(source, currentTime + interval);
    if (rc < 0)
    {
        log<level::ERR>("sd_event_source_set_time function failed",
                entry("RC=%d", rc));
        throw std::runtime_error("sd_event_source_set_time function failed");
    }

    rc = sd_event_source_set_enabled(source, SD_EVENT_ONESHOT);
    if (rc < 0)
    {
        log<level::ERR>("Failed to enable the timer", entry("RC=%d",rc));
        throw std::runtime_error("Failed to enable timer");
    }
}

} // namespace eventloop
