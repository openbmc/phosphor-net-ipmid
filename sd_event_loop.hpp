#pragma once

#include <systemd/sd-event.h>
#include <map>

namespace eventloop
{

using EventSource = sd_event_source *;

class EventLoop
{
    public:

        EventLoop() = default;
        ~EventLoop() = default;
        EventLoop(const EventLoop&) = delete;
        EventLoop& operator=(const EventLoop&) = delete;
        EventLoop(EventLoop&&) = delete;
        EventLoop& operator=(EventLoop&&) = delete;

        /** @brief SOL payload instance is the key for the map */
        using payloadMap = std::map<uint8_t, std::tuple<EventSource, uint64_t,
              EventSource, uint64_t>>;

        /**
         * @brief Initialise the event loop and add the handler for incoming
         *        IPMI packets
         *
         * @return EXIT_SUCCESS on success and EXIT_FAILURE on failure.
         */
        int startEventLoop();

        /*
         * @brief Adds Host Console I/O Event source to the event loop
         *
         * @return 0 on success and negative error number on error
         */
        int startConsolePayload(int fd);

        /**
         * @brief Destroy Host Console I/O Event source
         *
         * @return 0 on success and negative error number on error
         */
        int stopConsolePayload();

        /**
         * @brief Initialize the timers for the SOL Payload Instance
         *
         * This API would add the Character accumulate interval timer event
         * source and the retry interval timer event source for the SOL payload
         * instance to the event loop.
         *
         * @param[in] payloadInst - SOL Payload Instance
         * @param[in] accumulateInterval - Character Accumulate Interval in
         *                                 micro seconds
         * @param[in] retryInterval - Retry interval in microseconds
         *
         * @return 0 on success and negative error number on error
         */
        int startSOLPayloadInstance(uint8_t payloadInst,
                                    uint64_t accumulateInterval,
                                    uint64_t retryInterval);

        /**
         * @brief Stop the timers for the SOL Payload Instance
         *
         * This would remove the Character accumulate interval timer event
         * source and the retry interval timer event source from the event loop.
         *
         * @param[in] payloadInst - SOL Payload Instance
         *
         * @return 0 on success and negative error number on error
         */
        int stopSOLPayloadInstance(uint8_t payloadInst);

        /**
         * @brief Modify the Character accumulate timer event source to enable/
         *        disable
         *
         * @param[in] payloadInst- SOL Payload Instance
         * @param[in] status - on/off the event source
         */
        int switchAccumulateTimer(uint8_t payloadInst, bool status);

        /**
         * @brief Modify the retry interval timer event source to enable/disable
         *
         * @param[in] payloadInst- SOL Payload Instance
         * @param[in] status - on/off the event source
         */
        int switchRetryTimer(uint8_t payloadInst, bool status);

    private:

        /** @brief Event Source object for Host Console */
        EventSource hostConsole;

        /**
         * @brief Event Source for the UDP socket listening on IPMI standard
         *         port
         */
        EventSource udpIPMI;

        /**
         * Map to keep information regarding IPMI Payload instance and timers
         * for Character accumulate interval and Retry Interval
         */
        payloadMap payloadInfo;

        /** Event Loop Object */
        sd_event* event;
};

} // namespace eventloop
