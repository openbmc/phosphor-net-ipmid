#pragma once

#include <systemd/sd-event.h>
#include <map>

namespace eventloop
{

using EventSource = sd_event_source*;

class EventLoop
{
    public:

        EventLoop() = default;
        ~EventLoop() = default;
        EventLoop(const EventLoop&) = delete;
        EventLoop& operator=(const EventLoop&) = delete;
        EventLoop(EventLoop&&) = delete;
        EventLoop& operator=(EventLoop&&) = delete;

        /** @brief SOL Payload Map.
         *
         *  The key for the payload map is the payload instance, the entries in
         *  the value are the event source for the character accumulate timer,
         *  character accumulate timer interval, event source for the retry
         *  interval timer and retry timer interval.
         */
        using payloadMap = std::map<uint8_t, std::tuple<EventSource, uint64_t,
                EventSource, uint64_t>>;

        /** @brief Initialise the event loop and add the handler for incoming
         *         IPMI packets.
         *
         *  @return EXIT_SUCCESS on success and EXIT_FAILURE on failure.
         */
        int startEventLoop();

        /** @brief Add host console I/O event source to the event loop.
         *
         *  @param[in] fd - File descriptor for host console socket.
         */
        void startHostConsole(int fd);

        /** @brief Remove host console I/O event source. */
        void stopHostConsole();

        /** @brief Initialize the timers for the SOL payload instance
         *
         *  This API would add the Character accumulate interval timer event
         *  source and the retry interval timer event source for the SOL payload
         *  instance to the event loop.
         *
         *  @param[in] payloadInst - SOL payload instance.
         *  @param[in] accumulateInterval - Character accumulate interval in
         *                                  micro seconds.
         *  @param[in] retryInterval - Retry interval in microseconds.
         */
        void startSOLPayloadInstance(uint8_t payloadInst,
                                     uint64_t accumulateInterval,
                                     uint64_t retryInterval);

        /** @brief Stop the timers for the SOL payload instance.
         *
         *  This would remove the character accumulate interval timer event
         *  source and the retry interval timer event source from the event
         *  loop.
         *
         *  @param[in] payloadInst - SOL payload instance
         */
        void stopSOLPayloadInstance(uint8_t payloadInst);

        /** @brief Modify the character accumulate timer event source to enable/
         *         disable.
         *
         *  When the timer is enabled, the timer it set to fire again at
         *  character accumulate interval for the instance added to the event
         *  loop iteration timestamp. When the timer is disabled the event
         *  source for the character accumulate timer is disabled.
         *
         *  @param[in] payloadInst - SOL payload instance.
         *  @param[in] status - on/off the event source.
         */
        void switchAccumulateTimer(uint8_t payloadInst, bool status);

        /** @brief Modify the retry interval timer event source to enable/
         *         disable
         *
         *  When the timer is enabled, the timer it set to fire again at
         *  retry interval for the instance added to the event loop iteration
         *  timestamp. When the timer is disabled the event source for the
         *  retry interval timer is disabled.
         *
         *  @param[in] payloadInst - SOL payload instance.
         *  @param[in] status - on/off the event source.
         */
        void switchRetryTimer(uint8_t payloadInst, bool status);

    private:
        /** @brief Event source object for host console. */
        EventSource hostConsole = nullptr;

        /** @brief Event source for the UDP socket listening on IPMI standard
         *         port.
         */
        EventSource udpIPMI = nullptr;

        /** @brief Map to keep information regarding IPMI payload instance and
         *         timers for character accumulate interval and retry interval.
         */
        payloadMap payloadInfo;

        /** @brief Event loop object. */
        sd_event* event = nullptr;
};

} // namespace eventloop
