#pragma once

#include "console_buffer.hpp"

namespace sol
{

/*
 * @struct SequenceNumbers SOL Sequence Numbers
 */
struct SequenceNumbers
{
        auto get(bool inbound = true) const
        {
            return inbound ? in : out;
        }

        void set(uint32_t seqNumber, bool inbound = true)
        {
            inbound ? (in = seqNumber) : (out = seqNumber);
        }

        auto incExpectingSeqNum()
        {
            if ((++in) == 0x10)
            {
                in = 1;
            }

            return in;
        }

        auto incSendSeqNum()
        {
            if ((++out) == 0x10)
            {
                out = 1;
            }

            return out;
        }

    private:
        // Sequence numbers must be non-zero
        uint8_t in = 1;
        uint8_t out = 1;
};

class Context
{
    public:

        Context() = delete;
        ~Context() = default;
        Context(const Context&) = delete;
        Context& operator=(const Context&) = delete;
        Context(Context&&) = default;
        Context& operator=(Context&&) = default;

        /*
         * @brief Context Constructor
         *
         * This is issued by the SOL Manager when a SOL payload instance is
         * started for the Activate Payload command
         *
         * @param[in] retryCount  - Retry Count
         * @param[in] sendThreshold - Character Send Threshold
         * @param[in] instance - SOL Payload instance
         * @param[in] sessionID - BMC Session ID
         */
        explicit Context(uint8_t retryCount,
                         uint8_t sendThreshold,
                         uint8_t instance,
                         uint8_t sessionID):
                         maxRetryCount(retryCount),
                         sendThreshold(sendThreshold),
                         payloadInstance(instance),
                         sessionID(sessionID) {}

        /* Retry Max Counter */
        const uint8_t maxRetryCount;

        /* Character Send Threshold */
        const uint8_t sendThreshold = 0;

        /* SOL Payload Instance */
        const uint8_t payloadInstance = 0;

        /* Session ID */
        const uint32_t sessionID;

    /*
     * @brief Process the Inbound SOL payload
     *
     * The SOL payload from the remote console is processed and the
     * acknowledgment handling is done.
     *
     * @param[in] input - Incoming SOL Payload
     */
    void processInboundSOLData(buffer input);

    /*
     * @brief Send Outbound SOL payload
     *
     * @param[in] input - Outgoing SOL payload
     */
    void sendOutboundSOLData(buffer input);

    private:

    /*
     * Expected Sequence number and expected character count is set before
     * sending the SOL payload. The check is done against these value when an
     * incoming SOL payload is received.
     */
    size_t expectedCharCount = 0;
    SequenceNumbers seqNums;

    /* Retry Counter */
    uint8_t retryCounter = 0;
};

} // namespace sol
