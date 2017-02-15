#pragma once

#include "console_buffer.hpp"

namespace sol
{

/**
 * @struct Outbound
 *
 * Operation/Status in an Outbound SOL Payload format(BMC to Remote Console)
 */
struct Outbound
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t testMode: 2;       // Not supported
    uint8_t breakDetected: 1;  // Not supported
    uint8_t transmitOverrun: 1; // Not supported
    uint8_t SOLDeactivating: 1; // 0 : SOL active, 1 : SOL Deactive
    uint8_t charUnavailable: 1; // 0 : Available, 1 : Unavailable
    uint8_t ack: 1;            // 0 : ACK, 1 : NACK
    uint8_t reserved: 1;
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved: 1;
    uint8_t ack: 1;             // 0 : ACK, 1 : NACK
    uint8_t charUnavailable: 1; // 0 : Available, 1 : Unavailable
    uint8_t SOLDeactivating: 1; // 0 : SOL active, 1 : SOL Deactive
    uint8_t transmitOverrun: 1; // Not supported
    uint8_t breakDetected: 1;   // Not supported
    uint8_t testMode: 2;        // Not supported
#endif
} __attribute__((packed));

/**
 * @struct Inbound
 *
 * Operation/Status in an Inbound SOL Payload format(Remote Console to BMC)
 */
struct Inbound
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t flushOut: 1;        // Not supported
    uint8_t flushIn: 1;         // Not supported
    uint8_t dcd: 1;             // Not supported
    uint8_t cts: 1;             // Not supported
    uint8_t generateBreak: 1;   // Not supported
    uint8_t ring: 1;            // Not supported
    uint8_t ack: 1;             // 0 : ACK, 1: NACK
    uint8_t reserved: 1;
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved: 1;
    uint8_t ack: 1;             // 0 : ACK, 1 : NACK
    uint8_t ring: 1;            // Not supported
    uint8_t generateBreak: 1;   // Not supported
    uint8_t cts: 1;             // Not supported
    uint8_t dcd: 1;             // Not supported
    uint8_t flushIn: 1;         // Not supported
    uint8_t flushOut: 1;        // Not supported
#endif
} __attribute__((packed));

/**
 * @struct SOLPayload
 *
 * SOL Payload Data Format
 */
struct SOLPayload
{
    uint8_t packetSeqNum;       // Packet Sequence Number
    uint8_t packetAckSeqNum;    // Packet ACK/NACK Sequence Number
    uint8_t acceptedCharCount;  // Accepted Character Count
    union
    {
        uint8_t operation;
        struct Inbound inOperation;
        struct Outbound outOperation;
    };
} __attribute__((packed));

/**
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
        uint8_t out = 0;
};

class Context
{
    public:

        Context() = default;
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
        Context(uint8_t retryCount,
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
         * @param[in] seqNum - Packet Sequence Number
         * @param[in] ackSeqNum - Packet ACK/NACK Sequence Number
         * @param[in] count - Accepted Character Count
         * @param[in] operation - ACK is false, NACK is true
         * @param[in] input - Incoming SOL Data
         */
        void processInboundSOLPayload(uint8_t seqNum,
                                      uint8_t ackSeqNum,
                                      uint8_t count,
                                      bool status,
                                      const buffer& input);

        /**
         * @brief Send Response for Incoming SOL payload
         *
         * @param[in] ackSeqNum - Packet ACK/NACK Sequence Number
         * @param[in] count - Accepted Character Count
         * @param[in] ack - Set ACK/NACK in the Operation
         */
        void sendSOLPayloadResponse(uint8_t ackSeqNum,
                                    uint8_t count,
                                    bool ack);

        /**
         * @brief Send Outbound SOL Data
         */
        void sendOutboundSOLData();

        /**
         * @brief Decrement Retry Counter
         */
        auto decrementRetryCounter()
        {
            return (retryCounter ? --retryCounter : retryCounter);
        }

    private:

        /**
         * Expected Sequence number and expected character count is set before
         * sending the SOL payload. The check is done against these value when
         * an incoming SOL payload is received.
         */
        size_t expectedCharCount = 0;
        SequenceNumbers seqNums;

        /** Retry Counter */
        uint8_t retryCounter = 0;

        /**
         * The SOL payload send to the remote console is updated here, so that
         * we can retry and send the payload.
         */
        buffer sentPayload;
};

} // namespace sol
