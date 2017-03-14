#include <iostream>
#include "main.hpp"
#include "sd_event_loop.hpp"
#include "sol_context.hpp"
#include "sol_manager.hpp"

namespace sol
{

void Context::processInboundSOLPayload(uint8_t seqNum,
                                       uint8_t ackSeqNum,
                                       uint8_t count,
                                       bool status,
                                       const buffer& input)
{
    uint8_t respAckSeqNum = 0;
    uint8_t acceptedCount = 0;
    auto ack = false;

    /*
     * Check if the Inbound sequence number is same as the expected one.
     * If the Packet Sequence Number is 0, it is an ACK-Only packet
     */
    if(seqNum && (seqNum != seqNums.get(true)))
    {
        log<level::ERR>("Out of sequence SOL packet - packet is dropped");
        return;
    }

    /*
     * Check if the expected ACK/NACK sequence number is same as the
     * ACK/NACK sequence number in the packet. If packet ACK/NACK sequence
     * number is 0, then it is an informational packet. No request packet being
     * ACK'd or NACK'd.
     */
    if (ackSeqNum && (ackSeqNum != seqNums.get(false)))
    {
        log<level::ERR>("Out of sequence ack number - SOL packet is dropped");
        return;
    }

    /*
     * Retry the SOL payload packet in the following conditions:
     *
     * a) NACK in Operation/Status
     * b) Accepted Character Count does not match with the sent out SOL payload
     * c) Non-zero Packet ACK/NACK Sequence Number
     */
    if (status || ((count != expectedCharCount) && ackSeqNum))
    {
        // Retry the packet
    }
    else if ((count == expectedCharCount) && ackSeqNum)
    {
        // Clear the Host Console Buffer
        std::get<sol::Manager&>(singletonPool).buffer.eraseBuffer(count);

        // Once it is acknowledged stop the retry interval timer
        std::get<eventloop::EventLoop&>(singletonPool).switchRetryTimer(
                payloadInstance, false);

        retryCounter = maxRetryCount;

        // Clear the buffer
        sentPayload.clear();
    }

    // Write character data to the Host Console
    if (input.size() != 0 && seqNum)
    {
        int rc = std::get<sol::Manager&>(singletonPool).writeConsoleSocket(
                input);
        if (rc)
        {
            log<level::ERR>("Writing to console socket descriptor failed");
            ack = true;
        }
        else
        {
            respAckSeqNum = seqNum;
            ack = false;
            acceptedCount = input.size();
        }
    }

    if(seqNum != 0)
    {
        seqNums.incExpectingSeqNum();
        sendSOLPayloadResponse(respAckSeqNum, acceptedCount, ack);
    }

}

void Context::sendSOLPayloadResponse(uint8_t ackSeqNum,
                                     uint8_t count,
                                     bool ack)
{

}

} // namespace sol
