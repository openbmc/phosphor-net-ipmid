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
    auto ack = false;
    uint8_t acceptedCount = 0;

    /*
     * Check if the Inbound sequence number is same as the expected one.
     */
    if(seqNum && (seqNum != seqNums.get(true)))
    {
        std::cerr<<"Out of sequence SOL packet - packet is dropped and no "
                   "response is sent\n";
        return;
    }
    else
    {
        // If the Packet Sequence Number is 0, it is an ACK-Only packet
    }

    /*
     * Check if the expected ACK/NACK sequence number is same as the
     * ACK/NACK sequence number in the packet.
     */
    if (ackSeqNum && (ackSeqNum != seqNums.get(false)))
    {
        std::cerr<<"Out of sequence ack number in the SOL packet - packet is "
                   "dropped and no response is sent\n";
        return;
    }
    else
    {
        // Informational packet. No request packet being ACK’d or NACK’d.
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
            std::cerr<<"Writing to Host Console failed \n";
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
    auto bufferSize = std::get<sol::Manager&>(singletonPool).buffer.
                            getSize();

    if (bufferSize <= sendThreshold)
    {
        std::get<eventloop::EventLoop&>(singletonPool).
                switchAccumulateTimer(payloadInstance, true);
    }

    /* Sent a ACK only response */
    if (sentPayload.size() != 0 || (bufferSize <= sendThreshold))
    {
        buffer outPayload(sizeof(SOLPayload));
        auto response = reinterpret_cast<SOLPayload*>(outPayload.data());
        response->packetSeqNum = 0;
        response->packetAckSeqNum = ackSeqNum;
        response->acceptedCharCount = count;
        response->outOperation.ack = ack;
        // Invoke send SOL payload
        return;
    }

    sentPayload.resize(sizeof(SOLPayload));
    auto response = reinterpret_cast<SOLPayload*>(sentPayload.data());
    response->packetAckSeqNum = ackSeqNum;
    response->acceptedCharCount = count;
    response->outOperation.ack = ack;

    auto data = std::get<sol::Manager&>(singletonPool).buffer.
            readData(std::min(bufferSize, MAX_PAYLOAD_SIZE));

    sentPayload.insert(sentPayload.end(), data.begin(), data.end());

    response->packetSeqNum = seqNums.incSendSeqNum();
    expectedCharCount = data.size();
    std::get<eventloop::EventLoop&>(singletonPool).switchRetryTimer(
            payloadInstance, true);
}

void Context::sendOutboundSOLData()
{
    if (sentPayload.size() != 0)
    {
        std::get<eventloop::EventLoop&>(singletonPool).
                switchAccumulateTimer(payloadInstance, true);
        return;
    }

    auto bufferSize = std::get<sol::Manager&>(singletonPool).buffer.
                            getSize();

    if (bufferSize == 0)
    {
        std::get<eventloop::EventLoop&>(singletonPool).
                switchAccumulateTimer(payloadInstance, true);
        return;
    }

    sentPayload.resize(sizeof(SOLPayload));
    auto response = reinterpret_cast<SOLPayload*>(sentPayload.data());
    response->packetAckSeqNum = 0;
    response->acceptedCharCount = 0;
    response->outOperation.ack = false;

    auto data = std::get<sol::Manager&>(singletonPool).buffer.
            readData(std::min(bufferSize, MAX_PAYLOAD_SIZE));

    sentPayload.insert(sentPayload.end(), data.begin(), data.end());

    response->packetSeqNum = seqNums.incSendSeqNum();
    std::get<eventloop::EventLoop&>(singletonPool).switchRetryTimer(
            payloadInstance, true);
}

} // namespace sol
