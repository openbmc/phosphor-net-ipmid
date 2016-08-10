#include "message_handler.hpp"

#include <sys/socket.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "command_table.hpp"
#include "main.hpp"
#include "message.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

namespace message
{

std::unique_ptr<Message> Handler::receive()
{
    std::vector<uint8_t> packet;
    auto readStatus = 0;

    // Read the packet
    std::tie(readStatus, packet) = channel->read();

    // Read of the packet failed
    if (readStatus < 0)
    {
        std::cerr << "E> Error in Read : " << std::hex << readStatus << "\n";
        return nullptr;
    }

    // Unflatten the packet
    auto message = Parser::unflatten(packet, sessionHeader);
    if (message == nullptr)
    {
        return nullptr;
    }

    auto session = std::get<session::Manager&>(singletonPool).getSession(
                       message->bmcSessionID);
    if (session == nullptr)
    {
        return nullptr;
    }

    sessionID = message->bmcSessionID;
    message->rcSessionID = session->getRCSessionID();
    session->updateLastTransactionTime();

    return message;
}

std::unique_ptr<Message> Handler::executeCommand(
    Message* inMessage)
{
    // Get the CommandID to map into the command table
    auto command = getCommand(inMessage);

    auto inPayload(inMessage->payload);

    // If the payload type is IPMI then remove the IPMI LAN Message header and
    // trailer from the message payload
    if (inMessage->payloadType == PayloadType::IPMI)
    {
        inMessage->payload.erase(inMessage->payload.begin(),
                                 inMessage->payload.begin() +
                                 sizeof(LAN::header::Request));
        inMessage->payload.erase(inMessage->payload.end() - sizeof(
                                     LAN::trailer::Response),
                                 inMessage->payload.end());
    }

    auto output = std::get<command::Table&>(singletonPool).executeCommand(
                      command,
                      inMessage->payload,
                      *this);

    auto outMessage = std::make_unique<Message>();
    outMessage->rcSessionID = inMessage->rcSessionID;

    if (inMessage->payloadType == PayloadType::IPMI)
    {
        outMessage->payloadType = PayloadType::IPMI;

        outMessage->payload.resize(sizeof(LAN::header::Response) +
                                   output.size() +
                                   sizeof(LAN::trailer::Response));

        auto reqHeader = reinterpret_cast<LAN::header::Request*>
                         (inPayload.data());
        auto respHeader = reinterpret_cast<LAN::header::Response*>
                          (outMessage->payload.data());

        // Add IPMI LAN Message Response Header
        respHeader->rqaddr = reqHeader->rqaddr;
        respHeader->netfn  = reqHeader->netfn | 0x04;
        respHeader->cs     = crc8bit(&(respHeader->rqaddr), 2);
        respHeader->rsaddr = reqHeader->rsaddr;
        respHeader->rqseq  = reqHeader->rqseq;
        respHeader->cmd    = reqHeader->cmd;

        auto assembledSize = sizeof(LAN::header::Response);

        // Copy the output by the execution of the command
        std::copy(output.begin(), output.end(),
                  outMessage->payload.begin() + assembledSize);
        assembledSize += output.size();

        // Add the IPMI LAN Message Trailer
        auto trailer = reinterpret_cast<LAN::trailer::Response*>
                       (outMessage->payload.data() + assembledSize);
        trailer->checksum = crc8bit(&respHeader->rsaddr, assembledSize - 3);

    }
    else if (inMessage->payloadType == PayloadType::OPEN_SESSION_REQUEST)
    {
        outMessage->payloadType = PayloadType::OPEN_SESSION_RESPONSE;
        outMessage->payload.resize(output.size());
        std::copy(output.begin(), output.end(), outMessage->payload.begin());
    }
    else if (inMessage->payloadType == PayloadType::RAKP1)
    {
        outMessage->payloadType = PayloadType::RAKP2;
        outMessage->payload.resize(output.size());
        std::copy(output.begin(), output.end(), outMessage->payload.begin());
    }
    else if (inMessage->payloadType == PayloadType::RAKP3)
    {
        outMessage->payloadType = PayloadType::RAKP4;
        outMessage->payload.resize(output.size());
        std::copy(output.begin(), output.end(), outMessage->payload.begin());
    }

    return outMessage;
}

uint32_t Handler::getCommand(Message* message)
{
    uint32_t command = 0 ;

    if (message)
    {
        command |= (static_cast<uint8_t>(message->payloadType) << 16);
        if (message->payloadType == PayloadType::IPMI)
        {
            command |= ((reinterpret_cast<LAN::header::Request*>
                         (message->payload.data()))->netfn) << 8;
            command |= (reinterpret_cast<LAN::header::Request*>
                        (message->payload.data()))->cmd;
        }
    }

    return command;
}

int Handler::send(Message* outMessage)
{
    // Flatten the packet
    auto packet = Parser::flatten(outMessage, sessionHeader);

    // Read the packet
    auto writeStatus = channel->write(packet);
    if (writeStatus < 0)
    {
        std::cerr << "E> Error in writing : " << std::hex << writeStatus
                  << "\n";
    }

    return writeStatus;
}

uint8_t Handler::crc8bit(const uint8_t* ptr, const size_t len)
{
    uint8_t csum = 0;
    size_t inc = 0;

    while (inc != len)
    {
        csum += *(ptr + inc);
        inc++;
    }

    return 0x100 - csum;
}

} //namespace message

