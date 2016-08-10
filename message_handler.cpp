#include "message_handler.hpp"

#include <sys/socket.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "command_table.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"
#include "main.hpp"
#include "message.hpp"

MessageHandler::MessageHandler(std::shared_ptr<udpsocket::Channel> i_channel):
    channel()
{
    channel = i_channel;
}

std::unique_ptr<message::Message> MessageHandler::receive()
{
    std::vector<uint8_t> packet;
    auto readStatus = 0;

    // Read the packet
    std::tie(readStatus, packet) = channel->read();

    if (readStatus < 0)
    {
        std::cerr << "E> Error in Read : " << std::hex << readStatus << "\n";
    }

    // Unflatten the packet
    auto message = message::MessageParser::unflatten(packet, sessionHeader);

    if (message != nullptr)
    {
        auto session = std::get<session::Manager&>(singletonPool).getSession(
                           message->bmcSessionID);
        if (session == nullptr)
        {
            return nullptr;
        }
        else
        {
            sessionID = message->bmcSessionID;
            message->rcSessionID = session->getRCSessionID();
            session->updateLastTransactionTime();
        }

        return std::move(message);
    }
    else
    {
        return nullptr;
    }
    std::cout << "<<MessageHandler::receive\n";
}

std::unique_ptr<message::Message> MessageHandler::executeCommand(
    message::Message* inMessage)
{

    // Get the CommandID to map into the command table
    auto command = getCommand(inMessage);

    auto inPayload(inMessage->payload);

    // If the payload type is IPMI then remove the IPMI LAN Message header and trailer from the
    // message payload
    if (inMessage->payloadType == message::PayloadType::IPMI)
    {
        inMessage->payload.erase(inMessage->payload.begin(),
                                 inMessage->payload.begin() + sizeof(message::LAN::header::Request));
        inMessage->payload.erase(inMessage->payload.end() - sizeof(
                                     message::LAN::trailer::Response),
                                 inMessage->payload.end());
    }

    auto output = std::get<command::Table&>(singletonPool).executeCommand(command,
                  inMessage->payload, *this);

    auto outMessage = std::make_unique<message::Message>();
    outMessage->rcSessionID = inMessage->rcSessionID;

    if (inMessage->payloadType == message::PayloadType::IPMI)
    {
        outMessage->payloadType = message::PayloadType::IPMI;

        outMessage->payload.resize(sizeof(message::LAN::header::Response) +
                                   output.size()
                                   +
                                   sizeof(message::LAN::trailer::Response));

        auto reqHeader = reinterpret_cast<message::LAN::header::Request*>
                         (inPayload.data());
        auto respHeader = reinterpret_cast<message::LAN::header::Response*>
                          (outMessage->payload.data());

        // Add IPMI LAN Message Response Header
        respHeader->rqaddr = reqHeader->rqaddr;
        respHeader->netfn  = reqHeader->netfn | 0x04;
        respHeader->cs     = ipmiCrc8bit(&(respHeader->rqaddr), 2);
        respHeader->rsaddr = reqHeader->rsaddr;
        respHeader->rqseq  = reqHeader->rqseq;
        respHeader->cmd    = reqHeader->cmd;

        auto assembledSize = sizeof(message::LAN::header::Response);

        // Copy the output by the execution of the command
        std::copy(output.begin(), output.end(),
                  outMessage->payload.begin() + assembledSize);
        assembledSize += output.size();

        // Add the IPMI LAN Message Trailer
        auto trailer = reinterpret_cast<message::LAN::trailer::Response*>
                       (outMessage->payload.data() + assembledSize);
        trailer->checksum = ipmiCrc8bit(&respHeader->rsaddr, assembledSize - 3);

    }
    else if (inMessage->payloadType == message::PayloadType::OPEN_SESSION_REQUEST)
    {
        outMessage->payloadType = message::PayloadType::OPEN_SESSION_RESPONSE;
        outMessage->payload.resize(output.size());
        std::copy(output.begin(), output.end(), outMessage->payload.begin());
    }
    else if (inMessage->payloadType == message::PayloadType::RAKP1)
    {
        outMessage->payloadType = message::PayloadType::RAKP2;
        outMessage->payload.resize(output.size());
        std::copy(output.begin(), output.end(), outMessage->payload.begin());
    }
    else if (inMessage->payloadType == message::PayloadType::RAKP3)
    {
        outMessage->payloadType = message::PayloadType::RAKP4;
        outMessage->payload.resize(output.size());
        std::copy(output.begin(), output.end(), outMessage->payload.begin());
    }

    return std::move(outMessage);
}

uint32_t MessageHandler::getCommand(message::Message* message)
{
    uint32_t command = 0 ;

    if (message)
    {
        command |= (0 << 24);
        command |= (static_cast<uint8_t>(message->payloadType) << 16);
        if (message->payloadType == message::PayloadType::IPMI)
        {
            command |= ((reinterpret_cast<message::LAN::header::Request*>
                         (message->payload.data()))->netfn) << 8;
            command |= (reinterpret_cast<message::LAN::header::Request*>
                        (message->payload.data()))->cmd;
        }
    }

    return command;
}

int MessageHandler::send(message::Message* outMessage)
{
    // Flatten the packet
    auto packet = message::MessageParser::flatten(outMessage, sessionHeader);

    // Read the packet
    auto writeStatus = channel->write(packet);
    if (writeStatus < 0)
    {
        std::cerr << "E> Error in writing : " << std::hex << writeStatus << "\n";
    }

    return writeStatus;
}

uint8_t MessageHandler::ipmiCrc8bit(const uint8_t* ptr, const int len)
{
    uint8_t csum = 0;
    auto inc = 0;

    while (inc != len)
    {
        csum += *(ptr + inc);
        inc++;
    }

    return 0x100 - csum;
}

