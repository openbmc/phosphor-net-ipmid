#include "message_parsers.hpp"

#include <iostream>
#include <memory>

#include "endian.hpp"
#include "main.hpp"
#include "message.hpp"
#include "sessions_manager.hpp"

namespace message
{

std::unique_ptr<Message> Parser::unflatten(
    std::vector<uint8_t>& inPacket,
    SessionHeader& authType)
{
    auto rmcpHeaderPtr = reinterpret_cast<BasicHeader_t*>(inPacket.data());

    // Check if the packet has atleast the size of the RMCP Header
    if (inPacket.size() < sizeof(BasicHeader_t))
    {
        return nullptr;
    }

    // Verify if the fields in the RMCP header conforms to the specification
    if ((rmcpHeaderPtr->version != RMCP_VERSION) ||
        (rmcpHeaderPtr->rmcpSeqNum != RMCP_SEQ) ||
        (rmcpHeaderPtr->classOfMsg != RMCP_MESSAGE_CLASS_IPMI))
    {
        return nullptr;
    }

    // Read the Session Header and invoke the parser corresponding to the
    // header type
    switch (static_cast<SessionHeader>(rmcpHeaderPtr->format.formatType))
    {
        case SessionHeader::IPMI15:
        {
            authType = SessionHeader::IPMI15;
            return Ipmi15Parser::unflatten(inPacket);
        }
        case SessionHeader::IPMI20:
        {
            authType = SessionHeader::IPMI20;
            return Ipmi20Parser::unflatten(inPacket);
        }
        default:
        {
            return nullptr;
        }
    }
}

std::vector<uint8_t> Parser::flatten(Message* outMessage,
                                     SessionHeader authType)
{
    std::vector<uint8_t> blank;

    // Call the flatten routine based on the header type
    switch (authType)
    {
        case SessionHeader::IPMI15:
        {
            return Ipmi15Parser::flatten(outMessage);
        }
        case SessionHeader::IPMI20:
        {
            return Ipmi20Parser::flatten(outMessage);
        }
        default:
        {
            return blank;
        }
    }
}

std::unique_ptr<Message> Ipmi15Parser::unflatten(std::vector<uint8_t>& inPacket)
{
    auto message = std::make_unique<Message>();

    // Check if the packet has atleast the Session Header
    if (inPacket.size() < sizeof(SessionHeader_t))
    {
        return nullptr;
    }

    auto header = reinterpret_cast<SessionHeader_t*>(inPacket.data());

    message->payloadType = PayloadType::IPMI;
    message->bmcSessionID = endian::from_ipmi<uint32_t>(header->sessId);
    message->sessionSeqNum = endian::from_ipmi<uint32_t>(header->sessSeqNum);
    message->isPacketEncrypted = false;
    message->isPacketAuthenticated = false;

    auto payloadLen = endian::from_ipmi<uint16_t>(header->payloadLength);

    (message->payload).assign(inPacket.data() + sizeof(SessionHeader_t),
                              inPacket.data() + sizeof(SessionHeader_t) +
                              payloadLen);

    return std::move(message);
}

std::vector<uint8_t> Ipmi15Parser::flatten(Message* outMessage)
{
    std::vector<uint8_t> packet;
    packet.reserve(Parser::MESSAGE_MAX_PACKET_LENGTH);
    packet.resize(sizeof(SessionHeader_t));

    // Insert Session Header into the Packet
    auto header = reinterpret_cast<SessionHeader_t*>(packet.data());
    header->base.version = RMCP_VERSION;
    header->base.reserved = 0x00;
    header->base.rmcpSeqNum = RMCP_SEQ;
    header->base.classOfMsg = RMCP_MESSAGE_CLASS_IPMI;
    header->base.format.formatType =
        static_cast<uint8_t>(SessionHeader::IPMI15);
    header->sessSeqNum = 0;
    header->sessId = endian::to_ipmi<uint32_t>(outMessage->rcSessionID);

    header->payloadLength = static_cast<uint8_t>(outMessage->payload.size());

    // Insert the Payload into the Packet
    packet.insert(packet.end(), outMessage->payload.begin(),
                  outMessage->payload.end());

    // Insert the Session Trailer
    auto trailer = reinterpret_cast<SessionTrailer_t*>(packet.data() +
                   packet.size());
    trailer->legacyPad = 0x00;
    packet.resize(packet.size() + sizeof(SessionTrailer_t));

    std::cout << "I> Ipmi15Parser::flatten Packet Size " << packet.size()
              << "\n";

    return packet;
}

std::unique_ptr<Message> Ipmi20Parser::unflatten(std::vector<uint8_t>& inPacket)
{
    auto message = std::make_unique<Message>();

    // Check if the packet has atleast the Session Header
    if (inPacket.size() < sizeof(SessionHeader_t))
    {
        return nullptr;
    }

    auto header = reinterpret_cast<SessionHeader_t*>(inPacket.data());

    message->payloadType = static_cast<PayloadType>
                           (header->payloadType & 0x3F);
    message->bmcSessionID = endian::from_ipmi<uint32_t>(header->sessId);
    message->sessionSeqNum = endian::from_ipmi<uint32_t>(header->sessSeqNum);
    message->isPacketEncrypted =
        ((header->payloadType & PAYLOAD_ENCRYPT_MASK) ? true : false);
    message->isPacketAuthenticated =
        ((header->payloadType & PAYLOAD_AUTH_MASK) ? true : false);

    auto payloadLen = endian::from_ipmi<uint16_t>(header->payloadLength);
    message->payload.assign(inPacket.begin() + sizeof(SessionHeader_t),
                            inPacket.begin() + sizeof(SessionHeader_t) +
                            payloadLen);

    return std::move(message);
}

std::vector<uint8_t> Ipmi20Parser::flatten(Message* outMessage)
{
    auto returnCode = false;

    std::vector<uint8_t> packet;
    packet.reserve(Parser::MESSAGE_MAX_PACKET_LENGTH);
    packet.resize(sizeof(SessionHeader_t));

    SessionHeader_t* header = reinterpret_cast<SessionHeader_t*>(packet.data());
    header->base.version = RMCP_VERSION;
    header->base.reserved = 0x00;
    header->base.rmcpSeqNum = RMCP_SEQ;
    header->base.classOfMsg = RMCP_MESSAGE_CLASS_IPMI;
    header->base.format.formatType =
        static_cast<uint8_t>(SessionHeader::IPMI20);
    header->payloadType = static_cast<uint8_t>(outMessage->payloadType);
    header->sessId = endian::to_ipmi<uint32_t>(outMessage->rcSessionID);

    // Add session sequence number
    returnCode = addSequenceNumber(packet);
    if (returnCode == false)
    {
        std::cerr << "Adding Sequence Number failed";
    }

    // Add Payload
    header->payloadLength =
        endian::to_ipmi<uint16_t>(outMessage->payload.size());
    // Insert the Payload into the Packet
    packet.insert(packet.end(), outMessage->payload.begin(),
                  outMessage->payload.end());

    std::cout << "I> Ipmi20Parser::flatten Packet Size = " << packet.size()
              << "\n";

    return packet;
}

bool Ipmi20Parser::addSequenceNumber(std::vector<uint8_t>& packet)
{
    auto status = false;

    SessionHeader_t* header = reinterpret_cast<SessionHeader_t*>(packet.data());

    if (header->sessId == session::SESSION_ZERO)
    {
        header->sessSeqNum = 0x00;
        status = true;
    }
    else
    {
        auto session = std::get<session::Manager&>(singletonPool).getSession(
                           endian::from_ipmi<uint32_t>(header->sessId),
                           session::RetrieveOption::
                           RETRIEVE_OPTION_RC_SESSION_ID);
        if (session)
        {
            auto seqNum = session->sequenceNums.increment();
            header->sessSeqNum = endian::to_ipmi<uint32_t>(seqNum);
            status = true;
        }
    }
    return status;
}

} // namespace message
