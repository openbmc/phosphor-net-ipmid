#include "message.hpp"

#include <iostream>

#include "message_parsers.hpp"

Message::Message()
    : isFragmented(true),
      isPacketEncrypted(false),
      isPacketAuthenticated(false),
      payloadType(PayloadType::PAYLOAD_TYPE_INVALID),
      sessionId(Message::MESSAGE_INVALID_SESSION_ID),
      bmcSessionId(Message::MESSAGE_INVALID_SESSION_ID),
      sessionSeqNum(0) { }

Message::Message(uint32_t i_sessionId, uint32_t i_bmcSessionId,
                 PayloadType i_payloadType, uint8_t* i_pMessage, size_t i_msgLength,
                 Message* i_inMsg)
    : isFragmented(true),
      isPacketEncrypted(false),
      isPacketAuthenticated(false),
      payloadType(i_payloadType),
      sessionId(i_sessionId),
      bmcSessionId(i_bmcSessionId),
      sessionSeqNum(0)
{
    payload.assign(i_pMessage, i_pMessage + i_msgLength);

    if (i_payloadType != PayloadType::PAYLOAD_TYPE_IPMI)
    {
        parser = std::make_unique<Ipmi20Parser>();
    }
    else if (i_inMsg)
    {
        auto packet = i_inMsg->getPacket();
        parser = MessageParser::getParser(packet);
    }
    else
    {
        parser = std::make_unique<Ipmi20Parser>();
    }

    if (parser == nullptr)
    {
        std::cerr << "E> Message::Message parser == nullptr\n";
    }
}

void Message::flatten()
{
    if (parser && parser->flatten(this))
    {
        //Flatten was successful.. no longer fragmented
        isFragmented = false;
    }
    else
    {
        isFragmented = true;
        std::cerr << "E> Message::flatten : Error no parser available\n";
    }
}

void Message::unflatten()
{
    if (parser && parser->unflatten(this))
    {
        //Unflatten successful
    }
    else
    {
        std::cerr << "E> Message::unflatten : Error no parser available\n";
    }
}

int Message::Send(SocketData& i_channel)
{
    auto l_funRC = 0;
    auto l_channelStatus = 0;
    auto l_rc = 0;

    auto l_spuriousWakeup = false;

    fd_set l_writeSet;
    FD_ZERO(&l_writeSet);

    if (i_channel.getHandle() == -1)
    {
        std::cerr << "E> Not sending packet: i_channel.getHandle()" << std::hex
                  << i_channel.getHandle() << std::endl;
        l_funRC = -1;
        return l_funRC;
    }
    FD_SET(i_channel.getHandle(), &l_writeSet);

    struct timeval l_tv;
    l_tv.tv_sec = 60;
    l_tv.tv_usec = 0;

    do
    {
        // Message is a fragment .. cannot send fragments !
        if (isFragmented)
        {
            std::cerr << "E> Message is a fragment .. cannot send fragments !\n";
            l_funRC = -1;
            break;
        }

        l_spuriousWakeup = false;

        l_rc = select(((i_channel.getHandle()) + 1), NULL, &l_writeSet, NULL, &l_tv);

        if (l_rc > 0)
        {
            if (FD_ISSET(i_channel.getHandle(), &l_writeSet))
            {
                l_channelStatus = i_channel.Write(packet);

                if (l_channelStatus < 0)
                {
                    std::cerr << "E> Error in Write : " << std::hex << l_rc << "\n";
                    l_funRC = -1;
                    break;
                }
                logBuffer(packet.data(), packet.size(), true, i_channel.getPort());
            }
            else
            {
                // Spurious wake up
                std::cout << "I> Spurious wake up on select (Writeset)\n";
                l_spuriousWakeup = true;
            }
        }
        else
        {
            if (l_rc == 0)
            {
                // Timed out
                std::cout << "I> We timed out on select call (writeset)\n";
            }
            else
            {
                // Error
                std::cerr << "E> select call (writeset) had an error : " << errno << "\n";
            }
            l_funRC = -1;
        }
    }
    while (l_spuriousWakeup);

    return l_funRC;
}

int Message::Receive(SocketData& i_channel)
{
    auto l_rc = 0;
    auto l_channelStatus = 0;

    //Use the local buffer to peek into the packet
    packet.resize(Message::MESSAGE_MIN_PEEK_LENGTH);

    do
    {
        //Peek to figure out if we received a RMCP/RMCP+ packet
        l_channelStatus = i_channel.Peek(packet);
        if (l_channelStatus < 0)
        {
            std::cerr << "E> Error in peek :" << std::hex << l_rc << "\n";
            packet.resize(0);
            l_rc = -1;
            break;
        }

        parser = MessageParser::getParser(packet);
        if (parser == nullptr)
        {
            std::cerr << "E> Not an RMCP packet -OR- incorrect packet" << std::endl;
            l_channelStatus = i_channel.Read(packet);
            if (l_channelStatus < 0)
            {
                std::cerr << "E> Error in Read (after failed verify) :" << std::hex << l_rc <<
                          std::endl;
            }
            l_rc = -1;
            packet.resize(0);
            break;
        }

        auto packetLength = parser->getPacketSize(this);
        packet.resize(packetLength);

        std::cout << "Read>> Got parser: read packet length" << packetLength << "\n";

        // Read the packet
        l_channelStatus = i_channel.Read(packet);
        if (l_channelStatus < 0)
        {
            std::cerr << "E> Error in Read : " << std::hex << l_rc << "\n";
            l_rc = -1;
            break;
        }

        //Get the session ID for which this message is intended to.
        sessionId = parser->getSessionID(this);

        logBuffer(packet.data(), packet.size(), false, i_channel.getPort());

    }
    while (0);

    return l_rc;
}

void Message::logBuffer(uint8_t* i_buffer, uint32_t i_bufferLen, bool l_outMsg,
                        uint16_t i_remotePort)
{
    char logbuffer[(3 * i_bufferLen) + 26];
    int index = 0;
    if (l_outMsg)
    {
        sprintf(logbuffer, "0x%8X : Tx: %5d ", bmcSessionId, i_remotePort);
    }
    else
    {
        sprintf(logbuffer, "0x%8X : Rx: %5d ", sessionId, i_remotePort);
    }
    index += 23;

    for (uint16_t loop = 0; loop < (i_bufferLen); loop++)
    {
        sprintf(logbuffer + index, "%02x ", i_buffer[loop]);
        index += 3;
    }
    logbuffer[index] = '\0';
    std::cout << "I>@@ RMCP+: " << logbuffer << "\n";
}
