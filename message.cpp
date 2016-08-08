#include "message.hpp"

#include <iostream>

#include "message_parsers.hpp"

IpmiMessageParser::~IpmiMessageParser() {}

IpmiMessage::IpmiMessage()
    : isFragment(true),
      parser(),
      isPacketEncrypted(false),
      isPacketAuthenticated(false),
      payloadType(IPMI_PAYLOAD_TYPE_INVALID),
      sessionId(IPMI_MESSAGE_INVALID_SESSION_ID),
      bmcSessionId(IPMI_MESSAGE_INVALID_SESSION_ID),
      sessionSeqNum(0),
      packetLength(0),
      packet(nullptr),
      packetRequiresDelete(false),
      payloadLength(0),
      payload(nullptr),
      payloadRequiresDelete(false),
      integrityDataLength(0),
      integrityData(nullptr),
      integrityDataRequiresDelete(false) {}

//Outgoing Message
IpmiMessage::IpmiMessage(uint32_t i_sessionId, uint32_t i_bmcSessionId,
                         uint8_t i_payloadType, uint8_t* i_pMessage, uint16_t i_msgLength,
                         IpmiMessage* i_inMsg)
    : isFragment(true),
      parser(),
      isPacketEncrypted(false),
      isPacketAuthenticated(false),
      payloadType(i_payloadType),
      sessionId(i_sessionId),
      bmcSessionId(i_bmcSessionId),
      sessionSeqNum(0),
      packetLength(0),
      packet(nullptr),
      packetRequiresDelete(false),
      payloadLength(i_msgLength),
      payload(new uint8_t[i_msgLength]),
      payloadRequiresDelete(true),
      integrityDataLength(0),
      integrityData(nullptr),
      integrityDataRequiresDelete(false)
{
    memcpy(payload, i_pMessage, payloadLength);

    if (i_payloadType != IPMI_PAYLOAD_TYPE_IPMI)
    {
        parser = new Ipmi20Parser;
    }
    else if (i_inMsg)
    {
        parser = IpmiMessageParser::getParser(i_inMsg->getPacket(),
                                              i_inMsg->getPacketLength());
    }
    else
    {
        // i_payloadType != IPMI_PAYLOAD_TYPE_IPMI|| i_inMsg == nullptr
        parser = new Ipmi20Parser;
    }

    if (parser == nullptr)
    {
        std::cerr << "E> IpmiMessage::IpmiMessage parser == nullptr" << std::endl;
    }
}

//Default DTOR
IpmiMessage::~IpmiMessage()
{
    reset();
}

void IpmiMessage::reset()
{
    isFragment = true;

    if (parser)
    {
        delete parser;
        parser = nullptr;
    }

    isPacketEncrypted = false;
    isPacketAuthenticated = false;
    payloadType = IPMI_PAYLOAD_TYPE_INVALID;
    sessionId = IPMI_MESSAGE_INVALID_SESSION_ID;
    sessionSeqNum = 0;
    packetLength = 0;
    if (packetRequiresDelete && packet)
    {
        delete[] packet;
        packet = nullptr;
    }
    packetRequiresDelete = false;
    payloadLength = 0;
    if (payloadRequiresDelete && payload)
    {
        delete[] payload;
        payload = nullptr;
    }
    payloadRequiresDelete = false;
    integrityDataLength = 0;
    if (integrityDataRequiresDelete && integrityData)
    {
        delete[] integrityData;
        integrityData = nullptr;
    }
    integrityDataRequiresDelete = false;
}

//Get Payload Type
uint8_t IpmiMessage::getPayloadType(void)
{
    return payloadType;
}

uint8_t IpmiMessage::setPayloadType(uint8_t i_type)
{
    payloadType = i_type;
    return payloadType;
}

//Get the session ID from the Session ID field of the packet
uint32_t& IpmiMessage::getSessionId(void)
{
    return sessionId;
}

uint32_t& IpmiMessage::getBmcSessionId(void)
{
    return bmcSessionId;
}

void IpmiMessage::setSessionId(uint32_t& i_sessionID)
{
    sessionId = i_sessionID;
}

void IpmiMessage::setBmcSessionId(uint32_t& i_sessionID)
{
    bmcSessionId = i_sessionID;
}

//Get the session Sequence Number - Host-ordered
uint32_t& IpmiMessage::getSessionSeqNum(void)
{
    return sessionSeqNum;
}

void IpmiMessage::setSessionSeqNum(uint32_t& i_val)
{
    sessionSeqNum = i_val;
}

bool IpmiMessage::getIsPacketEncrypted()
{
    return isPacketEncrypted;
}

bool IpmiMessage::setIsPacketEncrypted(bool i_isEncrypted)
{
    isPacketEncrypted = i_isEncrypted;
    return isPacketEncrypted;
}

bool IpmiMessage::getIsPacketAuthenticated()
{
    return isPacketAuthenticated;
}

bool IpmiMessage::setIsPacketAuthenticated(bool i_isAuth)
{
    isPacketAuthenticated = i_isAuth;
    return isPacketAuthenticated;
}

//Get the packet
uint8_t* IpmiMessage::getPacket(void)
{
    return packet;
}

//Get the packet
uint8_t* IpmiMessage::setPacket(uint8_t* i_pkt, bool i_deleteRequired)
{
    packet = i_pkt;
    packetRequiresDelete = i_deleteRequired;
    return packet;
}

//Get the packet length
uint32_t IpmiMessage::getPacketLength(void)
{
    return packetLength;
}

uint32_t IpmiMessage::setPacketLength(uint32_t i_val)
{
    packetLength = i_val;
    return packetLength;
}

uint8_t* IpmiMessage::getPayload(void)
{
    return payload;
}

uint8_t* IpmiMessage::setPayload(uint8_t* i_pkt, bool i_deleteRequired)
{
    payload = i_pkt;
    payloadRequiresDelete = i_deleteRequired;
    return payload;
}

uint16_t& IpmiMessage::getPayloadLength(void)
{
    return payloadLength;
}

void IpmiMessage::setPayloadLength(uint16_t& i_val)
{
    payloadLength = i_val;
}

uint8_t* IpmiMessage::getIntegrityData(void)
{
    return integrityData;
}

uint8_t* IpmiMessage::setIntegrityData(uint8_t* i_pkt, bool i_deleteRequired)
{
    integrityData = i_pkt;
    integrityDataRequiresDelete = i_deleteRequired;
    return integrityData;
}

uint32_t IpmiMessage::getIntegrityDataLength(void)
{
    return integrityDataLength;
}

uint32_t IpmiMessage::setIntegrityDataLength(uint32_t i_val)
{
    integrityDataLength = i_val;
    return integrityDataLength;
}

void IpmiMessage::flatten()
{
    if (parser && parser->flatten(this))
    {
        //Flatten was successful.. no longer fragmented
        isFragment = false;
    }
    else
    {
        isFragment = true;
        std::cerr << "E> IpmiMessage::flatten : Error no parser available" << std::endl;
    }
}

int IpmiMessage::Send(IpmiSockChannelData& i_channel)
{
    int l_funRC = 0;
    int l_channelStatus = 0;
    int l_rc = 0;

    bool l_spuriousWakeup = false;

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
        if (isFragment)
        {
            std::cerr << "E> Message is a fragment .. cannot send fragments !" << std::endl;
            l_funRC = -1;
            break;
        }

        l_spuriousWakeup = false;

        l_rc = select(((i_channel.getHandle()) + 1), NULL, &l_writeSet, NULL, &l_tv);

        if (l_rc > 0)
        {
            if (FD_ISSET(i_channel.getHandle(), &l_writeSet))
            {
                l_channelStatus = i_channel.Write(packet, packetLength);

                if (l_channelStatus < 0)
                {
                    std::cerr << "E> Error in Write : " << std::hex << l_rc << std::endl;
                    l_funRC = -1;
                    break;
                }
                logBuffer(packet, packetLength, true, i_channel.getPort());
            }
            else
            {
                // Spurious wake up
                std::cout << "I> Spurious wake up on select (Writeset)" << std::endl;
                l_spuriousWakeup = true;
            }
        }
        else
        {
            if (l_rc == 0)
            {
                // Timed out
                std::cout << "I> We timed out on select call (writeset)" << std::endl;
            }
            else
            {
                // Error
                std::cerr << "E> select call (writeset) had an error : " << errno << std::endl;
            }
            l_funRC = -1;
        }
    }
    while (l_spuriousWakeup);

    return l_funRC;
}

int IpmiMessage::Receive(IpmiSockChannelData& i_channel)
{
    int l_rc = 0;
    int l_channelStatus = 0;

    //If we already have a packet, delete it
    if (packetRequiresDelete && packet)
    {
        delete[] packet;
        packet = nullptr;
        packetLength = 0;
    }

    //Use the local buffer to peek into the packet
    uint8_t l_peekBuffer[IPMI_MESSAGE_MIN_PEEK_LENGTH] = {};
    packet = l_peekBuffer;
    uint32_t l_bufferSize = IPMI_MESSAGE_MIN_PEEK_LENGTH;
    packetLength = l_bufferSize;

    do
    {
        //Peek to figure out if we received a RMCP/RMCP+ packet
        l_channelStatus = i_channel.Peek(packet, packetLength);
        if (l_channelStatus < 0)
        {
            std::cerr << "E> Error in peek :" << std::hex << l_rc << std::endl;
            packet = nullptr;
            l_rc = -1;
            break;
        }

        parser = IpmiMessageParser::getParser(packet, packetLength);
        if (parser == nullptr)
        {
            std::cerr << "E> Not an RMCP packet -OR- incorrect packet" << std::endl;
            l_channelStatus = i_channel.Read(packet, packetLength);
            if (l_channelStatus < 0)
            {
                std::cerr << "E> Error in Read (after failed verify) :" << std::hex << l_rc <<
                          std::endl;
            }
            l_rc = -1;
            packet = nullptr;
            break;
        }

        packetLength = parser->getPacketSize(this);
        std::cout << "Read>> Got parser: read packet length" << packetLength <<
                  std::endl;

        //Allocate memory to read the packet into.
        packet = new uint8_t[packetLength];
        packetRequiresDelete = true;
        //Clear the memory
        bzero(packet, packetLength);

        l_channelStatus = i_channel.Read(packet, packetLength);
        if (l_channelStatus < 0)
        {
            std::cerr << "E> Error in Read : " << std::hex << l_rc << std::endl;
            l_rc = -1;
            break;
        }
        std::cout << "<<Read" << std::endl;

        //Get the session ID for which this message is intended to.
        sessionId = parser->getSessionID(this);

        logBuffer(packet, packetLength, false, i_channel.getPort());

    }
    while (0);

    return l_rc;
}

void IpmiMessage::logBuffer(uint8_t* i_buffer, uint32_t i_bufferLen,
                            bool l_outMsg,
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
    std::cout << "I>@@ RMCP+: " << logbuffer << std::endl;
}

void IpmiMessage::unflatten()
{
    if (parser && parser->unflatten(this))
    {
        //Unflatten successful
    }
    else
    {
        std::cerr << "E> IpmiMessage::unflatten : Error no parser available" <<
                  std::endl;
    }
}
