#include "message.hpp"

#include <iostream>

#include "message_parsers.hpp"

IpmiMessageParser::~IpmiMessageParser() {}

IpmiMessage::IpmiMessage()
    : iv_isFragment(true),
      iv_parser(),
      iv_isPacketEncrypted(false),
      iv_isPacketAuthenticated(false),
      iv_payloadType(IPMI_PAYLOAD_TYPE_INVALID),
      iv_sessionId(IPMI_MESSAGE_INVALID_SESSION_ID),
      iv_bmcSessionId(IPMI_MESSAGE_INVALID_SESSION_ID),
      iv_sessionSeqNum(0),
      iv_packetLength(0),
      iv_packet(nullptr),
      iv_packetRequiresDelete(false),
      iv_payloadLength(0),
      iv_payload(nullptr),
      iv_payloadRequiresDelete(false),
      iv_integrityDataLength(0),
      iv_integrityData(nullptr),
      iv_integrityDataRequiresDelete(false) {}

//Outgoing Message
IpmiMessage::IpmiMessage(uint32_t i_sessionId, uint32_t i_bmcSessionId,
                         uint8_t i_payloadType, uint8_t* i_pMessage, uint16_t i_msgLength,
                         IpmiMessage* i_inMsg)
    : iv_isFragment(true),
      iv_parser(),
      iv_isPacketEncrypted(false),
      iv_isPacketAuthenticated(false),
      iv_payloadType(i_payloadType),
      iv_sessionId(i_sessionId),
      iv_bmcSessionId(i_bmcSessionId),
      iv_sessionSeqNum(0),
      iv_packetLength(0),
      iv_packet(nullptr),
      iv_packetRequiresDelete(false),
      iv_payloadLength(i_msgLength),
      iv_payload(new uint8_t[i_msgLength]),
      iv_payloadRequiresDelete(true),
      iv_integrityDataLength(0),
      iv_integrityData(nullptr),
      iv_integrityDataRequiresDelete(false)
{
    memcpy(iv_payload, i_pMessage, iv_payloadLength);

    if (i_payloadType != IPMI_PAYLOAD_TYPE_IPMI)
    {
        iv_parser = new Ipmi20Parser;
    }
    else if (i_inMsg)
    {
        iv_parser = IpmiMessageParser::getParser(i_inMsg->getPacket(),
                    i_inMsg->getPacketLength());
    }
    else
    {
        // i_payloadType != IPMI_PAYLOAD_TYPE_IPMI|| i_inMsg == nullptr
        iv_parser = new Ipmi20Parser;
    }

    if (iv_parser == nullptr)
    {
        std::cerr << "E> IpmiMessage::IpmiMessage iv_parser == nullptr" << std::endl;
    }
}

//Default DTOR
IpmiMessage::~IpmiMessage()
{
    reset();
}

void IpmiMessage::reset()
{
    iv_isFragment = true;

    if (iv_parser)
    {
        delete iv_parser;
        iv_parser = nullptr;
    }

    iv_isPacketEncrypted = false;
    iv_isPacketAuthenticated = false;
    iv_payloadType = IPMI_PAYLOAD_TYPE_INVALID;
    iv_sessionId = IPMI_MESSAGE_INVALID_SESSION_ID;
    iv_sessionSeqNum = 0;
    iv_packetLength = 0;
    if (iv_packetRequiresDelete && iv_packet)
    {
        delete[] iv_packet;
        iv_packet = nullptr;
    }
    iv_packetRequiresDelete = false;
    iv_payloadLength = 0;
    if (iv_payloadRequiresDelete && iv_payload)
    {
        delete[] iv_payload;
        iv_payload = nullptr;
    }
    iv_payloadRequiresDelete = false;
    iv_integrityDataLength = 0;
    if (iv_integrityDataRequiresDelete && iv_integrityData)
    {
        delete[] iv_integrityData;
        iv_integrityData = nullptr;
    }
    iv_integrityDataRequiresDelete = false;
}

//Get Payload Type
uint8_t IpmiMessage::getPayloadType(void)
{
    return iv_payloadType;
}

uint8_t IpmiMessage::setPayloadType(uint8_t i_type)
{
    iv_payloadType = i_type;
    return iv_payloadType;
}

//Get the session ID from the Session ID field of the packet
uint32_t& IpmiMessage::getSessionId(void)
{
    return iv_sessionId;
}

uint32_t& IpmiMessage::getBmcSessionId(void)
{
    return iv_bmcSessionId;
}

void IpmiMessage::setSessionId(uint32_t& i_sessionID)
{
    iv_sessionId = i_sessionID;
}

void IpmiMessage::setBmcSessionId(uint32_t& i_sessionID)
{
    iv_bmcSessionId = i_sessionID;
}

//Get the session Sequence Number - Host-ordered
uint32_t& IpmiMessage::getSessionSeqNum(void)
{
    return iv_sessionSeqNum;
}

void IpmiMessage::setSessionSeqNum(uint32_t& i_val)
{
    iv_sessionSeqNum = i_val;
}

bool IpmiMessage::getIsPacketEncrypted()
{
    return iv_isPacketEncrypted;
}

bool IpmiMessage::setIsPacketEncrypted(bool i_isEncrypted)
{
    iv_isPacketEncrypted = i_isEncrypted;
    return iv_isPacketEncrypted;
}

bool IpmiMessage::getIsPacketAuthenticated()
{
    return iv_isPacketAuthenticated;
}

bool IpmiMessage::setIsPacketAuthenticated(bool i_isAuth)
{
    iv_isPacketAuthenticated = i_isAuth;
    return iv_isPacketAuthenticated;
}

//Get the packet
uint8_t* IpmiMessage::getPacket(void)
{
    return iv_packet;
}

//Get the packet
uint8_t* IpmiMessage::setPacket(uint8_t* i_pkt, bool i_deleteRequired)
{
    iv_packet = i_pkt;
    iv_packetRequiresDelete = i_deleteRequired;
    return iv_packet;
}

//Get the packet length
uint32_t IpmiMessage::getPacketLength(void)
{
    return iv_packetLength;
}

uint32_t IpmiMessage::setPacketLength(uint32_t i_val)
{
    iv_packetLength = i_val;
    return iv_packetLength;
}

uint8_t* IpmiMessage::getPayload(void)
{
    return iv_payload;
}

uint8_t* IpmiMessage::setPayload(uint8_t* i_pkt, bool i_deleteRequired)
{
    iv_payload = i_pkt;
    iv_payloadRequiresDelete = i_deleteRequired;
    return iv_payload;
}

uint16_t& IpmiMessage::getPayloadLength(void)
{
    return iv_payloadLength;
}

void IpmiMessage::setPayloadLength(uint16_t& i_val)
{
    iv_payloadLength = i_val;
}

uint8_t* IpmiMessage::getIntegrityData(void)
{
    return iv_integrityData;
}

uint8_t* IpmiMessage::setIntegrityData(uint8_t* i_pkt, bool i_deleteRequired)
{
    iv_integrityData = i_pkt;
    iv_integrityDataRequiresDelete = i_deleteRequired;
    return iv_integrityData;
}

uint32_t IpmiMessage::getIntegrityDataLength(void)
{
    return iv_integrityDataLength;
}

uint32_t IpmiMessage::setIntegrityDataLength(uint32_t i_val)
{
    iv_integrityDataLength = i_val;
    return iv_integrityDataLength;
}

void IpmiMessage::flatten()
{
    if (iv_parser && iv_parser->flatten(this))
    {
        //Flatten was successful.. no longer fragmented
        iv_isFragment = false;
    }
    else
    {
        iv_isFragment = true;
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
        if (iv_isFragment)
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
                l_channelStatus = i_channel.Write(iv_packet, iv_packetLength);

                if (l_channelStatus < 0)
                {
                    std::cerr << "E> Error in Write : " << std::hex << l_rc << std::endl;
                    l_funRC = -1;
                    break;
                }
                logBuffer(iv_packet, iv_packetLength, true, i_channel.getPort());
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
    if (iv_packetRequiresDelete && iv_packet)
    {
        delete[] iv_packet;
        iv_packet = nullptr;
        iv_packetLength = 0;
    }

    //Use the local buffer to peek into the packet
    uint8_t l_peekBuffer[IPMI_MESSAGE_MIN_PEEK_LENGTH] = {};
    iv_packet = l_peekBuffer;
    uint32_t l_bufferSize = IPMI_MESSAGE_MIN_PEEK_LENGTH;
    iv_packetLength = l_bufferSize;

    do
    {
        //Peek to figure out if we received a RMCP/RMCP+ packet
        l_channelStatus = i_channel.Peek(iv_packet, iv_packetLength);
        if (l_channelStatus < 0)
        {
            std::cerr << "E> Error in peek :" << std::hex << l_rc << std::endl;
            iv_packet = nullptr;
            l_rc = -1;
            break;
        }

        iv_parser = IpmiMessageParser::getParser(iv_packet, iv_packetLength);
        if (iv_parser == nullptr)
        {
            std::cerr << "E> Not an RMCP packet -OR- incorrect packet" << std::endl;
            l_channelStatus = i_channel.Read(iv_packet, iv_packetLength);
            if (l_channelStatus < 0)
            {
                std::cerr << "E> Error in Read (after failed verify) :" << std::hex << l_rc <<
                          std::endl;
            }
            l_rc = -1;
            iv_packet = nullptr;
            break;
        }

        iv_packetLength = iv_parser->getPacketSize(this);
        std::cout << "Read>> Got parser: read packet length" << iv_packetLength <<
                  std::endl;

        //Allocate memory to read the packet into.
        iv_packet = new uint8_t[iv_packetLength];
        iv_packetRequiresDelete = true;
        //Clear the memory
        bzero(iv_packet, iv_packetLength);

        l_channelStatus = i_channel.Read(iv_packet, iv_packetLength);
        if (l_channelStatus < 0)
        {
            std::cerr << "E> Error in Read : " << std::hex << l_rc << std::endl;
            l_rc = -1;
            break;
        }
        std::cout << "<<Read" << std::endl;

        //Get the session ID for which this message is intended to.
        iv_sessionId = iv_parser->getSessionID(this);

        logBuffer(iv_packet, iv_packetLength, false, i_channel.getPort());

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
        sprintf(logbuffer, "0x%8X : Tx: %5d ", iv_bmcSessionId, i_remotePort);
    }
    else
    {
        sprintf(logbuffer, "0x%8X : Rx: %5d ", iv_sessionId, i_remotePort);
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
    if (iv_parser && iv_parser->unflatten(this))
    {
        //Unflatten successful
    }
    else
    {
        std::cerr << "E> IpmiMessage::unflatten : Error no parser available" <<
                  std::endl;
    }
}
