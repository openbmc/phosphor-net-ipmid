#include "message_handler.hpp"

#include <sys/socket.h>

#include <iostream>
#include <memory>
#include <string>

#include <ipmi.H>
#include "command_table.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

IpmiMessageHandler::IpmiMessageHandler(std::shared_ptr<IpmiSockChannelData>
                                       i_channel)
    : iv_inMsg(nullptr), iv_outMsg(nullptr), iv_channel()
{
    iv_channel = i_channel;
    init();
}

IpmiMessageHandler::~IpmiMessageHandler()
{
    if (iv_inMsg)
    {
        delete iv_inMsg ;
        iv_inMsg = nullptr;
    }
    if (iv_outMsg)
    {
        delete iv_outMsg;
        iv_outMsg = nullptr;
    }
}

//Extract payload
void IpmiMessageHandler::receive()
{
    std::cout << ">> IpmiMessageHandler::receive\n";

    do
    {
        iv_inMsg = new IpmiMessage();

        auto l_rc  = iv_inMsg->Receive(*iv_channel);
        if (l_rc < 0)
        {
            // Handle Error - Write Code
        }

        // Read the Session ID
        std::shared_ptr<Session> l_session =
            SessionsManager::getInstance().getSession
            (iv_inMsg->getSessionId());

        if (l_session == nullptr)
        {
            //The requested session is not found .. drop the message.
            if (iv_inMsg)
            {
                std::cerr << "E> IpmiMessageHandler::receive: No session available !!!\n";
                delete iv_inMsg;
                iv_inMsg = nullptr;
                break;
            }
        }
        else
        {
            iv_session = l_session.get();

            if (l_session->getBMCSessionID() == 0x00)
            {
                std::cout << "I> IpmiMessageHandler::receive: Session ID is zero\n";
            }

            //If the message is for session 0x00, then copy the channel into the session
            if (l_session->getBMCSessionID() == 0x00)
            {
                if ((l_session->getSessionState().isSessionActive()) &&
                    ((iv_channel->getPort() != l_session->getChannel()->getPort()) ||
                     (strcmp(iv_channel->getRemoteAddress(),
                             l_session->getChannel()->getRemoteAddress())
                      != 0)))
                {
                    // Session setup is in progress (Session 0x00 should never be in "Active state" it can
                    // only be in "Setup in Progress" state). If the zero session is in "Setup in progress"
                    // and the IPMI client is different from the one that is trying to setup the session
                    // drop the packet.
                    if (iv_inMsg)
                    {
                        delete iv_inMsg;
                        iv_inMsg = nullptr;
                        std::cerr <<
                                  "E> IpmiMessageHandler::receive: Session Zero is already active!\n";
                        break;
                    }
                }

                //Set the session with the IpmiSockChannel data
                l_session->setChannel(iv_channel);
            }

            if (l_session->getBMCSessionID() != 0x00)
            {
                l_session->getSessionState().updateLastTransactionTime();
            }
        }

        //Found Message
        iv_inMsg->unflatten();

        iv_ipmiFrame = iv_inMsg->getPayload();

        // Unflattening the encrypted payload failed  and the message
        // will be dropped
        if (iv_ipmiFrame == nullptr)
        {
            std::cerr <<
                      "E> IpmiMessageHandler::receive: Unflattening the payload failed !!!\n";
            delete iv_inMsg;
            iv_inMsg = nullptr;
        }
        iv_ipmiFrameLength = iv_inMsg->getPayloadLength();

        if (iv_inMsg->getPayloadType() == IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI)
        {
            //Skip the IPMI LAN Message header to get to the payload
            iv_requestPayload = (iv_ipmiFrame + sizeof(ipmiLanMsgRequestHeader));

            //Subtract length of IPMI LAN Message Header & trailer from the IPMI Frame
            //to get the length of the payload data
            iv_requestPayloadSize = iv_ipmiFrameLength - sizeof(ipmiLanMsgRequestHeader) -
                                    sizeof(ipmiLanMsgTrailer);
        }
        else
        {
            iv_requestPayload = iv_ipmiFrame;
            iv_requestPayloadSize = iv_ipmiFrameLength;
        }
    }
    while (0);

    std::cout << "<< IpmiMessageHandler::receive\n";
}

void IpmiMessageHandler::send()
{
    std::cout << ">> IpmiMessageHandler::send\n";

    IpmiMessageParser* l_parser = nullptr;

    // Get the message parser type from Incoming Packet
    if (iv_inMsg)
    {
        l_parser = IpmiMessageParser::getParser(iv_inMsg->getPacket(),
                                                iv_inMsg->getPacketLength());
    }

    if (iv_session &&
        iv_responsePayloadSize != 0 &&
        iv_inMsg &&
        iv_inMsg->getPayloadType() == IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI)
    {
        uint32_t l_respLen =  sizeof(ipmiLanMsgResponseHeader) + iv_responsePayloadSize
                              +
                              sizeof(ipmiLanMsgTrailer);
        uint8_t* l_resp = new uint8_t[l_respLen];
        uint8_t* l_pTempPtr = l_resp;
        uint32_t l_assembledSize = 0;
        // Assemble the IPMI LAN Message Header
        ipmiLanMsgResponseHeader* l_lanMsgRsHeader = (ipmiLanMsgResponseHeader*)((
                    void*)iv_ipmiFrame);
        ipmiLanMsgRequestHeader* l_lanMsgRqHeader = (ipmiLanMsgRequestHeader*)((
                    void*)iv_ipmiFrame);

        uint8_t l_rqHdrRsAddr    = l_lanMsgRqHeader->rsaddr;
        l_lanMsgRsHeader->rqaddr = l_lanMsgRqHeader->rqaddr;
        l_lanMsgRsHeader->netfn  = l_lanMsgRqHeader->netfn | 0x04;
        l_lanMsgRsHeader->cs     = ipmiCrc8bit(&l_lanMsgRsHeader->rqaddr, 2);
        l_lanMsgRsHeader->rsaddr = l_rqHdrRsAddr;
        l_lanMsgRsHeader->rqseq  = l_lanMsgRqHeader->rqseq; //This is a NOP
        l_lanMsgRsHeader->cmd    = l_lanMsgRqHeader->cmd;   //This is a NOP

        memcpy(l_pTempPtr, iv_ipmiFrame, sizeof(ipmiLanMsgResponseHeader));
        l_pTempPtr += sizeof(ipmiLanMsgResponseHeader);
        l_assembledSize += sizeof(ipmiLanMsgResponseHeader);

        //Assemble the IPMI LAN Message Payload
        memcpy(l_pTempPtr, iv_responsePayload, iv_responsePayloadSize);
        l_pTempPtr += iv_responsePayloadSize;
        l_assembledSize += iv_responsePayloadSize;

        //Add the IPMI LAN Message trailer (checksum2)
        ipmiLanMsgTrailer l_lanMsgRsTrailer = {};
        l_lanMsgRsHeader = (ipmiLanMsgResponseHeader*)l_resp;
        l_lanMsgRsTrailer.checksum2 = ipmiCrc8bit(&l_lanMsgRsHeader->rsaddr,
                                      l_assembledSize - 3);

        memcpy(l_pTempPtr, &l_lanMsgRsTrailer, sizeof(ipmiLanMsgTrailer));
        l_pTempPtr += sizeof(ipmiLanMsgTrailer);
        l_assembledSize += sizeof(ipmiLanMsgTrailer);

        iv_outMsg = new IpmiMessage(iv_session->getRCSessionID(),
                                    iv_session->getBMCSessionID(),
                                    IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI, l_resp, l_respLen, iv_inMsg);

        // Trace the IPMI Outgoing Message
        iv_outMsg->flatten();

        auto l_rc = 0;
        if (iv_channel)
        {
            l_rc = iv_outMsg->Send(*(iv_channel.get()));
        }
        else
        {
            //@TODO: Channel is null ... figure out why?
            std::cerr << "E> IpmiMessageHandler::send: iv_channel is NULL !!!\n";
        }

        if (l_rc < 0)
        {
            std::cerr << "E> IpmiMessageHandler::send: Error in iv_outMsg->Send !!!\n";
            l_rc = 0;
        }

        //Delete the response payload
        if (iv_responsePayload)
        {
            delete[] iv_responsePayload;
            iv_responsePayload = nullptr;
            iv_responsePayloadSize = 0;
        }

        if (l_resp)
        {
            delete[] l_resp;
            l_resp = nullptr;
            l_respLen = 0;
        }

        if (iv_outMsg)
        {
            delete iv_outMsg;
            iv_outMsg = nullptr;
        }
    }

    if (l_parser)
    {
        delete l_parser;
    }

    std::cout << "<< IpmiMessageHandler::send\n";
}

void IpmiMessageHandler::rawSend(IpmiPayloadTypes i_payloadType)
{
    if (iv_responsePayloadSize != 0)
    {
        std::cout << ">> IpmiMessageHandler::rawSend\n";

        iv_outMsg = new IpmiMessage(iv_session->getRCSessionID(),
                                    iv_session->getBMCSessionID(),
                                    i_payloadType, iv_responsePayload, iv_responsePayloadSize);

        // Trace the IPMI outgoing message
        iv_outMsg->flatten();

        auto l_rc = iv_outMsg->Send(*(iv_channel.get()));

        if (l_rc < 0)
        {
            std::cerr << "E> IpmiMessageHandler::rawSend: Error in iv_outMsg->Send !!!\n";
            l_rc = 0;
        }

        // Delete the response payload
        if (iv_responsePayload)
        {
            delete[] iv_responsePayload;
            iv_responsePayload = nullptr;
            iv_responsePayloadSize = 0;
        }

        if (iv_outMsg)
        {
            delete iv_outMsg;
            iv_outMsg = nullptr;
        }
    }
}

uint32_t IpmiMessageHandler::getSessionId(void)
{
    return (iv_session) ? iv_session->getBMCSessionID()
           : IpmiMessage::IPMI_MESSAGE_INVALID_SESSION_ID;
}

uint32_t IpmiMessageHandler::getRemoteConsoleSessionId(void)
{
    return (iv_session) ? iv_session->getRCSessionID()
           : IpmiMessage::IPMI_MESSAGE_INVALID_SESSION_ID;
}

uint8_t IpmiMessageHandler::getSessionHandle(void)
{
    return (iv_session) ? iv_session->getSessionHandle() : 0xFF;
}

uint16_t IpmiMessageHandler::getSessionPortNumber(void)
{
    uint16_t l_portNum = 0x0BAD;

    if (iv_session)
    {
        struct sockaddr_in l_sockName;
        uint32_t l_sockAddrLen = sizeof(l_sockName);
        if (!getsockname(iv_session->getChannel()->getHandle(),
                         (struct sockaddr*)&l_sockName, &l_sockAddrLen))
        {
            if (((struct sockaddr*)&l_sockName)->sa_family != AF_UNIX)
            {
                l_portNum = ntohs(l_sockName.sin_port);
            }
        }
        else
        {
            std::cerr << "E> Error in getsockname: Errno: 0x" << std::hex << errno << "\n";
        }
    }

    return l_portNum;
}

void IpmiMessageHandler::activateShutdown(void)
{
    if (iv_session && iv_session->getBMCSessionID() != 0)
    {
        SessionsManager::getInstance().stopSession(iv_session->getBMCSessionID());
    }
}

bool IpmiMessageHandler::wasShutdownActivated(void)
{
    bool l_ret = true;

    if (iv_session)
    {
        if (iv_session->getBMCSessionID() == 0)
        {
            l_ret = false;
        }
        else
        {
            l_ret = (iv_session->getSessionState().getSessionState()
                     != SessionState::IPMI_SESSION_IS_ACTIVE) ? true : false;
        }
    }

    return l_ret;
}

uint8_t IpmiMessageHandler::getPayloadType()
{
    return iv_inMsg ? iv_inMsg->getPayloadType() :
           IpmiMessage::IPMI_PAYLOAD_TYPE_INVALID;
}

uint32_t IpmiMessageHandler::getCommand(void)
{
    uint32_t l_cmd = 0 ;

    if (iv_inMsg)
    {
        l_cmd |= (0 << 24); //@TODO: use channel number?
        l_cmd |= (iv_inMsg->getPayloadType() << 16);
        if (iv_inMsg->getPayloadType() == IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI)
        {
            l_cmd |= ((reinterpret_cast<ipmiLanMsgRequestHeader*>(iv_ipmiFrame))->netfn) <<
                     8;
            l_cmd |= (reinterpret_cast<ipmiLanMsgRequestHeader*>(iv_ipmiFrame))->cmd;
        }
    }

    return l_cmd;
}

void IpmiMessageHandler::init()
{
    if (iv_inMsg)
    {
        delete iv_inMsg;
        iv_inMsg  = nullptr;
    }
    if (iv_outMsg)
    {
        delete iv_outMsg;
        iv_outMsg = nullptr;
    }

    iv_responsePayload = iv_requestPayload = iv_ipmiFrame = nullptr;
    iv_responsePayloadSize = iv_requestPayloadSize = iv_ipmiFrameLength = 0;
}

void IpmiMessageHandler::route(void)
{
    std::cout << ">> IpmiMessageHandler::route\n";
    if (iv_inMsg == nullptr)
    {
        std::cerr << "E> IpmiMessageHandler::route iv_inMsg == NULL !!!\n";
    }

    if (iv_inMsg)
    {
        std::cout << "I> IpmiMessageHandler::route Execute command\n";
        CommandTable::getInstance().ExecuteCommand(getCommand(), *this);
    }
}

uint32_t IpmiMessageHandler::getSessionPrivilegeLevel(void)
{
    return iv_session->getSessionState().getOperatingPrivilegeLevel();
}

void IpmiMessageHandler::setSessionPrivilegeLevel(uint32_t i_sessionPrivilege)
{
    iv_session->getSessionState().setOperatingPrivilegeLevel(i_sessionPrivilege);
}

uint32_t IpmiMessageHandler::getSessionMaxPrivilegeLevel(void)
{
    return iv_session->getSessionState().getMaxPrivilegeLevel();
}

uint32_t IpmiMessageHandler::getSessionUserID(void)
{
    return iv_session->getSessionState().getUserID();
}

std::shared_ptr<IpmiSockChannelData>& IpmiMessageHandler::getChannelObject()
{
    return iv_channel;
}

uint8_t ipmiCrc8bit(const uint8_t* i_ptr, const int i_len)
{
    uint8_t l_r = 0;
    int l_i = 0;

    while (l_i != i_len)
    {
        l_r += *(i_ptr + l_i);
        l_i++;
    }

    return 0x100 - l_r;
}

uint16_t ipmiCrc16bit(const uint8_t* i_ptr, int i_len)
{
    uint16_t l_r = 0;
    int l_i = 0;

    while (l_i != i_len)
    {
        l_r += *(i_ptr + l_i);
        l_i++;
    }

    return 0x10000 - l_r;
}

uint8_t ipmiProcessDataLen(uint8_t i_ipmiDataLen,
                           IpmiMessageHandler& i_sessCtl)
{
    uint8_t l_rc = IPMICC_NORMAL;

    // Validate the Request data length
    if (i_ipmiDataLen != (i_sessCtl.iv_requestPayloadSize))
    {
        l_rc = IPMICC_REQ_DATA_LEN_INVALID;
    }

    return l_rc;
}

uint8_t ipmiProcessDataLenRange(uint8_t i_ipmiDataLenLower,
                                uint16_t i_ipmiDataLenUpper,
                                IpmiMessageHandler& i_sessCtl)
{
    uint8_t l_rc = IPMICC_NORMAL;
    uint16_t l_packetlen = i_sessCtl.iv_requestPayloadSize;

    // Validate the Request data length if it is between the given range
    if ((l_packetlen >= i_ipmiDataLenLower) && (l_packetlen <= i_ipmiDataLenUpper))
    {
        l_rc = IPMICC_NORMAL;
    }
    else
    {
        l_rc = IPMICC_REQ_DATA_LEN_INVALID;
    }

    return l_rc;
}
