#pragma once

#include "message.hpp"
#include "session.hpp"

class IpmiMessageHandler
{
    public:

        enum IpmiPayloadTypes //@TODO: Move this to IpmiMessage::IpmiPayloadType
        {
            IPMI_REQUEST_PAYLOAD = 0x00,
            IPMI_SOL_PAYLOAD = 0x01,
            IPMI_OEM_EXPLICIT_PAYLOAD = 0x02,
            IPMI_RMCPP_OPEN_SESS_REQUEST = 0x10,
            IPMI_RMCPP_OPEN_SESS_RESPONSE = 0x11,
            IPMI_RMCPP_RAKP1 = 0x12,
            IPMI_RMCPP_RAKP2 = 0x13,
            IPMI_RMCPP_RAKP3 = 0x14,
            IPMI_RMCPP_RAKP4 = 0x15,
            IPMI_INVALID_PAYLOAD = 0xFF,
        };

#pragma pack(1)
        // IPMI Message Headers/Trailers
        struct ipmiLanMsgRequestHeader
        {
            uint8_t rsaddr;
            uint8_t netfn;
            uint8_t cs;
            uint8_t rqaddr;
            uint8_t rqseq;
            uint8_t cmd;
        };

        struct ipmiLanMsgResponseHeader
        {
            uint8_t rqaddr;
            uint8_t netfn;
            uint8_t cs;
            uint8_t rsaddr;
            uint8_t rqseq;
            uint8_t cmd;
        };

        struct ipmiLanMsgTrailer
        {
            uint8_t checksum2;
        };
#pragma pack()

        IpmiMessageHandler(std::shared_ptr<IpmiSockChannelData> i_channel);

        ~IpmiMessageHandler();

    public:
        //Extract payload
        void receive();

        void send();

        void rawSend(IpmiPayloadTypes i_payloadType);

        uint32_t getSessionId(void);

        uint32_t getRemoteConsoleSessionId(void);

        uint8_t getSessionHandle(void);

        uint16_t getSessionPortNumber(void);

        void activateShutdown(void);

        bool wasShutdownActivated(void);

        uint8_t getPayloadType();

        uint32_t getCommand(void);

        void init();

        void route(void);

        uint32_t getSessionPrivilegeLevel(void);

        void setSessionPrivilegeLevel(uint32_t i_sessionPrivilege);

        uint32_t getSessionMaxPrivilegeLevel(void);

        uint32_t getSessionUserID(void);

        std::shared_ptr<IpmiSockChannelData>& getChannelObject();

        /**
         *  @brief Default CTOR
         */
        IpmiMessageHandler();

        uint8_t* iv_responsePayload;         //<Pointer to the response payload
        // buffer. Command functions should
        // allocate memory.
        uint32_t iv_responsePayloadSize;     //<Size of the response payload buffer.
        // Allocator should fill the size.

        uint8_t* iv_requestPayload;          //<Pointer to the request payload
        // buffer.
        uint32_t iv_requestPayloadSize;      //<Size of the request payload buffer.

    private: //Attributes
        uint8_t* iv_ipmiFrame;              //Only for access .. do not delete
        uint16_t iv_ipmiFrameLength;

        std::shared_ptr<Session> iv_pSession;
        Session* iv_session;

        IpmiMessage* iv_inMsg;
        IpmiMessage* iv_outMsg;

        std::shared_ptr<IpmiSockChannelData> iv_channel;
};

//******************************************************************************
/**
 *@fn uint16_t ipmiCrc16bit(const uint8_t *, int)
 *
 * @brief Description:
 * This function will calculate a 16 bit 2s complement CRC
 *
 * @pre None
 *
 * @param i_ptr - uint8_t * - Buffer string to calculate CRC on
 * @param i_len - int - length of bytes to calculate CRC on
 *
 * @post None
 *
 * @return the 16bit CRC
 * @retval uint16_t
 *
 */
//******************************************************************************
uint16_t ipmiCrc16bit(const uint8_t* i_ptr, int i_len);
uint8_t ipmiCrc8bit(const uint8_t* i_ptr, const int i_len);


/**
 * @brief ipmiProcessDataLen : Validate length of the IPMI request packet
 *
 * @par Detailed Description:
 *  This function will validate the length of the IPMI request packet in the
 *  IpmiSessionControl frame and return the IPMI completion code value.
 *
 * @param i_ipmiDataLen: Expected length for the IPMI request packet
 *
 * @param i_sessCtl : Session control object for the IPMI commands
 *
 * @retval: IPMICC_NORMAL
 *          IPMICC_REQ_DATA_LEN_INVALID
 */
uint8_t ipmiProcessDataLen(uint8_t i_ipmiDataLen,
                           IpmiMessageHandler& i_sessCtl);

