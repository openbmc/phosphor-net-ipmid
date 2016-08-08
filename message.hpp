#pragma once

#include "app_util.hpp"
#include "sock_channel_data.hpp"

class IpmiMessage;

class IpmiMessageParser
{
    public:
        enum IpmiAuthTypeFormat
        {
            IPMI_AUTHTYPE_FORMAT_IPMI15_NONE = 0x00,
            IPMI_AUTHTYPE_FORMAT_IPMI20      = 0x06,
        };

#pragma pack(1)
        struct BasicHeader_t
        {
            //RMCP Header
            uint8_t version;
            uint8_t reserved;
            uint8_t rmcpSeqNum;
            uint8_t classOfMsg;

            //IPMI partial session header
            union
            {
                uint8_t reserved1: 4;
                uint8_t authType: 4;

                uint8_t formatType;
            } format;
        };
#pragma pack()

        static IpmiMessageParser* getParser(uint8_t* i_pkt, uint32_t i_pktLen);

        virtual ~IpmiMessageParser();

        virtual uint32_t getPacketSize(IpmiMessage* i_msg) = 0;

        virtual uint32_t getSessionID(IpmiMessage* i_msg) = 0;

        virtual bool unflatten(IpmiMessage* i_msg) = 0;

        virtual bool flatten(IpmiMessage* i_msg) = 0;

    protected:
        IpmiMessageParser() {}
};

class IpmiMessage
{
    public:
        enum IpmiPayloadType
        {
            IPMI_PAYLOAD_TYPE_IPMI                  = 0x00,
            IPMI_PAYLOAD_TYPE_SOL                   = 0x01,
            IPMI_PAYLOAD_TYPE_OEM                   = 0x02,
            IPMI_PAYLOAD_TYPE_OPEN_SESS_REQUEST     = 0x10,
            IPMI_PAYLOAD_TYPE_OPEN_SESS_RESPONSE    = 0x11,
            IPMI_PAYLOAD_TYPE_RAKP1                 = 0x12,
            IPMI_PAYLOAD_TYPE_RAKP2                 = 0x13,
            IPMI_PAYLOAD_TYPE_RAKP3                 = 0x14,
            IPMI_PAYLOAD_TYPE_RAKP4                 = 0x15,
            IPMI_PAYLOAD_TYPE_IPC                   = 0xFE,
            IPMI_PAYLOAD_TYPE_INVALID               = 0xFF,
        };

        enum IpmiMessageDefines
        {
            IPMI_MESSAGE_MIN_PEEK_LENGTH = 16, //Minimum required is the IPMI header
            //of a RMCP+ packet
            IPMI_MESSAGE_MAX_PACKET_LENGTH = 512, //Maximum packet size that we'll
            //handle
            IPMI_MESSAGE_INVALID_SESSION_ID = 0xBADBADFF,
        };

        //Incoming Message
        IpmiMessage();

        //Outgoing Message
        IpmiMessage(uint32_t i_sessionId, uint32_t i_bmcSessionId,
                    uint8_t i_payloadType,
                    uint8_t* i_pMessage, uint16_t i_msgLength, IpmiMessage* i_inMsg = NULL);

        //Default DTOR
        virtual ~IpmiMessage();

        virtual void reset();

        //Get Payload Type
        uint8_t getPayloadType(void);
        uint8_t setPayloadType(uint8_t i_type);

        //Get the session ID from the Session ID field of the packet
        uint32_t& getSessionId(void);

        //Get the BMC session ID ... use only when sending a response
        //Returns session ID when "outgoing message" ctor was used to construct this
        //object .. else will return IPMI_MESSAGE_INVALID_SESSION_ID.
        uint32_t& getBmcSessionId(void);

        void setSessionId(uint32_t& i_sessionID);
        void setBmcSessionId(uint32_t& i_sessionID);

        //Get the session Sequence Number - Host-ordered
        uint32_t& getSessionSeqNum(void);
        void setSessionSeqNum(uint32_t& i_val);

        bool getIsPacketEncrypted();
        bool setIsPacketEncrypted(bool i_isEncrypted);

        bool getIsPacketAuthenticated();

        bool setIsPacketAuthenticated(bool i_isAuth);

        //Get the packet
        uint8_t* getPacket(void);

        //Get the packet
        uint8_t* setPacket(uint8_t* i_pkt, bool i_deleteRequired = true);
        //Get the packet length
        uint32_t getPacketLength(void);

        uint32_t setPacketLength(uint32_t i_val);

        uint8_t* getPayload(void);
        uint8_t* setPayload(uint8_t* i_pkt, bool i_deleteRequired = true);

        uint16_t& getPayloadLength(void);

        void setPayloadLength(uint16_t& i_val);

        uint8_t* getIntegrityData(void);

        uint8_t* setIntegrityData(uint8_t* i_pkt, bool i_deleteRequired = true);

        uint32_t getIntegrityDataLength(void);

        uint32_t setIntegrityDataLength(uint32_t i_val);

        virtual void flatten();

        virtual int Send(IpmiSockChannelData& i_channel);
        virtual int Receive(IpmiSockChannelData& i_channel);
        virtual void unflatten();

        virtual void logBuffer(uint8_t* i_buffer, uint32_t i_bufferLen, bool i_outMsg,
                               uint16_t i_remotePort);

    protected:
        bool iv_isFragment;  //Has the packet been read completely?

        IpmiMessageParser* iv_parser;

        bool iv_isPacketEncrypted;
        bool iv_isPacketAuthenticated;
        uint8_t  iv_payloadType;

        uint32_t iv_sessionId;
        uint32_t iv_bmcSessionId;
        uint32_t iv_sessionSeqNum;

        uint32_t iv_packetLength;
        uint8_t* iv_packet;
        bool     iv_packetRequiresDelete;

        uint16_t iv_payloadLength;
        uint8_t* iv_payload;
        bool     iv_payloadRequiresDelete;

        uint32_t iv_integrityDataLength;
        uint8_t* iv_integrityData;
        bool     iv_integrityDataRequiresDelete;
};

