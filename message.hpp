#pragma once

#include <memory>
#include <vector>

#include "socket_data.hpp"

class Message;

/*
 * @class MessageParser
 *
 * Message Parser is the base class for IPMI message parsers.There are two parsers based on the
 * IPMI1.5 header and IPMI2.0 header
 */
class MessageParser
{
    public:
        enum class IpmiAuthTypeFormat
        {
            AUTHTYPE_FORMAT_IPMI15_NONE = 0x00,
            AUTHTYPE_FORMAT_IPMI20 = 0x06,
        };

        struct BasicHeader_t
        {
            // RMCP Header
            uint8_t version;
            uint8_t reserved;
            uint8_t rmcpSeqNum;
            uint8_t classOfMsg;

            // IPMI partial session header
            union
            {
                uint8_t reserved1: 4;
                uint8_t authType: 4;
                uint8_t formatType;
            } format;
        } __attribute__((packed));

        /*
         * @brief Get the parser based on the IPMI message
         *
         * This function would parse the packet and figure out the IPMI header
         *
         * @return On success return the instance of the parser based on the header
         *         On failure returns nullptr
         */
        static std::unique_ptr<MessageParser> getParser(std::vector<uint8_t>& i_pkt);

        virtual ~MessageParser() = default;

        /*
         * @brief Get the size of the packet from the message
         */
        virtual uint32_t getPacketSize(Message* i_msg) = 0;

        /*
         * @brief Get the Session ID from the message
         */
        virtual uint32_t getSessionID(Message* i_msg) = 0;

        /*
         * @brief Unflatten the incoming message
         *
         * Extract the payload from the incoming message
         */
        virtual bool unflatten(Message* i_msg) = 0;

        /*
         * @brief Flatten the outgoing message
         *
         * Pack the payload into the packet with header and trailer
         */
        virtual bool flatten(Message* i_msg) = 0;

    protected:
        MessageParser() {}
};

/*
 * @ class Message
 *
 * Message class encapsulates the incoming and outgoing IPMI packets and the operations
 * related to the message like Receive, Send, Flatten and unflatten.
 */
class Message
{
    public:
        enum class PayloadType : uint8_t
        {
            PAYLOAD_TYPE_IPMI                  = 0x00,
            PAYLOAD_TYPE_SOL                   = 0x01,
            PAYLOAD_TYPE_OEM                   = 0x02,
            PAYLOAD_TYPE_OPEN_SESS_REQUEST     = 0x10,
            PAYLOAD_TYPE_OPEN_SESS_RESPONSE    = 0x11,
            PAYLOAD_TYPE_RAKP1                 = 0x12,
            PAYLOAD_TYPE_RAKP2                 = 0x13,
            PAYLOAD_TYPE_RAKP3                 = 0x14,
            PAYLOAD_TYPE_RAKP4                 = 0x15,
            PAYLOAD_TYPE_INVALID               = 0xFF,
        };

        // Minimum required is the IPMI header of a RMCP+ packet
        static constexpr uint32_t MESSAGE_MIN_PEEK_LENGTH = 16;
        // Maximum packet size that we'll handle
        static constexpr uint32_t MESSAGE_MAX_PACKET_LENGTH = 512;
        static constexpr uint32_t MESSAGE_INVALID_SESSION_ID = 0xBADBADFF;

        //Incoming Message Constructor
        Message();

        //Outgoing Message Constructor
        Message(uint32_t i_sessionId, uint32_t i_bmcSessionId,
                PayloadType i_payloadType,
                uint8_t* i_pMessage, size_t i_msgLength, Message* i_inMsg = NULL);

        ~Message() = default;
        Message(const Message& right) = delete;
        Message& operator=(const Message& right) = delete;
        Message(Message&&) = delete;
        Message& operator=(Message&&) = delete;

        auto getPayloadType()
        {
            return payloadType;
        }

        auto setPayloadType(PayloadType i_type)
        {
            payloadType = i_type;
        }

        auto getSessionId()
        {
            return sessionId;
        }

        auto setSessionId(uint32_t i_sessionID)
        {
            sessionId = i_sessionID;
        }

        auto getBmcSessionId()
        {
            return bmcSessionId;
        }

        auto setBmcSessionId(uint32_t i_sessionID)
        {
            bmcSessionId = i_sessionID;
        }

        auto getSessionSeqNum()
        {
            return sessionSeqNum;
        }

        auto setSessionSeqNum(uint32_t i_seqNum)
        {
            sessionSeqNum = i_seqNum;
        }

        auto getIsPacketEncrypted()
        {
            return isPacketEncrypted;
        }

        auto setIsPacketEncrypted(bool i_isEncrypted)
        {
            isPacketEncrypted = i_isEncrypted;
        }

        auto getIsPacketAuthenticated()
        {
            return isPacketAuthenticated;
        }

        auto setIsPacketAuthenticated(bool i_isAuth)
        {
            isPacketAuthenticated = i_isAuth;
        }

        std::vector<uint8_t>& getPacket()
        {
            return packet;
        }

        std::vector<uint8_t>& getPayload()
        {
            return payload;
        }

        std::vector<uint8_t>& getIntegrityData()
        {
            return integrityData;
        }

        // Flatten the message
        void flatten();

        int Send(SocketData& i_channel);

        int Receive(SocketData& i_channel);

        // Unflatten the message
        void unflatten();

        // Log the contents of the Message
        void logBuffer(uint8_t* i_buffer, uint32_t i_bufferLen, bool i_outMsg,
                       uint16_t i_remotePort);

    protected:
        bool isFragmented;  // Flag to ensure that complete message has been read

        bool isPacketEncrypted; // Message's encryption status
        bool isPacketAuthenticated; // Message's authentication status
        PayloadType  payloadType; // Type of message payload (IPMI,SOL ..etc)

        // Session ID field of the packet
        uint32_t sessionId;
        /*
         * BMC Session ID is used only when sending a response message to populate the
         * integrity data and encrypt the payload if needed.
         */
        uint32_t bmcSessionId;

        // Session Sequence Number
        uint32_t sessionSeqNum;


        std::unique_ptr<MessageParser> parser; // Message Parser


        std::vector<uint8_t> packet; // Packet


        std::vector<uint8_t> payload; // Payload


        std::vector<uint8_t> integrityData; // Integrity Data
};

