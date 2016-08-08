#pragma once

#include <memory>
#include <vector>

/*
 * @ struct Message
 *
 * IPMI message is data encapsulated in an IPMI Session packet. The IPMI
 * Session packets are encapsulated in RMCP packets, which are encapsulated in UDP datagrams.
 * Refer Section 13.5 of IPMI specification(IPMI Messages Encapsulation Under RMCP).
 * IPMI Payload is a special class of data encapsulated in an IPMI session packet.
 */

struct Message
{
    public:
        enum class PayloadType : uint8_t
        {
            PAYLOAD_TYPE_IPMI                  = 0x00,
            PAYLOAD_TYPE_OPEN_SESS_REQUEST     = 0x10,
            PAYLOAD_TYPE_OPEN_SESS_RESPONSE    = 0x11,
            PAYLOAD_TYPE_RAKP1                 = 0x12,
            PAYLOAD_TYPE_RAKP2                 = 0x13,
            PAYLOAD_TYPE_RAKP3                 = 0x14,
            PAYLOAD_TYPE_RAKP4                 = 0x15,
            PAYLOAD_TYPE_INVALID               = 0xFF,
        };

        static constexpr uint32_t MESSAGE_INVALID_SESSION_ID = 0xBADBADFF;

        Message()
            : payloadType(PayloadType::PAYLOAD_TYPE_INVALID),
              rcSessionID(Message::MESSAGE_INVALID_SESSION_ID),
              bmcSessionID(Message::MESSAGE_INVALID_SESSION_ID) {}

        bool isPacketEncrypted;         // Message's Encryption Status
        bool isPacketAuthenticated;     // Message's Authentication Status
        PayloadType  payloadType;       // Type of message payload (IPMI,SOL ..etc)
        uint32_t rcSessionID;           // Remote Client's Session ID
        uint32_t bmcSessionID;          // BMC's session ID
        uint32_t sessionSeqNum;         // Session Sequence Number
        std::vector<uint8_t> payload;   // Payload
};

