#pragma once

#include <vector>

#include "message_handler.hpp"

namespace command
{

struct OpenSessionRequest_t
{
    uint8_t messageTag;  // Message tag from request buffer
    uint8_t maxPrivLevel : 4 ;// Requested maximum privilege level
    uint8_t reserved1 : 4;  // Reserved for future definition
    uint16_t reserved2;
    uint32_t remoteConsoleSessionID ;

    uint8_t authPayload ;
    uint16_t  reserved3;
    uint8_t  authPayloadLen;
    uint8_t authAlgo : 6;
    uint8_t reserved4 : 2;
    uint8_t reserved5;
    uint16_t reserved6;

    uint8_t intPayload;
    uint16_t reserved7;
    uint8_t  intPayloadLen;
    uint8_t intAlgo : 6;
    uint8_t reserved8 : 2;
    uint8_t reserved9;
    uint16_t reserved10;

    uint8_t confPayload;
    uint16_t reserved11;
    uint8_t  confPayloadLen;
    uint8_t confAlgo : 6;
    uint8_t reserved12 : 2;
    uint8_t reserved13;
    uint16_t reserved14;
} __attribute__((packed));

struct OpenSessionResponse_t
{
    uint8_t messageTag;
    uint8_t status_code;
    uint8_t maxPrivLevel : 4;
    uint8_t reserved1 : 4;
    uint8_t reserved2;
    uint32_t remoteConsoleSessionID;
    uint32_t managedSystemSessionID;

    uint8_t authPayload;
    uint16_t reserved3;
    uint8_t authPayloadLen;
    uint8_t authAlgo : 6;
    uint8_t reserved4 : 2;
    uint8_t reserved5;
    uint16_t reserved6;

    uint8_t intPayload;
    uint16_t reserved7;
    uint8_t  intPayloadLen;
    uint8_t intAlgo : 6;
    uint8_t reserved8 : 2;
    uint8_t reserved9;
    uint16_t reserved10;

    uint8_t confPayload;
    uint16_t reserved11;
    uint8_t  confPayloadLen;
    uint8_t confAlgo : 6;
    uint8_t reserved12 : 2;
    uint8_t reserved13;
    uint16_t reserved14;
} __attribute__((packed));

/*
 * @brief RMCP+ Open Session Request, RMCP+ Open Session Response
 *
 * The RMCP+ Open Session request and response messages are used to enable a
 * remote console to discover what Cipher Suite(s) can be used for establishing
 * a session at a requested maximum privilege level. These messages are also
 * used for transferring the sessions IDs that the remote console and BMC wish
 *  to for the session once it’s been activated, and to track each party during
 *  the exchange of messages used for establishing the session.
 *
 * @param[in] inPayload - Request Data for the command
 * @param[in] handler - Reference to the Message Handler
 *
 * @return Response data for the command
 */
std::vector<uint8_t> openSession(std::vector<uint8_t>& inPayload,
                                 const message::Handler& handler);

} // namespace command
