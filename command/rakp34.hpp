#pragma once

#include <vector>

#include "message_handler.hpp"
#include "comm_module.hpp"

struct RAKP3request_t
{
    uint8_t messageTag;
    uint8_t rmcpStatusCode;
    uint16_t reserved;
    uint32_t managedSystemSessionID;
    uint8_t keyExchangeAuthCode[20];
} __attribute__((packed));
struct RAKP4response_t
{
    uint8_t messageTag;
    uint8_t rmcpStatusCode;
    uint16_t reserved;
    uint32_t remoteConsoleSessionID;
} __attribute__((packed));

/*
 * @brief RAKP Message 3, RAKP Message 4
 *
 * The session activation process is completed by the remote console and BMC
 * exchanging messages that are signed according to the Authentication Algorithm
 * that was negotiated, and the parameters that were passed in the earlier
 * messages. RAKP Message 3 is the signed message from the remote console to the
 * BMC. After receiving RAKP Message 3, the BMC returns RAKP Message 4 - a
 * signed message from BMC to the remote console.
 */
std::vector<uint8_t> RAKP34(std::vector<uint8_t>& inPayload,
                            message::Handler& handler);
