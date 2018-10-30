#pragma once

#include "message_handler.hpp"

#include <vector>

namespace command
{

constexpr uint8_t IPMI_CC_INVALID_PRIV_LEVEL = 0x80;
constexpr uint8_t IPMI_CC_EXCEEDS_USER_PRIV = 0x81;

/**
 * @struct SetSessionPrivLevelReq
 *
 * IPMI Request data for Set Session Privilege Level command
 */
struct SetSessionPrivLevelReq
{

#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t reqPrivLevel : 4;
    uint8_t reserved : 4;
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved : 4;
    uint8_t reqPrivLevel : 4;
#endif

} __attribute__((packed));

/**
 * @struct SetSessionPrivLevelResp
 *
 * IPMI Response data for Set Session Privilege Level command
 */
struct SetSessionPrivLevelResp
{
    uint8_t completionCode;

#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t newPrivLevel : 4;
    uint8_t reserved : 4;
#endif

#if BYTE_ORDER == BIG_ENDIAN
    uint8_t reserved : 4;
    uint8_t newPrivLevel : 4;
#endif

} __attribute__((packed));

/**
 * @brief Set Session Privilege Command
 *
 * This command is sent in authenticated format. When a session is activated,
 * the session is set to an initial privilege level. A session that is
 * activated at a maximum privilege level of Callback is set to an initial
 * privilege level of Callback and cannot be changed. All other sessions are
 * initially set to USER level, regardless of the maximum privilege level
 * requested in the RAKP Message 1.
 *
 * This command cannot be used to set a privilege level higher than the lowest
 * of the privilege level set for the user(via the Set User Access command) and
 * the privilege limit for the channel that was set via the Set Channel Access
 * command.
 *
 * @param[in] inPayload - Request Data for the command
 * @param[in] handler - Reference to the Message Handler
 *
 * @return Response data for the command
 */
std::vector<uint8_t>
    setSessionPrivilegeLevel(const std::vector<uint8_t>& inPayload,
                             const message::Handler& handler);

constexpr uint8_t IPMI_CC_INVALID_SESSIONID = 0x87;

/**
 * @struct CloseSessionRequest
 *
 * IPMI Request data for Close Session command
 */
struct CloseSessionRequest
{
    uint32_t sessionID;
    uint8_t sessionHandle;
} __attribute__((packed));

/**
 * @struct CloseSessionResponse
 *
 * IPMI Response data for Close Session command
 */
struct CloseSessionResponse
{
    uint8_t completionCode;
} __attribute__((packed));

/**
 * @brief Close Session Command
 *
 * This command is used to immediately terminate a session in progress. It is
 * typically used to close the session that the user is communicating over,
 * though it can be used to other terminate sessions in progress (provided that
 * the user is operating at the appropriate privilege level, or the command is
 * executed over a local channel - e.g. the system interface). Closing
 * sessionless session ( session zero) is restricted in this command
 *
 * @param[in] inPayload - Request Data for the command
 * @param[in] handler - Reference to the Message Handler
 *
 * @return Response data for the command
 */
std::vector<uint8_t> closeSession(const std::vector<uint8_t>& inPayload,
                                  const message::Handler& handler);

/**
 * @struct GetSessionInfoRequest
 *
 * IPMI Request data for getSession info command
 */
struct GetSessionInfoRequest
{
    uint8_t sessionIndex;
    union
    {
        uint8_t sessionHandle;
        uint32_t sessionID;
    };
} __attribute__((packed));

/**
 * @struct getSessionInfoResponse
 *
 * IPMI Response data for getSession info command
 */
struct GetSessionInfoResponse
{
    uint8_t completionCode;
    uint8_t sessionHandle;
    uint8_t totalSessionCount;
    uint8_t activeSessioncount;
    uint8_t userID;
    uint8_t privLevel;
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t chanNum : 4;
    uint8_t ipmiVer : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t ipmiVer : 4;
    uint8_t chanNum : 4;
#endif
    uint32_t remoteIpAddr; // for channel private data
    uint8_t remoteMACAddr[6];
    uint16_t remotePort;
} __attribute__((packed));

/**
 * @brief GetSessionInfo Command
 *
 * This command is used to  get the session information based on
 * session handle or session ID. Retreive all session information.

 * @param[in] inPayload - Request Data for the command
 * @param[in] handler - Reference to the Message Handler
 *
 * @return Response data for the command
 */
std::vector<uint8_t> getSessionInfo(const std::vector<uint8_t>& inPayload,
                                    const message::Handler& handler);

} // namespace command
