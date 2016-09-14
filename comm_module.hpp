#pragma once

#include <vector>

#include "message_handler.hpp"

enum class RAKP_ReturnCode : uint8_t
{
    NO_ERROR = 0x00,
    INSUFFICIENT_RESOURCE,
    INVALID_SESSION_ID,
    INVLALID_PAYLOAD_TYPE,
    INVALID_AUTH_ALGO,
    INVALID_INTEGRITY_ALGO,
    NO_MATCH_AUTH_PAYLOAD,
    NO_MATCH_INTEGRITY_PAYLOAD,
    INACTIVE_SESSIONID,
    INACTIVE_ROLE,
    UNAUTH_ROLE_PRIV,
    INSUFFICIENT_RESOURCES_ROLE,
    INVALID_NAME_LENGTH,
    UNAUTH_NAME,
    UNAUTH_GUID,
    INVALID_INTEGRITY_CHECK_VALUE,
    INVALID_CONF_ALGO,
    NO_CIPHER_SUITE_MATCH,
    ILLEGAL_PARAMETER,
};

struct GetChannelCapabilitiesReq_t
{
    uint8_t channelNumber;
    uint8_t reqMaxPrivLevel;
};

struct GetChannelCapabilitiesResp_t
{
    uint8_t completionCode;     // Completion Code

    uint8_t channelNumber;      // Channel number that the request was
                                // received on

    uint8_t none : 1;
    uint8_t md2 : 1;
    uint8_t md5 : 1;
    uint8_t reserved2 : 1;
    uint8_t straightKey : 1;   // Straight password/key support
    // Support OEM identified by the IANA OEM ID in RMCP+ ping response
    uint8_t oem : 1;
    uint8_t reserved1 : 1;
uint8_t ipmiVersion :
    1;    // 0b = IPMIV1.5 support only, 1B = IPMI V2.0 support

    // Two key login status . only for IPMI V2.0 RMCP+ RAKP
    uint8_t KGStatus : 1;
    uint8_t perMessageAuth : 1; // Per-message authentication support
    uint8_t userAuth : 1;       // User - level authentication status
    // Anonymous login status for non_null usernames enabled/disabled
    uint8_t nonNullUsers : 1;
    // Anonymous login status for null user names enabled/disabled
    uint8_t nullUsers : 1;
    // Anonymous login status for anonymous login enabled/disabled
    uint8_t anonymousLogin : 1;

    uint8_t reserved3 : 2;
    // Extended capabilities will be present only if IPMI version is V2.0
    uint8_t extCapabilities : 2; // Channel support for IPMI V2.0 connections
    uint8_t reserved4 : 6;

    // Below 4 bytes will all the 0's if no OEM authentication type available.
    uint8_t oemID[3];  // IANA enterprise number for OEM/organization
    uint8_t oemAuxillary;  // Addition OEM specific information..
} __attribute__((packed));

/*
 * @brief Get Channel Authentication Capabilities
 *
 * This message exchange provides a way for a remote console to discover what
 * IPMI version is supported i.e. whether or not the BMC supports the IPMI
 * v2.0 / RMCP+ packet format. It also provides information that the remote
 * console can use to determine whether anonymous, “one-key”, or “two-key”
 * logins are used.This information can guide a remote console in how it
 * presents queries to users for username and password information. This is a
 * ‘session-less’ command that the BMC accepts in both IPMI v1.5 and v2.0/RMCP+
 * packet formats.
 */
std::vector<uint8_t> GetChannelCapabilities(std::vector<uint8_t>& inPayload,
        message::Handler& handler);

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
 */
std::vector<uint8_t> openSession(std::vector<uint8_t>& inPayload,
                                 message::Handler& handler);

struct RAKP1request_t
{
    uint8_t messageTag;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t managedSystemSessionID;
    uint8_t remote_console_random_number[16];
    uint8_t req_max_privilege_level;
    uint16_t reserved3;
    uint8_t user_name_len;
    char user_name[16];
} __attribute__((packed));

struct RAKP2response_t
{
    uint8_t messageTag;
    uint8_t rmcpStatusCode;
    uint16_t reserved;
    uint32_t remoteConsoleSessionID;
    uint8_t managed_system_random_number[16];
    uint8_t managed_system_guid[16];
} __attribute__((packed));

/*
 * @brief RAKP Message 1, RAKP Message 2
 *
 * These messages are used to exchange random number and identification
 * information between the BMC and the remote console that are, in effect,
 * mutual challenges for a challenge/response. (Unlike IPMI v1.5, the v2.0/RMCP+
 * challenge/response is symmetric. I.e. the remote console and BMC both issues
 * challenges,and both need to provide valid responses for the session to be
 * activated.)
 *
 * The remote console request (RAKP Message 1) passes a random number and
 * username/privilege information that the BMC will later use to ‘sign’ a
 * response message based on key information associated with the user and the
 * Authentication Algorithm negotiated in the Open Session Request/Response
 * exchange. The BMC responds with RAKP Message 2 and passes a random number and
 * GUID (globally unique ID) for the managed system that the remote console
 * uses according the Authentication Algorithm to sign a response back to the
 * BMC.
 */
std::vector<uint8_t> RAKP12(std::vector<uint8_t>& inPayload,
                            message::Handler& handler);

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

constexpr uint8_t IPMI_CC_INVALID_PRIV_LEVEL = 0x80;
constexpr uint8_t IPMI_CC_EXCEEDS_USER_PRIV = 0x81;

struct SetSessionPrivilegeLevel_t
{
    uint8_t completionCode;
    uint8_t newPrivLevel : 4;
    uint8_t reserved : 4;
} __attribute__((packed));

/*
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
 */
std::vector<uint8_t> setSessionPrivilegeLevel(std::vector<uint8_t>& inPayload,
        message::Handler& handler);

constexpr uint8_t IPMI_CC_INVALID_SESSIONID = 0x87;

struct CloseSessionRequest
{
    uint32_t sessionID;
    uint8_t sessionHandle;
} __attribute__((packed));

struct CloseSessionResponse
{
    uint8_t completionCode;
} __attribute__((packed));

/*
 * @brief Close Session Command
 *
 * This command is used to immediately terminate a session in progress. It is
 * typically used to close the session that the user is communicating over,
 * though it can be used to other terminate sessions in progress (provided that
 * the user is operating at the appropriate privilege level, or the command is
 * executed over a local channel - e.g. the system interface). Closing
 * sessionless session ( session zero) is restricted in this command
 */
std::vector<uint8_t> closeSession(std::vector<uint8_t>& inPayload,
                                  message::Handler& handler);

void getSystemGUID(uint8_t* i_buffer, uint32_t io_numBytes);

void sessionSetupCommands();

