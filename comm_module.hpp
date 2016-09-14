#pragma once

#include <vector>

#include "message_handler.hpp"

struct GetChannelCapabilities_t
{
    uint8_t completionCode;   // Completion Code
    uint8_t channelNumber;    // Channel number that the request was received on

    uint8_t none : 1;
    uint8_t md2_support : 1;
    uint8_t md5_support : 1;
    uint8_t reserved2 : 1;
    uint8_t straight_key : 1;  // Straight password/key support

uint8_t oem_proprietary :
    1; // support OEM identified by the IANA OEM ID in RMCP+ ping response
    uint8_t reserved1 : 1;
    uint8_t ipmi_ver : 1;   // 0b = IPMIV1.5 support only, 1B = IPMI V2.0 support

uint8_t Kg_Status :
    1;      // Two key login status . only for IPMI V2.0 RMCP+ RAKP
    uint8_t per_msg_auth : 1;   // Per-message authentication support
    uint8_t usr_auth : 1;       // User - level authentication status
uint8_t non_null_usrs :
    1;  // Anonymous login status for non_null usernames enabled/disabled
uint8_t null_usrs :
    1;      // Anonymous login status for null user names enabled/disabled
uint8_t anonym_login :
    1;   // Anonymous login status for anonymous login enabled/disabled
    uint8_t reserved3 : 2;

    // Extended capabilities will be present only if ipmi_ver is 1b i.e., for IPMI V2.0
    uint8_t ext_capabilities : 2; // Channel support for IPMI V2.0 connections
    uint8_t reserved4 : 6;


    // Below 4 bytes will all the 0's if no OEM authentication type available.
    uint8_t oem_id[3];  // IANA enterprise number for OEM/organization
    uint8_t oem_auxillary;  // Addition OEM specific information..
} __attribute__((packed));

/*
 * @brief Get Channel Authentication Capabilities
 *
 * This message exchange provides a way for a remote console to discover what IPMI version is
 * supported i.e. whether or not the BMC supports the IPMI v2.0 / RMCP+ packet format.
 * It also provides information that the remote console can use to determine whether anonymous,
 * “one-key”, or “two-key” logins are used.This information can guide a remote console in how it
 *  presents queries to users for username and password information. This is a ‘session-less’
 *  command that the BMC accepts in both IPMI v1.5 and v2.0/RMCP+ packet formats.
 */
std::vector<uint8_t> GetChannelCapabilities(std::vector<uint8_t>& inPayload,
        MessageHandler& handler);

struct OpenSessionRequest_t
{
    uint8_t message_tag;  // Message tag from request buffer
    uint8_t req_max_privilage_level : 4 ;// Requested maximum privilage level
    uint8_t reserved1 : 4;  // Reserved for future defenation
    uint16_t reserved2;
    uint32_t remote_console_session_id ;
    uint8_t auth_payload_pt ;
    uint16_t  reserved3;
    uint8_t  auth_payload_length;
    uint8_t auth_algo : 6;
    uint8_t reserved4 : 2;
    uint8_t reserved5;
    uint16_t reserved6;
    uint8_t int_payload_pt;
    uint16_t reserved7;
    uint8_t  int_payload_length;
    uint8_t int_algo : 6;
    uint8_t reserved8 : 2;
    uint8_t reserved9;
    uint16_t reserved10;
    uint8_t conf_payload_pt;
    uint16_t reserved11;
    uint8_t  conf_payload_length;
    uint8_t conf_algo : 6;
    uint8_t reserved12 : 2;
    uint8_t reserved13;
    uint16_t reserved14;
} __attribute__((packed));

struct ipmiOpenSessionResponse_t
{
    uint8_t message_tag ;
    uint8_t status_code ;
    uint8_t req_max_privilage_level   : 4 ;
    uint8_t max_priv_reserved1   : 4 ;
    uint8_t reserved2 ;
    uint32_t remote_console_session_id ;
    uint32_t managed_system_session_id ;

    uint8_t auth_payload_pt ;
    uint16_t reserved3;
    uint8_t auth_payload_length;
    uint8_t auth_algo : 6;
    uint8_t reserved4 : 2;
    uint8_t reserved5;
    uint16_t reserved6;

    uint8_t int_payload_pt;
    uint16_t reserved7;
    uint8_t  int_payload_length;
    uint8_t int_algo : 6;
    uint8_t reserved8 : 2;
    uint8_t reserved9;
    uint16_t reserved10;

    uint8_t conf_payload_pt;
    uint16_t reserved11;
    uint8_t  conf_payload_length;
    uint8_t conf_algo : 6;
    uint8_t reserved12 : 2;
    uint8_t reserved13;
    uint16_t reserved14;
} __attribute__((packed));

/*
 * @brief RMCP+ Open Session Request, RMCP+ Open Session Response
 *
 * The RMCP+ Open Session request and response messages are used to enable a remote console to
 * discover what Cipher Suite(s) can be used for establishing a session at a requested maximum
 * privilege level. These messages are also used for transferring the sessions IDs that the remote
 * console and BMC wish to for the session once it’s been activated, and to track each party during
 * the exchange of messages used for establishing the session.
 *
 */
std::vector<uint8_t> openSession(std::vector<uint8_t>& inPayload,
                                 MessageHandler& handler);

struct ipmiRAKP1request_t
{
    uint8_t message_tag;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t managed_system_session_id;
    uint8_t remote_console_random_number[16];
    uint8_t req_max_privilege_level;
    uint16_t reserved3;
    uint8_t user_name_len;
    char user_name[16];
} __attribute__((packed));

struct ipmiRAKP2response_t
{
    uint8_t message_tag;
    uint8_t rmcp2_status_code;
    uint16_t reserved1;
    uint32_t remote_console_session_id;
    uint8_t managed_system_random_number[16];
    uint8_t managed_system_guid[16];
} __attribute__((packed));

/*
 * @brief RAKP Message 1, RAKP Message 2
 *
 * These messages are used to exchange random number and identification information between the BMC
 * and the remote console that are, in effect, mutual challenges for a challenge/response. (Unlike
 * IPMI v1.5, the v2.0/RMCP+ challenge/response is symmetric. I.e. the remote console and BMC both
 * issues challenges,and both need to provide valid responses for the session to be activated.)
 *
 * The remote console request (RAKP Message 1) passes a random number and username/privilege
 * information that the BMC will later use to ‘sign’ a response message based on key information
 * associated with the user and the Authentication Algorithm negotiated in the Open Session
 * Request/Response exchange. The BMC responds with RAKP Message 2 and passes a random number and
 * GUID (globally unique ID) for the managed system that the remote console uses according the
 * Authentication Algorithm to sign a response back to the BMC.
 */
std::vector<uint8_t> RAKP12(std::vector<uint8_t>& inPayload,
                            MessageHandler& handler);


struct ipmiRAKP3request_t
{
    uint8_t message_tag;
    uint8_t rmcp2_status_code;
    uint16_t reserved1;
    uint32_t managed_system_session_id;
    uint8_t Key_Exch_Auth_Code[20];
} __attribute__((packed));
struct ipmiRAKP4response_t
{
    uint8_t message_tag;
    uint8_t rmcp2_status_code;
    uint16_t reserved1;
    uint32_t remote_console_session_id;
} __attribute__((packed));

/*
 * @brief RAKP Message 3, RAKP Message 4
 *
 * The session activation process is completed by the remote console and BMC exchanging messages
 * that are signed according to the Authentication Algorithm that was negotiated, and the parameters
 * that were passed in the earlier messages. RAKP Message 3 is the signed message from the remote
 * console to the BMC.After receiving RAKP Message 3, the BMC returns RAKP Message 4 - a signed
 * message from BMC to the remote console.
 */
std::vector<uint8_t> RAKP34(std::vector<uint8_t>& inPayload,
                            MessageHandler& handler);

struct ipmiSetSessionPrivilegeLevel_t
{
    uint8_t completionCode;
    uint8_t reserved : 4;
    uint8_t newPrivLevel : 4;
} __attribute__((packed));

/*
 * @brief Set Session Privilege Command
 *
 * This command is sent in authenticated format. When a session is activated, the session is set to
 * an initial privilege level. A session that is activated at a maximum privilege level of Callback
 * is set to an initial privilege level of Callback and cannot be changed. All other sessions are
 * initially set to USER level, regardless of the maximum privilege level requested in the RAKP
 * Message 1.
 *
 * This command cannot be used to set a privilege level higher than the lowest of the privilege
 * level set for the user(via the Set User Access command) and the privilege limit for the channel
 * that was set via the Set Channel Access command.
 */
std::vector<uint8_t> setSessionPrivilegeLevel(std::vector<uint8_t>& inPayload,
        MessageHandler& handler);

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
 * This command is used to immediately terminate a session in progress. It is typically used to
 * close the session that the user is communicating over, though it can be used to other terminate
 * sessions in progress (provided that the user is operating at the appropriate privilege level,
 * or the command is executed over a local channel - e.g. the system interface). Closing sessionless
 * session ( session zero) is restricted in this command
 */
std::vector<uint8_t> closeSession(std::vector<uint8_t>& inPayload,
                                  MessageHandler& handler);

void getSystemGUID(uint8_t* i_buffer, uint32_t io_numBytes);

void sessionSetupCommands();

