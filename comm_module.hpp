#pragma once

#include "app_util.hpp"
#include "command_table.hpp"
#include "message_handler.hpp"

#pragma pack(1)
struct ipmiGetChannelCapabilities_t
{
    uint8_t completion_code;  // Completion Code
    uint8_t channel_num;    // Channel number that the request was received on

    uint8_t none   : 1;
    uint8_t md2_support   : 1;   // MD2 support
    uint8_t md5_support   : 1;   // MD5 support
    uint8_t reserved2   : 1;
    uint8_t straight_key   : 1;  // straight password/key support
    // 5 bits from here on represents authentication types enabled for given Requested Max privilage level
    // 1b represnts the presence of support.
uint8_t oem_proprietry   :
    1; // support OEM identified by the IANA OEM ID in RMCP+ ping response
    uint8_t reserved1   : 1;
    uint8_t ipmi_ver   : 1;    // 0b = IPMIV1.5 support only, 1B = IPMI V2.0 support

    uint8_t Kg_Status   : 1; // Two key login status . only for IPMI V2.0 RMCP+ RAKP
    uint8_t per_msg_auth   : 1; // Per-message authentication support
    uint8_t usr_auth   : 1;     // User - level authentication status
uint8_t non_null_usrs   :
    1; // Anonymous login status for non_null usernames enabled/disabled
uint8_t null_usrs   :
    1; // Anonymous login status for null user names enabled/disabled
uint8_t anonym_login   :
    1; // Anonymous login status for anonymous login enabled/disabled
    uint8_t reserved3   : 2;

    // Extended capabilities will be present only if ipmi_ver is 1b i.e., for IPMI V2.0
    uint8_t ext_capabilities   : 2; // Channel support for IPMI V2.0 connections
    uint8_t reserved4   : 6;


    // Below 4 bytes will all the 0's if no OEM authentication type available.
    uint8_t oem_id[3];  // IANA enterprise number for OEM/organization
    uint8_t oem_auxillary;  // Addition OEM specific information..
} ;
#pragma pack()

void ipmiGetChannelCapabilities(IpmiMessageHandler& io_ipmiTransaction);

#pragma pack(1)
struct ipmiOpenSessionRequest_t
{
    uint8_t message_tag ;  // Message tag from request buffer
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
};

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
};
#pragma pack()

void ipmiOpenSession(IpmiMessageHandler& io_ipmiTransaction);

#pragma pack(1)
struct ipmiRAKP1request_t
{
    uint8_t message_tag ; // Message Tag
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t managed_system_session_id;
    uint8_t remote_console_random_number[16]; // Remote console Random Number
    uint8_t req_max_pribvilage_level;
    uint16_t reserved3;
    uint8_t user_name_len;
    char user_name[16];
};

struct ipmiRAKP2response_t
{
    uint8_t message_tag;
    uint8_t rmcp2_status_code;
    uint16_t reserved1;
    uint32_t remote_console_session_id;
    uint8_t managed_system_random_number[16];
    uint8_t managed_system_guid[16];
};
#pragma pack()

void ipmi_RAKP12(IpmiMessageHandler& io_ipmiTransaction);

#pragma pack(1)
struct ipmiRAKP3request_t
{
    uint8_t message_tag;
    uint8_t rmcp2_status_code;
    uint16_t reserved1;
    uint32_t managed_system_session_id;
    uint8_t Key_Exch_Auth_Code[20];
};

struct ipmiRAKP4response_t
{
    uint8_t message_tag;
    uint8_t rmcp2_status_code;
    uint16_t reserved1;
    uint32_t remote_console_session_id;
} ;
#pragma pack()

#define RAKP4_INK_LEN 20
void ipmi_RAKP34(IpmiMessageHandler& io_ipmiTransaction);

#pragma pack(1)

struct ipmiSetSessionPrivilegeLevel_t
{
    uint8_t completion_code;   // Completion Code
    uint8_t reserved : 4;
    uint8_t new_Privilage_Level : 4;
};

#pragma pack()

#pragma pack(1)

typedef struct _ipmiDeviceID_t
{
    uint8_t completion_code;
    uint8_t device_id;
    uint8_t device_revision;
    uint8_t major_fw_revision;
    uint8_t minor_fw_revision;
    uint8_t ipmi_version;
    uint8_t Additional_device_support;
    uint8_t manufacture_id[3];
    uint16_t product_id;
    uint8_t auxiliary_fw[4];
} ipmiDeviceID_t ;

#pragma pack()

void ipmi_SetSessionPrivilegeLevel(IpmiMessageHandler& io_ipmiTransaction);

#pragma pack(1)
struct IpmiCloseSessionRequest
{
    uint32_t sessionID; //Little Endian
    uint8_t sessionHandle; //Optional
};

struct IpmiCloseSessionResponse
{
    uint8_t completionCode;
};
#pragma pack()
void ipmiCloseSession(IpmiMessageHandler& io_ipmiTransaction);

#pragma pack(1)
struct IpmiGetSessionInfoRequest
{
    uint8_t sessionIndex;
    union
    {
        uint8_t sessionHandle;
        uint32_t sessionID; //Little Endian
    } options;
};

struct IpmiGetSessionInfoResponse
{
    uint8_t completionCode;
    uint8_t session_handle;
    uint8_t num_active_sessions;
    uint8_t num_current_active_sessions;
    //Following are present only if there is an active session
    uint8_t active_session_userid;
    uint8_t operating_priv_level;
    uint8_t sess_prot_data : 4; //protocol
    uint8_t active_session_channel_num : 4;
    //Other optional fields exists but currently not implemented
};
#pragma pack()

typedef struct _ipmiChsStatusRsp_t
{
    uint8_t cc;
    uint8_t powerState;
    uint8_t powerEvent;
    uint8_t miscState;
} ipmiChsStatusRsp_t;

void getSystemGUID(uint8_t* i_buffer, uint32_t io_numBytes);

void registerCommands();

