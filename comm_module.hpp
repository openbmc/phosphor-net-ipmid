#pragma once

#include <cstdint>

#include "message_handler.hpp"

enum class RAKP_ReturnCode : uint8_t
{
    NO_ERROR,
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

/*
 * @brief Register Session Setup commands to the Command Table
 */
void sessionSetupCommands();
