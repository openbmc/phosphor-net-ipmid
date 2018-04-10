#pragma once

namespace usermanagement
{

namespace command
{

/**
 * @struct SetPwdRequest
 *
 * IPMI Request data for set user password command
 */
struct SetPwdRequest
{
    uint8_t userId;            //!< User ID to change password
    uint8_t operation;         //!< Operation on user ID
    uint8_t pwd[20];           //!< New password
};

/**
 * @struct SetPwdRequest
 *
 * IPMI Response data for set user password command
 */
struct SetPwdResponse
{
    uint8_t completionCode;     //!< Completion code.
    uint8_t reserved1;          //!< Reserved.
    uint8_t reserved2;          //!< Reserved.
    uint8_t reserved3;          //!< Reserved.
};

/** @brief Register User management commands to the Command Table */
void registerCommands();

std::vector<uint8_t> ipmiAppSetUserPwd(const std::vector<uint8_t>& inPayload,
                             const message::Handler& handler);
}
}
