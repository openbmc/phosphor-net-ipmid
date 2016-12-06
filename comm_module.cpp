#include "comm_module.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "command/channel_auth.hpp"
#include "command/open_session.hpp"
#include "command/rakp12.hpp"
#include "command/rakp34.hpp"
#include "command/session_cmds.hpp"
#include "command_table.hpp"
#include "main.hpp"
#include "session.hpp"

namespace command
{

void sessionSetupCommands()
{
    command::CmdDetails commands[] =
    {
        // Open Session Request/Response
        {
            {
                (static_cast<uint32_t>
                (message::PayloadType::OPEN_SESSION_REQUEST) << 16)
            },
            &openSession, session::Privilege::HIGHEST_MATCHING,  true
        },
        // RAKP1 & RAKP2 Message
        {
            {(static_cast<uint32_t>(message::PayloadType::RAKP1) << 16)},
            &RAKP12, session::Privilege::HIGHEST_MATCHING, true
        },
        // RAKP3 & RAKP4 Message
        {
            {(static_cast<uint32_t>(message::PayloadType::RAKP3) << 16)},
            &RAKP34, session::Privilege::HIGHEST_MATCHING, true
        },
        // Get Channel Authentication Capabilities Command
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x38
            },
            &GetChannelCapabilities,
            session::Privilege::HIGHEST_MATCHING, true
        },
        // Set Session Privilege Command
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x3B
            },
            &setSessionPrivilegeLevel, session::Privilege::USER, false
        },
        // Close Session Command
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x3C
            },
            &closeSession, session::Privilege::CALLBACK, false
        },
    };

    auto count = sizeof(commands) / sizeof(command::CmdDetails);

    for (size_t iter = 0; iter < count ; ++iter)
    {
        std::get<command::Table&>(singletonPool).registerCommand(
            commands[iter].command,
            std::make_unique<command::NetIpmidEntry>
            (commands[iter].command, commands[iter].functor,
             commands[iter].privilege, commands[iter].sessionless));
    }
}

} // namespace command
