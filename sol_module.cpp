#include "command/sol_cmds.hpp"
#include "command/payload_cmds.hpp"
#include "command_table.hpp"
#include "main.hpp"
#include "session.hpp"

namespace command
{

void solCommands()
{
    static const command::CmdDetails commands[] =
    {
        // SOL Payload Handler
        {
            {(static_cast<uint32_t>(message::PayloadType::SOL) << 16)},
            &sol::command::payloadHandler, session::Privilege::HIGHEST_MATCHING,
            false
        },
        // Activate Payload Command
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x48
            },
            &sol::command::activatePayload, session::Privilege::USER, false
        },
        // Deactivate Payload Command
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x49
            },
            &sol::command::deactivatePayload, session::Privilege::USER, false
        },
        // Get Payload Activation Status
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x4A
            },
            &sol::command::getPayloadStatus, session::Privilege::USER, false
        },
    };

    for (auto& iter : commands)
    {
        std::get<command::Table&>(singletonPool).registerCommand(
            iter.command, std::make_unique<command::NetIpmidEntry>
            (iter.command, iter.functor, iter.privilege, iter.sessionless));
    }
}

} // namespace command
