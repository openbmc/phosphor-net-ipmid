#include "command_table.hpp"

#include <iomanip>
#include <iostream>

#include <main.hpp>
#include "message_handler.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace phosphor::logging;

namespace command
{

void Table::registerCommand(CommandID inCommand, std::unique_ptr<Entry>&& entry)
{
    auto& command = commandTable[inCommand.command];

    if (command)
    {
        log<level::DEBUG>("Already Registered", phosphor::logging::entry(
            "SKIPPED_ENTRY=0x%x", uint32_t(inCommand.command)));
        return;
    }

    command = std::move(entry);
}

std::vector<uint8_t> Table::executeCommand(uint32_t inCommand,
                                           std::vector<uint8_t>& commandData,
                                           const message::Handler& handler)
{
    using namespace std::chrono_literals;

    std::vector<uint8_t> response;

    auto iterator = commandTable.find(inCommand);

    if (iterator == commandTable.end())
    {
        auto bus = getSdBus();
        // forward the request onto the main ipmi queue
        auto method = bus->new_method_call(
                    "xyz.openbmc_project.IPMI",
                    "/xyz/openbmc_project/IPMI",
                    "xyz.openbmc_project.ipmi.server",
                    "execute");
        uint8_t seq = 0; // where can we get this from?
        uint8_t lun = 0; // where can we get this from?
        uint8_t netFn = static_cast<uint8_t>(inCommand >> 8);
        uint8_t cmd = static_cast<uint8_t>(inCommand);
        method.append(seq, netFn, lun, cmd, commandData);
        auto reply = bus->call(method);
        if (reply.is_method_error())
        {
            log<level::ERR>("Error sending command to ipmi queue");
            elog<InternalFailure>();
            response.resize(1);
            response[0] = IPMI_CC_UNSPECIFIED_ERROR;
        }
        else
        {
            std::vector<uint8_t> responseData;
            uint8_t rseq, rlun, rnetFn, rcmd, cc;
            reply.read(rseq, rnetFn, rlun, rcmd, cc, responseData);
            if (seq != rseq || netFn != rnetFn || lun != rlun || cmd != rcmd)
            {
                log<level::ERR>("Invalid response from ipmi queue");
                elog<InternalFailure>();
                response.resize(1);
                response[0] = IPMI_CC_UNSPECIFIED_ERROR;
            }
            else
            {
                response.resize(1 + responseData.size());
                response[0] = cc;
                std::copy(response.begin() + 1,
                        responseData.begin(), responseData.end());
            }
        }
    }
    else
    {
        auto start = std::chrono::steady_clock::now();

        response = iterator->second->executeCommand(commandData, handler);

        auto end = std::chrono::steady_clock::now();

        auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>
                              (end - start);

        // If command time execution time exceeds 2 seconds, log a time
        // exceeded message
        if (elapsedSeconds > 2s)
        {
            std::cerr << "E> IPMI command timed out:Elapsed time = "
                      << elapsedSeconds.count() << "s" << "\n";
        }
    }
    return response;
}

std::vector<uint8_t> NetIpmidEntry::executeCommand(
        std::vector<uint8_t>& commandData,
        const message::Handler& handler)
{
    std::vector<uint8_t> errResponse;

    // Check if the command qualifies to be run prior to establishing a session
    if (!sessionless && (handler.sessionID == session::SESSION_ZERO))
    {
        errResponse.resize(1);
        errResponse[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE;
        std::cerr << "E> Table::Not enough privileges for command 0x"
                  << std::hex << command.command << "\n";
        return errResponse;
    }

    return functor(commandData, handler);
}

} // namespace command
