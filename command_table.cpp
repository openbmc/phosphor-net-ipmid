#include "command_table.hpp"

#include "message_handler.hpp"
#include "message_parsers.hpp"
#include "sessions_manager.hpp"

#include <iomanip>
#include <iostream>
#include <main.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace phosphor::logging;

namespace ipmi
{
using Value = sdbusplus::message::variant<bool, uint8_t, int16_t, uint16_t,
                                          int32_t, uint32_t, int64_t, uint64_t,
                                          double, std::string>;

} // namespace ipmi

namespace command
{

void Table::registerCommand(CommandID inCommand, std::unique_ptr<Entry>&& entry)
{
    auto& command = commandTable[inCommand.command];

    if (command)
    {
        log<level::DEBUG>(
            "Already Registered",
            phosphor::logging::entry("SKIPPED_ENTRY=0x%x",
                                     uint32_t(inCommand.command)));
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
            "xyz.openbmc_project.Ipmi.Host", "/xyz/openbmc_project/Ipmi",
            "xyz.openbmc_project.Ipmi.Server", "execute");
        uint8_t netFnLun = static_cast<uint8_t>(inCommand >> 8);
        uint8_t lun = netFnLun & 0x03;
        uint8_t netFn = netFnLun >> 2;
        uint8_t cmd = static_cast<uint8_t>(inCommand);
        auto session = std::get<session::Manager&>(singletonPool)
                           .getSession(handler.sessionID);
        std::map<std::string, ipmi::Value> options = {
            {"username", ipmi::Value(session->userName)},
            {"privilege",
             ipmi::Value(static_cast<int>(session->curPrivLevel))}};
        method.append(netFn, lun, cmd, commandData, options);
        using IpmiDbusRspType = std::tuple<uint8_t, uint8_t, uint8_t, uint8_t,
                                           std::vector<uint8_t>>;
        IpmiDbusRspType rspTuple;
        try
        {
            auto reply = bus->call(method);
            reply.read(rspTuple);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            response.push_back(IPMI_CC_UNSPECIFIED_ERROR);
            log<level::ERR>("Error sending command to ipmi queue");
            elog<InternalFailure>();
        }
        auto& [rnetFn, rlun, rcmd, cc, responseData] = rspTuple;
        if (uint8_t(netFn + 1) != rnetFn || rlun != lun || rcmd != cmd)
        {
            response.push_back(IPMI_CC_UNSPECIFIED_ERROR);
            log<level::ERR>("DBus call/response mismatch from ipmi queue");
            elog<InternalFailure>();
        }
        else
        {
            response.reserve(1 + responseData.size());
            response.push_back(cc);
            response.insert(response.end(), responseData.begin(),
                            responseData.end());
        }
    }
    else
    {
        auto start = std::chrono::steady_clock::now();

        response = iterator->second->executeCommand(commandData, handler);

        auto end = std::chrono::steady_clock::now();

        auto elapsedSeconds =
            std::chrono::duration_cast<std::chrono::seconds>(end - start);

        // If command time execution time exceeds 2 seconds, log a time
        // exceeded message
        if (elapsedSeconds > 2s)
        {
            std::cerr << "E> IPMI command timed out:Elapsed time = "
                      << elapsedSeconds.count() << "s"
                      << "\n";
        }
    }
    return response;
}

std::vector<uint8_t>
    NetIpmidEntry::executeCommand(std::vector<uint8_t>& commandData,
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
