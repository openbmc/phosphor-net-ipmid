#include "command_table.hpp"

#include <host-ipmid/ipmid-api.h>

#include <iomanip>
#include <iostream>

#include "message_handler.hpp"
#include "sessions_manager.hpp"

namespace command
{

void Table::registerCommand(uint32_t inCommand, std::unique_ptr<Entry> entry)
{
    std::cout << "I> Registering Command" << std::hex << inCommand << "\n";

    commandTable[inCommand] = std::move(entry);
}

std::vector<uint8_t> Table::executeCommand(uint32_t inCommand,
        std::vector<uint8_t>& commandData, MessageHandler& handler)
{
    std::vector<uint8_t> response;

    auto iterator = commandTable.find(inCommand);

    if (iterator == commandTable.end())
    {
        std::cerr << "E> Table:: Command Not found: 0x" << std::hex << inCommand <<
                  "\n";

        response.resize(1);
        *(response.data()) = IPMI_CC_INVALID;
    }
    else
    {
        std::chrono::time_point<std::chrono::system_clock> start, end;
        start = std::chrono::system_clock::now();

        response = iterator->second->executeCommand(commandData, handler);


        end = std::chrono::system_clock::now();

        std::chrono::duration<double> elapsed_seconds = end - start;

        // If command time execution time exceeds 2 seconds, log a time exceeded message
        if (elapsed_seconds.count() > 2)
        {
            std::cerr << "E> IPMI command timed out:Elapsed time = "
                      << elapsed_seconds.count() << "s" << "\n";
        }
    }
    return response;
}

std::vector<uint8_t> NetIpmidEntry::executeCommand(std::vector<uint8_t>&
        commandData, MessageHandler& handler)
{
    std::vector<uint8_t> errResponse;

    // Check if the command qualifies to be run prior to establishing a session
    if (!sessionless && (handler.getSessionID() == session::SESSION_ZERO))
    {
        errResponse.resize(1);
        *(errResponse.data()) = IPMI_CC_INSUFFICIENT_PRIVILEGE;
        std::cerr << "E> Table::Not enough privileges for command 0x" << std::hex <<
                  command.cmdCode << "\n";
        return errResponse;
    }

    return functor(commandData, handler);
}

} // namespace command
