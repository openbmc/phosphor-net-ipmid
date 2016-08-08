#include "command_table.hpp"

#include <iomanip>
#include <iostream>
#include <ipmi.H>
#include "message_handler.hpp"

void CommandTable::Register(IpmiCommandTableEntry& i_entry)
{
    std::cout << "I> Registering Command" << std::hex << i_entry.CommandID.cmdCode
              << std::endl;

    std::lock_guard<std::mutex> l_lock(iv_cmdTblMapMutex);

    iv_cmdTblMap[i_entry.CommandID.cmdCode] = i_entry;
}

void CommandTable::Register(IpmiCommandTableEntry* i_array,
                                uint32_t l_numOfEntries)
{
    for (uint32_t l_itor = 0; l_itor < l_numOfEntries ; ++l_itor)
    {
        Register(i_array[l_itor]);
    }
}

void CommandTable::Register(uint32_t i_cmd, IpmiCommandFunc_t i_functor)
{
    IpmiCommandTableEntry l_entry;
    l_entry.CommandID.cmdCode = i_cmd;
    l_entry.concreteCommand = i_functor;
    l_entry.concreteCallBackCommand = nullptr;
    l_entry.canExecuteSessionless = false;
    l_entry.privilegeMask = IPMI_SESSION_PRIVILEGE_ANY;
    l_entry.supportedChannels = IPMI_CHANNEL_ANY;
    l_entry.commandSupportMask = IPMI_COMMAND_SUPPORT_NO_DISABLE;

    Register(l_entry);
}

void CommandTable::Unregister(uint32_t i_commandID)
{
    std::lock_guard<std::mutex> l_lock(iv_cmdTblMapMutex);

    iv_cmdTblMap.erase(i_commandID);

    std::cout << "I> Un-Registering Command " << std::hex << i_commandID <<
              std::endl;
}

CommandTable& CommandTable::getInstance()
{
    return SingletonHolder<CommandTable>::Instance();
}

void CommandTable::ExecuteCommand(uint32_t i_commandID,
                                      IpmiMessageHandler& io_sessCtrl)
{
    do
    {
        std::lock_guard<std::mutex> l_lock(iv_cmdTblMapMutex);

        auto l_itor = iv_cmdTblMap.find(i_commandID);

        if (l_itor == iv_cmdTblMap.end())
        {
            std::cerr << "E> CommandTable:: Command Not found: 0x" << std::hex <<
                      i_commandID << std::endl;


            //@TODO: Command is not registered. Send a completion code (Node Busy).
            io_sessCtrl.iv_responsePayload = new uint8_t[1];
            io_sessCtrl.iv_responsePayloadSize = sizeof(uint8_t);

            *(io_sessCtrl.iv_responsePayload) = IPMICC_CMD_UNKNOWN;
        }
        else
        {
            //There is a handler registered.
            std::cout << "I> CommandTable:: Command found: 0x" << std::hex <<
                      i_commandID << std::endl;

            if (!l_itor->second.canExecuteSessionless)
            {
                //Check Command execution privileges
                if (l_itor->second.privilegeMask > (io_sessCtrl.getSessionPrivilegeLevel() &
                                                    0x0F))
                {
                    std::cerr << "E> CommandTable::Not enough privileges for command 0x" <<
                              std::hex
                              << i_commandID << std::endl;
                    io_sessCtrl.iv_responsePayload = new uint8_t[1];
                    io_sessCtrl.iv_responsePayloadSize = sizeof(uint8_t);
                    *(io_sessCtrl.iv_responsePayload) = IPMICC_WRONG_PRIV;

                    break;
                }
            }

            if (l_itor->second.supportedChannels == IPMI_CHANNEL_SYSTEM_INTERFACE_ONLY)
            {
                std::cerr << "E> CommandTable::Not supported on LAN interface 0x" <<
                          std::hex
                          << i_commandID << std::endl;
                io_sessCtrl.iv_responsePayload = new uint8_t[1];
                io_sessCtrl.iv_responsePayloadSize = sizeof(uint8_t);
                *(io_sessCtrl.iv_responsePayload) = IPMICC_WRONG_PRIV;

                break;
            }

            std::chrono::time_point<std::chrono::system_clock> l_startTime, l_endTime;
            l_startTime = std::chrono::system_clock::now();

            if (l_itor->second.concreteCommand != nullptr)
            {
                //Run the command
                //If the payload type is IPMI add ipmi_ret_t to the response pointer
                l_itor->second.concreteCommand(io_sessCtrl);
            }
            else
            {
                io_sessCtrl.iv_responsePayload = new uint8_t[64];
                io_sessCtrl.iv_responsePayloadSize = 0;
                ipmi_ret_t ipmiRC = l_itor->second.concreteCallBackCommand(0, 0,
                                    io_sessCtrl.iv_requestPayload,
                                    &io_sessCtrl.iv_responsePayload[1],
                                    &io_sessCtrl.iv_responsePayloadSize, NULL);

                io_sessCtrl.iv_responsePayload[0] = ipmiRC;
                io_sessCtrl.iv_responsePayloadSize = io_sessCtrl.iv_responsePayloadSize + 1;

            }

            l_endTime = std::chrono::system_clock::now();

            std::chrono::duration<double> elapsed_seconds = l_endTime - l_startTime;

            if (elapsed_seconds.count() > 1)
            {
                std::cerr << "E> IPMI command timed out:Elapsed time = "
                          << elapsed_seconds.count() << "s" << std::endl;
            }
        }
    }
    while (0);
}

CommandTable::CommandTable() {}

CommandTable::~CommandTable() {}

// Method that gets called by shared libraries to get their command handlers registered
void ipmi_register_callback(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_context_t context,
                            ipmid_callback_t handler, ipmi_cmd_data_t data)
{
    CommandTable::IpmiCommandTableEntry l_entry;

    uint16_t net_fun = netfn << 10;
    l_entry.CommandID.cmdCode = (IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI << 16) |
                                net_fun | cmd;
    l_entry.concreteCommand = nullptr;
    l_entry.concreteCallBackCommand = handler;
    l_entry.canExecuteSessionless = data.canExecuteSessionless;
    l_entry.privilegeMask = data.privilegeMask;
    l_entry.supportedChannels = data.supportedChannels;
    l_entry.commandSupportMask = data.commandSupportMask;

    CommandTable::getInstance().Register(l_entry);
}

