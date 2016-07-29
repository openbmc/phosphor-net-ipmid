#include <iomanip>
#include <iostream>
#include <ipmiCommandTable.H>
#include <ipmiMessageHandler.H>

/*# Function Specification
 *
 * @Overview:
 *  Atomically register a command with Command Table.
 *
 * @Thread: Daemon
 *
 * @note NOTES:
 *  # Registering an already registered command will overwrite the command entry
 *    with the new one.
 */
void IpmiCommandTable::Register(IpmiCommandTableEntry& i_entry)
{
    std::cout<<"I> Registering Command"<<std::hex<<i_entry.CommandID.cmdCode<<std::endl;

    std::lock_guard<std::mutex> l_lock(iv_cmdTblMapMutex);

    iv_cmdTblMap[i_entry.CommandID.cmdCode] = i_entry;
}

void IpmiCommandTable::Register(IpmiCommandTableEntry* i_array,
                                uint32_t l_numOfEntries)
{
    for(uint32_t l_itor = 0; l_itor < l_numOfEntries ; ++l_itor)
    {
        Register(i_array[l_itor]);
    }
}

void IpmiCommandTable::Register(uint32_t i_cmd, IpmiCommandFunc_t i_functor)
{
    IpmiCommandTableEntry l_entry;
    l_entry.CommandID.cmdCode = i_cmd;
    l_entry.concreteCommand = i_functor;
    l_entry.canExecuteSessionless = false;
    l_entry.privilegeMask = IPMI_SESSION_PRIVILEGE_ANY;
    l_entry.supportedChannels = IPMI_CHANNEL_ANY;
    l_entry.commandSupportMask = IPMI_COMMAND_SUPPORT_NO_DISABLE;

    Register(l_entry);
}

/*# Function Specification
 *
 * @Overview:
 *  Atomically unregister a command from the Command Table.
 *
 * @Thread: Daemon
 *
 * @note NOTES:
 *  # None.
 */
void IpmiCommandTable::Unregister(uint32_t i_commandID)
{
    std::lock_guard<std::mutex> l_lock(iv_cmdTblMapMutex);

    iv_cmdTblMap.erase(i_commandID);

    std::cout<<"I> Un-Registering Command "<<std::hex<<i_commandID<<std::endl;
}

/*# Function Specification
 *
 * @Overview:
 *  Return the singleton reference to IpmiCommandTable object.
 *
 * @Thread: Daemon
 *
 * @note NOTES:
 *  # None.
 */
IpmiCommandTable& IpmiCommandTable::getInstance()
{
    return SingletonHolder<IpmiCommandTable>::Instance();
}

/*# Function Specification
 *
 * @Overview:
 *  Execute the requested command.
 *
 * @Thread: Daemon
 *
 * @note NOTES:
 *  # None.
 */
void IpmiCommandTable::ExecuteCommand(uint32_t i_commandID,
                                      IpmiMessageHandler& io_sessCtrl)
{
    do
    {
        std::lock_guard<std::mutex> l_lock(iv_cmdTblMapMutex);

        auto l_itor = iv_cmdTblMap.find(i_commandID);

        if(l_itor == iv_cmdTblMap.end() )
        {
            std::cerr<<"E> IpmiCommandTable:: Command Not found: 0x"<<std::hex
            											<<i_commandID<<std::endl;

            //@TODO: Command is not registered. Send a completion code (Node Busy).
            io_sessCtrl.iv_responsePayload = new uint8_t[1];
            io_sessCtrl.iv_responsePayloadSize = sizeof(uint8_t);

            *(io_sessCtrl.iv_responsePayload) = IPMICC_CMD_UNKNOWN;
         }
        else
        {
            //There is a handler registered.
            std::cout<<"I> IpmiCommandTable:: Command found: 0x"<<std::hex
            											<<i_commandID<<std::endl;

            if(!l_itor->second.canExecuteSessionless)
            {
                //Check Command execution privileges
                if(l_itor->second.privilegeMask > (io_sessCtrl.getSessionPrivilegeLevel() & 0x0F))
                {
                    std::cerr<<"E> IpmiCommandTable::Not enough privileges for command 0x"<<std::hex
                    											<<i_commandID<<std::endl;
                     io_sessCtrl.iv_responsePayload = new uint8_t[1];
                    io_sessCtrl.iv_responsePayloadSize = sizeof(uint8_t);
                    *(io_sessCtrl.iv_responsePayload) = IPMICC_WRONG_PRIV;

                    break;
                }

                //@TODO: Validate whether the command can be executed :#@Firewall
            }

            std::chrono::time_point<std::chrono::system_clock> l_startTime, l_endTime;
            l_startTime = std::chrono::system_clock::now();

            //Run the command
            l_itor->second.concreteCommand(io_sessCtrl);

            l_endTime = std::chrono::system_clock::now();

            std::chrono::duration<double> elapsed_seconds = l_endTime-l_startTime;

            if (elapsed_seconds.count() > 1)
            {
                std::cerr<<"E> IPMI command timed out:Elapsed time = "
                							<<elapsed_seconds.count()<<"s"<<std::endl;
            }
        }
    }while(0);
}

IpmiCommandTable::IpmiCommandTable()
{

}

IpmiCommandTable::~IpmiCommandTable()
{

}

