#pragma once

#include <functional>
#include <map>

#include "message_handler.hpp"

namespace command
{

union CommandID
{
    uint32_t cmdCode;

    uint8_t reserved;
    uint8_t payloadType;

    union
    {
        uint8_t netFn: 6;
        uint8_t lun: 2;

        uint8_t netFnLun;
    } NetFnLun;

    uint8_t cmd;
} __attribute__((packed));

/*
 * CommandFunctor_t is the functor register for commands defined in phosphor-net-ipmid. This
 * would take the request part of the command as a vector and a reference to the message handler.
 * The response part of the command is returned as a vector.
 */
using CommandFunctor_t =
    std::function<std::vector<uint8_t> (std::vector<uint8_t>&, MessageHandler&)> ;

/*
 * @struct CmdDetails
 *
 * Command details is used to register commands supported in phosphor-net-ipmid.
 */
struct CmdDetails
{
    CommandID command;
    CommandFunctor_t functor;
    session::Privilege privilege;
    bool sessionless;
};

/*
 * @enum NetFns
 *
 * A field that identifies the functional class of the message. The Network Function clusters IPMI
 * commands into different sets
 */
enum class NetFns
{
    CHASSIS            = 0x0000,   //0x00<<10
    CHASSIS_RESP       = 0x0400,   //0x01<<10

    BRIDGE             = 0x0800,   //0x02<<10
    BRIDGE_RESP        = 0x0C00,   //0x03<<10

    SENSOR             = 0x1000,   //0x04<<10
    SENSOR_RESP        = 0x1400,   //0x05<<10
    EVENT              = 0x1000,   //0x04<<10
    EVENT_RESP         = 0x1400,   //0x05<<10

    APP                = 0x1800,   //0x06<<10
    APP_RESP           = 0x1C00,   //0x07<<10

    FIRMWARE           = 0x2000,   //0x08<<10
    FIRMWARE_RESP      = 0x2400,   //0x09<<10

    STORAGE            = 0x2800,   //0x0A<<10
    STORAGE_RESP       = 0x2C00,   //0x0B<<10

    TRANSPORT          = 0x3000,   //0x0C<<10
    TRANSPORT_RESP     = 0x3400,   //0x0D<<10

    //>>
    RESERVED_START     = 0x3800,   //0x0E<<10
    RESERVED_END       = 0xAC00,   //0x2B<<10
    //<<

    GROUP_EXTN         = 0xB000,   //0x2C<<10
    GROUP_EXTN_RESP    = 0xB400,   //0x2D<<10

    OEM                = 0xB800,   //0x2E<<10
    OEM_RESP           = 0xBC00,   //0x2F<<10
};

/*
 * @class Entry
 *
 * This is the base class for registering IPMI commands. There are two ways of registering commands
 * to phosphor-net-ipmid, the session related commands and provider commands
 *
 * Every commands has a privilege level which mentions the minimum session privilege level needed to
 * execute the command
 */

class Entry
{

    public:
        Entry(CommandID command, session::Privilege privilege): command(command),
            privilege(privilege) {}

        virtual std::vector<uint8_t> executeCommand(std::vector<uint8_t>& commandData,
                MessageHandler& handler) = 0;

        auto getCommand()
        {
            return command;
        }

        auto getPrivilege()
        {
            return privilege;
        }

        virtual ~Entry() {};

    protected:
        CommandID command;

        //Specifies the minimum privilege level required to execute this command.
        session::Privilege privilege;
};

/*
 * @class NetIpmidEntry
 *
 * NetIpmidEntry is used to register commands that are consumed only in phosphor-net-ipmid.
 * The RAKP commands, session commands and user management commands are examples of this.
 *
 * There are certain IPMI commands that can be executed before session can be established like
 * Get System GUID, Get Channel Authentication Capabilities and RAKP commands.
 */
class NetIpmidEntry: public Entry
{

    public:
        NetIpmidEntry(CommandID command, CommandFunctor_t functor,
                      session::Privilege privilege,
                      bool sessionless): Entry(command, privilege) , functor(functor),
            sessionless(sessionless) {}

        std::vector<uint8_t> executeCommand(std::vector<uint8_t>& commandData,
                                            MessageHandler& handler);

        virtual ~NetIpmidEntry() {};

    protected:
        CommandFunctor_t functor;

        bool sessionless;
};

class Table
{
    public:

        Table() = default;
        ~Table() = default;

        using  CommandTable_t = std::map<uint32_t, std::unique_ptr<Entry>>;

        /**
         * @brief Register a commands
         *
         * Register a command with the command table dispatcher
         *
         * @param [in] Command ID
         * @param [in] Command Entry
         *
         * @return: None
         *
         * @note Registering an already registered command will overwrite the existing
         *       entry with the new one.
         */
        void registerCommand(uint32_t inCommand, std::unique_ptr<Entry> entry);

        /**
         * @brief Execute the command
         *
         * Execute the command for the corresponding CommandID
         *
         * @param [in] Command ID to execute.
         * @param [in] Request Data for the command
         * @param [in] Reference to the Message Handler
         *
         * @return Response data for the command
         */
        std::vector<uint8_t> executeCommand(uint32_t inCommand,
                                            std::vector<uint8_t>& commandData, MessageHandler& handler);

    private:
        CommandTable_t commandTable;
};

}// namespace command
