#pragma once

#include <functional>
#include <map>

#include <host-ipmid/ipmid-api.h>

#include "app_util.hpp"
#include "message_handler.hpp"

class CommandTable
{
    public:
        typedef std::function<void (IpmiMessageHandler&) > IpmiCommandFunc_t;

        enum IpmiNetFns
        {
            CHASSIS                                 = 0x0000,   //0x00<<10
            CHASSIS_RESP                            = 0x0400,   //0x01<<10

            BRIDGE                                  = 0x0800,   //0x02<<10
            BRIDGE_RESP                             = 0x0C00,   //0x03<<10

            SENSOR                                  = 0x1000,   //0x04<<10
            SENSOR_RESP                             = 0x1400,   //0x05<<10
            EVENT                                   = 0x1000,   //0x04<<10
            EVENT_RESP                              = 0x1400,   //0x05<<10

            APP                                     = 0x1800,   //0x06<<10
            APP_RESP                                = 0x1C00,   //0x07<<10

            FIRMWARE                                = 0x2000,   //0x08<<10
            FIRMWARE_RESP                           = 0x2400,   //0x09<<10

            STORAGE                                 = 0x2800,   //0x0A<<10
            STORAGE_RESP                            = 0x2C00,   //0x0B<<10

            TRANSPORT                               = 0x3000,   //0x0C<<10
            TRANSPORT_RESP                          = 0x3400,   //0x0D<<10

            //>>
            RESERVED_START                          = 0x3800,   //0x0E<<10
            RESERVED_END                            = 0xAC00,   //0x2B<<10
            //<<

            GROUP_EXTN                              = 0xB000,   //0x2C<<10
            GROUP_EXTN_RESP                         = 0xB400,   //0x2D<<10

            OEM                                     = 0xB800,   //0x2E<<10
            OEM_RESP                                = 0xBC00,   //0x2F<<10
        };

#pragma pack(1)
        union IpmiCommandID
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
        };
#pragma pack()

        struct IpmiCommandTableEntry
        {
            IpmiCommandID CommandID;

            IpmiCommandFunc_t concreteCommand;

            ipmid_callback_t concreteCallBackCommand;

            bool canExecuteSessionless;  // Note: When true, command works at any privilege level,can
            // be sent prior to a session being established

            IpmiSessionPrivileges
            privilegeMask;  //Specifies the minimum privilege level required to
            // execute this command.
            //Note: Command is supported at given
            //privilege level or higher

            IpmiChannels supportedChannels;  //Specifies the channels this command
            //can be requested on.
            //Note: This can be used with
            //"Get NetFn Support" command.

            IpmiCommandSupportMask commandSupportMask;  //Used to derive the values for the
            //firmware firewall.
        };

        typedef std::map<uint32_t, IpmiCommandTableEntry> IpmiCommandTableMap_t;

        /**
         * @brief CommandTable::Register : Register a command.
         *
         * @par Detailed Description:
         *  Register a command with the dispatcher (Command Table)
         *
         * @param (IpmiCommandTableEntry&)i_entry: Reference to the table entry
         *
         * @retval: None
         *
         * @note NOTES:
         *  # Registering an already registered command will overwrite the existing
         *    entry with the new one.
         */
        virtual void Register(IpmiCommandTableEntry& i_entry);
        virtual void Register(IpmiCommandTableEntry* i_array, uint32_t l_numOfEntries);

        virtual void Register(uint32_t i_cmd, IpmiCommandFunc_t i_functor);

        /**
         * @brief CommandTable::Unregister : Unregister a command.
         *
         * @par Detailed Description:
         *  Unregister a command from the command table (dispatcher).
         *
         * @param (uint32_t) i_commandID: Command ID to unregister.
         *
         * @retval None.
         *
         */
        virtual void Unregister(uint32_t i_commandID);

        /**
         * @brief CommandTable::getInstance : Get instance of the CommandTable
         *        class
         *
         * @par Detailed Description:
         *  This static method returns the singleton reference to the CommandTable
         *  class.
         */
        static CommandTable& getInstance();

        /**
         * @brief CommandTable::ExecuteCommand : Execute the requested command
         *
         * @par Detailed Description:
         *  Execute the requested command. Commands are expected to get input from
         *  MessageHandler object and are expected to populate the output in the
         *  MessageHandler object.
         *
         * @param (uint32_t) i_commandID: Command ID to execute.
         * @param (IpmiMessageHandler) io_sessCtrl: Message Handler required for
         *                                            executing the command.
         *
         * @retval None.
         */
        virtual void ExecuteCommand(uint32_t i_commandID,
                                    IpmiMessageHandler& io_sessCtrl);

        virtual ~CommandTable();

    protected:
        /**
         * @brief CommandTable::CommandTable : (Disabled) Default CTOR
         *
         * @par Detailed Description:
         *  Default CTOR, does nothing.
         */
        CommandTable();

    private:
        IpmiCommandTableMap_t iv_cmdTblMap;
        std::mutex iv_cmdTblMapMutex;
};

// This is the constructor function that is called into by each plugin handlers.
// When ipmi sets up the callback handlers, a call is made to this with
// information of netfn, cmd, callback handler pointer and context data.
void ipmi_register_callback(ipmi_netfn_t, ipmi_cmd_t, ipmi_context_t,
                            ipmid_callback_t);
