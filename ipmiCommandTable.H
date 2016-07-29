#ifndef IPMICOMMANDTABLE_H_
#define IPMICOMMANDTABLE_H_

#include <functional>
#include <map>
#include <ipmiAppUtil.H>
#include <ipmiMessageHandler.H>

class IpmiCommandTable {
 public:

    //synonyms
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

    enum IpmiSessionPrivileges
    {
        IPMI_SESSION_PRIVILEGE_ANY      = 0x00000000,
        IPMI_SESSION_PRIVILEGE_CALLBACK = 0x01,
        IPMI_SESSION_PRIVILEGE_USER     = 0x02,
        IPMI_SESSION_PRIVILEGE_OPERATOR = 0x03,
        IPMI_SESSION_PRIVILEGE_ADMIN    = 0x04,
        IPMI_SESSION_PRIVILEGE_OEM      = 0x05,

        IPMI_SESSION_PRIVILEGE_NONE     = 0xFFFFFFFF,
    };

    enum IpmiChannels
    {
        IPMI_CHANNEL_ANY                    = 0x00000000,
        IPMI_CHANNEL_SYSTEM_INTERFACE_ONLY  = 0x00000001,
        IPMI_CHANNEL_LOCAL_INTERFACES_ONLY  = 0x00000002,
    };

    enum IpmiCommandSupportMask
    {
        IPMI_COMMAND_SUPPORT_DEFAULT    = 0x00000000, //Supported by default
                                                      //Can be configured
                                                      //(enabled/disabled)

        IPMI_COMMAND_SUPPORT_NO_DISABLE = 0x00000001, //Supported and cannot be
                                                      //configured (enable/disable)

        IPMI_COMMAND_SUPPORT_NO_DEFAULT = 0x00000002, //Disabled but can be
                                                      //configured

        IPMI_COMMAND_SUPPORT_DISABLED   = 0x10000000, //Support has been disabled
    };

    struct IpmiCommandTableEntry
    {
        IpmiCommandID CommandID;

        IpmiCommandFunc_t concreteCommand;

        bool canExecuteSessionless;      //Note: When true, command works at any
                                         //privilege level,can be sent prior to
                                         //a session being established

        IpmiSessionPrivileges privilegeMask;//Specifies the minimum privilege level
                                            //required to execute this command.
                                            //Note: Command is supported at given
                                            //privilege level or higher

        IpmiChannels supportedChannels;  //Specifies the channels this command
                                         //can be requested on.
                                         //Note: This can be used with
                                         //"Get NetFn Support" command.

        IpmiCommandSupportMask commandSupportMask;  //Used to derive the values for the
                                                    //firmware firewall.
    };

    typedef std::map<uint32_t,IpmiCommandTableEntry> IpmiCommandTableMap_t;

    /**
     * @brief IpmiCommandTable::Register : Register a command.
     *
     * @par Detailed Description:
     *  Register a command with the dispatcher (Command Table)
     *
     * @param (IpmiCommandTableEntry&)i_entry: Reference to the table entry
     *
     * @retval: None
     *
     * @pre None.
     *
     * @post None.
     *
     * @test Test Cases:
     *  <Test Case Description paragraph>
     *
     * @todo TO DOs:
     *  # Populate the test case section.
     *
     * @note NOTES:
     *  # Registering an already registered command will overwrite the existing
     *    entry with the new one.
     */
    virtual void Register(IpmiCommandTableEntry& i_entry);
    virtual void Register(IpmiCommandTableEntry* i_array,uint32_t l_numOfEntries);

    virtual void Register(uint32_t i_cmd, IpmiCommandFunc_t i_functor);

    /**
     * @brief IpmiCommandTable::Unregister : Unregister a command.
     *
     * @par Detailed Description:
     *  Unregister a command from the command table (dispatcher).
     *
     * @param (uint32_t) i_commandID: Command ID to unregister.
     *
     * @retval None.
     *
     * @pre None.
     *
     * @post None.
     *
     * @test Test Cases:
     *  <Test Case Description paragraph>
     *
     * @todo TO DOs:
     *  # Populate the test case section.
     *
     * @note NOTES:
     *  # None
     */
    virtual void Unregister(uint32_t i_commandID);

    /**
     * @brief IpmiCommandTable::getInstance : Get instance of the IpmiCommandTable
     *        class
     *
     * @par Detailed Description:
     *  This static method returns the singleton reference to the IpmiCommandTable
     *  class.
     */
    static IpmiCommandTable& getInstance();

    /**
     * @brief IpmiCommandTable::ExecuteCommand : Execute the requested command
     *
     * @par Detailed Description:
     *  Execute the requested command. Commands are expected to get input from
     *  SessionControl object and are expected to populate the output in the
     *  SessionControl object.
     *
     * @param (uint32_t) i_commandID: Command ID to execute.
     * @param (IpmiSessionControl_t) io_sessCtrl: Session Control required for
     *                                            executing the command.
     *
     * @retval None.
     *
     * @pre None.
     *
     * @post None.
     *
     * @test Test Cases:
     *  <Test Case Description paragraph>
     *
     * @todo TO DOs:
     *  # Populate the test case section.
     *
     * @note NOTES:
     *  # None
     */
    virtual void ExecuteCommand(uint32_t i_commandID,
                                IpmiMessageHandler& io_sessCtrl);

    virtual ~IpmiCommandTable();

protected:

    /**
     * @brief IpmiCommandTable::IpmiCommandTable : (Disabled) Default CTOR
     *
     * @par Detailed Description:
     *  Default CTOR, does nothing.
     */
    IpmiCommandTable();

private:
    IpmiCommandTableMap_t iv_cmdTblMap;
    std::mutex iv_cmdTblMapMutex;
};

#endif /* IPMICOMMANDTABLE_H_ */
