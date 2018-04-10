#include "command/payload_cmds.hpp"
#include "command_table.hpp"
#include "main.hpp"
#include "session.hpp"
#include "user_module.hpp"

#include <experimental/filesystem>
#include <fstream>
#include <host-ipmid/ipmid-api.h>

namespace usermanagement
{
namespace command
{
void registerCommands()
{
    static const ::command::CmdDetails commands[] =
    {
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(::command::NetFns::APP) | 0x47
            },
            &ipmiAppSetUserPwd, session::Privilege::ADMIN, false
        },
    };

    for (const auto& iter : commands)
    {
        std::get<::command::Table&>(singletonPool).registerCommand(
            iter.command, std::make_unique<::command::NetIpmidEntry>
            (iter.command, iter.functor, iter.privilege, iter.sessionless));
    }
}

std::vector<uint8_t> ipmiAppSetUserPwd(const std::vector<uint8_t>& inPayload,
                             const message::Handler& handler)
{
    constexpr auto ipmiUserPwdPath = "/etc/ipmipwd";
    constexpr auto ipmiChangePwd = 0x02;
    constexpr auto ipmiPwdLength20Bytes = 0x80;

    std::vector<uint8_t> outPayload(sizeof(SetPwdResponse));
    uint8_t pwdLength = 16;
    auto requestData =
        reinterpret_cast<const SetPwdRequest *>(inPayload.data());
    auto responseData =
        reinterpret_cast<SetPwdResponse *>(outPayload.data());
    responseData->completionCode = IPMI_CC_OK;

    if (requestData->userId & ipmiPwdLength20Bytes)
    {
        pwdLength = 20;
    }

    if (requestData->operation != ipmiChangePwd)
    {
        responseData->completionCode = IPMI_CC_INVALID;
        return outPayload;
    }

    std::ifstream pwdFile;
    pwdFile.open(ipmiUserPwdPath, std::ifstream::binary);
    if (pwdFile.is_open())
    {
        std::error_code ec;
        auto pwdLengthFile = std::experimental::filesystem::file_size(
            ipmiUserPwdPath,ec);

        if (pwdLength != pwdLengthFile)
        {
            pwdFile.close();
            responseData->completionCode = IPMI_CC_PWD_LENGTH_NOT_MATCHING;
            return outPayload;
        }
        pwdFile.close();
    }

    std::ofstream os(ipmiUserPwdPath, std::ofstream::binary);
    os.write(reinterpret_cast<const char *>(requestData->pwd), pwdLength);
    os.close();
    return outPayload;
}

}
}
