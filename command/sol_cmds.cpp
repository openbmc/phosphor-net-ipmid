#include "sol_cmds.hpp"

#include "sessions_manager.hpp"
#include "sol/sol_context.hpp"
#include "sol/sol_manager.hpp"

#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>

namespace sol
{

namespace command
{

using namespace phosphor::logging;

std::vector<uint8_t> payloadHandler(const std::vector<uint8_t>& inPayload,
                                    std::shared_ptr<message::Handler>& handler)
{
    // Check inPayload size is at least Payload
    if (inPayload.size() < sizeof(Payload))
    {
        return std::vector<uint8_t>();
    }

    auto request = reinterpret_cast<const Payload*>(inPayload.data());
    auto solDataSize = inPayload.size() - sizeof(Payload);

    std::vector<uint8_t> charData(solDataSize);
    if (solDataSize > 0)
    {
        std::copy_n(inPayload.data() + sizeof(Payload), solDataSize,
                    charData.begin());
    }

    try
    {
        auto& context = sol::Manager::get().getContext(handler->sessionID);

        context.processInboundPayload(
            request->packetSeqNum, request->packetAckSeqNum,
            request->acceptedCharCount, request->inOperation.ack, charData);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        return std::vector<uint8_t>();
    }

    return std::vector<uint8_t>();
}

void activating(uint8_t payloadInstance, uint32_t sessionID)
{
    std::vector<uint8_t> outPayload(sizeof(ActivatingRequest));

    auto request = reinterpret_cast<ActivatingRequest*>(outPayload.data());

    request->sessionState = 0;
    request->payloadInstance = payloadInstance;
    request->majorVersion = MAJOR_VERSION;
    request->minorVersion = MINOR_VERSION;

    auto session = session::Manager::get().getSession(sessionID);

    message::Handler msgHandler(session->channelPtr, sessionID);

    msgHandler.sendUnsolicitedIPMIPayload(netfnTransport, solActivatingCmd,
                                          outPayload);
}

std::vector<uint8_t> setConfParams(const std::vector<uint8_t>& inPayload,
                                   std::shared_ptr<message::Handler>& handler)
{
    std::vector<uint8_t> outPayload(sizeof(SetConfParamsResponse));
    auto request =
        reinterpret_cast<const SetConfParamsRequest*>(inPayload.data());
    auto response = reinterpret_cast<SetConfParamsResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;

    sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());
    static std::string solService{};
    ipmi::PropertyMap properties;
    std::string ethdevice = ipmi::getChannelName(ipmi::convertCurrentChannelNum(
        ipmi::currentChNum, getInterfaceIndex()));

    std::string solPathWitheEthName = solPath + ethdevice;
    if (solService.empty())
    {
        try
        {
            solService =
                ipmi::getService(dbus, solInterface, solPathWitheEthName);
        }
        catch (const std::runtime_error& e)
        {
            solService.clear();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error: get SOL service failed");
            response->completionCode = IPMI_CC_BUSY;
            return outPayload;
        }
    }

    try
    {
        switch (static_cast<Parameter>(request->paramSelector))
        {
            case Parameter::PROGRESS:
            {
                uint8_t progress =
                    static_cast<uint8_t>(request->value & progressMask);
                ipmi::setDbusProperty(dbus, solService, solPathWitheEthName,
                                      solInterface, "Progress",
                                      static_cast<uint8_t>(progress));
                break;
            }
            case Parameter::ENABLE:
            {
                bool enable = static_cast<bool>(request->value & enableMask);
                ipmi::setDbusProperty(dbus, solService, solPathWitheEthName,
                                      solInterface, "Enable",
                                      static_cast<bool>(enable));
                break;
            }
            case Parameter::AUTHENTICATION:
            {
                bool encrypt = static_cast<bool>(request->auth.encrypt);
                bool auth = static_cast<bool>(request->auth.auth);
                uint8_t privilege =
                    static_cast<uint8_t>(request->auth.privilege);

                ipmi::setDbusProperty(dbus, solService, solPathWitheEthName,
                                      solInterface, "ForceEncryption",
                                      static_cast<bool>(encrypt));
                ipmi::setDbusProperty(dbus, solService, solPathWitheEthName,
                                      solInterface, "ForceAuthentication",
                                      static_cast<bool>(auth));
                ipmi::setDbusProperty(dbus, solService, solPathWitheEthName,
                                      solInterface, "Privilege",
                                      static_cast<uint8_t>(privilege));
                break;
            }
            case Parameter::ACCUMULATE:
            {
                if (request->acc.threshold == 0)
                {
                    response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
                    break;
                }
                ipmi::setDbusProperty(
                    dbus, solService, solPathWitheEthName, solInterface,
                    "AccumulateIntervalMS",
                    static_cast<uint8_t>(request->acc.interval));
                ipmi::setDbusProperty(
                    dbus, solService, solPathWitheEthName, solInterface,
                    "Threshold", static_cast<uint8_t>(request->acc.threshold));
                break;
            }
            case Parameter::RETRY:
            {
                ipmi::setDbusProperty(
                    dbus, solService, solPathWitheEthName, solInterface,
                    "RetryCount", static_cast<uint8_t>(request->retry.count));
                ipmi::setDbusProperty(
                    dbus, solService, solPathWitheEthName, solInterface,
                    "RetryIntervalMS",
                    static_cast<uint8_t>(request->retry.interval));
                break;
            }
            case Parameter::PORT:
            {
                response->completionCode = ipmiCCWriteReadParameter;
                break;
            }
            case Parameter::NVBITRATE:
            case Parameter::VBITRATE:
            case Parameter::CHANNEL:
            default:
                response->completionCode = ipmiCCParamNotSupported;
        }
    }
    catch (const std::runtime_error&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error setting sol parameter");
        response->completionCode = IPMI_CC_BUSY;
        return outPayload;
    }

    return outPayload;
}

std::vector<uint8_t> getConfParams(const std::vector<uint8_t>& inPayload,
                                   std::shared_ptr<message::Handler>& handler)
{
    std::vector<uint8_t> outPayload(sizeof(GetConfParamsResponse));
    auto request =
        reinterpret_cast<const GetConfParamsRequest*>(inPayload.data());
    auto response = reinterpret_cast<GetConfParamsResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    response->paramRev = parameterRevision;

    // Update latest property values from dbus to sol mananger
    sol::Manager::get().updateSOLParameter(ipmi::convertCurrentChannelNum(
        ipmi::currentChNum, getInterfaceIndex()));
    if (request->getParamRev)
    {
        return outPayload;
    }

    switch (static_cast<Parameter>(request->paramSelector))
    {
        case Parameter::PROGRESS:
        {
            outPayload.push_back(sol::Manager::get().progress);
            break;
        }
        case Parameter::ENABLE:
        {
            outPayload.push_back(sol::Manager::get().enable);
            break;
        }
        case Parameter::AUTHENTICATION:
        {
            Auth value{0};

            value.encrypt = sol::Manager::get().forceEncrypt;
            value.auth = sol::Manager::get().forceAuth;
            value.privilege =
                static_cast<uint8_t>(sol::Manager::get().solMinPrivilege);
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::ACCUMULATE:
        {
            Accumulate value{0};

            value.interval = sol::Manager::get().accumulateInterval.count() /
                             sol::accIntervalFactor;
            value.threshold = sol::Manager::get().sendThreshold;
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::RETRY:
        {
            Retry value{0};

            value.count = sol::Manager::get().retryCount;
            value.interval = sol::Manager::get().retryInterval.count() /
                             sol::retryIntervalFactor;
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::PORT:
        {
            auto port = endian::to_ipmi<uint16_t>(IPMI_STD_PORT);
            auto buffer = reinterpret_cast<const uint8_t*>(&port);

            std::copy_n(buffer, sizeof(port), std::back_inserter(outPayload));
            break;
        }
        case Parameter::CHANNEL:
        {
            outPayload.push_back(sol::Manager::get().channel);
            break;
        }
        case Parameter::NVBITRATE:
        case Parameter::VBITRATE:
        default:
            response->completionCode = ipmiCCParamNotSupported;
    }

    return outPayload;
}

} // namespace command

} // namespace sol
