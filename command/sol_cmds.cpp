#include "sol_cmds.hpp"

#include "main.hpp"
#include "sol/sol_context.hpp"
#include "sol/sol_manager.hpp"

#include <phosphor-logging/log.hpp>

namespace sol
{

namespace command
{

using namespace phosphor::logging;

std::vector<uint8_t> payloadHandler(const std::vector<uint8_t>& inPayload,
                                    const message::Handler& handler)
{
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
        auto& context = std::get<sol::Manager&>(singletonPool)
                            .getContext(handler.sessionID);

        context.processInboundPayload(
            request->packetSeqNum, request->packetAckSeqNum,
            request->acceptedCharCount, request->inOperation.ack, charData);
    }
    catch (std::exception& e)
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

    auto session =
        std::get<session::Manager&>(singletonPool).getSession(sessionID);

    message::Handler msgHandler(session->channelPtr, sessionID);

    msgHandler.sendUnsolicitedIPMIPayload(netfnTransport, solActivatingCmd,
                                          outPayload);
}

std::vector<uint8_t> getConfParams(const std::vector<uint8_t>& inPayload,
                                   const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(GetConfParamsResponse));
    auto request =
        reinterpret_cast<const GetConfParamsRequest*>(inPayload.data());
    auto response = reinterpret_cast<GetConfParamsResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    response->paramRev = parameterRevision;

    if (request->getParamRev)
    {
        return outPayload;
    }

    switch (static_cast<Parameter>(request->paramSelector))
    {
        case Parameter::PROGRESS:
        {
            outPayload.push_back(
                std::get<sol::Manager&>(singletonPool).progress);
            break;
        }
        case Parameter::ENABLE:
        {
            outPayload.push_back(std::get<sol::Manager&>(singletonPool).enable);
            break;
        }
        case Parameter::AUTHENTICATION:
        {
            Auth value{0};

            value.encrypt = std::get<sol::Manager&>(singletonPool).forceEncrypt;
            value.auth = std::get<sol::Manager&>(singletonPool).forceAuth;
            value.privilege = static_cast<uint8_t>(
                std::get<sol::Manager&>(singletonPool).solMinPrivilege);
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::ACCUMULATE:
        {
            Accumulate value{0};

            value.interval = std::get<sol::Manager&>(singletonPool)
                                 .accumulateInterval.count() /
                             sol::accIntervalFactor;
            value.threshold =
                std::get<sol::Manager&>(singletonPool).sendThreshold;
            auto buffer = reinterpret_cast<const uint8_t*>(&value);

            std::copy_n(buffer, sizeof(value), std::back_inserter(outPayload));
            break;
        }
        case Parameter::RETRY:
        {
            Retry value{0};

            value.count = std::get<sol::Manager&>(singletonPool).retryCount;
            value.interval =
                std::get<sol::Manager&>(singletonPool).retryInterval.count() /
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
            outPayload.push_back(
                std::get<sol::Manager&>(singletonPool).channel);
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
