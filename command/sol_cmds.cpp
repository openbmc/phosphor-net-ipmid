#include <phosphor-logging/log.hpp>
#include "main.hpp"
#include "sol/sol_context.hpp"
#include "sol/sol_manager.hpp"
#include "sol_cmds.hpp"

namespace command
{

using namespace phosphor::logging;

std::vector<uint8_t> SOLPayloadHandler(std::vector<uint8_t>& inPayload,
                                       const message::Handler& handler)
{
    std::vector<uint8_t> response;
    auto request = reinterpret_cast<sol::Payload*>(inPayload.data());

    auto solDataSize = inPayload.size() - sizeof(sol::Payload);

    sol::Buffer charData(solDataSize);
    if( solDataSize > 0)
    {
        std::copy_n(inPayload.data() + sizeof(sol::Payload),
                    solDataSize,
                    charData.begin());
    }

    try
    {
        auto& context = std::get<sol::Manager&>(singletonPool).
                getContext(handler.sessionID);

        context.processInboundPayload(request->packetSeqNum,
                                      request->packetAckSeqNum,
                                      request->acceptedCharCount,
                                      request->inOperation.ack,
                                      charData);
    }
    catch (std::exception& e)
    {
        log<level::ERR>(e.what());
        return response;
    }

    return response;
}

void SOLActivating(uint8_t payloadInstance, uint32_t sessionID)
{
    std::vector<uint8_t> outPayload(sizeof(SOLActivatingRequest));

    auto request = reinterpret_cast<SOLActivatingRequest*>
                    (outPayload.data());

    request->sessionState = 0;
    request->payloadInstance = payloadInstance;
    request->majorVersion = sol::MAJOR_VERSION;
    request->minorVersion = sol::MINOR_VERSION;

    auto session = (std::get<session::Manager&>(singletonPool).getSession(
            sessionID)).lock();

    message::Handler msgHandler(sessionID, session->channelPtr);

    msgHandler.sendUnsolicitedIPMIPayload(NETFN_TRANSPORT,
                                          SOL_ACTIVATING_COMMAND,
                                          outPayload);
}

} // command
