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
                getContextSessionID(handler.sessionID);

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

} // command
