#include "open_session.hpp"

#include <iostream>

#include "comm_module.hpp"
#include "endian.hpp"
#include "main.hpp"

namespace command
{

std::vector<uint8_t> openSession(std::vector<uint8_t>& inPayload,
                                 const message::Handler& handler)
{
    std::cout << ">> openSession\n";

    std::vector<uint8_t> outPayload(sizeof(OpenSessionResponse_t));
    auto request = reinterpret_cast<OpenSessionRequest_t*>(inPayload.data());
    auto response = reinterpret_cast<OpenSessionResponse_t*>(outPayload.data());

    // Check for valid Authentication Algorithms
    if (request->authAlgo != static_cast<uint8_t>
        (cipher::rakp_auth::Algorithms::RAKP_HMAC_SHA1))
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_AUTH_ALGO);
        return outPayload;
    }

    // Check for valid Integrity Algorithms
    if (request->intAlgo != 0)
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_INTEGRITY_ALGO);
        return outPayload;
    }

    // Check for valid Confidentiality Algorithms
    if (request->confAlgo != 0)
    {
        response->status_code =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_CONF_ALGO);
        return outPayload;
    }

    // Start an IPMI session
    auto session = (std::get<session::Manager&>(singletonPool).startSession(
            endian::from_ipmi<uint32_t>(request->remoteConsoleSessionID),
            static_cast<session::Privilege>
            (request->maxPrivLevel),
            request->authAlgo,
            request->intAlgo,
            request->confAlgo)).lock();

    response->messageTag = request->messageTag;

    if (session)
    {
        response->status_code = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
        response->maxPrivLevel = static_cast<uint8_t>(session->curPrivLevel);
        response->remoteConsoleSessionID = request->remoteConsoleSessionID;
        response->managedSystemSessionID = endian::to_ipmi<uint32_t>
                                           (session->getBMCSessionID());

        response->authPayload = request->authPayload ;
        response->authPayloadLen = request->authPayloadLen ;
        response->authAlgo = request->authAlgo;

        response->intPayload = request->intPayload ;
        response->intPayloadLen = request->intPayloadLen ;
        response->intAlgo = request->intAlgo;

        response->confPayload = request->confPayload ;
        response->confPayloadLen = request->confPayloadLen ;
        response->confAlgo = request->confAlgo;

        session->updateLastTransactionTime();

        // Session state is Setup in progress
        session->state = session::State::SETUP_IN_PROGRESS;

    }
    else
    {
        response->status_code = static_cast<uint8_t>
                                (RAKP_ReturnCode::INSUFFICIENT_RESOURCE);
        std::cerr << "openSession : Problem opening a session\n";
    }

    std::cout << "<< openSession\n";
    return outPayload;
}

} // namespace command
