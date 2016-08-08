#include "sessions_manager.hpp"

#include <openssl/err.h>

#include <iomanip>
#include <iostream>
#include <memory>

#include "session.hpp"

namespace session
{

Manager::Manager()
{
    sessionsMap[0] = std::make_unique<Session>();
}

Session* Manager::startSession(uint32_t remoteConsoleSessID, Privilege priv,
                               uint8_t authAlgo, uint8_t intgAlgo, uint8_t confAlgo)
{
    std::unique_ptr<Session> session;
    uint32_t sessionID = 0;
    auto activeSessions = sessionsMap.size() - MAX_SESSIONLESS_COUNT;
    cleanStaleEntries();

    if (activeSessions < MAX_SESSION_COUNT)
    {
        do
        {
            try
            {
                session = std::make_unique<Session>(remoteConsoleSessID, priv);
            }
            catch (std::exception& e)
            {
                std::cerr << "RAND failed" << ERR_get_error() << "\n";
                return nullptr;
            }

            if (getSession(session->getBMCSessionID()))
            {
                //Detected BMC Session ID collisions
                session.reset();
                continue;
            }
            else
            {
                break;
            }
        }
        while (1);

        // Session state is Setup in progress
        session->setSessionState(State::SETUP_IN_PROGRESS);

        // Set the Authentication Algorithm to RAKP_HMAC_SHA1
        switch (authAlgo)
        {
            case static_cast<int>(cipher::auth::RAKPAuthAlgorithms::RAKP_HMAC_SHA1):
            {
                session->setAuthAlgo(std::make_unique<cipher::auth::RAKPAlgoSHA1>());
                break;
            }
            default:
                authAlgo = static_cast<uint8_t>
                           (cipher::auth::RAKPAuthAlgorithms::RAKP_HMAC_INVALID);
        }

        sessionID = session->getBMCSessionID();
        sessionsMap[sessionID] = std::move(session);
    }
    else
    {
        std::cerr << "E> No free sessions left: Active: " << activeSessions <<
                  " Allowed: " <<
                  MAX_SESSION_COUNT << "\n";

        for (const auto& iterator : sessionsMap)
        {
            std::cerr << "E> Active Session: 0x" << std::hex << std::setfill('0') <<
                      std::setw(8) << (iterator.second)->getBMCSessionID() << "\n";
        }
    }

    return getSession(sessionID);
}

void Manager::stopSession(uint32_t bmcSessionID)
{
    auto session = getSession(bmcSessionID);

    // If the session is valid and not session zero
    if (session && (bmcSessionID != SESSION_ZERO))
    {
        session->setSessionState(State::TEAR_DOWN_IN_PROGRESS);
    }
}

Session* Manager::getSession(uint32_t sessionID, RetrieveOption option)
{
    Session* session = nullptr;

    switch (option)
    {
        case RetrieveOption::RETRIEVE_OPTION_BMC_SESSION_ID:
        {
            auto iterator = sessionsMap.find(sessionID);
            if (iterator != sessionsMap.end())
            {
                session = (iterator->second).get();
            }
            break;
        }
        case RetrieveOption::RETRIEVE_OPTION_RC_SESSION_ID:
        {
            for (const auto& iterator : sessionsMap)
            {
                if (sessionID == iterator.second->getRCSessionID())
                {
                    session = (iterator.second).get();
                    break;
                }
            }
            break;
        }
        default:
            break;
    }

    return session;
}

void Manager::cleanStaleEntries()
{
    for (const auto& iterator : sessionsMap)
    {
        auto session = (iterator.second).get();

        if ((session->getBMCSessionID() != SESSION_ZERO) &&
            !(session->isSessionActive()))
        {
            sessionsMap.erase(session->getBMCSessionID());
        }
    }
}

} // namespace session
