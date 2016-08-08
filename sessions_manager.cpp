#include "sessions_manager.hpp"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>

#include "session.hpp"

namespace session
{

Manager::Manager()
{
    sessionsMap.emplace(0, std::make_shared<Session>());
    // Seeding the pseudo-random generator
    std::srand(std::time(0));
}

std::weak_ptr<Session> Manager::startSession(SessionID remoteConsoleSessID,
                                             Privilege priv,
                                             uint8_t authAlgo,
                                             uint8_t intgAlgo,
                                             uint8_t confAlgo)
{
    std::shared_ptr<Session> session = nullptr;
    SessionID sessionID = 0;
    auto activeSessions = sessionsMap.size() - MAX_SESSIONLESS_COUNT;
    cleanStaleEntries();

    if (activeSessions < MAX_SESSION_COUNT)
    {
        do
        {
            session = std::make_shared<Session>(remoteConsoleSessID, priv);

            auto iterator = sessionsMap.find(session->getBMCSessionID());
            if (iterator != sessionsMap.end())
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

        // Set the Authentication Algorithm to RAKP_HMAC_SHA1
        switch (authAlgo)
        {
            case static_cast<int>
                    (cipher::rakp_auth::Algorithms::RAKP_HMAC_SHA1):
            {
                session->setAuthAlgo(
                    std::make_unique<cipher::rakp_auth::AlgoSHA1>());
                break;
            }
            default:
            {
                authAlgo = static_cast<uint8_t>
                           (cipher::rakp_auth::Algorithms::RAKP_HMAC_INVALID);
                break;
            }
        }
        sessionID = session->getBMCSessionID();
        sessionsMap.emplace(std::pair<uint32_t, std::shared_ptr<Session>>
                            (sessionID, std::move(session)));
    }
    else
    {
        std::cerr << "E> No free sessions left: Active: " << activeSessions <<
                  " Allowed: " <<
                  MAX_SESSION_COUNT << "\n";

        for (const auto& iterator : sessionsMap)
        {
            std::cerr << "E> Active Session: 0x" << std::hex
                      << std::setfill('0') << std::setw(8)
                      << (iterator.second)->getBMCSessionID() << "\n";
        }
        throw std::runtime_error("No free sessions left");;
    }

    return getSession(sessionID);
}

void Manager::stopSession(SessionID bmcSessionID)
{
    // If the session is valid and not session zero
    if(bmcSessionID != SESSION_ZERO)
    {
        auto iter = sessionsMap.find(bmcSessionID);
        if (iter != sessionsMap.end())
        {
            iter->second->state = State::TEAR_DOWN_IN_PROGRESS;
        }
    }
}

std::weak_ptr<Session> Manager::getSession(SessionID sessionID,
                                           RetrieveOption option)
{
    std::shared_ptr<Session> session = nullptr;

    switch (option)
    {
        case RetrieveOption::BMC_SESSION_ID:
        {
            auto iter = sessionsMap.find(sessionID);
            if (iter != sessionsMap.end())
            {
                session = iter->second;
            }
            return session;
        }
        case RetrieveOption::RC_SESSION_ID:
        {
            auto iter = std::find_if(sessionsMap.begin(),
                                     sessionsMap.end(),
                                     [sessionID](const std::pair<const uint32_t,
                                                 std::shared_ptr<Session>>& in)
                                                 -> bool
            {
                return sessionID == in.second->getRCSessionID();
            });

            if (iter != sessionsMap.end())
            {
                session = iter->second;
            }
            return session;
        }
        default:
            throw std::runtime_error("Session ID not found");
    }
}

void Manager::cleanStaleEntries()
{
    for(auto iter = sessionsMap.begin(); iter != sessionsMap.end();)
    {
        auto session = iter->second;
        if ((session->getBMCSessionID() != SESSION_ZERO) &&
            !(session->isSessionActive()))
        {
            iter = sessionsMap.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
}

} // namespace session
