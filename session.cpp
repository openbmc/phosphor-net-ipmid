#include "session.hpp"

#include <openssl/rand.h>

#include "endian.hpp"

namespace session
{

Session::Session(uint32_t& inRemoteConsoleSessID, Privilege priv)
{
    remoteConsoleSessionID = endian::from_ipmi<uint32_t>(inRemoteConsoleSessID);

    uint32_t sessionID = 0;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&sessionID), sizeof(sessionID)) == 0)
    {
        throw std::exception();
    }
    bmcSessionID = sessionID;
    curPrivLevel = priv;
    state = State::INACTIVE;
}

bool Session::isSessionActive()
{
    bool isActive = false;
    std::chrono::duration<double> elapsed_seconds;

    std::chrono::time_point<std::chrono::system_clock> currentTime;
    currentTime = std::chrono::system_clock::now();

    elapsed_seconds = currentTime - lastTime;

    switch (state)
    {
        case State::SETUP_IN_PROGRESS:
            if (elapsed_seconds.count() < SESSION_SETUP_TIMEOUT)
            {
                isActive = true;
            }
            break;
        case State::ACTIVE:
            if (elapsed_seconds.count() < SESSION_INACTIVITY_TIMEOUT)
            {
                isActive = true;
            }
            break;
        default:
            isActive = false;
            break;
    }

    return isActive;
}

} // namespace session
