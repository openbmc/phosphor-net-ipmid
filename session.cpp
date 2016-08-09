#include "session.hpp"

#include <ctime>

#include "endian.hpp"

namespace session
{

Session::Session(uint32_t inRemoteConsoleSessID, Privilege priv):
    remoteConsoleSessionID(endian::from_ipmi<uint32_t>(inRemoteConsoleSessID)),
    bmcSessionID(std::rand()),
    curPrivLevel(priv),
    state(State::INACTIVE) {}

bool Session::isSessionActive()
{
    auto currentTime = std::chrono::steady_clock::now();
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>
                          (currentTime - lastTime);

    switch (state)
    {
        case State::SETUP_IN_PROGRESS:
            if (elapsedSeconds < SESSION_SETUP_TIMEOUT)
            {
                return true;
            }
            break;
        case State::ACTIVE:
            if (elapsedSeconds < SESSION_INACTIVITY_TIMEOUT)
            {
                return true;
            }
            break;
        default:
            return false;
            break;
    }
}

} // namespace session
