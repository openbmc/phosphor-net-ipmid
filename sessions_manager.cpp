#include "sessions_manager.hpp"

#include "main.hpp"
#include "session.hpp"

#include <algorithm>
#include <cstdlib>
#include <iomanip>
#include <memory>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <user_channel/channel_layer.hpp>

using namespace phosphor::logging;

uint8_t ipmiNetworkInstance = 0;

namespace session
{

static std::array<uint8_t, maxNetworkInstanceSupported>
    ipmiNetworkChannelNoList = {0};

void Manager::setNetworkInstance(void)
{

    uint8_t index = 0;
    // Constructing newtipmid instances list based on channel info
    for (uint8_t ch = 1;
         ch < ipmi::maxIpmiChannels && index < maxNetworkInstanceSupported;
         ch++)
    {
        ipmi::ChannelInfo chInfo;
        ipmi::getChannelInfo(ch, chInfo);
        if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
            ipmi::EChannelMediumType::lan8032)
        {
            ipmiNetworkChannelNoList[index++] = ch;
        }
    }

    // Assign the unique netipmid instance number
    for (uint8_t i = 0; i < maxNetworkInstanceSupported; i++)
    {
        if (getInterfaceIndex() == ipmiNetworkChannelNoList[i])
            ipmiNetworkInstance = i;
    }
}

Manager::Manager()
{
}

void Manager::managerInit(const std::string& channel)
{

    /*
     * Session ID is 0000_0000h for messages that are sent outside the session.
     * The session setup commands are sent on this session, so when the session
     * manager comes up, is creates the Session ID  0000_0000h. It is active
     * through the lifetime of the Session Manager.
     */

    objManager = std::make_unique<sdbusplus::server::manager::manager>(
        *getSdBus(), session::sessionManagerRootPath);

    auto objPath = std::string(session::sessionManagerRootPath) + "/" +
                   channel.c_str() + "/0";

    chName = channel;
    setNetworkInstance();
    sessionsMap.emplace(
        0, std::make_shared<Session>(*getSdBus(), objPath.c_str(), 0, 0, 0));
}

std::shared_ptr<Session>
    Manager::startSession(SessionID remoteConsoleSessID, Privilege priv,
                          cipher::rakp_auth::Algorithms authAlgo,
                          cipher::integrity::Algorithms intAlgo,
                          cipher::crypt::Algorithms cryptAlgo)
{
    std::shared_ptr<Session> session = nullptr;
    SessionID sessionID = 0, BMCSessionID = 0;
    cleanStaleEntries();
    auto activeSessions = sessionsMap.size() - session::maxSessionlessCount;

    if (activeSessions < session::maxSessionCountPerChannel)
    {
        do
        {
            BMCSessionID = (crypto::prng::rand());
            BMCSessionID &= multiIntfaceSessionIDMask;
            // In sessionID , BIT 31 BIT30 are used for netipmid instance
            BMCSessionID |= ipmiNetworkInstance << 30;
            std::stringstream sstream;
            sstream << std::hex << BMCSessionID;
            std::string result = sstream.str();
            auto objPath = std::string(session::sessionManagerRootPath) + "/" +
                           chName.c_str() + "/" + result.c_str();
            session = std::make_shared<Session>(
                *getSdBus(), objPath.c_str(), remoteConsoleSessID, BMCSessionID,
                static_cast<uint8_t>(priv));
            /*
             * Every IPMI Session has two ID's attached to it Remote Console
             * Session ID and BMC Session ID. The remote console ID is passed
             * along with the Open Session request command. The BMC session ID
             * is the key for the session map and is generated using std::rand.
             * There is a rare chance for collision of BMC session ID, so the
             * following check validates that. In the case of collision the
             * created session is reset and a new session is created for
             * validating collision.
             */
            auto iterator = sessionsMap.find(session->getBMCSessionID());
            if (iterator != sessionsMap.end())
            {
                // Detected BMC Session ID collisions
                session.reset();
                continue;
            }
            else
            {
                break;
            }
        } while (1);

        // Set the Authentication Algorithm
        switch (authAlgo)
        {
            case cipher::rakp_auth::Algorithms::RAKP_HMAC_SHA1:
            {
                session->setAuthAlgo(
                    std::make_unique<cipher::rakp_auth::AlgoSHA1>(intAlgo,
                                                                  cryptAlgo));
                break;
            }
            case cipher::rakp_auth::Algorithms::RAKP_HMAC_SHA256:
            {
                session->setAuthAlgo(
                    std::make_unique<cipher::rakp_auth::AlgoSHA256>(intAlgo,
                                                                    cryptAlgo));
                break;
            }
            default:
            {
                throw std::runtime_error("Invalid Authentication Algorithm");
            }
        }
        sessionID = session->getBMCSessionID();
        sessionsMap.emplace(sessionID, session);
        storeSessionHandle(sessionID);
        session->sessionHandle(getSessionHandle(sessionID));

        return session;
    }

    log<level::INFO>("No free RMCP+ sessions left");

    throw std::runtime_error("No free sessions left");
}

bool Manager::stopSession(SessionID bmcSessionID)
{
    auto iter = sessionsMap.find(bmcSessionID);
    if (iter != sessionsMap.end())
    {
        iter->second->state(
            static_cast<uint8_t>(session::State::tearDownInProgress));
        return true;
    }
    else
    {
        return false;
    }
}

std::shared_ptr<Session> Manager::getSession(SessionID sessionID,
                                             RetrieveOption option)
{
    switch (option)
    {
        case RetrieveOption::BMC_SESSION_ID:
        {
            auto iter = sessionsMap.find(sessionID);
            if (iter != sessionsMap.end())
            {
                return iter->second;
            }
            break;
        }
        case RetrieveOption::RC_SESSION_ID:
        {
            auto iter = std::find_if(
                sessionsMap.begin(), sessionsMap.end(),
                [sessionID](
                    const std::pair<const uint32_t, std::shared_ptr<Session>>&
                        in) -> bool {
                    return sessionID == in.second->getRCSessionID();
                });

            if (iter != sessionsMap.end())
            {
                return iter->second;
            }
            break;
        }
        default:
            throw std::runtime_error("Invalid retrieval option");
    }

    throw std::runtime_error("Session ID not found");
}

void Manager::cleanStaleEntries()
{
    for (auto iter = sessionsMap.begin(); iter != sessionsMap.end();)
    {
        auto session = iter->second;
        if ((session->getBMCSessionID() != session::sessionZero) &&
            !(session->isSessionActive()))
        {
            sessionHandleMap[getSessionHandle(session->getBMCSessionID())] = 0;
            iter = sessionsMap.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
}

uint8_t Manager::storeSessionHandle(SessionID bmcSessionID)
{
    // Handler index 0 is  reserved for invalid session.
    // index starts with 1, for direct usage. Index 0 reserved
    for (uint8_t i = 1; i <= session::maxSessionCountPerChannel; i++)
    {
        if (sessionHandleMap[i] == 0)
        {
            sessionHandleMap[i] = bmcSessionID;
            break;
        }
    }
    return 0;
}

uint32_t Manager::getSessionIDbyHandle(uint8_t sessionHandle) const
{
    sessionHandle &= multiIntfaceSessionHandleMask;
    if (sessionHandle <= session::maxSessionCountPerChannel)
    {
        return sessionHandleMap[sessionHandle];
    }
    return 0;
}

uint8_t Manager::getSessionHandle(SessionID bmcSessionID) const
{

    // Handler index 0 is  reserved for invalid session.
    // index starts with 1, for direct usage. Index 0 reserved

    for (uint8_t i = 1; i <= session::maxSessionCountPerChannel; i++)
    {
        if (sessionHandleMap[i] == bmcSessionID)
        {
            // In SessionHandle , BIT7 BIT6 are used for netipmid instance
            i |= ipmiNetworkInstance << 6;
            return i;
        }
    }
    return 0;
}
uint8_t Manager::getActiveSessionCount() const
{
    uint8_t count = 0;
    for (const auto& it : sessionsMap)
    {
        const auto& session = it.second;
        if (session->state() == static_cast<uint8_t>(session::State::active))
        {
            count++;
        }
    }
    return count;
}
} // namespace session
