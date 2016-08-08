#include "sessions_manager.hpp"

#include <iomanip>
#include <iostream>
#include <memory>

#include "cipher_algo.hpp"
#include "session.hpp"

SessionsManager& SessionsManager::getInstance()
{
    return SingletonHolder<SessionsManager>::Instance();
}

SessionsManager::SessionsManager() :  sessionsMap(), mapMutex()
{
    std::shared_ptr<Session> l_pSession(new Session);
    sessionsMap[0] = l_pSession;
}

SessionsManager::~SessionsManager() {}

Session* SessionsManager::startSession(
    uint32_t i_remoteConsoleSessID,
    uint32_t i_priv,
    uint8_t i_authAlgo,
    uint8_t i_intgAlgo,
    uint8_t i_confAlgo,
    UserAuthInterface::AuthenticationMethod i_authMethod)
{
    std::shared_ptr<Session> l_pSession;
    uint8_t l_allowed = 0, l_active = 0;
    sessionsCount(l_allowed, l_active);

    if (l_active < l_allowed)
    {
        //We still have some free slots, so lets open up a new session.

        bool l_collisionDetected = false;

        do
        {
            l_collisionDetected = false;
            l_pSession.reset(new Session(i_remoteConsoleSessID, i_priv));

            if ((getSession(l_pSession->getBMCSessionID(),
                            IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID)))
            {
                //Detected BMC session ID collisions
                l_collisionDetected = true;
            }
        }
        while (l_collisionDetected);

        //The session setup is now in progress. Set the session object accordingly.
        l_pSession->getSessionState().setSessionState(
            SessionState::IPMI_SESSION_SETUP_IN_PROGRESS);

        //<PROTECTED>
        {
            std::lock_guard<std::mutex> l_lock(mapMutex);
            sessionsMap[l_pSession->getBMCSessionID()] = l_pSession;
        }
        //</PROTECTED>

        AuthAlgoInterface* l_authAlgo = nullptr;
        IntegrityAlgoInterface* l_intgAlgo = nullptr;
        ConfidentialityAlgoInterface* l_confAlgo = nullptr;

        //Add ciphers to session
        switch (i_authAlgo)
        {
            case AuthAlgoInterface::IPMI_RAKP_NONE:
            case AuthAlgoInterface::IPMI_RAKP_HMAC_SHA1:
            default:
                std::get<std::unique_ptr<AuthAlgoInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<AuthAlgoNone>();

                l_authAlgo = std::get<std::unique_ptr<AuthAlgoInterface>>
                             (l_pSession->getSessionCipherSuite()).get();

                l_authAlgo->setApplied(AuthAlgoInterface::IPMI_RAKP_HMAC_SHA1);
        };
        l_authAlgo->setRequested(i_authAlgo);
        l_authAlgo->setState(true);

        switch (i_intgAlgo)
        {
            case IntegrityAlgoInterface::IPMI_INTEGRITY_NONE:
                std::get<std::unique_ptr<IntegrityAlgoInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IntegrityAlgoNone>();

                l_intgAlgo = std::get<std::unique_ptr<IntegrityAlgoInterface>>
                             (l_pSession->getSessionCipherSuite()).get();

                l_intgAlgo->setApplied(IntegrityAlgoInterface::IPMI_INTEGRITY_NONE);

                break;
            case IntegrityAlgoInterface::IPMI_INTEGRITY_HMAC_SHA1_96:
                std::get<std::unique_ptr<IntegrityAlgoInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IntegrityAlgoHmacSha1_96>();

                l_intgAlgo = std::get<std::unique_ptr<IntegrityAlgoInterface>>
                             (l_pSession->getSessionCipherSuite()).get();

                l_intgAlgo->setApplied(IntegrityAlgoInterface::IPMI_INTEGRITY_HMAC_SHA1_96);
                break;
            default:
                std::get<std::unique_ptr<IntegrityAlgoInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IntegrityAlgoNone>();

                l_intgAlgo = std::get<std::unique_ptr<IntegrityAlgoInterface>>
                             (l_pSession->getSessionCipherSuite()).get();

                l_intgAlgo->setApplied(IntegrityAlgoInterface::IPMI_INTEGRITY_NONE);
        };
        l_intgAlgo->setRequested(i_intgAlgo);
        l_intgAlgo->setState(true);

        switch (i_confAlgo)
        {
            case ConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_NONE:
                std::get<std::unique_ptr<ConfidentialityAlgoInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IpmiConfidentialityAlgoNone>();

                l_confAlgo = std::get<std::unique_ptr<ConfidentialityAlgoInterface>>
                             (l_pSession->getSessionCipherSuite()).get();

                l_confAlgo->setApplied(
                    ConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_NONE);
                break;
            case ConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_AES_CBC_128:
                std::get<std::unique_ptr<ConfidentialityAlgoInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IpmiConfidentialityAlgoAesCbc128>();

                l_confAlgo = std::get<std::unique_ptr<ConfidentialityAlgoInterface>>
                             (l_pSession->getSessionCipherSuite()).get();

                l_confAlgo->setApplied(
                    ConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_AES_CBC_128);
                break;
            default:
                std::get<std::unique_ptr<ConfidentialityAlgoInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IpmiConfidentialityAlgoNone>();

                l_confAlgo = std::get<std::unique_ptr<ConfidentialityAlgoInterface>>
                             (l_pSession->getSessionCipherSuite()).get();

                l_confAlgo->setApplied(
                    ConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_NONE);
        };
        l_confAlgo->setRequested(i_confAlgo);
        l_confAlgo->setState(true);

        //Different user authentication methods for this session can be
        //chosen here
        switch (i_authMethod)
        {
            case UserAuthInterface::IPMI_AUTH_METHOD_STATIC_PASS_KEY:
                std::get<std::unique_ptr<UserAuthInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IpmiStaticPasswordAuthentication>();
                break;
            default:
                std::get<std::unique_ptr<UserAuthInterface>>
                        (l_pSession->getSessionCipherSuite()) =
                            std::make_unique<IpmiUnsupportedPasswordAuthentication>();
                break;
        }
    }
    else
    {
        std::cerr << "E> No free sessions left: Active: " << l_active << " Allowed: " <<
                  l_allowed << "\n";

        SessionMap_t::iterator l_mapItor;

        //<PROTECTED>
        {
            std::lock_guard<std::mutex> l_lock(mapMutex);

            SessionMap_t::iterator l_mapItor;

            for (l_mapItor = sessionsMap.begin(); l_mapItor != sessionsMap.end();
                 ++l_mapItor)
            {
                std::cerr << "E> Active Session: 0x" << std::hex << std::setfill('0') <<
                          std::setw(8)
                          << (l_mapItor->second)->getBMCSessionID() << std::endl;
            }
        }
        //</PROTECTED>

        cleanStaleEntries();
        sessionsCount(l_allowed, l_active);
        std::cerr << "E> Cleaned any stale entries: Active: " << l_active <<
                  " Allowed: " << l_allowed
                  << std::endl;
    }

    return l_pSession.get();
}

void SessionsManager::stopSession(uint32_t i_bmcSessionId)
{
    std::shared_ptr<Session> l_pSession = getSession(i_bmcSessionId,
                                          IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID);

    if (l_pSession.get() && i_bmcSessionId != 0x00)  //Not the session 0x00
    {
        //<PROTECTED>
        {
            std::lock_guard<std::mutex> l_lock(mapMutex);
            sessionsMap.erase(i_bmcSessionId);
        }
        //</PROTECTED>

        l_pSession->getSessionState().setSessionState(
            SessionState::IPMI_SESSION_IS_INACTIVE);
    }

    //Cleanup stale entries
    cleanStaleEntries();
}

void SessionsManager::stopChannelSessions()
{
    SessionMap_t::iterator l_itor;
    std::shared_ptr<Session> l_pSession;

    //<PROTECTED>
    {
        std::lock_guard<std::mutex> l_lock(mapMutex);

        for (l_itor = sessionsMap.begin(); l_itor != sessionsMap.end(); ++l_itor)
        {
            l_pSession = l_itor->second;

            if (l_pSession && (l_pSession->getBMCSessionID() != 0))
            {
                sessionsMap.erase(l_pSession->getBMCSessionID());
            }
        }
    }
    //</PROTECTED>
}

void SessionsManager::cleanStaleEntries()
{
    SessionMap_t::iterator l_itor;
    std::shared_ptr<Session> l_pSession;

    //<PROTECTED>
    {
        std::lock_guard<std::mutex> l_lock(mapMutex);

        for (l_itor = sessionsMap.begin(); l_itor != sessionsMap.end(); ++l_itor)
        {
            l_pSession = l_itor->second;

            if (l_pSession &&
                !(l_pSession->getSessionState().isSessionActive()) &&
                (l_pSession->getBMCSessionID() != 0))
            {
                sessionsMap.erase(l_pSession->getBMCSessionID());
            }
        }
    }
    //</PROTECTED>
}

void SessionsManager::sessionsCount(uint8_t& o_allowed, uint8_t& o_active)
{
    o_allowed = IPMI_MAX_SESSION_HANDLES;

    //<PROTECTED>
    {
        std::lock_guard<std::mutex> l_lock(mapMutex);
        o_active = sessionsMap.size() - IPMI_MAX_SESSIONLESS_HANDLES;
    }
    //</PROTECTED>
}

//Called when Session Object is required to work with
std::shared_ptr<Session> SessionsManager::getSession(
    uint32_t i_sessionId,
    SessionRetrieveOption i_option)
{
    std::shared_ptr<Session> l_pSession;

    SessionMap_t::iterator l_mapItor;

    //<PROTECTED>
    {
        std::lock_guard<std::mutex> l_lock(mapMutex);

        switch (i_option)
        {
            case IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID:
            {
                l_mapItor = sessionsMap.find(i_sessionId);
                if (l_mapItor != sessionsMap.end())
                {
                    l_pSession = l_mapItor->second;
                }
                break;
            }
            case IPMI_SESSION_RETRIEVE_OPTION_RC_SESSION_ID:
            {
                for (const auto& l_mapItor : sessionsMap)
                {
                    if (i_sessionId == l_mapItor.second->getRCSessionID())
                    {
                        l_pSession = l_mapItor.second;
                        break;
                    }
                }
                break;
            }
            case IPMI_SESSION_RETRIEVE_OPTION_SESSION_HANDLE:
            {
                for (const auto& l_mapItor : sessionsMap)
                {
                    if (i_sessionId == l_mapItor.second->getSessionHandle())
                    {
                        l_pSession = l_mapItor.second;
                        break;
                    }
                }
                break;
            }
            case IPMI_SESSION_RETRIEVE_OPTION_SUBSCRIPTIONS:
            {
                for (const auto& l_mapItor : sessionsMap)
                {
                    if (i_sessionId & l_mapItor.second->getSessionState().getSubscriptions())
                    {
                        l_pSession = l_mapItor.second;
                        break;
                    }
                }
                break;
            }
            default:
            {
                l_pSession.reset();
                break;
            }
        }
    }
    //</PROTECTED>

    return l_pSession;
}
