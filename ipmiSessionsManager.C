#include <memory>

#include <ipmiCiphers.H>
#include <ipmiSession.H>
#include <ipmiSessionsManager.H>
#include <ipmiTrace.H>

IpmiSessionsManager& IpmiSessionsManager::getInstance() {
  return SingletonHolder<IpmiSessionsManager>::Instance();
}

IpmiSessionsManager::IpmiSessionsManager() :  iv_sessionsMap(), iv_mapMutex() {
  std::shared_ptr<IpmiSession> l_pSession(new IpmiSession);
  iv_sessionsMap[0] = l_pSession;
}

IpmiSessionsManager::~IpmiSessionsManager() {}

IpmiSession* IpmiSessionsManager::startSession(
    uint32_t i_remoteConsoleSessID,
    uint32_t i_priv,
    uint8_t i_authAlgo,
    uint8_t i_intgAlgo,
    uint8_t i_confAlgo,
    IpmiUserAuthenticationInterface::IpmiAuthenticationMethod i_authMethod) {
  std::shared_ptr<IpmiSession> l_pSession;
  uint8_t l_allowed = 0, l_active = 0;
  sessionsCount(l_allowed,l_active);

  if (l_active < l_allowed) {
    //We still have some free slots, so lets open up a new session.

    bool l_collisionDetected = false;

    do {
      l_collisionDetected = false;
      l_pSession.reset(new IpmiSession(i_remoteConsoleSessID,i_priv));

      if((getSession(l_pSession->getBMCSessionID().get(),
                     IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID)).get()) {
        //Detected BMC session ID collisions
        l_collisionDetected = true;
      }
    } while (l_collisionDetected);

    //The session setup is now in progress. Set the session object accordingly.
    l_pSession->getSessionState().setSessionState(IpmiSessionState::IPMI_SESSION_SETUP_IN_PROGRESS);

    //<PROTECTED>
    {
      std::lock_guard<std::mutex> l_lock(iv_mapMutex);
      iv_sessionsMap[l_pSession->getBMCSessionID().get()] = l_pSession;
    }
    //</PROTECTED>

    IpmiAuthenticationAlgoInterface* l_authAlgo = nullptr;
    IpmiIntegrityAlgoInterface* l_intgAlgo = nullptr;
    IpmiConfidentialityAlgoInterface* l_confAlgo = nullptr;

    //Add ciphers to session
    switch (i_authAlgo) {
      case IpmiAuthenticationAlgoInterface::IPMI_RAKP_NONE:
      case IpmiAuthenticationAlgoInterface::IPMI_RAKP_HMAC_SHA1:
      default:
        l_authAlgo = l_pSession->getSessionCipherSuite().setAuthCipher
                                                                (new IpmiAuthenticationAlgoNone);
        l_authAlgo->setApplied(IpmiAuthenticationAlgoInterface::IPMI_RAKP_HMAC_SHA1);
    };
    l_authAlgo->setRequested(i_authAlgo);
    l_authAlgo->setState(true);

    switch (i_intgAlgo) {
      case IpmiIntegrityAlgoInterface::IPMI_INTEGRITY_NONE:
        l_intgAlgo = l_pSession->getSessionCipherSuite().setIntegrityCipher
                                                                    (new IpmiIntegrityAlgoNone);
        l_intgAlgo->setApplied(IpmiIntegrityAlgoInterface::IPMI_INTEGRITY_NONE);
        break;
      case IpmiIntegrityAlgoInterface::IPMI_INTEGRITY_HMAC_SHA1_96:
        l_intgAlgo = l_pSession->getSessionCipherSuite().setIntegrityCipher
                                                               (new IpmiIntegrityAlgoHmacSha1_96);
        l_intgAlgo->setApplied(IpmiIntegrityAlgoInterface::IPMI_INTEGRITY_HMAC_SHA1_96);
        break;
      default:
        l_intgAlgo = l_pSession->getSessionCipherSuite().setIntegrityCipher
                                                                      (new IpmiIntegrityAlgoNone);
        l_intgAlgo->setApplied(IpmiIntegrityAlgoInterface::IPMI_INTEGRITY_NONE);
    };
    l_intgAlgo->setRequested(i_intgAlgo);
    l_intgAlgo->setState(true);

    switch (i_confAlgo) {
      case IpmiConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_NONE:
        l_confAlgo = l_pSession->getSessionCipherSuite().setConfidentialityCipher
                                                                (new IpmiConfidentialityAlgoNone);
        l_confAlgo->setApplied(IpmiConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_NONE);
        break;
      case IpmiConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_AES_CBC_128:
        l_confAlgo = l_pSession->getSessionCipherSuite().setConfidentialityCipher
                                                          (new IpmiConfidentialityAlgoAesCbc128);
        l_confAlgo->setApplied(IpmiConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_AES_CBC_128);
        break;
      default:
        l_confAlgo = l_pSession->getSessionCipherSuite().setConfidentialityCipher
                                                               (new IpmiConfidentialityAlgoNone);
        l_confAlgo->setApplied(IpmiConfidentialityAlgoInterface::IPMI_CONFIDENTIALITY_NONE);
    };
    l_confAlgo->setRequested(i_confAlgo);
    l_confAlgo->setState(true);

    //Different user authentication methods for this session can be
    //chosen here
    switch (i_authMethod) {
      case IpmiUserAuthenticationInterface::IPMI_AUTH_METHOD_STATIC_PASS_KEY:
        l_pSession->getSessionCipherSuite().setUserAuthInterface
                                                          (new IpmiStaticPasswordAuthentication);
        break;
      case IpmiUserAuthenticationInterface::IPMI_AUTH_METHOD_PASSWORD_FILE:
        l_pSession->getSessionCipherSuite().setUserAuthInterface
                                                            (new IpmiPasswordFileAuthentication);
        break;
      default:
        l_pSession->getSessionCipherSuite().setUserAuthInterface
                                                     (new IpmiUnsupportedPasswordAuthentication);
        break;
    }
  } else {
    TRACFCOMP(IpmiTrc(IpmiTrace::COMM),ERR_MRK
              "No free sessions left: Active: %d  Allowed: %d ",l_active, l_allowed);

    SessionMap_t::iterator l_mapItor;

    //<PROTECTED>
    {
      std::lock_guard<std::mutex> l_lock(iv_mapMutex);

      SessionMap_t::iterator l_mapItor;

      for (l_mapItor = iv_sessionsMap.begin(); l_mapItor != iv_sessionsMap.end(); ++l_mapItor) {
        TRACFCOMP(IpmiTrc(IpmiTrace::COMM),INFO_MRK
                  "Active Session: 0x%8X",(l_mapItor->second)->getBMCSessionID().get());
      }
    }
    //</PROTECTED>

    cleanStaleEntries();
    sessionsCount(l_allowed,l_active);
    TRACFCOMP(IpmiTrc(IpmiTrace::COMM),ERR_MRK
              "Cleaned any stale entries: Active: %d  Allowed: %d ",l_active, l_allowed);
  }

  return l_pSession.get();
}

void IpmiSessionsManager::stopSession(uint32_t i_bmcSessionId) {
  std::shared_ptr<IpmiSession> l_pSession = getSession(i_bmcSessionId,
                            IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID);

  if(l_pSession.get() && i_bmcSessionId != 0x00) { //Not the session 0x00
    //<PROTECTED>
    {
      std::lock_guard<std::mutex> l_lock(iv_mapMutex);
      iv_sessionsMap.erase(i_bmcSessionId);
    }
    //</PROTECTED>

    l_pSession->getSessionState().setSessionState(IpmiSessionState::IPMI_SESSION_IS_INACTIVE);
  }

  //Cleanup stale entries
  cleanStaleEntries();
}

void IpmiSessionsManager::stopChannelSessions() {
  SessionMap_t::iterator l_itor;
  std::shared_ptr<IpmiSession> l_pSession;

  //<PROTECTED>
  {
    std::lock_guard<std::mutex> l_lock(iv_mapMutex);

    for (l_itor = iv_sessionsMap.begin(); l_itor != iv_sessionsMap.end(); ++l_itor) {
      l_pSession = l_itor->second;

      if (l_pSession && (l_pSession->getBMCSessionID().get() != 0)) {
        iv_sessionsMap.erase(l_pSession->getBMCSessionID().get());
      }
    }
  }
  //</PROTECTED>
}

void IpmiSessionsManager::cleanStaleEntries() {
  SessionMap_t::iterator l_itor;
  std::shared_ptr<IpmiSession> l_pSession;

  //<PROTECTED>
  {
    std::lock_guard<std::mutex> l_lock(iv_mapMutex);

    for (l_itor = iv_sessionsMap.begin(); l_itor != iv_sessionsMap.end(); ++l_itor) {
      l_pSession = l_itor->second;

      if (l_pSession &&
          !(l_pSession->getSessionState().isSessionActive()) &&
          (l_pSession->getBMCSessionID().get() != 0)) {
        iv_sessionsMap.erase(l_pSession->getBMCSessionID().get());
      }
    }
  }
  //</PROTECTED>
}

void IpmiSessionsManager::sessionsCount(uint8_t& o_allowed, uint8_t& o_active) {
  o_allowed = IPMI_MAX_SESSION_HANDLES;

  //<PROTECTED>
  {
    std::lock_guard<std::mutex> l_lock(iv_mapMutex);
    o_active = iv_sessionsMap.size() - IPMI_MAX_SESSIONLESS_HANDLES;
  }
  //</PROTECTED>
}

//Called when Session Object is required to work with
std::shared_ptr<IpmiSession> IpmiSessionsManager::getSession(uint32_t i_sessionId,
                                            IpmiSessionRetrieveOption i_option ) {
  std::shared_ptr<IpmiSession> l_pSession;

  SessionMap_t::iterator l_mapItor;

  //<PROTECTED>
  {
    std::lock_guard<std::mutex> l_lock(iv_mapMutex);

    switch (i_option) {
      case IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID: {
        l_mapItor = iv_sessionsMap.find(i_sessionId);
        if (l_mapItor != iv_sessionsMap.end()) {
          l_pSession = l_mapItor->second;
        }
        break;
      }
      case IPMI_SESSION_RETRIEVE_OPTION_RC_SESSION_ID: {
        for (l_mapItor = iv_sessionsMap.begin(); l_mapItor != iv_sessionsMap.end(); ++l_mapItor) {
          if (i_sessionId == l_mapItor->second->getRCSessionID().get()) {
            l_pSession = l_mapItor->second;
            break;
          }
        }
        break;
      }
      case IPMI_SESSION_RETRIEVE_OPTION_SESSION_HANDLE: {
        for (l_mapItor = iv_sessionsMap.begin(); l_mapItor != iv_sessionsMap.end(); ++l_mapItor) {
          if (i_sessionId == l_mapItor->second->getSessionHandle()) {
            l_pSession = l_mapItor->second;
            break;
          }
        }
        break;
      }
      case IPMI_SESSION_RETRIEVE_OPTION_SUBSCRIPTIONS: {
        for (l_mapItor = iv_sessionsMap.begin(); l_mapItor != iv_sessionsMap.end(); ++l_mapItor) {
          if (i_sessionId & l_mapItor->second->getSessionState().getSubscriptions()) {
            l_pSession = l_mapItor->second;
            break;
          }
        }
        break;
      }
      default: {
        l_pSession.reset();
        break;
      }
    }
  }
  //</PROTECTED>

  return l_pSession;
}
