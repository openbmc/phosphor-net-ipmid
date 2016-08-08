#ifndef IPMISESSIONSMANAGER_H_
#define IPMISESSIONSMANAGER_H_

#include <map>
#include <memory>
#include <mutex>

#include <ipmiCipherInterfaces.H>
#include <ipmiSession.H>

class IpmiSessionsManager {
 public:
  typedef std::map<uint32_t,std::shared_ptr<IpmiSession> > SessionMap_t;

  enum IpmiSessionRetrieveOption {
    IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID,
    IPMI_SESSION_RETRIEVE_OPTION_RC_SESSION_ID,
    IPMI_SESSION_RETRIEVE_OPTION_SESSION_HANDLE,
    IPMI_SESSION_RETRIEVE_OPTION_SUBSCRIPTIONS,
  };

  enum IpmiSessionHandles {
    //Remote Console
    IPMI_SESSION_ZERO_HANDLE                = 0x00,
    IPMI_MAX_SESSION_HANDLES                = 0x05,

    // Sessionless Handles
    //  1. Session 0 for RMCP+
    IPMI_MAX_SESSIONLESS_HANDLES            = 0x01,

    IPMI_INVALID_SESSION_HANDLE             = 0xFF,
    };

  static IpmiSessionsManager& getInstance();

  /**
   *  @brief Default destructor
  */
  ~IpmiSessionsManager();

  IpmiSession* startSession(uint32_t i_remoteConsoleSessID, uint32_t i_priv, uint8_t i_authAlgo,
                            uint8_t i_intgAlgo, uint8_t i_confAlgo,
                            IpmiUserAuthenticationInterface::IpmiAuthenticationMethod i_authMethod);

    void stopSession(uint32_t i_bmcSessionId);
    void stopChannelSessions();
    void cleanStaleEntries();
    void sessionsCount(uint8_t& o_allowed, uint8_t& o_active);

    //Called when Session Object is required to work with
    std::shared_ptr<IpmiSession> getSession(uint32_t i_sessionId,
                            IpmiSessionRetrieveOption i_option
                                = IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID );

 protected:
  /**
   *  @brief Default constructor
  */
  IpmiSessionsManager();

  //Map
  SessionMap_t iv_sessionsMap;
  std::mutex iv_mapMutex;      //Mutex Lock for critical sections
};

#endif /*IPMISESSIONSMANAGER_H_*/
