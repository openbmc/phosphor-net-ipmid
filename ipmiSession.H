#ifndef IPMISESSION_H_
#define IPMISESSION_H_

#include <atomic>
#include <chrono>
#include <list>
#include <memory>
#include <mutex>

#include <ipmiAppUtil.H>
#include <ipmiCipherInterfaces.H>
#include <ipmiMessage.H>

class IpmiSessionState {
 public:
  enum IpmiSessionPrivilegeMask {
    IPMI_SESSION_PRIVILEGE_NONE     = 0x00000000,
    IPMI_SESSION_PRIVILEGE_CALLBACK = 0x00000001,
    IPMI_SESSION_PRIVILEGE_USER     = 0x00000002,
    IPMI_SESSION_PRIVILEGE_OPERATOR = 0x00000004,
    IPMI_SESSION_PRIVILEGE_ADMIN    = 0x00000008,
    IPMI_SESSION_PRIVILEGE_OEM      = 0x00000010,
  };

  //@TODO: keep only one of IpmiSessionPrivilegeMask or IpmiSessionPrivileges?
  enum IpmiSessionPrivileges {
    IPMI_PRIVILEGE_HIGHEST_MATCHING = 0x00,
    IPMI_PRIVILEGE_CALLBACK         = 0x01,
    IPMI_PRIVILEGE_USER             = 0x02,
    IPMI_PRIVILEGE_OPERATOR         = 0x03,
    IPMI_PRIVILEGE_ADMIN            = 0x04,
    IPMI_PRIVILEGE_OEM              = 0x05,
  };

  enum IpmiSubscriptions {
    IPMI_SESSION_SUBSCRIPTION_NONE = 0x00000000,
    IPMI_SESSION_SUBSCRIPTION_DEME = 0x00000001,
    IPMI_SESSION_SUBSCRIPTION_SOL  = 0x00000002,


    IPMI_SESSION_SUBSCRIPTION_NEXT = 0x00000004,
    IPMI_SESSION_SUBSCRIPTION_LAST = 0x80000000,

    IPMI_SESSION_SUBSCRIPTION_ALL  = 0xFFFFFFFF,
  };

  enum IpmiState {
    IPMI_SESSION_IS_INACTIVE,          //When the session is not in use
    IPMI_SESSION_SETUP_IN_PROGRESS,    //When Session Setup Seq. is going on
    IPMI_SESSION_IS_ACTIVE,            //When Session setup successful
    IPMI_SESSION_TEAR_DOWN_IN_PROGRESS,//When Closing Session
  };

  enum IpmiStateDefines {
    IPMI_SESSION_SETUP_TIMEOUT = 10, //# Seconds of inactivity allowed
                                     //during session setup stage
    IPMI_SESSION_INACTIVITY_TIMEOUT = 60, //# Seconds of inactivity allowed
                                          //when session is in progress
  };

  IpmiSessionState();

  ~IpmiSessionState();

  void setPrivilegeLevel(uint32_t i_privilegeLevel);

  uint32_t getPrivilegeLevel(void);

  void setOperatingPrivilegeLevel(uint32_t i_previlegeLevel);

  uint32_t getOperatingPrivilegeLevel(void);

  void setMaxPrivilegeLevel(uint32_t i_privilegeLevel);

  uint32_t getMaxPrivilegeLevel(void);

  void addSubscriptions(uint32_t i_newSubscriptionsMask);

  void removeSubscriptions(uint32_t i_subscriptionsMask);

  uint32_t getSubscriptions();

  uint32_t getSequenceNumber(bool i_authenticated = true);

  void setSequenceNumber(uint32_t i_seqNum, bool i_authenticated = true);

  uint32_t& incrementSequenceNumber(bool i_authenticated = true);

  uint32_t& getSlidingWindowNumber(bool i_authenticated = true);

  void setSlidingWindowNumber(uint32_t i_seqNum, bool i_authenticated = true);

  uint32_t& incrementSlidingWindowNumber(bool i_authenticated = true);

  void updateLastTransactionTime();

  uint32_t& getSessionState(void);

  void setSessionState(uint32_t i_state);

  bool isSessionActive();

  void setUserID(uint32_t i_userID);

  uint32_t getUserID(void);

 private:
  struct IpmiSessionSeqNumbers_t {
    uint32_t iv_authSessionSeqNumber;
    uint32_t iv_unauthSessionSeqNumber;

    uint32_t& get(bool i_authenticated);
    uint32_t& set(uint32_t i_val, bool i_authenticated);
    uint32_t& increment(bool i_authenticated);
  };

  std::atomic<uint32_t> iv_requestedMaxPrevilegeLevel;
  std::atomic<uint32_t> iv_operatingPrivilegeLevel;
  std::atomic<uint32_t> iv_userIDMaxPrivilegeLevel;

  std::mutex iv_sessionSubscriptionsMutex;
  uint32_t iv_sessionSubscriptions;

  std::mutex iv_sessionSeqNumsMutex;
  IpmiSessionSeqNumbers_t iv_sessionSeqNums;

  std::mutex iv_sessionSlidingWindowMutex;
  IpmiSessionSeqNumbers_t iv_sessionSlidingWindow;

  std::mutex iv_lastTransactionTimeMutex;
  std::chrono::time_point<std::chrono::system_clock> iv_lastTime;

  std::mutex iv_sessionStateMutex;
  uint32_t iv_sessionState;

  std::atomic<uint32_t> iv_userID;
};

class IpmiSession {
 public:
  // Defines & Types
  typedef void (*IpmiCleanupCallbackPtr_t)(void*);
  typedef std::list<IpmiCleanupCallbackPtr_t> IpmiSessionCleanupList;

  //Methods
  IpmiSession();

  IpmiSession(uint32_t i_remoteConsoleSessID,
              uint32_t i_priv);

  virtual ~IpmiSession();

  uint8_t getSessionHandle();

  PacketField32_t& getBMCSessionID();
  PacketField32_t& getRCSessionID();

  IpmiSessionCipherSuite& getSessionCipherSuite();

  IpmiSessionState& getSessionState();

  IpmiSessionCleanupList& getSessionCleanupList();

  std::shared_ptr<IpmiSockChannelData>& getChannel();

  void setChannel(std::shared_ptr<IpmiSockChannelData>& i_channel);

 private:
  // Session Handle Generator
  static uint8_t iv_sessionHandleGenerator;
  static std::mutex iv_sessionHandleGeneratorMutex;

  //Session Handle
  uint8_t iv_sessionHandle; // Session Handle

  //Session IDs
  PacketField32_t iv_bmcSessionId;  //BMC Session ID
  PacketField32_t iv_remoteConsoleSessionId; //Remote Console Session ID

  //Session CipherSuite
  IpmiSessionCipherSuite iv_sessionCiphers;

  //Session State Information
  IpmiSessionState iv_sessionState;

  //Session Cleanup List
  IpmiSessionCleanupList iv_sessionCleanupList;

  //Session Communication channel
  std::shared_ptr<IpmiSockChannelData> iv_channel;
  std::mutex iv_channelMutex;
};

#endif /* IPMISESSION_H_ */
