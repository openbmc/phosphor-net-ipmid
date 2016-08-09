#include <ipmiSession.H>

uint8_t IpmiSession::iv_sessionHandleGenerator = 0;
std::mutex IpmiSession::iv_sessionHandleGeneratorMutex;


IpmiSessionState::IpmiSessionState()
    : iv_requestedMaxPrevilegeLevel(),
      iv_operatingPrivilegeLevel(),
      iv_userIDMaxPrivilegeLevel(),
      iv_sessionSubscriptions(),
      iv_sessionSeqNums(),
      iv_sessionSlidingWindow(),
      iv_sessionState(),
      iv_userID() {}

IpmiSessionState::~IpmiSessionState() {}

void IpmiSessionState::setPrivilegeLevel(uint32_t i_previlegeLevel) {
  iv_requestedMaxPrevilegeLevel.store(i_previlegeLevel);
}

uint32_t IpmiSessionState::getPrivilegeLevel(void) {
  return iv_requestedMaxPrevilegeLevel.load();
}

void IpmiSessionState::setOperatingPrivilegeLevel(uint32_t i_privilegeLevel) {
  iv_operatingPrivilegeLevel.store(i_privilegeLevel);
}

uint32_t IpmiSessionState::getOperatingPrivilegeLevel(void) {
  return iv_operatingPrivilegeLevel.load();
}

void IpmiSessionState::setMaxPrivilegeLevel(uint32_t i_privilegeLevel) {
  iv_userIDMaxPrivilegeLevel.store(i_privilegeLevel);
}

uint32_t IpmiSessionState::getMaxPrivilegeLevel(void)
{
  return iv_userIDMaxPrivilegeLevel.load();
}

void IpmiSessionState::addSubscriptions(uint32_t i_newSubscriptionsMask) {
  std::lock_guard<std::mutex> lock(iv_sessionSubscriptionsMutex);
  uint32_t l_newSubscription = iv_sessionSubscriptions;
  l_newSubscription |= i_newSubscriptionsMask;
  iv_sessionSubscriptions = l_newSubscription;
}

void IpmiSessionState::removeSubscriptions(uint32_t i_subscriptionsMask) {
  std::lock_guard<std::mutex> lock(iv_sessionSubscriptionsMutex);
  uint32_t l_newSubscription = iv_sessionSubscriptions;
  l_newSubscription &= (~i_subscriptionsMask);
  iv_sessionSubscriptions = l_newSubscription;
}

uint32_t IpmiSessionState::getSubscriptions() {
  std::lock_guard<std::mutex> lock(iv_sessionSubscriptionsMutex);
  return iv_sessionSubscriptions;
}

uint32_t IpmiSessionState::getSequenceNumber(bool i_authenticated) {
  std::lock_guard<std::mutex> lock(iv_sessionSeqNumsMutex);
  return iv_sessionSeqNums.get(i_authenticated);
}

void IpmiSessionState::setSequenceNumber(uint32_t i_seqNum, bool i_authenticated) {
  std::lock_guard<std::mutex> lock(iv_sessionSeqNumsMutex);
  iv_sessionSeqNums.set(i_seqNum,i_authenticated);
}

uint32_t& IpmiSessionState::incrementSequenceNumber(bool i_authenticated) {
  std::lock_guard<std::mutex> lock(iv_sessionSeqNumsMutex);
  return iv_sessionSeqNums.increment(i_authenticated);
}

uint32_t& IpmiSessionState::getSlidingWindowNumber(bool i_authenticated) {
  std::lock_guard<std::mutex> lock(iv_sessionSlidingWindowMutex);
  return iv_sessionSlidingWindow.get(i_authenticated);
}

void IpmiSessionState::setSlidingWindowNumber(uint32_t i_seqNum, bool i_authenticated) {
  std::lock_guard<std::mutex> lock(iv_sessionSlidingWindowMutex);
  iv_sessionSlidingWindow.set(i_seqNum,i_authenticated);
}

uint32_t& IpmiSessionState::incrementSlidingWindowNumber(bool i_authenticated) {
  std::lock_guard<std::mutex> lock(iv_sessionSlidingWindowMutex);
  return iv_sessionSlidingWindow.increment(i_authenticated);
}

void IpmiSessionState::updateLastTransactionTime() {
  std::lock_guard<std::mutex> l_lock(iv_lastTransactionTimeMutex);
  iv_lastTime = std::chrono::system_clock::now();
}

uint32_t& IpmiSessionState::getSessionState(void) {
  std::lock_guard<std::mutex> l_lock(iv_sessionStateMutex);
  return iv_sessionState;
}

void IpmiSessionState::setSessionState(uint32_t i_state) {
  std::lock_guard<std::mutex> l_lock(iv_sessionStateMutex);
  iv_sessionState = i_state;
  //@TODO: if particular state .. do some actions
  //e.g: if tear down, reset message queue.
}

bool IpmiSessionState::isSessionActive() {
  bool l_isActive = false;
  std::chrono::duration<double> elapsed_seconds;
  std::lock_guard<std::mutex> l_lock(iv_sessionStateMutex);

  std::chrono::time_point<std::chrono::system_clock> l_curTime;
  l_curTime = std::chrono::system_clock::now();

  //<PROTECTED>
  {
    std::lock_guard<std::mutex> l_lock(iv_lastTransactionTimeMutex);
      elapsed_seconds = l_curTime - iv_lastTime;
  }
  //</PROTECTED>

  switch (iv_sessionState) {
    case IPMI_SESSION_SETUP_IN_PROGRESS:
      if(elapsed_seconds.count() < IPMI_SESSION_SETUP_TIMEOUT) l_isActive = true;
      break;
    case IPMI_SESSION_IS_ACTIVE:
      if(elapsed_seconds.count() < IPMI_SESSION_INACTIVITY_TIMEOUT) l_isActive = true;
      break;
    default:
      l_isActive = false;
      break;
  }

  return l_isActive;
}

void IpmiSessionState::setUserID(uint32_t i_userID) {
  iv_userID.store(i_userID);
}

uint32_t IpmiSessionState::getUserID(void) {
  return iv_userID.load();
}

uint32_t& IpmiSessionState::IpmiSessionSeqNumbers_t::get(bool i_authenticated) {
  return i_authenticated?iv_authSessionSeqNumber:iv_unauthSessionSeqNumber;
}

uint32_t& IpmiSessionState::IpmiSessionSeqNumbers_t::set(uint32_t i_val, bool i_authenticated) {
  if (i_authenticated) {
    iv_authSessionSeqNumber = i_val;
  } else {
    iv_unauthSessionSeqNumber = i_val;
  }

  return get(i_authenticated);
}

uint32_t& IpmiSessionState::IpmiSessionSeqNumbers_t::increment(bool i_auth) {
  if (i_auth) {
    ++iv_authSessionSeqNumber;
  } else {
    ++iv_unauthSessionSeqNumber;
  }

  return get(i_auth);
}

IpmiSession::IpmiSession()
    : iv_sessionHandle(),
      iv_bmcSessionId(),
      iv_remoteConsoleSessionId(),
      iv_sessionCiphers(),
      iv_sessionState(),
      iv_sessionCleanupList(),
      iv_channel(),
      iv_channelMutex() {
  //Protected>>
  {
    std::lock_guard<std::mutex> l_lock(iv_sessionHandleGeneratorMutex);
    iv_sessionHandle = iv_sessionHandleGenerator++;
  }
  //<<Protected
}

IpmiSession::IpmiSession(uint32_t i_remoteConsoleSessID,
                         uint32_t i_priv)
:iv_sessionHandle(0xFF),iv_bmcSessionId(),iv_remoteConsoleSessionId(),
 iv_sessionCiphers(),iv_sessionState(),iv_sessionCleanupList(),
 iv_channel(),iv_channelMutex()
{
    //Protected>>
    {
        std::lock_guard<std::mutex> l_lock(iv_sessionHandleGeneratorMutex);
        iv_sessionHandle = iv_sessionHandleGenerator++;
    }
    //<<Protected

    iv_remoteConsoleSessionId.set(i_remoteConsoleSessID,IPMI);

    uint32_t l_sessionID = 0;
    ipmiGenerateRandomBytes(reinterpret_cast<uint8_t*>(&l_sessionID),
                            sizeof(l_sessionID));
    iv_bmcSessionId.set(l_sessionID);

    if(i_priv == 0)
    {
        iv_sessionState.setPrivilegeLevel(IpmiSessionState::IPMI_PRIVILEGE_ADMIN);
    }
    else
    {
        iv_sessionState.setPrivilegeLevel(i_priv);
    }
}

IpmiSession::~IpmiSession() {}

uint8_t IpmiSession::getSessionHandle() {
  return iv_sessionHandle;
}

PacketField32_t& IpmiSession::getBMCSessionID() {
  return iv_bmcSessionId;
}
PacketField32_t& IpmiSession::getRCSessionID() {
  return iv_remoteConsoleSessionId;
}

IpmiSessionCipherSuite& IpmiSession::getSessionCipherSuite() {
  return iv_sessionCiphers;
}

IpmiSessionState& IpmiSession::getSessionState() {
  return iv_sessionState;
}

IpmiSession::IpmiSessionCleanupList& IpmiSession::getSessionCleanupList() {
  return iv_sessionCleanupList;
}

std::shared_ptr<IpmiSockChannelData>& IpmiSession::getChannel() {
  std::lock_guard<std::mutex> l_lock(iv_channelMutex);
  return iv_channel;
}

void IpmiSession::setChannel(std::shared_ptr<IpmiSockChannelData>& i_channel) {
  std::lock_guard<std::mutex> l_lock(iv_channelMutex);
  iv_channel = i_channel;
}


