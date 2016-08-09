#include <openssl/rand.h>

#include "endian.hpp"
#include "session.hpp"



uint8_t Session::iv_sessionHandleGenerator = 0;
std::mutex Session::iv_sessionHandleGeneratorMutex;


SessionState::SessionState()
    : iv_requestedMaxPrevilegeLevel(),
      iv_operatingPrivilegeLevel(),
      iv_userIDMaxPrivilegeLevel(),
      iv_sessionSubscriptions(),
      iv_sessionSeqNums(),
      iv_sessionSlidingWindow(),
      iv_sessionState(),
      iv_userID() {}

SessionState::~SessionState() {}

void SessionState::setPrivilegeLevel(uint32_t i_previlegeLevel)
{
    iv_requestedMaxPrevilegeLevel.store(i_previlegeLevel);
}

uint32_t SessionState::getPrivilegeLevel(void)
{
    return iv_requestedMaxPrevilegeLevel.load();
}

void SessionState::setOperatingPrivilegeLevel(uint32_t i_privilegeLevel)
{
    iv_operatingPrivilegeLevel.store(i_privilegeLevel);
}

uint32_t SessionState::getOperatingPrivilegeLevel(void)
{
    return iv_operatingPrivilegeLevel.load();
}

void SessionState::setMaxPrivilegeLevel(uint32_t i_privilegeLevel)
{
    iv_userIDMaxPrivilegeLevel.store(i_privilegeLevel);
}

uint32_t SessionState::getMaxPrivilegeLevel(void)
{
    return iv_userIDMaxPrivilegeLevel.load();
}

void SessionState::addSubscriptions(uint32_t i_newSubscriptionsMask)
{
    std::lock_guard<std::mutex> lock(iv_sessionSubscriptionsMutex);
    uint32_t l_newSubscription = iv_sessionSubscriptions;
    l_newSubscription |= i_newSubscriptionsMask;
    iv_sessionSubscriptions = l_newSubscription;
}

void SessionState::removeSubscriptions(uint32_t i_subscriptionsMask)
{
    std::lock_guard<std::mutex> lock(iv_sessionSubscriptionsMutex);
    uint32_t l_newSubscription = iv_sessionSubscriptions;
    l_newSubscription &= (~i_subscriptionsMask);
    iv_sessionSubscriptions = l_newSubscription;
}

uint32_t SessionState::getSubscriptions()
{
    std::lock_guard<std::mutex> lock(iv_sessionSubscriptionsMutex);
    return iv_sessionSubscriptions;
}

uint32_t SessionState::getSequenceNumber(bool i_authenticated)
{
    std::lock_guard<std::mutex> lock(iv_sessionSeqNumsMutex);
    return iv_sessionSeqNums.get(i_authenticated);
}

void SessionState::setSequenceNumber(uint32_t i_seqNum,
        bool i_authenticated)
{
    std::lock_guard<std::mutex> lock(iv_sessionSeqNumsMutex);
    iv_sessionSeqNums.set(i_seqNum, i_authenticated);
}

uint32_t& SessionState::incrementSequenceNumber(bool i_authenticated)
{
    std::lock_guard<std::mutex> lock(iv_sessionSeqNumsMutex);
    return iv_sessionSeqNums.increment(i_authenticated);
}

uint32_t& SessionState::getSlidingWindowNumber(bool i_authenticated)
{
    std::lock_guard<std::mutex> lock(iv_sessionSlidingWindowMutex);
    return iv_sessionSlidingWindow.get(i_authenticated);
}

void SessionState::setSlidingWindowNumber(uint32_t i_seqNum,
        bool i_authenticated)
{
    std::lock_guard<std::mutex> lock(iv_sessionSlidingWindowMutex);
    iv_sessionSlidingWindow.set(i_seqNum, i_authenticated);
}

uint32_t& SessionState::incrementSlidingWindowNumber(bool i_authenticated)
{
    std::lock_guard<std::mutex> lock(iv_sessionSlidingWindowMutex);
    return iv_sessionSlidingWindow.increment(i_authenticated);
}

void SessionState::updateLastTransactionTime()
{
    std::lock_guard<std::mutex> l_lock(iv_lastTransactionTimeMutex);
    iv_lastTime = std::chrono::system_clock::now();
}

uint32_t& SessionState::getSessionState(void)
{
    std::lock_guard<std::mutex> l_lock(iv_sessionStateMutex);
    return iv_sessionState;
}

void SessionState::setSessionState(uint32_t i_state)
{
    std::lock_guard<std::mutex> l_lock(iv_sessionStateMutex);
    iv_sessionState = i_state;
    //@TODO: if particular state .. do some actions
    //e.g: if tear down, reset message queue.
}

bool SessionState::isSessionActive()
{
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

    switch (iv_sessionState)
    {
        case IPMI_SESSION_SETUP_IN_PROGRESS:
            if (elapsed_seconds.count() < IPMI_SESSION_SETUP_TIMEOUT)
            {
                l_isActive = true;
            }
            break;
        case IPMI_SESSION_IS_ACTIVE:
            if (elapsed_seconds.count() < IPMI_SESSION_INACTIVITY_TIMEOUT)
            {
                l_isActive = true;
            }
            break;
        default:
            l_isActive = false;
            break;
    }

    return l_isActive;
}

void SessionState::setUserID(uint32_t i_userID)
{
    iv_userID.store(i_userID);
}

uint32_t SessionState::getUserID(void)
{
    return iv_userID.load();
}

uint32_t& SessionState::IpmiSessionSeqNumbers_t::get(bool i_authenticated)
{
    return i_authenticated ? iv_authSessionSeqNumber : iv_unauthSessionSeqNumber;
}

uint32_t& SessionState::IpmiSessionSeqNumbers_t::set(uint32_t i_val,
        bool i_authenticated)
{
    if (i_authenticated)
    {
        iv_authSessionSeqNumber = i_val;
    }
    else
    {
        iv_unauthSessionSeqNumber = i_val;
    }

    return get(i_authenticated);
}

uint32_t& SessionState::IpmiSessionSeqNumbers_t::increment(bool i_auth)
{
    if (i_auth)
    {
        ++iv_authSessionSeqNumber;
    }
    else
    {
        ++iv_unauthSessionSeqNumber;
    }

    return get(i_auth);
}

Session::Session()
    : iv_sessionHandle(),
      iv_bmcSessionId(),
      iv_remoteConsoleSessionId(),
//      iv_sessionCiphers(),
      iv_sessionState(),
      iv_sessionCleanupList(),
      iv_channel(),
      iv_channelMutex()
{
    //Protected>>
    {
        std::lock_guard<std::mutex> l_lock(iv_sessionHandleGeneratorMutex);
        iv_sessionHandle = iv_sessionHandleGenerator++;
    }
    //<<Protected
}

Session::Session(uint32_t i_remoteConsoleSessID,
                         uint32_t i_priv)
    : iv_sessionHandle(0xFF), iv_bmcSessionId(), iv_remoteConsoleSessionId(),
      iv_sessionState(), iv_sessionCleanupList(),
      iv_channel(), iv_channelMutex()
{
    //Protected>>
    {
        std::lock_guard<std::mutex> l_lock(iv_sessionHandleGeneratorMutex);
        iv_sessionHandle = iv_sessionHandleGenerator++;
    }
    //<<Protected

    iv_remoteConsoleSessionId = endian::from_ipmi<uint32_t>(i_remoteConsoleSessID);

    uint32_t l_sessionID = 0;
    RAND_bytes(reinterpret_cast<uint8_t*>(&l_sessionID), sizeof(l_sessionID));
    iv_bmcSessionId = l_sessionID;

    if (i_priv == 0)
    {
        iv_sessionState.setPrivilegeLevel(SessionState::IPMI_PRIVILEGE_ADMIN);
    }
    else
    {
        iv_sessionState.setPrivilegeLevel(i_priv);
    }
}

Session::~Session() {}

uint8_t Session::getSessionHandle()
{
    return iv_sessionHandle;
}

uint32_t Session::getBMCSessionID()
{
    return iv_bmcSessionId;
}
uint32_t Session::getRCSessionID()
{
    return iv_remoteConsoleSessionId;
}

CipherSuite& Session::getSessionCipherSuite()
{
    return sessionCiphers;
}

SessionState& Session::getSessionState()
{
    return iv_sessionState;
}

Session::IpmiSessionCleanupList& Session::getSessionCleanupList()
{
    return iv_sessionCleanupList;
}

std::shared_ptr<IpmiSockChannelData>& Session::getChannel()
{
    std::lock_guard<std::mutex> l_lock(iv_channelMutex);
    return iv_channel;
}

void Session::setChannel(std::shared_ptr<IpmiSockChannelData>& i_channel)
{
    std::lock_guard<std::mutex> l_lock(iv_channelMutex);
    iv_channel = i_channel;
}


