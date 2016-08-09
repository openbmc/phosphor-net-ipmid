#pragma once

#include <chrono>
#include <list>
#include <memory>
#include <vector>

#include "auth_algo.hpp"
#include "socket_channel.hpp"


namespace session
{

enum class Privilege : uint8_t
{
    PRIVILEGE_HIGHEST_MATCHING = 0x00,
    PRIVILEGE_CALLBACK         = 0x01,
    PRIVILEGE_USER             = 0x02,
    PRIVILEGE_OPERATOR         = 0x03,
    PRIVILEGE_ADMIN            = 0x04,
    PRIVILEGE_OEM              = 0x05,
};

enum class State
{
    INACTIVE,             // Session is not in use
    SETUP_IN_PROGRESS,    // Session Setup Sequence is progressing
    ACTIVE,               // Session is active
    TEAR_DOWN_IN_PROGRESS,// When Closing Session
};

// Seconds of inactivity allowed during session setup stage
constexpr size_t SESSION_SETUP_TIMEOUT = 5;
// Seconds of inactivity allowed when session is active
constexpr size_t SESSION_INACTIVITY_TIMEOUT  = 60;

/*
 * @struct SequenceNumbers Session Sequence Numbers
 *
 * IPMI v2.0 RMCP+ Session Sequence Numbers are used for rejecting packets that may have been
 * duplicated by the network or intentionally replayed. There are two sets of Session Sequence
 * Numbers for a given session.One set of inbound and outbound sequence numbers is used for
 * authenticated (signed) packets, and the other set is used for unauthenticated packets.
 *
 * The individual Session Sequence Numbers is are initialized to zero whenever a session is created
 * and incremented by one at the start of outbound processing for a given packet (i.e. the first
 * transmitted packet has a ‘1’ as the sequence number, not 0). Session Sequence numbers are
 * incremented for every packet that is transmitted by a given sender, regardless of whether
 * the payload for the packet is a ‘retry’ or not.
 */
struct SequenceNumbers
{
    uint32_t inboundSeqNumber;
    uint32_t outboundSeqNumber;

    auto get(bool inbound)
    {
        return inbound ? inboundSeqNumber : outboundSeqNumber;
    }

    void set(uint32_t seqNumber, bool inbound)
    {
        if (inbound)
        {
            inboundSeqNumber = seqNumber;
        }
        else
        {
            outboundSeqNumber = seqNumber;
        }
    }

    auto increment()
    {
        return (++outboundSeqNumber);
    }
};
/*
 * @class Session
 *
 * Encapsulates the data related to an IPMI Session
 *
 * Authenticated IPMI communication to the BMC is accomplished by establishing a session. Once
 * established, a session is identified by a Session ID. The Session ID may be thought of as a
 * handle that identifies a connection between a given remote user and the BMC. The specification
 * supports having multiple active sessions established with the BMC. It is recommended that a
 * BMC implementation support at least four simultaneous sessions
 */

class Session
{
    public:

        Session() = default;
        ~Session() = default;
        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;
        Session(Session&&) = delete;
        Session& operator=(Session&&) = delete;

        /*
         * @brief Session Constructor
         *
         * This is issued by the Session Manager when a session is started for the Open Session
         * Request command
         *
         * @param Remote Console Session ID
         * @param Privilege Level requested in the Command
         */
        Session(uint32_t& inRemoteConsoleSessID, Privilege priv);

        auto getBMCSessionID()
        {
            return bmcSessionID;
        }

        auto getRCSessionID()
        {
            return remoteConsoleSessionID;
        }

        auto getSessionState()
        {
            return state;
        }

        void setSessionState(State inState)
        {
            state = inState;
        }

        auto getUserName()
        {
            return userName;
        }

        auto getAuthAlgo()
        {
            return authAlgoInterface.get();
        }

        void setAuthAlgo(std::unique_ptr<cipher::auth::RAKPAlgoInterface> inAuthAlgo)
        {
            authAlgoInterface = std::move(inAuthAlgo);
        }

        auto getPrivilegeLevel()
        {
            return curPrivLevel;
        }

        void setPrivilegeLevel(Privilege privLevel)
        {
            curPrivLevel = privLevel;
        }

        auto getMaxPrivilegeLevel()
        {
            return maxPrivLevel;
        }

        void setMaxPrivilegeLevel(Privilege privLevel)
        {
            maxPrivLevel = privLevel;
        }

        auto getSeqNumber()
        {
            return sequenceNums;
        }

        void updateLastTransactionTime()
        {
            lastTime = std::chrono::system_clock::now();
        }

        /*
         * @brief Session Active Status
         *
         * Session Active status is decided upon the Session State and the last transaction
         * time is compared against the session inactivity timeout.
         *
         */
        bool isSessionActive();

    private:

        Privilege curPrivLevel; // Session's Current Privilege Level
        Privilege maxPrivLevel; // Session's Maximum Privilege Level
        SequenceNumbers sequenceNums; // Session Sequence Numbers
        State state; // Session State
        uint32_t bmcSessionID; //BMC Session ID
        uint32_t remoteConsoleSessionID; //Remote Console Session ID
        std::vector<char> userName; // User Name

        // Authentication Algorithm Interface for the Session
        std::unique_ptr<cipher::auth::RAKPAlgoInterface> authAlgoInterface;

        // Last Transaction Time
        std::chrono::time_point<std::chrono::system_clock> lastTime;
};

} // namespace session
