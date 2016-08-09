#pragma once

#include <chrono>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "auth_algo.hpp"
#include "endian.hpp"
#include "socket_channel.hpp"

namespace session
{

using namespace std::chrono;
using namespace std::chrono_literals;

enum class Privilege : uint8_t
{
    HIGHEST_MATCHING,
    CALLBACK,
    USER,
    OPERATOR,
    ADMIN,
    OEM,
};

enum class State
{
    INACTIVE,             // Session is not in use
    SETUP_IN_PROGRESS,    // Session Setup Sequence is progressing
    ACTIVE,               // Session is active
    TEAR_DOWN_IN_PROGRESS,// When Closing Session
};

// Seconds of inactivity allowed during session setup stage
constexpr auto SESSION_SETUP_TIMEOUT = 5s;
// Seconds of inactivity allowed when session is active
constexpr auto SESSION_INACTIVITY_TIMEOUT = 60s;

/*
 * @struct SequenceNumbers Session Sequence Numbers
 *
 * IPMI v2.0 RMCP+ Session Sequence Numbers are used for rejecting packets that
 * may have beenduplicated by the network or intentionally replayed. There are
 * two sets of Session SequenceNumbers for a given session.One set of inbound
 * and outbound sequence numbers is used for authenticated (signed) packets,
 * and the other set is used for unauthenticated packets.
 *
 * The individual Session Sequence Numbers is are initialized to zero whenever
 * a session is created and incremented by one at the start of outbound
 * processing for a given packet (i.e. the first transmitted packet has a ‘1’
 * as the sequence number, not 0). Session Sequence numbers are incremented for
 * every packet that is transmitted by a given sender, regardless of whether
 * the payload for the packet is a ‘retry’ or not.
 */
struct SequenceNumbers
{
        auto get(bool inbound = true) const
        {
            return inbound ? in : out;
        }

        void set(uint32_t seqNumber, bool inbound = true)
        {
            inbound ? (in = seqNumber) : (out = seqNumber);
        }

        auto increment()
        {
            return ++out;
        }

    private:
        uint32_t in;
        uint32_t out;
};
/*
 * @class Session
 *
 * Encapsulates the data related to an IPMI Session
 *
 * Authenticated IPMI communication to the BMC is accomplished by establishing
 * a session. Once established, a session is identified by a Session ID. The
 * Session ID may be thought of as a handle that identifies a connection between
 * a given remote user and the BMC. The specification supports having multiple
 * active sessions established with the BMC. It is recommended that a BMC
 * implementation support at least four simultaneous sessions
 */
class Session
{
    public:

        Session() = default;
        ~Session() = default;
        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;
        Session(Session&&) = default;
        Session& operator=(Session&&) = default;

        /*
         * @brief Session Constructor
         *
         * This is issued by the Session Manager when a session is started for
         * the Open SessionRequest command
         *
         * @param[in] inRemoteConsoleSessID - Remote Console Session ID
         * @param[in] priv - Privilege Level requested in the Command
         */
        Session(uint32_t inRemoteConsoleSessID, Privilege priv):
            remoteConsoleSessionID(endian::from_ipmi<uint32_t>(inRemoteConsoleSessID)),
            bmcSessionID(std::rand()),
            curPrivLevel(priv),
            state(State::INACTIVE) {}

        auto getBMCSessionID() const
        {
            return bmcSessionID;
        }

        auto getRCSessionID() const
        {
            return remoteConsoleSessionID;
        }

        auto getAuthAlgo() const
        {
            return authAlgoInterface.get();
        }

        void setAuthAlgo(std::unique_ptr<cipher::rakp_auth::Interface>&&
                         inAuthAlgo)
        {
            authAlgoInterface = std::move(inAuthAlgo);
        }

        void updateLastTransactionTime()
        {
            lastTime = steady_clock::now();
        }

        /*
         * @brief Session Active Status
         *
         * Session Active status is decided upon the Session State and the last
         * transaction time is compared against the session inactivity timeout.
         *
         */
        bool isSessionActive();

        Privilege curPrivLevel; // Session's Current Privilege Level
        Privilege maxPrivLevel; // Session's Maximum Privilege Level
        SequenceNumbers sequenceNums; // Session Sequence Numbers
        State state; // Session State
        std::vector<char> userName; // User Name

    private:

        uint32_t bmcSessionID; //BMC Session ID
        uint32_t remoteConsoleSessionID; //Remote Console Session ID

        // Authentication Algorithm Interface for the Session
        std::unique_ptr<cipher::rakp_auth::Interface> authAlgoInterface;

        // Last Transaction Time
        decltype(steady_clock::now()) lastTime;
};

} // namespace session
