#pragma once

#include <chrono>
#include <exception>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "auth_algo.hpp"
#include "integrity_algo.hpp"
#include "endian.hpp"
#include "socket_channel.hpp"

namespace session
{

using namespace std::chrono_literals;
using SessionID = uint32_t;

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
 * may have been duplicated by the network or intentionally replayed. There are
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
        Session(SessionID inRemoteConsoleSessID, Privilege priv):
            curPrivLevel(priv),
            bmcSessionID(std::rand()),
            remoteConsoleSessionID(inRemoteConsoleSessID) {}

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
            if(authAlgoInterface)
            {
                return authAlgoInterface.get();
            }
            else
            {
                throw std::runtime_error("Authentication Algorithm Empty");
            }
        }

        void setAuthAlgo(std::unique_ptr<cipher::rakp_auth::Interface>&&
                         inAuthAlgo)
        {
            authAlgoInterface = std::move(inAuthAlgo);
        }

        /*
         * @brief Get Session's Integrity Algorithm
         *
         * @return pointer to the integrity algorithm
         */
        auto getIntegrityAlgo() const
        {
            if(integrityAlgoInterface)
            {
                return integrityAlgoInterface.get();
            }
            else
            {
                throw std::runtime_error("Integrity Algorithm Empty");
            }
        }

        /*
         * @brief Set Session's Integrity Algorithm
         *
         * @param[in] integrityAlgo - unique pointer to integrity algorithm
         *                              instance
         */
        void setIntegrityAlgo(
                std::unique_ptr<cipher::integrity::Interface>&& integrityAlgo)
        {
            integrityAlgoInterface = std::move(integrityAlgo);
        }

        void updateLastTransactionTime()
        {
            lastTime = std::chrono::steady_clock::now();
        }

        /*
         * @brief Session Active Status
         *
         * Session Active status is decided upon the Session State and the last
         * transaction time is compared against the session inactivity timeout.
         *
         */
        bool isSessionActive();

        /*
         * @brief Session's Current Privilege Level
         */
        Privilege curPrivLevel;

        /*
         * @brief Session's Maximum Privilege Level
         */
        Privilege maxPrivLevel = Privilege::CALLBACK;

        SequenceNumbers sequenceNums; // Session Sequence Numbers
        State state = State::INACTIVE; // Session State
        std::vector<char> userName; // User Name

    private:

        SessionID bmcSessionID = 0; //BMC Session ID
        SessionID remoteConsoleSessionID = 0; //Remote Console Session ID

        // Authentication Algorithm Interface for the Session
        std::unique_ptr<cipher::rakp_auth::Interface> authAlgoInterface;

        // Integrity Algorithm Interface for the Session
        std::unique_ptr<cipher::integrity::Interface> integrityAlgoInterface =
                                                                        nullptr;

        // Last Transaction Time
        decltype(std::chrono::steady_clock::now()) lastTime;
};

} // namespace session
