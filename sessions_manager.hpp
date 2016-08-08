#pragma once

#include <map>
#include <memory>
#include <mutex>

#include "session.hpp"

namespace session
{

enum class RetrieveOption
{
    RETRIEVE_OPTION_BMC_SESSION_ID,
    RETRIEVE_OPTION_RC_SESSION_ID,
};

constexpr size_t SESSION_ZERO = 0;
constexpr size_t MAX_SESSIONLESS_COUNT = 1;
constexpr size_t MAX_SESSION_COUNT = 5;

/*
 * @class Manager
 *
 * Manager class acts a manager for the IPMI sessions and provides interfaces
 * to start a session, stop a session and get reference to the session objects.
 *
 */

class Manager
{
    public:

        // BMC Session ID is the key for the map
        using SessionMap = std::map<uint32_t, std::unique_ptr<Session>>;

        Manager();
        ~Manager() = default;
        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&&) = delete;
        Manager& operator=(Manager&&) = delete;

        /*
         * @brief Start an IPMI session
         *
         * @param[in] remoteConsoleSessID - Remote Console Session ID mentioned
         *            in the Open SessionRequest Command
         * @param[in] priv - Privilege level requested
         * @param[in] authAlgo - Authentication Algorithm
         * @param[in] intgAlgo - Integrity Algorithm
         * @param[in] confAlgo - Confidentiality Algorithm
         *
         * @return session handle on success and nullptr on failure
         *
         */
        Session* startSession(uint32_t remoteConsoleSessID,
                              Privilege priv,
                              uint8_t authAlgo,
                              uint8_t intgAlgo,
                              uint8_t confAlgo);

        /*
         * @brief Stop IPMI Session
         *
         * @param[in] bmcSessionID - BMC Session ID
         *
         */
        void stopSession(uint32_t bmcSessionID);

        /*
         * @brief Get Session Handle
         *
         * @param[in] sessionID - Session ID
         * @param[in] option - Select between BMC Session ID and Remote Console
         *            Session ID, Default option is BMC Session ID
         *
         * @return session handle on success and nullptr on failure
         *
         */
        Session* getSession(uint32_t sessionID, RetrieveOption option =
                                RetrieveOption::RETRIEVE_OPTION_BMC_SESSION_ID);

    private:

        /*
         * @brief Session Manager keeps the session objects as a sorted
         *        associative container with Session ID as the unique key
         */
        SessionMap sessionsMap;

        /*
         * @brief Clean Session Stale Entries
         *
         *  Removes the inactive sessions entries from the Session Map
         */
        void cleanStaleEntries();
};

} // namespace session
