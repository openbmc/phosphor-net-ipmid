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
 * Manager class acts a manager for the IPMI sessions and provides interfaces to start a session,
 * stop a session and get reference to the session objects.
 *
 */

class Manager
{
    public:

        // BMC Session ID is the key for the map
        using SessionMap_t = std::map<uint32_t, std::unique_ptr<Session>> ;

        Manager();
        ~Manager() = default;
        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&&) = delete;
        Manager& operator=(Manager&&) = delete;

        /*
         * @brief Start an IPMI session
         *
         * @param [in] Remote Console Session ID mentioned in the Open Session Request Command
         * @param [in] Privilege level requested
         * @param [in] Authentication Algorithm
         * @param [in] Integrity Algorithm
         * @param [in] Confidentiality Algorithm
         *
         * @return session handle on success and nullptr on failure
         *
         */
        Session* startSession(uint32_t remoteConsoleSessID, Privilege priv,
                              uint8_t authAlgo, uint8_t intgAlgo, uint8_t confAlgo);

        /*
         * @brief Stop IPMI Session
         *
         * @param [in] BMC Session ID
         *
         */
        void stopSession(uint32_t bmcSessionID);

        /*
         * @brief Get Session Handle
         *
         * @param [in] Session ID
         * @param [in] Select between BMC Session ID and Remote Console Session ID
         *             Default option is BMC Session ID
         *
         * @return session handle on success and nullptr on failure
         *
         */
        Session* getSession(uint32_t sessionID, RetrieveOption option =
                                RetrieveOption::RETRIEVE_OPTION_BMC_SESSION_ID);

    private:
        SessionMap_t sessionsMap;
        void cleanStaleEntries();
};

} // namespace session
