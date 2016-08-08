#pragma once

#include <map>
#include <memory>
#include <mutex>

#include "cipher.hpp"
#include "session.hpp"

class SessionsManager
{
    public:
        typedef std::map<uint32_t, std::shared_ptr<Session> > SessionMap_t;

        enum SessionRetrieveOption
        {
            IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID,
            IPMI_SESSION_RETRIEVE_OPTION_RC_SESSION_ID,
            IPMI_SESSION_RETRIEVE_OPTION_SESSION_HANDLE,
            IPMI_SESSION_RETRIEVE_OPTION_SUBSCRIPTIONS,
        };

        enum SessionHandles
        {
            //Remote Console
            IPMI_SESSION_ZERO_HANDLE                = 0x00,
            IPMI_MAX_SESSION_HANDLES                = 0x05,

            // Sessionless Handles
            //  1. Session 0 for RMCP+
            IPMI_MAX_SESSIONLESS_HANDLES            = 0x01,

            IPMI_INVALID_SESSION_HANDLE             = 0xFF,
        };

        static SessionsManager& getInstance();

        /**
         *  @brief Default destructor
        */
        ~SessionsManager();

        Session* startSession(uint32_t i_remoteConsoleSessID, uint32_t i_priv,
                              uint8_t i_authAlgo,
                              uint8_t i_intgAlgo, uint8_t i_confAlgo,
                              UserAuthInterface::AuthenticationMethod i_authMethod);

        void stopSession(uint32_t i_bmcSessionId);
        void stopChannelSessions();
        void cleanStaleEntries();
        void sessionsCount(uint8_t& o_allowed, uint8_t& o_active);

        //Called when Session Object is required to work with
        std::shared_ptr<Session> getSession(uint32_t i_sessionId,
                                            SessionRetrieveOption i_option
                                            = IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID);

    protected:
        /**
         *  @brief Default constructor
        */
        SessionsManager();

        //Map
        SessionMap_t sessionsMap;
        std::mutex mapMutex;      //Mutex Lock for critical sections
};

