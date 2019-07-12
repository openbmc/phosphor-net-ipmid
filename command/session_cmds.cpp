#include "session_cmds.hpp"

#include "endian.hpp"
#include "main.hpp"

#include <ipmid/api.h>

#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>

namespace command
{
using namespace phosphor::logging;

std::vector<uint8_t>
    setSessionPrivilegeLevel(const std::vector<uint8_t>& inPayload,
                             const message::Handler& handler)
{

    std::vector<uint8_t> outPayload(sizeof(SetSessionPrivLevelResp));
    auto request =
        reinterpret_cast<const SetSessionPrivLevelReq*>(inPayload.data());
    auto response =
        reinterpret_cast<SetSessionPrivLevelResp*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;
    uint8_t reqPrivilegeLevel = request->reqPrivLevel;

    auto session = std::get<session::Manager&>(singletonPool)
                       .getSession(handler.sessionID);

    if (reqPrivilegeLevel == 0) // Just return present privilege level
    {
        response->newPrivLevel = session->currentPrivilege();
        return outPayload;
    }
    if (reqPrivilegeLevel > (static_cast<uint8_t>(session->reqMaxPrivLevel) &
                             session::reqMaxPrivMask))
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
        return outPayload;
    }
    // Use the minimum privilege of user or channel
    uint8_t minPriv = 0;
    if (session->sessionChannelAccess.privLimit <
        session->sessionUserPrivAccess.privilege)
    {
        minPriv = session->sessionChannelAccess.privLimit;
    }
    else
    {
        minPriv = session->sessionUserPrivAccess.privilege;
    }
    if (reqPrivilegeLevel > minPriv)
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
    }
    else
    {
        // update current privilege of the session.
        session->currentPrivilege(static_cast<uint8_t>(reqPrivilegeLevel));
        response->newPrivLevel = reqPrivilegeLevel;
    }

    return outPayload;
}

/**
 * @brief parse session input payload.
 *
 * This function retrives the session id and session handle from the session
 * object path.
 * A valid object path will be in the form
 * "/xyz/openbmc_project/ipmi/session/channel/sessionId_sessionHandle"
 *
 * Ex: "/xyz/openbmc_project/ipmi/session/eth0/12a4567d_8a"
 * SessionId    : 0X12a4567d
 * SessionHandle: 0X8a

 * @param[in] objectPath - session object path
 * @param[in] sessionId - retrived session id will be asigned.
 * @param[in] sessionHandle - retrived session handle will be asigned.
 *
 * @return true if session id and session handle are retrived else returns
 false.
 */
bool parseCloseSessionInputPayload(const std::string& objectPath,
                                   uint32_t& sessionId, uint8_t& sessionHandle)
{
    if (objectPath.empty())
    {
        return false;
    }
    // getting the position of session id and session handle string from
    // object path.
    std::size_t ptrPosition = objectPath.rfind("/");
    uint16_t tempSessionHandle = 0;

    if (ptrPosition != std::string::npos)
    {
        // get the sessionid & session handle string from the session object
        // path Ex: sessionIdString: "12a4567d_8a"
        std::string sessionIdString = objectPath.substr(ptrPosition + 1);
        std::size_t pos = sessionIdString.rfind("_");

        if (pos != std::string::npos)
        {
            // extracting the session handle
            std::string sessionHandleString = sessionIdString.substr(pos + 1);
            // extracting the session id
            sessionIdString = sessionIdString.substr(0, pos);
            // converting session id string  and session handle string to
            // hexadecimal.
            std::stringstream handle(sessionHandleString);
            handle >> std::hex >> tempSessionHandle;
            sessionHandle = tempSessionHandle & 0xFF;
            std::stringstream idString(sessionIdString);
            idString >> std::hex >> sessionId;
            return true;
        }
    }
    return false;
}

/**
 * @brief is session object matched.
 *
 * This function checks whether the objectPath contains reqSessionId and
 * reqSessionHandle, e.g., "/xyz/openbmc_project/ipmi/session/eth0/12a4567d_8a"
 * matches sessionId 0x12a4567d and sessionHandle 0x8a.
 *
 * @param[in] objectPath - session object path
 * @param[in] reqSessionId - request session id
 * @param[in] reqSessionHandle - request session handle
 *
 *@return true if the object is matched else return false
 **/
bool isSessionObjectMatched(const std::string objectPath,
                            const uint32_t reqSessionId,
                            const uint8_t reqSessionHandle)
{
    uint32_t sessionId = 0;
    uint8_t sessionHandle = 0;

    if (parseCloseSessionInputPayload(objectPath, sessionId, sessionHandle))
    {
        return (reqSessionId == sessionId) ||
               (reqSessionHandle == sessionHandle);
    }

    return false;
}

/**
 * @brief set the session state as teardown
 *
 * This function is to set the session state to tear down in progress if the
 * state is active.
 *
 * @param[in] busp - Dbus obj
 * @param[in] service - service name
 * @param[in] obj - object path
 *
 *@return success completion code if it sets the session state to
 *tearDownInProgress else return the corresponding error completion code.
 **/
uint8_t setSessionState(std::shared_ptr<sdbusplus::asio::connection>& busp,
                        const std::string& service, const std::string& obj)
{
    try
    {
        uint8_t sessionState = std::get<uint8_t>(ipmi::getDbusProperty(
            *busp, service, obj, session::sessionIntf, "State"));

        if (sessionState == static_cast<uint8_t>(session::State::active))
        {
            ipmi::setDbusProperty(
                *busp, service, obj, session::sessionIntf, "State",
                static_cast<uint8_t>(session::State::tearDownInProgress));
            return ipmi::ccSuccess;
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed in getting session state property",
                        entry("service=%s", service.c_str()),
                        entry("object path=%s", obj.c_str()),
                        entry("interface=%s", session::sessionIntf));
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccInvalidFieldRequest;
}

uint8_t closeOtherNetInstanceSession(const uint32_t reqSessionId,
                                     const uint8_t reqSessionHandle,
                                     const uint8_t currentSessionPriv)
{
    auto busp = getSdBus();

    try
    {
        ipmi::ObjectTree objectTree = ipmi::getAllDbusObjects(
            *busp, session::sessionManagerRootPath, session::sessionIntf);

        for (auto& objectTreeItr : objectTree)
        {
            const std::string obj = objectTreeItr.first;

            if (isSessionObjectMatched(obj, reqSessionId, reqSessionHandle))
            {
                auto& serviceMap = objectTreeItr.second;

                if (serviceMap.size() != 1)
                {
                    return ipmi::ccUnspecifiedError;
                }

                auto itr = serviceMap.begin();
                const std::string service = itr->first;
                uint8_t closeSessionPriv =
                    std::get<uint8_t>(ipmi::getDbusProperty(
                        *busp, service, obj, session::sessionIntf,
                        "CurrentPrivilege"));

                if (currentSessionPriv < closeSessionPriv)
                {
                    return ipmi::ccInsufficientPrivilege;
                }
                return setSessionState(busp, service, obj);
            }
        }
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to fetch object from dbus",
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", e.what()));
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccInvalidFieldRequest;
}

uint8_t closeMyNetInstanceSession(uint32_t reqSessionId,
                                  uint8_t reqSessionHandle,
                                  const uint8_t currentSessionPriv)
{
    bool status = false;

    try
    {
        if (reqSessionId == session::sessionZero)
        {
            reqSessionId = std::get<session::Manager&>(singletonPool)
                               .getSessionIDbyHandle(
                                   reqSessionHandle &
                                   session::multiIntfaceSessionHandleMask);
            if (!reqSessionId)
            {
                return session::ccInvalidSessionHandle;
            }
        }

        auto closeSessionInstance =
            std::get<session::Manager&>(singletonPool).getSession(reqSessionId);
        uint8_t closeSessionPriv = closeSessionInstance->currentPrivilege();

        if (currentSessionPriv < closeSessionPriv)
        {
            return ipmi::ccInsufficientPrivilege;
        }
        status = std::get<session::Manager&>(singletonPool)
                     .stopSession(reqSessionId);

        if (!status)
        {
            return session::ccInvalidSessionId;
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get session manager instance",
                        entry("ERRMSG=%s", e.what()));
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccSuccess;
}

std::vector<uint8_t> closeSession(const std::vector<uint8_t>& inPayload,
                                  const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(CloseSessionResponse));
    auto request =
        reinterpret_cast<const CloseSessionRequest*>(inPayload.data());
    auto response = reinterpret_cast<CloseSessionResponse*>(outPayload.data());
    uint32_t reqSessionId = request->sessionID;
    uint8_t ipmiNetworkInstance = 0;
    uint8_t currentSessionPriv = 0;
    uint8_t reqSessionHandle = request->sessionHandle;

    if (reqSessionId == session::sessionZero &&
        reqSessionHandle == session::invalidSessionHandle)
    {
        response->completionCode = session::ccInvalidSessionHandle;
        return outPayload;
    }

    if (inPayload.size() == sizeof(reqSessionId) &&
        reqSessionId == session::sessionZero)
    {
        response->completionCode = session::ccInvalidSessionId;
        return outPayload;
    }

    if (reqSessionId != session::sessionZero &&
        inPayload.size() != sizeof(reqSessionId))
    {
        response->completionCode = ipmi::ccInvalidFieldRequest;
        return outPayload;
    }

    try
    {
        ipmiNetworkInstance =
            std::get<session::Manager&>(singletonPool).getNetworkInstance();
        auto currentSession = std::get<session::Manager&>(singletonPool)
                                  .getSession(handler.sessionID);
        currentSessionPriv = currentSession->currentPrivilege();
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to fetch object from dbus",
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", e.what()));
        response->completionCode = ipmi::ccUnspecifiedError;
        return outPayload;
    }

    if (reqSessionId >> myNetInstanceSessionIdShiftMask ==
            ipmiNetworkInstance ||
        (reqSessionId == session::sessionZero &&
         (reqSessionHandle >> myNetInstanceSessionHandleShiftMask ==
          ipmiNetworkInstance)))
    {
        response->completionCode = closeMyNetInstanceSession(
            reqSessionId, reqSessionHandle, currentSessionPriv);
    }
    else
    {
        response->completionCode = closeOtherNetInstanceSession(
            reqSessionId, reqSessionHandle, currentSessionPriv);
    }

    return outPayload;
}

} // namespace command
