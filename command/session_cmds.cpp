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
 * @brief Parse Session Input payload.
 *
 * This finction retrives the session id and session handle from the session
 object path.
 * A valid object path will be in the form
 "/xyz/openbmc_project/ipmi/session/channel/sessionId_sessionHandle"
 *
 * Ex: "/xyz/openbmc_project/ipmi/session/eth0/12345678_01"
 * SessionId	: 0X12345678
 * SessionHandle: 0X01

 * @param[in] objectPath - Sessoin object path
 * @param[in] sessionID - Retrived session Id will be asigned to it
 * @param[in] sessionHandle - Retrived session handle will be asigned to it
 *
 * @return true if session id and session handle are retrived else returns
 false.
 */
bool parseCloseSessionInputPayload(const std::string& objectPath,
                                   uint32_t& sessionID, uint8_t& sessionHandle)
{
    std::size_t ptrPosition = objectPath.rfind("/");
    uint16_t tempSessionHandle = 0;

    if (ptrPosition != std::string::npos)
    {
        std::string sessionIdString = objectPath.substr(ptrPosition + 1);
        std::size_t pos = sessionIdString.rfind("_");

        if (pos != std::string::npos)
        {
            std::string sessionHandleString = sessionIdString.substr(pos + 1);
            sessionIdString = sessionIdString.substr(0, pos);
            std::stringstream handle(sessionHandleString);
            handle >> std::hex >> tempSessionHandle;
            sessionHandle = tempSessionHandle & 0xFF;
            std::stringstream Id(sessionIdString);
            Id >> std::hex >> sessionID;
            return true;
        }
    }
    return false;
}

/**
 * @brief Is session object matched.
 *
 * This function is used to check if the session object is matched or not.
 *
 * @param[in] objectPath - Sessoin object path
 * @param[in] reqSessionId - request session Id
 * @param[in] reqSessionHandle - request session Handle
 *
 *@return true if the object is matched elase returns false
 **/
bool isSessionObjectMatched(const std::string& objectPath,
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
 * @brief Sets session state
 *
 * This function is to set the session state to tear down in progress if the
 *state is active.
 *
 * @param[in] busp - Dbus obj
 * @param[in] service - service name
 * @param[in] obj - object path
 *
 *@return success completion code if it sests the session state to
 *tearDownInProgress else returns the correcponding error completion code.
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
        log<level::ERR>("Failed in getting session State property",
                        entry("service=%s", service.c_str()),
                        entry("Object path=%s", obj.c_str()),
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
