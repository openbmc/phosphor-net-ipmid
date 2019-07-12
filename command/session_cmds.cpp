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

bool parseCloseSessionInputPayload(std::string& objectPath, uint32_t& sessionID,
                                   uint8_t& sessionHandle)
{
    std::size_t ptrPosition = objectPath.rfind("/");
    uint16_t tempSessionHandle = 0;

    if (ptrPosition != std::string::npos)
    {
        std::string sessionIdString = objectPath.substr(ptrPosition + 1);
        std::size_t ptr = sessionIdString.rfind("_");

        if (ptr != std::string::npos)
        {
            std::string sessionHandleString = sessionIdString.substr(ptr + 1);
            sessionIdString = sessionIdString.substr(0, ptr);
            std::stringstream handle(sessionHandleString);
            handle >> std::hex >> tempSessionHandle;
            sessionHandle = tempSessionHandle & 0xFF;
            std::stringstream ID(sessionIdString);
            ID >> std::hex >> sessionID;
            return true;
        }
    }
    return false;
}

bool isSessionObjectMatched(std::string& objectPath, uint32_t& reqSessionID,
                            uint8_t& reqSessionHandle)
{
    uint32_t sessionID = 0;
    uint8_t sessionHandle = 0;

    if (parseCloseSessionInputPayload(objectPath, sessionID, sessionHandle) ==
        true)
    {
        if ((reqSessionID == session::sessionZero &&
             reqSessionHandle == sessionHandle) ||
            (reqSessionID == sessionID))
        {
            return true;
        }
    }

    return false;
}

uint8_t setSessionState(std::shared_ptr<sdbusplus::asio::connection>& busp,
                        std::string& service, std::string& obj)
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
            return IPMI_CC_OK;
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed in getting session State property",
                        entry("service=%s", service.c_str()),
                        entry("Object path=%s", obj.c_str()),
                        entry("interface=%s", session::sessionIntf));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_INVALID_FIELD_REQUEST;
}

uint8_t closeOtherNetInstanceSession(uint32_t& reqSessionID,
                                     uint8_t& reqSessionHandle)
{
    auto busp = getSdBus();
    ipmi::ObjectTree objectTree;

    try
    {
        objectTree = ipmi::getAllDbusObjects(
            *busp, session::sessionManagerRootPath, session::sessionIntf);
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to fetch object from dbus",
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", e.what()));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    for (auto& objectTreeItr : objectTree)
    {
        std::string obj = objectTreeItr.first;

        if (isSessionObjectMatched(obj, reqSessionID, reqSessionHandle) == true)
        {
            auto& serviceMap = objectTreeItr.second;
            auto itr = serviceMap.begin();

            if (itr == serviceMap.end())
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }

            auto service = itr->first;
            return setSessionState(busp, service, obj);
        }
    }

    return IPMI_CC_INVALID_FIELD_REQUEST;
}

uint8_t closeMyNetInstanceSession(uint32_t& reqSessionID,
                                  uint8_t& reqSessionHandle)
{
    bool status = false;
    constexpr uint8_t IPMI_CC_INVALID_SESSIONID = 0x87;

    try
    {
        if (reqSessionID == session::sessionZero)
        {
            reqSessionID = std::get<session::Manager&>(singletonPool)
                               .getSessionIDbyHandle(reqSessionHandle);
        }

        status = std::get<session::Manager&>(singletonPool)
                     .stopSession(reqSessionID);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to get session manager instance",
                        entry("ERRMSG=%s", e.what()));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (!status)
    {
        return IPMI_CC_INVALID_SESSIONID;
    }

    return IPMI_CC_OK;
}

std::vector<uint8_t> closeSession(const std::vector<uint8_t>& inPayload,
                                  const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(CloseSessionResponse));
    auto request =
        reinterpret_cast<const CloseSessionRequest*>(inPayload.data());
    auto response = reinterpret_cast<CloseSessionResponse*>(outPayload.data());
    uint32_t reqSessionID = request->sessionID;
    uint8_t ipmiNetworkInstance = 0;
    uint8_t reqSessionHandle = request->sessionHandle;
    constexpr uint8_t IPMI_CC_INVALID_SESSION_HANDLE = 0x88;

    if (reqSessionID == session::sessionZero &&
        reqSessionHandle == session::invalidSessionHandle)
    {
        response->completionCode = IPMI_CC_INVALID_SESSION_HANDLE;
        return outPayload;
    }

    try
    {
        ipmiNetworkInstance =
            std::get<session::Manager&>(singletonPool).getNetworkInstance();
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to fetch object from dbus",
                        entry("INTERFACE=%s", session::sessionIntf),
                        entry("ERRMSG=%s", e.what()));
        response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
        return outPayload;
    }

    if (reqSessionID >> myNetInstanceSessionIdMask == ipmiNetworkInstance ||
        (reqSessionID == session::sessionZero &&
         (reqSessionHandle >> myNetInstanceSessionHandleMask ==
          ipmiNetworkInstance)))
    {
        response->completionCode =
            closeMyNetInstanceSession(reqSessionID, reqSessionHandle);
    }
    else
    {
        response->completionCode =
            closeOtherNetInstanceSession(reqSessionID, reqSessionHandle);
    }

    return outPayload;
}

} // namespace command
