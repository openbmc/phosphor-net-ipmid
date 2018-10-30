#include "session_cmds.hpp"

#include "endian.hpp"
#include "main.hpp"

#include <host-ipmid/ipmid-api.h>

#include <user_channel/channel_layer.hpp>
#include <user_channel/user_layer.hpp>

namespace command
{
// Defined as per IPMI specification
static constexpr uint8_t searchCurrentSession = 0x00;
static constexpr uint8_t searchSessionByHandle = 0xFE;
static constexpr uint8_t searchSessionByID = 0xFF;

static constexpr uint8_t ipmi15VerSession = 0x00;
static constexpr uint8_t ipmi20VerSession = 0x01;

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
        response->newPrivLevel = static_cast<uint8_t>(session->curPrivLevel);
        return outPayload;
    }
    if (reqPrivilegeLevel >
        (session->reqMaxPrivLevel & session::reqMaxPrivMask))
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
        return outPayload;
    }

    uint8_t userId = ipmi::ipmiUserGetUserId(session->userName);
    if (userId == ipmi::invalidUserId)
    {
        response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
        return outPayload;
    }
    ipmi::PrivAccess userAccess{};
    ipmi::ChannelAccess chAccess{};
    if ((ipmi::ipmiUserGetPrivilegeAccess(userId, session->chNum, userAccess) !=
         IPMI_CC_OK) ||
        (ipmi::getChannelAccessData(session->chNum, chAccess) != IPMI_CC_OK))
    {
        response->completionCode = IPMI_CC_INVALID_PRIV_LEVEL;
        return outPayload;
    }
    // Use the minimum privilege of user or channel
    uint8_t minPriv = 0;
    if (chAccess.privLimit < userAccess.privilege)
    {
        minPriv = chAccess.privLimit;
    }
    else
    {
        minPriv = userAccess.privilege;
    }
    if (reqPrivilegeLevel > minPriv)
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
    }
    else
    {
        // update current privilege of the session.
        session->curPrivLevel =
            static_cast<session::Privilege>(reqPrivilegeLevel);
        response->newPrivLevel = reqPrivilegeLevel;
    }

    return outPayload;
}

std::vector<uint8_t> closeSession(const std::vector<uint8_t>& inPayload,
                                  const message::Handler& handler)
{
    std::vector<uint8_t> outPayload(sizeof(CloseSessionResponse));
    auto request =
        reinterpret_cast<const CloseSessionRequest*>(inPayload.data());
    auto response = reinterpret_cast<CloseSessionResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK;

    auto bmcSessionID = endian::from_ipmi(request->sessionID);

    // Session 0 is needed to handle session setup, so session zero is never
    // closed
    if (bmcSessionID == session::SESSION_ZERO)
    {
        response->completionCode = IPMI_CC_INVALID_SESSIONID;
    }
    else
    {
        auto status = std::get<session::Manager&>(singletonPool)
                          .stopSession(bmcSessionID);
        if (!status)
        {
            response->completionCode = IPMI_CC_INVALID_SESSIONID;
        }
    }
    return outPayload;
}

std::vector<uint8_t> getSessionInfo(const std::vector<uint8_t>& inPayload,
                                    const message::Handler& handler)

{
    std::vector<uint8_t> outPayload(sizeof(GetSessionInfoResponse));
    auto request =
        reinterpret_cast<const GetSessionInfoRequest*>(inPayload.data());
    auto response =
        reinterpret_cast<GetSessionInfoResponse*>(outPayload.data());
    uint32_t reqSessionID = handler.sessionID;
    response->completionCode = IPMI_CC_OK;
    if (inPayload.size() == sizeof(request->sessionIndex) &&
        request->sessionIndex != 0)
    {
        if (request->sessionIndex <= session::MAX_SESSION_COUNT)
        {
            reqSessionID = std::get<session::Manager&>(singletonPool)
                               .getSessionIDbyHandle(request->sessionIndex);
        }
        else
        {
            response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
            outPayload.resize(sizeof(response->completionCode));
            return outPayload;
        }
    }

    // Here we look for session info according to session index parameter
    switch (request->sessionIndex)
    {
        // Look for current active session which this cmd is received over
        case searchCurrentSession:
            // Request data should only contain session index byte
            if (inPayload.size() != sizeof(request->sessionIndex))
            {
                response->completionCode = IPMI_CC_REQ_DATA_LEN_INVALID;
                outPayload.resize(sizeof(response->completionCode));
                return outPayload;
            }
            // To look for current active session which the command came over,
            // the session ID cannot be 0.
            if (0 == reqSessionID)
            {
                response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
                outPayload.resize(sizeof(response->completionCode));
                return outPayload;
            }
            break;
        case searchSessionByHandle:
            // Request data should only contain session index byte and Session
            // handle
            if (inPayload.size() != (sizeof(request->sessionIndex) +
                                     sizeof(request->sessionHandle)))
            {
                response->completionCode = IPMI_CC_REQ_DATA_LEN_INVALID;
                outPayload.resize(sizeof(response->completionCode));
                return outPayload;
            }

            // Retrieve session id based on session handle
            if (request->sessionHandle <= session::MAX_SESSION_COUNT)
            {
                reqSessionID =
                    std::get<session::Manager&>(singletonPool)
                        .getSessionIDbyHandle(request->sessionHandle);
            }
            else
            {
                response->completionCode = IPMI_CC_INVALID_FIELD_REQUEST;
                outPayload.resize(sizeof(response->completionCode));
                return outPayload;
            }
            break;
        case searchSessionByID:
            // Request data should only contain session index byte and Session
            // handle
            if (inPayload.size() != sizeof(GetSessionInfoRequest))
            {
                response->completionCode = IPMI_CC_REQ_DATA_LEN_INVALID;
                outPayload.resize(sizeof(response->completionCode));
                return outPayload;
            }
            reqSessionID = endian::from_ipmi(request->sessionID);

            break;
        default:
            if (inPayload.size() != sizeof(request->sessionIndex))
            {
                response->completionCode = IPMI_CC_REQ_DATA_LEN_INVALID;
                outPayload.resize(sizeof(response->completionCode));
                return outPayload;
            }
    }

    response->totalSessionCount = session::MAX_SESSION_COUNT;
    response->activeSessioncount =
        std::get<session::Manager&>(singletonPool).getActiveSessionCount();
    response->sessionHandle = 0;
    if (reqSessionID != 0)
    {

        std::shared_ptr<session::Session> sessionInfo;
        try
        {
            sessionInfo = std::get<session::Manager&>(singletonPool)
                              .getSession(reqSessionID);
        }
        catch (std::exception& e)
        {
            response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
            outPayload.resize(sizeof(response->completionCode));
            return outPayload;
        }
        response->sessionHandle = std::get<session::Manager&>(singletonPool)
                                      .getSessionHandle(reqSessionID);
        uint8_t userId = ipmi::ipmiUserGetUserId(sessionInfo->userName);
        if (userId == ipmi::invalidUserId)
        {
            response->completionCode = IPMI_CC_UNSPECIFIED_ERROR;
            outPayload.resize(sizeof(response->completionCode));
            return outPayload;
        }
        response->userID = userId; // userId;
        response->privLevel = static_cast<uint8_t>(sessionInfo->curPrivLevel);
        response->chanNum = sessionInfo->chNum; // byte7 3:0
        response->ipmiVer = ipmi20VerSession;   // byte7 7:4
        response->remoteIpAddr =
            sessionInfo->channelPtr->getRemoteAddressInbytes();
        response->remotePort =
            sessionInfo->channelPtr->getPort(); // remoteSessionPort;

        // TODO: Filling the Remote MACAddress
    }
    else
    {
        outPayload.resize(4);
    }
    return outPayload;
}

} // namespace command
