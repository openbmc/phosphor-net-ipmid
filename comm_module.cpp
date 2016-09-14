#include "comm_module.hpp"

#include <systemd/sd-bus.h>
#include <iostream>
#include <ipmi.H>
#include <host-ipmid/ipmid-api.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>


#include "command_table.hpp"
#include "endian.hpp"
#include "sessions_manager.hpp"
#include "session.hpp"

static constexpr size_t IPMI_BMC_GUID_LEN = 16;

void registerCommands()
{
    CommandTable::IpmiCommandTableEntry l_table[] =
    {
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_OPEN_SESS_REQUEST << 16)},
            &ipmiOpenSession, nullptr, true,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_RAKP1 << 16)},
            &ipmi_RAKP12, nullptr, true,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_RAKP3 << 16)},
            &ipmi_RAKP34, nullptr, true,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI << 16) | CommandTable::APP | 0x38},
            &ipmiGetChannelCapabilities, nullptr, true,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI << 16) | CommandTable::APP | 0x3B},
            &ipmi_SetSessionPrivilegeLevel, nullptr, false,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI << 16) | CommandTable::APP | 0x3C},
            &ipmiCloseSession, nullptr, false,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
    };

    CommandTable::getInstance().Register(l_table,
            sizeof(l_table) / sizeof(CommandTable::IpmiCommandTableEntry));
}

void ipmiGetChannelCapabilities(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmiGetChannelCapabilities\n";

    ipmiGetChannelCapabilities_t* response = new ipmiGetChannelCapabilities_t;

    uint8_t req_Channel_num = *((uint8_t*)io_ipmiTransaction.iv_requestPayload);
    uint8_t req_max_privilage_level = *(((uint8_t*)
                                         io_ipmiTransaction.iv_requestPayload) + 1);

    // Mask the byte to get the channel number. only last 4 bits contain the stuff.
    req_Channel_num = req_Channel_num & 15 ;

    // Mask the byte to get actual Requested maximum privilege level. only last 4 bits contain the stuff.
    req_max_privilage_level = req_max_privilage_level & 15 ;

    response->completion_code = IPMICC_NORMAL;
    response->channel_num = 1;//(uint8_t)l_channelNumber;
    response->ipmi_ver = 1 ; //IPMI v2.0 extended capabilities available.
    response->reserved1 = 0;
    response->oem_proprietry = 0;
    response->straight_key = 0;
    response->reserved2 = 0;
    response->md5_support = 0;
    response->md2_support = 0;
    response->none = 0;
    response->reserved3 = 0;
    response->Kg_Status = 0; //KG is set to default
    response->per_msg_auth = 0; //Per-message Authentication is enabled
    response->usr_auth = 0; //User Level Authentication is enabled
    response->non_null_usrs = 1; //Non-null usernames enabled
    response->null_usrs = 1; //Null usernames enabled
    response->anonym_login = 0; //Anonymous Login disabled
    response->reserved4 = 0;
    response->ext_capabilities = 0x2; //channel supports IPMI v2.0 connections
    response->oem_id[0] = 0;
    response->oem_id[1] = 0;
    response->oem_id[2] = 0;
    response->oem_auxillary = 0;

    // Let send the IPMI reponse data...
    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(
                ipmiGetChannelCapabilities_t);

    std::cout << "<< ipmiGetChannelCapabilities\n";
}

void ipmiOpenSession(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmiOpenSession\n";

    std::shared_ptr<Session> l_zeroSess
        = SessionsManager::getInstance().getSession(
              io_ipmiTransaction.getSessionId());
    l_zeroSess->getSessionState().setSessionState(
        SessionState::IPMI_SESSION_SETUP_IN_PROGRESS);
    l_zeroSess->getSessionState().updateLastTransactionTime();

    ipmiOpenSessionResponse_t* response = new ipmiOpenSessionResponse_t;
    ipmiOpenSessionRequest_t* request  = (ipmiOpenSessionRequest_t*)
                                         io_ipmiTransaction.iv_requestPayload;

    memset((uint8_t*)response, 0, sizeof(ipmiOpenSessionResponse_t));

    // For IPMI standard port the User Authentication is defaulted to read the password from
    // the file
    UserAuthInterface::AuthenticationMethod l_authMethod =
        UserAuthInterface::IPMI_AUTH_METHOD_STATIC_PASS_KEY;

    Session* l_pSession = SessionsManager::getInstance().startSession(
                              request->remote_console_session_id,
                              request->req_max_privilage_level,
                              request->auth_algo,
                              request->int_algo,
                              request->conf_algo,
                              l_authMethod);

    response->message_tag = request->message_tag;

    // Channel should be enabled to honor the Open Session Request
    if (l_pSession)
    {
        response->status_code = 0;
        response->max_priv_reserved1 =  0;
        response->req_max_privilage_level =
            l_pSession->getSessionState().getPrivilegeLevel();
        response->reserved2 = 0;
        response->remote_console_session_id =
            request->remote_console_session_id ;
        response->managed_system_session_id = endian::to_ipmi<uint32_t>
                                              (l_pSession->getBMCSessionID());

        response->auth_payload_pt = request->auth_payload_pt ;
        response->auth_payload_length = request->auth_payload_length ;
        response->auth_algo = (std::get<std::unique_ptr<AuthAlgoInterface>>
                               (l_pSession->getSessionCipherSuite()).get())->getApplied();
        response->int_payload_pt = request->int_payload_pt ;
        response->int_payload_length = request->int_payload_length ;
        response->int_algo = (std::get<std::unique_ptr<IntegrityAlgoInterface>>
                              (l_pSession->getSessionCipherSuite()).get())->getApplied();
        response->conf_payload_pt = request->conf_payload_pt ;
        response->conf_payload_length = request->conf_payload_length ;
        response->conf_algo = (std::get<std::unique_ptr<ConfidentialityAlgoInterface>>
                               (l_pSession->getSessionCipherSuite()).get())->getApplied();

        l_pSession->getSessionState().updateLastTransactionTime();
        l_pSession->getSessionState().setSessionState(
            SessionState::IPMI_SESSION_SETUP_IN_PROGRESS);

        l_pSession->setChannel(io_ipmiTransaction.getChannelObject());
    }
    else
    {
        response->status_code = 0x01;
        std::cerr <<
                  "ipmiOpenSession : Problem opening a session (slots full or bad machine state)\n";
        l_zeroSess->getSessionState().setSessionState(
            SessionState::IPMI_SESSION_IS_INACTIVE);
    }

    // Let send the IPMI reponse data...
    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(ipmiOpenSessionResponse_t);
    io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_OPEN_SESS_RESPONSE);

    std::cout << "<< ipmiOpenSession\n";
}

void ipmi_RAKP12(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmi_RAKP12\n";

    std::shared_ptr<Session> l_zeroSess
        = SessionsManager::getInstance().getSession(
              io_ipmiTransaction.getSessionId());
    l_zeroSess->getSessionState().updateLastTransactionTime();

    ipmiRAKP1request_t* request  = (ipmiRAKP1request_t*)
                                   io_ipmiTransaction.iv_requestPayload;

    std::shared_ptr<Session> l_pSession =
        SessionsManager::getInstance().getSession(
            request->managed_system_session_id);
    fprintf(stderr, "\nRAKP12 0x%X\n",
            le32toh(request->managed_system_session_id));

    // Session ID is zero is reserved for session setup, don't proceed
    // or if the session requested is not found
    if (l_pSession == nullptr || request->managed_system_session_id == 0)
    {
        fprintf(stderr, "\nRAKP12 got bad session ID 0x%X\n",
                le32toh(request->managed_system_session_id));
        return;  //@TODO: Need to return RMCP+ Status codes?
    }
    l_pSession->getSessionState().updateLastTransactionTime();

    uint32_t l_rcSessID = endian::to_ipmi<uint32_t>(l_pSession->getRCSessionID());
    uint32_t l_bmcSessID = endian::to_ipmi<uint32_t>(l_pSession->getBMCSessionID());
    fprintf(stderr, "\nRAKP12 0x%X\n", l_rcSessID);
    fprintf(stderr, "\nRAKP12 0x%X\n", l_bmcSessID);
    uint8_t l_buffer[256] = {};
    int i = 0;

    memcpy(l_buffer + i, &l_rcSessID, sizeof(l_rcSessID));
    i += sizeof(l_rcSessID);
    memcpy(l_buffer + i, &l_bmcSessID, sizeof(l_bmcSessID));
    i += sizeof(l_bmcSessID);

    // Read Session Cipher Suite
    SessionKeys& l_sessKeys = std::get<SessionKeys>
                              (l_pSession->getSessionCipherSuite());

    // Remote Console Random Number
    l_sessKeys.rcRandomNum.resize(
        SessionKeys::IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN);
    std::copy((uint8_t*)request->remote_console_random_number,
              (uint8_t*)request->remote_console_random_number +
              SessionKeys::IPMI_REMOTE_CONSOLE_RANDOM_NUMBER_LEN,
              l_sessKeys.rcRandomNum.begin());

    memcpy(l_buffer + i, request->remote_console_random_number, 16);
    i += 16;

    RAND_bytes(l_buffer + i, 16);

    // BMC Random Number
    l_sessKeys.bmcRandomNum.resize(SessionKeys::IPMI_BMC_RANDOM_NUMBER_LEN);
    std::copy(l_buffer + i, l_buffer + i + SessionKeys::IPMI_BMC_RANDOM_NUMBER_LEN,
              l_sessKeys.bmcRandomNum.begin());
    i += 16;

    getSystemGUID(l_buffer + i, 16);
    i += 16;

    l_pSession->getSessionState().setPrivilegeLevel(
        request->req_max_pribvilage_level);
    memcpy(l_buffer + i, &(request->req_max_pribvilage_level),
           sizeof(request->req_max_pribvilage_level));
    i += sizeof(request->req_max_pribvilage_level);

    memcpy(l_buffer + i, &(request->user_name_len),
           sizeof(request->user_name_len));
    i += sizeof(request->user_name_len);

    uint8_t l_userName[20] = {};
    uint8_t l_userNameLen = sizeof(l_userName);

    if (request->user_name_len != 0)
    {
        memcpy(l_buffer + i, request->user_name, request->user_name_len);
        i += (request->user_name_len);

//        l_sessKeys.setUserName(request->user_name, request->user_name_len);

        l_sessKeys.userName.assign(request->user_name,
                                   request->user_name +
                                   ((SessionKeys::IPMI_USER_NAME_MAX_LENGTH > request->user_name_len) ?
                                    request->user_name_len : SessionKeys::IPMI_USER_NAME_MAX_LENGTH));

//        l_sessKeys.getUserName(l_userName, l_userNameLen);

        std::copy(l_sessKeys.userName.begin(), l_sessKeys.userName.end(), l_userName);
        l_userNameLen = l_sessKeys.userName.size();
    }

    uint8_t l_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_hmacBuflen = 0;

    uint8_t l_userKey[20] = {'P', 'A', 'S', 'S', 'W', '0', 'R', 'D'};
    uint32_t l_userKeyLength = sizeof(l_userKey);
    l_userKeyLength = 8;

    bool l_userValid = true;
    std::string l_str = (const char*)l_userName;

    uint8_t l_reqPrvLevel = request->req_max_pribvilage_level;
    if (l_userValid)
    {
        auto l_authAlgo = std::get<std::unique_ptr<UserAuthInterface>>
                          (l_pSession->getSessionCipherSuite()).get();

        l_userValid = l_authAlgo->AuthenticateUser
                      (&l_userName[0], (uint32_t)l_userNameLen,
                       &l_userKey[0], l_userKeyLength,
                       l_reqPrvLevel);
    }

    if (l_userValid)
    {
        auto l_userAlgo = std::get<std::unique_ptr<UserAuthInterface>>
                          (l_pSession->getSessionCipherSuite()).get();

        if (l_userAlgo->getAuthMethod()
            == UserAuthInterface::IPMI_AUTH_METHOD_STATIC_PASS_KEY)
        {
            std::string l_name((char*)l_userName);
            l_name.resize(l_userNameLen, '\0');
            l_pSession->getSessionState().setMaxPrivilegeLevel(
                IPMI_SESSION_PRIVILEGE_ADMIN);
        }
        else
        {
            l_reqPrvLevel = 5;
            l_pSession->getSessionState().setMaxPrivilegeLevel(l_reqPrvLevel & 0x0F);
        }
        l_pSession->getSessionState().setOperatingPrivilegeLevel(l_reqPrvLevel & 0x0F);
        l_pSession->getSessionState().setPrivilegeLevel(
            request->req_max_pribvilage_level);

//        l_sessKeys.setUserKey(l_userKey, l_userKeyLength);
        l_sessKeys.userKey.resize(SessionKeys::IPMI_USER_KEY_MAX_LENGTH);
        std::copy(l_userKey, l_userKey + SessionKeys::IPMI_USER_KEY_MAX_LENGTH,
                  l_sessKeys.userKey.begin());
        //l_sessKeys.userKey.assign(l_userKey, l_userKey + l_userKeyLength);

        auto l_authAlgo = std::get<std::unique_ptr<AuthAlgoInterface>>
                          (l_pSession->getSessionCipherSuite()).get();

        l_authAlgo->generateKeyExchangeAuthCode_RAKP2(
            &l_sessKeys, l_buffer, i, l_hmacBuffer, l_hmacBuflen);

        ipmiRAKP2response_t* response = (ipmiRAKP2response_t*)(new uint8_t[(sizeof(
                                            ipmiRAKP2response_t)) + l_hmacBuflen]);

        response->message_tag = request->message_tag;
        response->rmcp2_status_code = 0;
        response->reserved1 = 0;
        response->remote_console_session_id = l_rcSessID ;

        std::copy(l_sessKeys.bmcRandomNum.begin(), l_sessKeys.bmcRandomNum.end(),
                  response->managed_system_random_number);

        getSystemGUID(response->managed_system_guid,
                      sizeof(response->managed_system_guid));
        memcpy(response + 1, l_hmacBuffer, l_hmacBuflen);

        // Let send the IPMI reponse data...
        io_ipmiTransaction.iv_responsePayload = (uint8_t*)response;
        io_ipmiTransaction.iv_responsePayloadSize = (sizeof(ipmiRAKP2response_t)) +
                l_hmacBuflen;
        io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP2);
    }
    else
    {
        ipmiRAKP2response_t* response = (ipmiRAKP2response_t*)(new uint8_t[sizeof(
                                            ipmiRAKP2response_t)]);
        memset(response, 0, sizeof(ipmiRAKP2response_t));
        response->message_tag = request->message_tag;
        response->rmcp2_status_code = 0x12;
        // Let send the IPMI reponse data...
        io_ipmiTransaction.iv_responsePayload = (uint8_t*)response;
        io_ipmiTransaction.iv_responsePayloadSize = (sizeof(ipmiRAKP2response_t));
        io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP2);

        //close the session
        SessionsManager::getInstance().stopSession(l_pSession->getBMCSessionID());
        l_zeroSess->getSessionState().setSessionState(
            SessionState::IPMI_SESSION_IS_INACTIVE);
    }

    std::cout << "<< ipmi_RAKP12\n";
}

void ipmi_RAKP34(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmi_RAKP34\n";

    std::shared_ptr<Session> l_zeroSess
        = SessionsManager::getInstance().getSession(
              io_ipmiTransaction.getSessionId());
    l_zeroSess->getSessionState().updateLastTransactionTime();

    ipmiRAKP3request_t* request  = (ipmiRAKP3request_t*)
                                   io_ipmiTransaction.iv_requestPayload;

    uint8_t l_buffer[256] = {};
    int i = 0;

    std::shared_ptr<Session> l_pSession =
        SessionsManager::getInstance().getSession(
            le32toh(request->managed_system_session_id));

    // Session ID is zero is reserved for session setup, don't proceed
    // or if the session requested is not found
    if (l_pSession == nullptr || request->managed_system_session_id == 0)
    {
        return; //@TODO: Need to return RMCP+ Status codes?
    }
    l_pSession->getSessionState().updateLastTransactionTime();

    SessionKeys& l_sessKeys = (std::get<SessionKeys>
                               (l_pSession->getSessionCipherSuite()));

    // Get BMC Random Number
    std::copy(l_sessKeys.bmcRandomNum.begin(), l_sessKeys.bmcRandomNum.end(),
              l_buffer + i);
    i += 16;

    uint32_t l_rcSessID = endian::to_ipmi<uint32_t>(l_pSession->getRCSessionID());
    memcpy(l_buffer + i, &l_rcSessID, sizeof(l_rcSessID));
    i += sizeof(l_rcSessID);

    uint8_t l_prvLvl = l_pSession->getSessionState().getPrivilegeLevel();
    memcpy(l_buffer + i, &(l_prvLvl), sizeof(l_prvLvl));
    i += sizeof(l_prvLvl);

    uint8_t l_usrNameLen = 20;
    uint32_t l_usrName[20] = {};
    // Get User Name
    std::copy(l_sessKeys.userName.begin(), l_sessKeys.userName.end(), l_usrName);
    l_usrNameLen = l_sessKeys.userName.size();

    memcpy(l_buffer + i, &(l_usrNameLen), sizeof(l_usrNameLen));
    i += sizeof(l_usrNameLen);

    if (l_usrNameLen != 0)
    {
        memcpy(l_buffer + i, l_usrName, l_usrNameLen);
        i += (l_usrNameLen);
    }

    uint8_t l_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_hmacBuflen = 0;

    uint8_t l_key[SessionKeys::IPMI_USER_KEY_MAX_LENGTH] = {};
    uint32_t l_keyLength = SessionKeys::IPMI_USER_KEY_MAX_LENGTH;
//    l_sessKeys.getUserKey(l_key, l_keyLength);
    std::copy(l_sessKeys.userKey.begin(), l_sessKeys.userKey.end(), l_key);

    HMAC(EVP_sha1(), l_key, l_keyLength, l_buffer, i, l_hmacBuffer, &l_hmacBuflen);

    if (memcmp(l_hmacBuffer , request->Key_Exch_Auth_Code , l_hmacBuflen))
    {
        std::cerr << "mismatch in HMAC sent by remote console\n";

        ipmiRAKP4response_t* response = (ipmiRAKP4response_t*)(new uint8_t[sizeof(
                                            ipmiRAKP4response_t)]);
        memset(response, 0, (sizeof(ipmiRAKP4response_t)));

        response->message_tag = request->message_tag;
        response->rmcp2_status_code = 0x0F;
        response->reserved1 = 0;
        response->remote_console_session_id = l_rcSessID;

        io_ipmiTransaction.iv_responsePayload = (uint8_t*)response;
        io_ipmiTransaction.iv_responsePayloadSize = sizeof(ipmiRAKP4response_t);

        //Send Response
        io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP4);

        //close the session
        SessionsManager::getInstance().stopSession(l_pSession->getBMCSessionID());
        l_zeroSess->getSessionState().setSessionState(
            SessionState::IPMI_SESSION_IS_INACTIVE);

        return;
    }

    uint8_t sik_buffer[256] = {};
    i = 0;
    // Get Remote Console Random Number
    std::copy(l_sessKeys.rcRandomNum.begin(), l_sessKeys.rcRandomNum.end(),
              sik_buffer + i);
    i += 16;

//    l_sessKeys.getBmcRandomNum(sik_buffer + i, l_temp);
    std::copy(l_sessKeys.bmcRandomNum.begin(), l_sessKeys.bmcRandomNum.end(),
              sik_buffer + i);
    i += 16;

    memcpy(sik_buffer + i, &(l_prvLvl), sizeof(l_prvLvl));
    i += sizeof(l_prvLvl);

    memcpy(sik_buffer + i, &(l_usrNameLen), sizeof(l_usrNameLen));
    i += sizeof(l_usrNameLen);

    if (l_usrNameLen != 0)
    {
        memcpy(sik_buffer + i, l_usrName, l_usrNameLen);
        i += (l_usrNameLen);
    }

    uint8_t l_sik_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_sik_hmacBuflen = 0;

    HMAC(EVP_sha1(), l_key, l_keyLength, sik_buffer, i, l_sik_hmacBuffer,
         &l_sik_hmacBuflen);
//    l_sessKeys.setSIK(l_sik_hmacBuffer, l_sik_hmacBuflen);
    l_sessKeys.sessionIntegrityKey.resize(l_sik_hmacBuflen);
    std::copy(l_sik_hmacBuffer, l_sik_hmacBuffer + l_sik_hmacBuflen,
              l_sessKeys.sessionIntegrityKey.begin());
//    l_sessKeys.sessionIntegrityKey.assign(l_sik_hmacBuffer, l_sik_hmacBuffer + SessionKeys::IPMI_SESSION_INTEGRITY_KEY_LENGTH);
    std::cout << "Session integrity size =" << l_sessKeys.sessionIntegrityKey.size()
              << "\n";

    uint8_t inck_buffer[256] = {};
    i = 0;
    // Get Remote Console Random Number
    std::copy(l_sessKeys.rcRandomNum.begin(), l_sessKeys.rcRandomNum.end(),
              inck_buffer + i);
    i += 16;

    uint32_t inck_mssi = endian::to_ipmi<uint32_t>(l_pSession->getBMCSessionID());
    memcpy(inck_buffer + i, (uint8_t*)&inck_mssi, sizeof(inck_mssi));
    i += sizeof(inck_mssi);

    getSystemGUID(inck_buffer + i, 16);
    i += 16;

    uint8_t inck_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t inck_hmacBuflen = 0;

    HMAC(EVP_sha1(), l_sik_hmacBuffer, 20, inck_buffer, i, inck_hmacBuffer,
         &inck_hmacBuflen);

    ipmiRAKP4response_t* response = (ipmiRAKP4response_t*)(new uint8_t[(sizeof(
                                        ipmiRAKP4response_t)) + RAKP4_INK_LEN ]);
    memset(response, 0, ((sizeof(ipmiRAKP4response_t)) + RAKP4_INK_LEN));

    response->message_tag = request->message_tag;
    response->rmcp2_status_code = 0;
    response->reserved1 = 0;
    response->remote_console_session_id = l_rcSessID;
    memcpy(response + 1, inck_hmacBuffer, RAKP4_INK_LEN);

    // Let send the IPMI reponse data...
    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(ipmiRAKP4response_t) +
            RAKP4_INK_LEN;

    l_pSession->getSessionState().setSessionState(
        SessionState::IPMI_SESSION_IS_ACTIVE);

    //Send Response
    io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP4);

    l_zeroSess->getSessionState().setSessionState(
        SessionState::IPMI_SESSION_IS_INACTIVE);
    std::cout << "<< ipmi_RAKP34\n";
}

void ipmi_SetSessionPrivilegeLevel(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmi_SetSessionPrivilegeLevel\n";
    uint8_t l_requestedPrvLevel = *((uint8_t*)io_ipmiTransaction.iv_requestPayload);
    ipmiSetSessionPrivilegeLevel_t* response =
        (ipmiSetSessionPrivilegeLevel_t*) new uint8_t[sizeof(
                    ipmiSetSessionPrivilegeLevel_t)];
    memset((uint8_t*)response, 0, sizeof(ipmiSetSessionPrivilegeLevel_t));
    response->completion_code = IPMICC_NORMAL;

    if (0 == l_requestedPrvLevel)
    {
        response->new_Privilage_Level =
            io_ipmiTransaction.getSessionPrivilegeLevel();
    }
    else if ((1 == l_requestedPrvLevel) ||
             (l_requestedPrvLevel > ((uint8_t)(IPMI_SESSION_PRIVILEGE_OEM))))
    {
        response->completion_code = IPMICC_REQ_FIELD_INVALID;
    }
    else
    {
        if (l_requestedPrvLevel <= io_ipmiTransaction.getSessionMaxPrivilegeLevel())
        {
            io_ipmiTransaction.setSessionPrivilegeLevel(l_requestedPrvLevel);
            response->new_Privilage_Level = l_requestedPrvLevel;
        }
        else
        {
            response->completion_code = 0x81;
        }
    }

    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(
                ipmiSetSessionPrivilegeLevel_t);
    std::cout << "<< ipmi_SetSessionPrivilegeLevel\n";
}

void ipmiCloseSession(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmiCloseSession\n";

    std::shared_ptr<Session> l_session;
    IpmiCloseSessionRequest* l_reqPtr  = (IpmiCloseSessionRequest*)
                                         io_ipmiTransaction.iv_requestPayload;

    auto l_sessionID = endian::from_ipmi<uint32_t>(l_reqPtr->sessionID);

    IpmiCloseSessionResponse* l_pResponse
        = (IpmiCloseSessionResponse*)new uint8_t[sizeof(IpmiCloseSessionResponse)];

    memset(l_pResponse, 0, sizeof(IpmiCloseSessionResponse));

    if (io_ipmiTransaction.getSessionId() == l_sessionID)
    {
        // Close session request for the current session
        if (io_ipmiTransaction.getSessionId() == 0x00)
        {
            //We are in the sessionless thread, need more logic than just setting flag
            //Take care of case where flag not set when checking but set when
            //waiting for a message.

            l_pResponse->completionCode = 0x88;
        }
        else
        {
            l_session = SessionsManager::getInstance().getSession(
                            io_ipmiTransaction.getSessionId());
        }
    }
    else
    {
        // Close session request not for the current session
        if (SessionState::IPMI_PRIVILEGE_ADMIN !=
            io_ipmiTransaction.getSessionPrivilegeLevel())
        {
            //Not enough privileges
            l_pResponse->completionCode = IPMICC_WRONG_PRIV;
        }
        else
        {
            if (l_sessionID == 0x00)
            {
                //Close requested using session handle
                l_session = SessionsManager::getInstance().getSession(
                                l_reqPtr->sessionHandle,
                                SessionsManager::IPMI_SESSION_RETRIEVE_OPTION_SESSION_HANDLE);

                if (nullptr == l_session || (l_session->getBMCSessionID() == 0x00))
                {
                    l_pResponse->completionCode = 0x88;
                }
            }
            else
            {
                //Close requested using session ID
                l_session = SessionsManager::getInstance().getSession(l_sessionID,
                            SessionsManager::IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID);

                if (nullptr == l_session)
                {
                    l_pResponse->completionCode = 0x87;
                }
            }
        }
    }

    io_ipmiTransaction.iv_responsePayload = (uint8_t*)l_pResponse;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(IpmiCloseSessionResponse);
    io_ipmiTransaction.send();

    if (nullptr != l_session)
    {
        SessionsManager::getInstance().stopSession(l_session->getBMCSessionID());
    }

    std::cout << "<< ipmiCloseSession\n";
}

void getSystemGUID(uint8_t* i_buffer, uint32_t io_numBytes)
{
    uint8_t l_managedSystemGUID[IPMI_BMC_GUID_LEN] = { 0x53, 0x61, 0x6E, 0x74,
                                                       0x6F, 0x73, 0x68, 0x20,
                                                       0x44, 0x65, 0x76, 0x61,
                                                       0x6C, 0x65, 0x20, 0x00
                                                     };

    uint32_t l_len = (io_numBytes > sizeof(l_managedSystemGUID)) ?
                     sizeof(l_managedSystemGUID)
                     : io_numBytes;
    memcpy(i_buffer, l_managedSystemGUID, l_len);
}

