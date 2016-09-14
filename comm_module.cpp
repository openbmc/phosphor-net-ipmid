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
    IpmiCommandTable::IpmiCommandTableEntry l_table[] =
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
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI << 16) | IpmiCommandTable::APP | 0x38},
            &ipmiGetChannelCapabilities, nullptr, true,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI << 16) | IpmiCommandTable::APP | 0x3B},
            &ipmi_SetSessionPrivilegeLevel, nullptr, false,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
        {
            {(IpmiMessage::IPMI_PAYLOAD_TYPE_IPMI << 16) | IpmiCommandTable::APP | 0x3C},
            &ipmiCloseSession, nullptr, false,
            IPMI_SESSION_PRIVILEGE_ANY, IPMI_CHANNEL_ANY, IPMI_COMMAND_SUPPORT_DEFAULT
        },
    };

    IpmiCommandTable::getInstance().Register(l_table,
            sizeof(l_table) / sizeof(IpmiCommandTable::IpmiCommandTableEntry));
}

void ipmiGetChannelCapabilities(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmiGetChannelCapabilities\n";

    ipmiGetChannelCapabilities_t* response_data = new ipmiGetChannelCapabilities_t;

    uint8_t req_Channel_num = *((uint8_t*)io_ipmiTransaction.iv_requestPayload);
    uint8_t req_max_privilage_level = *(((uint8_t*)
                                         io_ipmiTransaction.iv_requestPayload) + 1);

    // Mask the byte to get the channel number. only last 4 bits contain the stuff.
    req_Channel_num = req_Channel_num & 15 ;

    // Mask the byte to get actual Requested maximum privilege level. only last 4 bits contain the stuff.
    req_max_privilage_level = req_max_privilage_level & 15 ;

    response_data->completion_code = IPMICC_NORMAL;
    response_data->channel_num = 1;//(uint8_t)l_channelNumber;
    response_data->ipmi_ver = 1 ; //IPMI v2.0 extended capabilities available.
    response_data->reserved1 = 0;
    response_data->oem_proprietry = 0;
    response_data->straight_key = 0;
    response_data->reserved2 = 0;
    response_data->md5_support = 0;
    response_data->md2_support = 0;
    response_data->none = 0;
    response_data->reserved3 = 0;
    response_data->Kg_Status = 0; //KG is set to default
    response_data->per_msg_auth = 0; //Per-message Authentication is enabled
    response_data->usr_auth = 0; //User Level Authentication is enabled
    response_data->non_null_usrs = 1; //Non-null usernames enabled
    response_data->null_usrs = 1; //Null usernames enabled
    response_data->anonym_login = 0; //Anonymous Login disabled
    response_data->reserved4 = 0;
    response_data->ext_capabilities = 0x2; //channel supports IPMI v2.0 connections
    response_data->oem_id[0] = 0;
    response_data->oem_id[1] = 0;
    response_data->oem_id[2] = 0;
    response_data->oem_auxillary = 0;

    // Let send the IPMI reponse data...
    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response_data;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(
                ipmiGetChannelCapabilities_t);

    std::cout << "<< ipmiGetChannelCapabilities\n";
}

void ipmiOpenSession(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmiOpenSession\n";

    std::shared_ptr<IpmiSession> l_zeroSess
        = IpmiSessionsManager::getInstance().getSession(
              io_ipmiTransaction.getSessionId());
    l_zeroSess->getSessionState().setSessionState(
        IpmiSessionState::IPMI_SESSION_SETUP_IN_PROGRESS);
    l_zeroSess->getSessionState().updateLastTransactionTime();

    ipmiOpenSessionResponse_t* response_data = new ipmiOpenSessionResponse_t;
    ipmiOpenSessionRequest_t* request_data  = (ipmiOpenSessionRequest_t*)
            io_ipmiTransaction.iv_requestPayload;

    memset((uint8_t*)response_data, 0, sizeof(ipmiOpenSessionResponse_t));

    // For IPMI standard port the User Authentication is defaulted to read the password from
    // the file
    IpmiUserAuthenticationInterface::IpmiAuthenticationMethod l_authMethod =
        IpmiUserAuthenticationInterface::IPMI_AUTH_METHOD_PASSWORD_FILE;

    IpmiSession* l_pSession = IpmiSessionsManager::getInstance().startSession(
                                  request_data->remote_console_session_id,
                                  request_data->req_max_privilage_level,
                                  request_data->auth_algo,
                                  request_data->int_algo,
                                  request_data->conf_algo,
                                  l_authMethod);

    response_data->message_tag = request_data->message_tag;

    // Channel should be enabled to honor the Open Session Request
    if (l_pSession)
    {
        response_data->status_code = 0;
        response_data->max_priv_reserved1 =  0;
        response_data->req_max_privilage_level =
            l_pSession->getSessionState().getPrivilegeLevel();
        response_data->reserved2 = 0;
        response_data->remote_console_session_id =
            request_data->remote_console_session_id ;
        response_data->managed_system_session_id = endian::to_ipmi<uint32_t>
                (l_pSession->getBMCSessionID());

        response_data->auth_payload_pt = request_data->auth_payload_pt ;
        response_data->auth_payload_length = request_data->auth_payload_length ;
        response_data->auth_algo =
            l_pSession->getSessionCipherSuite().getAuthCipher()->getApplied();
        response_data->int_payload_pt = request_data->int_payload_pt ;
        response_data->int_payload_length = request_data->int_payload_length ;
        response_data->int_algo =
            l_pSession->getSessionCipherSuite().getIntegrityCipher()->getApplied();
        response_data->conf_payload_pt = request_data->conf_payload_pt ;
        response_data->conf_payload_length = request_data->conf_payload_length ;
        response_data->conf_algo =
            l_pSession->getSessionCipherSuite().getConfidentialityCipher()->getApplied();

        l_pSession->getSessionState().updateLastTransactionTime();
        l_pSession->getSessionState().setSessionState(
            IpmiSessionState::IPMI_SESSION_SETUP_IN_PROGRESS);

        l_pSession->setChannel(io_ipmiTransaction.getChannelObject());
    }
    else
    {
        response_data->status_code = 0x01;
        std::cerr <<
                  "ipmiOpenSession : Problem opening a session (slots full or bad machine state)\n";
        l_zeroSess->getSessionState().setSessionState(
            IpmiSessionState::IPMI_SESSION_IS_INACTIVE);
    }

    // Let send the IPMI reponse data...
    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response_data;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(ipmiOpenSessionResponse_t);
    io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_OPEN_SESS_RESPONSE);

    std::cout << "<< ipmiOpenSession\n";
}

void ipmi_RAKP12(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmi_RAKP12\n";

    std::shared_ptr<IpmiSession> l_zeroSess
        = IpmiSessionsManager::getInstance().getSession(
              io_ipmiTransaction.getSessionId());
    l_zeroSess->getSessionState().updateLastTransactionTime();

    ipmiRAKP1request_t* request_data  = (ipmiRAKP1request_t*)
                                        io_ipmiTransaction.iv_requestPayload;

    std::shared_ptr<IpmiSession> l_pSession =
        IpmiSessionsManager::getInstance().getSession(
            request_data->managed_system_session_id);
    fprintf(stderr, "\nRAKP12 0x%X\n",
            le32toh(request_data->managed_system_session_id));

    // Session ID is zero is reserved for session setup, don't proceed
    // or if the session requested is not found
    if (l_pSession == nullptr || request_data->managed_system_session_id == 0)
    {
        fprintf(stderr, "\nRAKP12 got bad session ID 0x%X\n",
                le32toh(request_data->managed_system_session_id));
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

    IpmiSessionKeys& l_sessKeys =
        l_pSession->getSessionCipherSuite().getSessionKeys();
    l_sessKeys.setRcRandomNum((void*)request_data->remote_console_random_number,
                              16);
    memcpy(l_buffer + i, request_data->remote_console_random_number, 16);
    i += 16;

    RAND_bytes(l_buffer + i, 16);
    l_sessKeys.setBmcRandomNum(l_buffer + i, 16);
    i += 16;

    getSystemGUID(l_buffer + i, 16);
    i += 16;

    l_pSession->getSessionState().setPrivilegeLevel(
        request_data->req_max_pribvilage_level);
    memcpy(l_buffer + i, &(request_data->req_max_pribvilage_level),
           sizeof(request_data->req_max_pribvilage_level));
    i += sizeof(request_data->req_max_pribvilage_level);

    memcpy(l_buffer + i, &(request_data->user_name_len),
           sizeof(request_data->user_name_len));
    i += sizeof(request_data->user_name_len);

    uint8_t l_userName[20] = {};
    uint8_t l_userNameLen = sizeof(l_userName);

    if (request_data->user_name_len != 0)
    {
        memcpy(l_buffer + i, request_data->user_name, request_data->user_name_len);
        i += (request_data->user_name_len);

        l_sessKeys.setUserName(request_data->user_name, request_data->user_name_len);
        l_sessKeys.getUserName(l_userName, l_userNameLen);
    }

    uint8_t l_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_hmacBuflen = 0;

    uint8_t l_userKey[20] = {'P', 'A', 'S', 'S', 'W', '0', 'R', 'D'};
    uint32_t l_userKeyLength = sizeof(l_userKey);
    l_userKeyLength = 8;

    bool l_userValid = true;
    std::string l_str = (const char*)l_userName;

    uint8_t l_reqPrvLevel = request_data->req_max_pribvilage_level;
    if (l_userValid)
    {
        l_userValid = l_pSession->getSessionCipherSuite().getUserAuthInterface()
                      ->AuthenticateUser(&l_userName[0], (uint32_t)l_userNameLen,
                                         &l_userKey[0], l_userKeyLength,
                                         l_reqPrvLevel);
    }

    if (l_userValid)
    {
        if (l_pSession->getSessionCipherSuite().getUserAuthInterface()->getAuthMethod()
            == IpmiUserAuthenticationInterface::IPMI_AUTH_METHOD_PASSWORD_FILE)
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
            request_data->req_max_pribvilage_level);
        l_sessKeys.setUserKey(l_userKey, l_userKeyLength);

        l_pSession->getSessionCipherSuite()
        .getAuthCipher()->generateKeyExchangeAuthCode_RAKP2(
            &l_sessKeys, l_buffer, i, l_hmacBuffer, l_hmacBuflen);

        ipmiRAKP2response_t* response_data = (ipmiRAKP2response_t*)(new uint8_t[(sizeof(
                ipmiRAKP2response_t)) + l_hmacBuflen]);

        response_data->message_tag = request_data->message_tag;
        response_data->rmcp2_status_code = 0;
        response_data->reserved1 = 0;
        response_data->remote_console_session_id = l_rcSessID ;
        uint32_t l_temp = sizeof(response_data->managed_system_random_number);
        l_sessKeys.getBmcRandomNum(response_data->managed_system_random_number, l_temp);
        getSystemGUID(response_data->managed_system_guid,
                      sizeof(response_data->managed_system_guid));
        memcpy(response_data + 1, l_hmacBuffer, l_hmacBuflen);

        // Let send the IPMI reponse data...
        io_ipmiTransaction.iv_responsePayload = (uint8_t*)response_data;
        io_ipmiTransaction.iv_responsePayloadSize = (sizeof(ipmiRAKP2response_t)) +
                l_hmacBuflen;
        io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP2);
    }
    else
    {
        ipmiRAKP2response_t* response_data = (ipmiRAKP2response_t*)(new uint8_t[sizeof(
                ipmiRAKP2response_t)]);
        memset(response_data, 0, sizeof(ipmiRAKP2response_t));
        response_data->message_tag = request_data->message_tag;
        response_data->rmcp2_status_code = 0x12;
        // Let send the IPMI reponse data...
        io_ipmiTransaction.iv_responsePayload = (uint8_t*)response_data;
        io_ipmiTransaction.iv_responsePayloadSize = (sizeof(ipmiRAKP2response_t));
        io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP2);

        //close the session
        IpmiSessionsManager::getInstance().stopSession(l_pSession->getBMCSessionID());
        l_zeroSess->getSessionState().setSessionState(
            IpmiSessionState::IPMI_SESSION_IS_INACTIVE);
    }

    std::cout << "<< ipmi_RAKP12\n";
}

void ipmi_RAKP34(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmi_RAKP34\n";

    std::shared_ptr<IpmiSession> l_zeroSess
        = IpmiSessionsManager::getInstance().getSession(
              io_ipmiTransaction.getSessionId());
    l_zeroSess->getSessionState().updateLastTransactionTime();

    ipmiRAKP3request_t* request_data  = (ipmiRAKP3request_t*)
                                        io_ipmiTransaction.iv_requestPayload;

    uint8_t l_buffer[256] = {};
    int i = 0;
    uint32_t l_temp = 0;

    std::shared_ptr<IpmiSession> l_pSession =
        IpmiSessionsManager::getInstance().getSession(
            le32toh(request_data->managed_system_session_id));

    // Session ID is zero is reserved for session setup, don't proceed
    // or if the session requested is not found
    if (l_pSession == nullptr || request_data->managed_system_session_id == 0)
    {
        return; //@TODO: Need to return RMCP+ Status codes?
    }
    l_pSession->getSessionState().updateLastTransactionTime();

    IpmiSessionKeys& l_sessKeys =
        l_pSession->getSessionCipherSuite().getSessionKeys();
    l_temp = 16;
    l_sessKeys.getBmcRandomNum(l_buffer + i, l_temp);
    i += 16;

    uint32_t l_rcSessID = endian::to_ipmi<uint32_t>(l_pSession->getRCSessionID());
    memcpy(l_buffer + i, &l_rcSessID, sizeof(l_rcSessID));
    i += sizeof(l_rcSessID);

    uint8_t l_prvLvl = l_pSession->getSessionState().getPrivilegeLevel();
    memcpy(l_buffer + i, &(l_prvLvl), sizeof(l_prvLvl));
    i += sizeof(l_prvLvl);

    uint8_t l_usrNameLen = 20;
    uint32_t l_usrName[20] = {};
    l_sessKeys.getUserName(l_usrName, l_usrNameLen);

    memcpy(l_buffer + i, &(l_usrNameLen), sizeof(l_usrNameLen));
    i += sizeof(l_usrNameLen);

    if (l_usrNameLen != 0)
    {
        memcpy(l_buffer + i, l_usrName, l_usrNameLen);
        i += (l_usrNameLen);
    }

    uint8_t l_hmacBuffer[SHA_DIGEST_LENGTH] = {};
    uint32_t l_hmacBuflen = 0;

    uint8_t l_key[20] = {};
    uint32_t l_keyLength = 20;
    l_sessKeys.getUserKey(l_key, l_keyLength);

    HMAC(EVP_sha1(), l_key, l_keyLength, l_buffer, i, l_hmacBuffer, &l_hmacBuflen);

    if (memcmp(l_hmacBuffer , request_data->Key_Exch_Auth_Code , l_hmacBuflen))
    {
        std::cerr << "mismatch in HMAC sent by remote console\n";

        ipmiRAKP4response_t* response_data = (ipmiRAKP4response_t*)(new uint8_t[sizeof(
                ipmiRAKP4response_t)]);
        memset(response_data, 0, (sizeof(ipmiRAKP4response_t)));

        response_data->message_tag = request_data->message_tag;
        response_data->rmcp2_status_code = 0x0F;
        response_data->reserved1 = 0;
        response_data->remote_console_session_id = l_rcSessID;

        io_ipmiTransaction.iv_responsePayload = (uint8_t*)response_data;
        io_ipmiTransaction.iv_responsePayloadSize = sizeof(ipmiRAKP4response_t);

        //Send Response
        io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP4);

        //close the session
        IpmiSessionsManager::getInstance().stopSession(l_pSession->getBMCSessionID());
        l_zeroSess->getSessionState().setSessionState(
            IpmiSessionState::IPMI_SESSION_IS_INACTIVE);

        return;
    }

    uint8_t sik_buffer[256] = {};
    i = 0;
    l_temp = 16;
    l_sessKeys.getRcRandomNum(sik_buffer + i, l_temp);
    i += 16;

    l_sessKeys.getBmcRandomNum(sik_buffer + i, l_temp);
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
    l_sessKeys.setSIK(l_sik_hmacBuffer, l_sik_hmacBuflen);

    uint8_t inck_buffer[256] = {};
    i = 0;
    l_temp = 16;
    l_sessKeys.getRcRandomNum(inck_buffer + i, l_temp);
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

    ipmiRAKP4response_t* response_data = (ipmiRAKP4response_t*)(new uint8_t[(sizeof(
            ipmiRAKP4response_t)) + RAKP4_INK_LEN ]);
    memset(response_data, 0, ((sizeof(ipmiRAKP4response_t)) + RAKP4_INK_LEN));

    response_data->message_tag = request_data->message_tag;
    response_data->rmcp2_status_code = 0;
    response_data->reserved1 = 0;
    response_data->remote_console_session_id = l_rcSessID;
    memcpy(response_data + 1, inck_hmacBuffer, RAKP4_INK_LEN);

    // Let send the IPMI reponse data...
    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response_data;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(ipmiRAKP4response_t) +
            RAKP4_INK_LEN;

    l_pSession->getSessionState().setSessionState(
        IpmiSessionState::IPMI_SESSION_IS_ACTIVE);

    //Send Response
    io_ipmiTransaction.rawSend(IpmiMessageHandler::IPMI_RMCPP_RAKP4);

    l_zeroSess->getSessionState().setSessionState(
        IpmiSessionState::IPMI_SESSION_IS_INACTIVE);
    std::cout << "<< ipmi_RAKP34\n";
}

void ipmi_SetSessionPrivilegeLevel(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmi_SetSessionPrivilegeLevel\n";
    uint8_t l_requestedPrvLevel = *((uint8_t*)io_ipmiTransaction.iv_requestPayload);
    ipmiSetSessionPrivilegeLevel_t* response_data =
        (ipmiSetSessionPrivilegeLevel_t*) new uint8_t[sizeof(
                    ipmiSetSessionPrivilegeLevel_t)];
    memset((uint8_t*)response_data, 0, sizeof(ipmiSetSessionPrivilegeLevel_t));
    response_data->completion_code = IPMICC_NORMAL;

    if (0 == l_requestedPrvLevel)
    {
        response_data->new_Privilage_Level =
            io_ipmiTransaction.getSessionPrivilegeLevel();
    }
    else if ((1 == l_requestedPrvLevel) ||
             (l_requestedPrvLevel > ((uint8_t)(IPMI_SESSION_PRIVILEGE_OEM))))
    {
        response_data->completion_code = IPMICC_REQ_FIELD_INVALID;
    }
    else
    {
        if (l_requestedPrvLevel <= io_ipmiTransaction.getSessionMaxPrivilegeLevel())
        {
            io_ipmiTransaction.setSessionPrivilegeLevel(l_requestedPrvLevel);
            response_data->new_Privilage_Level = l_requestedPrvLevel;
        }
        else
        {
            response_data->completion_code = 0x81;
        }
    }

    io_ipmiTransaction.iv_responsePayload = (uint8_t*)response_data;
    io_ipmiTransaction.iv_responsePayloadSize = sizeof(
                ipmiSetSessionPrivilegeLevel_t);
    std::cout << "<< ipmi_SetSessionPrivilegeLevel\n";
}

void ipmiCloseSession(IpmiMessageHandler& io_ipmiTransaction)
{
    std::cout << ">> ipmiCloseSession\n";

    std::shared_ptr<IpmiSession> l_session;
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
            l_session = IpmiSessionsManager::getInstance().getSession(
                            io_ipmiTransaction.getSessionId());
        }
    }
    else
    {
        // Close session request not for the current session
        if (IpmiSessionState::IPMI_PRIVILEGE_ADMIN !=
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
                l_session = IpmiSessionsManager::getInstance().getSession(
                                l_reqPtr->sessionHandle,
                                IpmiSessionsManager::IPMI_SESSION_RETRIEVE_OPTION_SESSION_HANDLE);

                if (nullptr == l_session || (l_session->getBMCSessionID() == 0x00))
                {
                    l_pResponse->completionCode = 0x88;
                }
            }
            else
            {
                //Close requested using session ID
                l_session = IpmiSessionsManager::getInstance().getSession(l_sessionID,
                            IpmiSessionsManager::IPMI_SESSION_RETRIEVE_OPTION_BMC_SESSION_ID);

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
        IpmiSessionsManager::getInstance().stopSession(l_session->getBMCSessionID());
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

