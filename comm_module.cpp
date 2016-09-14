#include "comm_module.hpp"

#include <systemd/sd-bus.h>
#include <iostream>
#include <host-ipmid/ipmid-api.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>

#include <cstring>
#include <algorithm>


#include "command_table.hpp"
#include "endian.hpp"
#include "main.hpp"
#include "sessions_manager.hpp"
#include "session.hpp"

constexpr size_t BMC_GUID_LEN = 16;

void sessionSetupCommands()
{
    command::CmdDetails commands[] =
    {
        {
            {(static_cast<uint32_t>(Message::PayloadType::OPEN_SESS_REQUEST) << 16)},
            &openSession, session::Privilege::PRIVILEGE_HIGHEST_MATCHING,  true
        },
        {
            {(static_cast<uint32_t>(Message::PayloadType::RAKP1) << 16)},
            &RAKP12, session::Privilege::PRIVILEGE_HIGHEST_MATCHING, true
        },
        {
            {(static_cast<uint32_t>(Message::PayloadType::RAKP3) << 16)},
            &RAKP34, session::Privilege::PRIVILEGE_HIGHEST_MATCHING, true
        },
        {
            {
                (static_cast<uint32_t>(Message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x38
            },
            &GetChannelCapabilities, session::Privilege::PRIVILEGE_HIGHEST_MATCHING, true
        },
        {
            {
                (static_cast<uint32_t>(Message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x3B
            },
            &setSessionPrivilegeLevel, session::Privilege::PRIVILEGE_USER, false
        },
        {
            {
                (static_cast<uint32_t>(Message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x3C
            },
            &closeSession, session::Privilege::PRIVILEGE_CALLBACK, false
        },
    };

    auto count = sizeof(commands) / sizeof(command::CmdDetails);


    for (size_t iter = 0; iter < count ; ++iter)
    {
        std::get<command::Table&>(singletonPool).registerCommand(
            commands[iter].command.cmdCode,
            std::make_unique<command::NetIpmidEntry>
            (commands[iter].command, commands[iter].functor,
             commands[iter].privilege, commands[iter].sessionless));
    }
}

std::vector<uint8_t> GetChannelCapabilities(std::vector<uint8_t>& inPayload,
        MessageHandler& handler)
{
    std::cout << ">> GetChannelCapabilities\n";

    std::vector<uint8_t> outPayload;
    outPayload.resize(sizeof(GetChannelCapabilities_t));
    auto response = reinterpret_cast<GetChannelCapabilities_t*>(outPayload.data());

    uint8_t req_Channel_num = *((uint8_t*)inPayload.data());
    uint8_t req_max_privilage_level = *(((uint8_t*)inPayload.data()) + 1);

    // Mask the byte to get the channel number. only last 4 bits contain the stuff.
    req_Channel_num = req_Channel_num & 15 ;

    // Mask the byte to get actual Requested maximum privilege level. only last 4 bits contain the stuff.
    req_max_privilage_level = req_max_privilage_level & 15 ;

    response->completionCode = IPMI_CC_OK ;
    response->channelNumber = 1;//(uint8_t)l_channelNumber;
    response->ipmi_ver = 1 ; //IPMI v2.0 extended capabilities available.
    response->reserved1 = 0;
    response->oem_proprietary = 0;
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

    std::cout << "<< GetChannelCapabilities\n";
    return outPayload;
}

std::vector<uint8_t> openSession(std::vector<uint8_t>& inPayload,
                                 MessageHandler& handler)
{
    std::cout << ">> openSession\n";

    std::vector<uint8_t> outPayload;
    outPayload.resize(sizeof(ipmiOpenSessionResponse_t));
    auto request = reinterpret_cast<OpenSessionRequest_t*>(inPayload.data());
    auto response = reinterpret_cast<ipmiOpenSessionResponse_t*>(outPayload.data());

    // Start an IPMI session
    session::Session* l_pSession = std::get<session::Manager&>
                                   (singletonPool).startSession(
                                       request->remote_console_session_id,
                                       static_cast<session::Privilege>(request->req_max_privilage_level),
                                       request->auth_algo,
                                       request->int_algo,
                                       request->conf_algo);

    response->message_tag = request->message_tag;

    if (l_pSession)
    {
        response->status_code = 0;
        response->max_priv_reserved1 =  0;
        response->req_max_privilage_level = static_cast<uint8_t>
                                            (l_pSession->getPrivilegeLevel());
        response->reserved2 = 0;
        response->remote_console_session_id = request->remote_console_session_id ;
        response->managed_system_session_id = endian::to_ipmi<uint32_t>
                                              (l_pSession->getBMCSessionID());

        response->auth_payload_pt = request->auth_payload_pt ;
        response->auth_payload_length = request->auth_payload_length ;
        response->auth_algo = request->auth_algo;
        response->int_payload_pt = request->int_payload_pt ;
        response->int_payload_length = request->int_payload_length ;
        response->int_algo = request->int_algo;
        response->conf_payload_pt = request->conf_payload_pt ;
        response->conf_payload_length = request->conf_payload_length ;
        response->conf_algo = request->conf_algo;

        l_pSession->updateLastTransactionTime();
        l_pSession->setSessionState(session::State::SETUP_IN_PROGRESS);

    }
    else
    {
        response->status_code = 0x01;
        std::cerr <<
                  "openSession : Problem opening a session (slots full or bad machine state)\n";
    }

    std::cout << "<< openSession\n";
    return outPayload;
}

std::vector<uint8_t> RAKP12(std::vector<uint8_t>& inPayload,
                            MessageHandler& handler)
{
    std::cout << ">> RAKP12\n";

    auto request = reinterpret_cast<ipmiRAKP1request_t*>(inPayload.data());
    std::vector<uint8_t> outPayload;

    auto l_pSession = std::get<session::Manager&>(singletonPool).getSession(
                          request->managed_system_session_id);
    fprintf(stderr, "\nRAKP12 0x%X\n", le32toh(request->managed_system_session_id));

    // Session ID is zero is reserved for session setup, don't proceed
    // or if the session requested is not found
    if (l_pSession == nullptr || request->managed_system_session_id == 0)
    {
        fprintf(stderr, "\nRAKP12 got bad session ID 0x%X\n",
                le32toh(request->managed_system_session_id));
        return outPayload;  //@TODO: Need to return RMCP+ Status codes?
    }

    // Update transaction time
    l_pSession->updateLastTransactionTime();

    auto rcSessionID = endian::to_ipmi<uint32_t>(l_pSession->getRCSessionID());
    auto bmcSessionID = endian::to_ipmi<uint32_t>(l_pSession->getBMCSessionID());

    fprintf(stderr, "\nRAKP12 0x%X\n", rcSessionID);
    fprintf(stderr, "\nRAKP12 0x%X\n", bmcSessionID);

    auto authAlgo = l_pSession->getAuthAlgo();

    /*
     * Generate Key Authentication Code - RAKP 2
     *
     * 1) Remote Console Session ID - 4 bytes
     * 2) Managed System Session ID - 4 bytes
     * 3) Remote Console Random Number - 16 bytes
     * 4) Managed System Random Number - 16 bytes
     * 5) Managed System GUID - 16 bytes
     * 6) Requested Privilege Level - 1 byte
     * 7) User Name Length Byte - 1 byte (0 for 'null' username)
     * 8) User Name - variable (absent for 'null' username)
     */

    std::vector<uint8_t> input;
    input.resize(sizeof(rcSessionID) + sizeof(bmcSessionID) +
                 cipher::auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN +
                 cipher::auth::BMC_RANDOM_NUMBER_LEN +
                 BMC_GUID_LEN + sizeof(request->req_max_privilege_level) +
                 sizeof(request->user_name_len));

    // Remote Console Session ID
    std::copy_n((uint8_t*)(&rcSessionID), sizeof(rcSessionID), input.data());
    auto inSize = sizeof(rcSessionID);

    // Managed System Session ID
    std::copy_n((uint8_t*)(&bmcSessionID), sizeof(bmcSessionID),
                input.data() + inSize);
    inSize += sizeof(bmcSessionID);

    // Remote Console Random Number
    auto& rcRandomNum = authAlgo->getRCRandomNum();

    std::copy_n((uint8_t*)request->remote_console_random_number,
                cipher::auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN,
                rcRandomNum.begin());

    std::copy(rcRandomNum.begin(), rcRandomNum.end(), input.data() + inSize);
    inSize += cipher::auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN;


    // Managed System Random Number
    auto& bmcRandomNum = authAlgo->getBMCRandomNum();

    RAND_bytes(input.data() + inSize, cipher::auth::BMC_RANDOM_NUMBER_LEN);

    std::copy(input.data() + inSize,
              input.data() + inSize + cipher::auth::BMC_RANDOM_NUMBER_LEN,
              bmcRandomNum.begin());
    inSize += cipher::auth::BMC_RANDOM_NUMBER_LEN;

    // Managed System GUID
    getSystemGUID(input.data() + inSize, BMC_GUID_LEN);
    inSize += BMC_GUID_LEN;

    // Requested Privilege Level
    l_pSession->setPrivilegeLevel(static_cast<session::Privilege>
                                  (request->req_max_privilege_level));
    std::copy_n(&(request->req_max_privilege_level),
                sizeof(request->req_max_privilege_level), input.data() + inSize);
    inSize += sizeof(request->req_max_privilege_level);

    // Set Max Privilege to ADMIN
    l_pSession->setMaxPrivilegeLevel(session::Privilege::PRIVILEGE_ADMIN);

    // User Name Length Byte
    std::copy_n(&(request->user_name_len), sizeof(request->user_name_len),
                input.data() + inSize);

    // User Key - Hardcoded to PASSW0RD
    uint8_t l_userKey[cipher::auth::USER_KEY_MAX_LENGTH] = {'P', 'A', 'S', 'S', 'W', '0', 'R', 'D'};
    auto& userKey = authAlgo->getUserKey();
    std::copy(l_userKey, l_userKey + cipher::auth::USER_KEY_MAX_LENGTH,
              userKey.begin());

    // Generate Key Exchange Authentication Code - RAKP2
    auto output = authAlgo->generateHMAC(input);

    outPayload.resize(sizeof(ipmiRAKP2response_t));
    auto response = reinterpret_cast<ipmiRAKP2response_t*>(outPayload.data());

    response->message_tag = request->message_tag;
    response->rmcp2_status_code = 0;
    response->reserved1 = 0;
    response->remote_console_session_id = rcSessionID ;

    // Copy Managed System Random Number to the Response
    std::copy(bmcRandomNum.begin(), bmcRandomNum.end(),
              response->managed_system_random_number);

    // Copy System GUID to the Response
    getSystemGUID(response->managed_system_guid,
                  sizeof(response->managed_system_guid));

    // Insert the HMAC output into the payload
    outPayload.insert(outPayload.end(), output.begin(), output.end());

    std::cout << "<< RAKP12\n";
    return outPayload;
}

std::vector<uint8_t> RAKP34(std::vector<uint8_t>& inPayload,
                            MessageHandler& handler)
{
    std::cout << ">> RAKP34\n";

    std::vector<uint8_t> outPayload;
    outPayload.resize(sizeof(ipmiRAKP4response_t));
    auto request = reinterpret_cast<ipmiRAKP3request_t*>(inPayload.data());
    auto response = reinterpret_cast<ipmiRAKP4response_t*>(outPayload.data());

    auto l_pSession = std::get<session::Manager&>(singletonPool).getSession(le32toh(
                          request->managed_system_session_id));

    // Session ID is zero is reserved for session setup, don't proceed
    // or if the session requested is not found
    if (l_pSession == nullptr || request->managed_system_session_id == 0)
    {
        return outPayload; //@TODO: Need to return RMCP+ Status codes?
    }
    l_pSession->updateLastTransactionTime();

    auto authAlgo = l_pSession->getAuthAlgo();
    /*
     * Key Authentication Code - RAKP 3
     *
     * 1) Managed System Random Number - 16 bytes
     * 2) Remote Console Session ID - 4 bytes
     * 3) Session Privilege Level - 1 byte
     * 4) User Name Length Byte - 1 byte (0 for 'null' username)
     * 5) User Name - variable (absent for 'null' username)
     */

    // Managed System Random Number
    auto& bmcRandomNum = authAlgo->getBMCRandomNum();

    // Remote Console Session ID
    auto rcSessionID = endian::to_ipmi<uint32_t>(l_pSession->getRCSessionID());

    // Session Privilege Level
    auto sessPrivLevel = static_cast<uint8_t>(l_pSession->getPrivilegeLevel());

    // User Name Length Byte
    uint8_t userLength = 0;

    std::vector<uint8_t> input;
    input.resize(cipher::auth::BMC_RANDOM_NUMBER_LEN +
                 sizeof(rcSessionID) + sizeof(sessPrivLevel) + sizeof(userLength));

    // Managed System Random Number
    std::copy(bmcRandomNum.begin(), bmcRandomNum.end(), input.data());
    auto inSize = cipher::auth::BMC_RANDOM_NUMBER_LEN;

    // Remote Console Session ID
    std::copy_n((uint8_t*)(&rcSessionID), sizeof(rcSessionID),
                input.data() + inSize);
    inSize += sizeof(rcSessionID);

    // Session Privilege Level
    std::copy_n((uint8_t*)(&sessPrivLevel), sizeof(sessPrivLevel),
                input.data() + inSize);
    inSize += sizeof(sessPrivLevel);

    // User Name Length Byte
    std::copy_n(&userLength, sizeof(userLength), input.data() + inSize);

    // Generate Key Exchange Authentication Code - RAKP2
    auto output = authAlgo->generateHMAC(input);

    if (std::memcmp(output.data(), request->Key_Exch_Auth_Code , output.size()))
    {
        std::cerr << "mismatch in HMAC sent by remote console\n";

        response->message_tag = request->message_tag;
        response->rmcp2_status_code = 0x0F;
        response->reserved1 = 0;
        response->remote_console_session_id = rcSessionID;

        //close the session
        std::get<session::Manager&>(singletonPool).stopSession(
            l_pSession->getBMCSessionID());

        return outPayload;
    }

    /*
     * Session Integrity Key
     *
     * 1) Remote Console Random Number - 16 bytes
     * 2) Managed System Random Number - 16 bytes
     * 3) Session Privilege Level - 1 byte
     * 4) User Name Length Byte - 1 byte (0 for 'null' username)
     * 5) User Name - variable (absent for 'null' username)
     */

    input.resize(0);
    inSize = 0;

    input.resize(cipher::auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN +
                 cipher::auth::BMC_RANDOM_NUMBER_LEN +
                 sizeof(sessPrivLevel) + sizeof(userLength));

    // Remote Console Random Number
    auto& rcRandomNum = authAlgo->getRCRandomNum();
    std::copy(rcRandomNum.begin(), rcRandomNum.end(), input.data());
    inSize += cipher::auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN;

    // Managed Console Random Number
    std::copy(bmcRandomNum.begin(), bmcRandomNum.end(), input.data() + inSize);
    inSize += cipher::auth::BMC_RANDOM_NUMBER_LEN;

    // Session Privilege Level
    std::copy_n((uint8_t*)(&sessPrivLevel), sizeof(sessPrivLevel),
                input.data() + inSize);
    inSize += sizeof(sessPrivLevel);

    // User Name Length Byte
    std::copy_n(&userLength, sizeof(userLength), input.data() + inSize);

    // Generate Session Integrity Key
    auto sikOutput = authAlgo->generateHMAC(input);

    // Update the SIK in the Authentication Algo Interface
    auto& sik = authAlgo->getSIK();
    sik.insert(sik.begin(), sikOutput.begin(), sikOutput.end());

    /*
     * Integrity Check Value
     *
     * 1) Remote Console Random Number - 16 bytes
     * 2) Managed System Session ID - 4 bytes
     * 3) Managed System GUID - 16 bytes
     */

    // Get Managed System Session ID
    auto bmcSessionID = endian::to_ipmi<uint32_t>(l_pSession->getBMCSessionID());

    input.resize(0);
    inSize = 0;

    input.resize(cipher::auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN +
                 sizeof(bmcSessionID) + BMC_GUID_LEN);

    // Remote Console Random Number
    std::copy(rcRandomNum.begin(), rcRandomNum.end(), input.data());
    inSize += cipher::auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN;

    // Managed System Session ID
    std::copy_n((uint8_t*)(&bmcSessionID), sizeof(bmcSessionID),
                input.data() + inSize);
    inSize += sizeof(bmcSessionID);

    // Managed System GUID
    getSystemGUID(input.data() + inSize, BMC_GUID_LEN);

    // Integrity Check Value
    auto icv = authAlgo->generateICV(input);


    outPayload.resize(sizeof(ipmiRAKP4response_t));

    response->message_tag = request->message_tag;
    response->rmcp2_status_code = 0;
    response->reserved1 = 0;
    response->remote_console_session_id = rcSessionID;

    // Insert the HMAC output into the payload
    outPayload.insert(outPayload.end(), icv.begin(), icv.end());


    l_pSession->setSessionState(session::State::ACTIVE);

    std::cout << "<< RAKP34\n";
    return outPayload;
}
std::vector<uint8_t> setSessionPrivilegeLevel(std::vector<uint8_t>& inPayload,
        MessageHandler& handler)
{
    std::cout << ">> setSessionPrivilegeLevel\n";

    std::vector<uint8_t> outPayload;
    outPayload.resize(sizeof(ipmiSetSessionPrivilegeLevel_t));
    auto response = reinterpret_cast<ipmiSetSessionPrivilegeLevel_t*>
                    (outPayload.data());
    response->completionCode = IPMI_CC_OK ;
    uint8_t reqPrivilegeLevel = *((uint8_t*)inPayload.data());

    auto session = std::get<session::Manager&>(singletonPool).getSession(
                       handler.getSessionID());

    if (reqPrivilegeLevel = 0)
    {
        response->newPrivLevel = static_cast<uint8_t>(session->getPrivilegeLevel());
    }
    else if (reqPrivilegeLevel <= static_cast<uint8_t>(session->getMaxPrivilegeLevel()))
    {
        session->setPrivilegeLevel(static_cast<session::Privilege>(reqPrivilegeLevel));
        response->newPrivLevel = reqPrivilegeLevel;
    }

    std::cout << "<< setSessionPrivilegeLevel\n";
    return outPayload;
}

std::vector<uint8_t> closeSession(std::vector<uint8_t>& inPayload,
                                  MessageHandler& handler)
{
    std::cout << ">> closeSession\n";

    std::vector<uint8_t> outPayload;
    outPayload.resize(sizeof(CloseSessionResponse));
    auto request = reinterpret_cast<CloseSessionRequest*>(inPayload.data());
    auto response = reinterpret_cast<CloseSessionResponse*>(outPayload.data());
    response->completionCode = IPMI_CC_OK ;

    auto bmcSessionID = endian::from_ipmi<uint32_t>(request->sessionID);

    // Session 0 is the not closed
    if (bmcSessionID == session::SESSION_ZERO)
    {
        response->completionCode = IPMI_CC_INVALID_SESSIONID;
    }
    else
    {
        auto session = std::get<session::Manager&>(singletonPool).getSession(
                           bmcSessionID);

        // Valid Session ID
        if (nullptr != session)
        {
            std::get<session::Manager&>(singletonPool).stopSession(
                session->getBMCSessionID());
        }
        else
        {
            response->completionCode = IPMI_CC_INVALID_SESSIONID;
        }
    }

    std::cout << "<< closeSession\n";
    return outPayload;
}

void getSystemGUID(uint8_t* i_buffer, uint32_t io_numBytes)
{
    uint8_t l_managedSystemGUID[BMC_GUID_LEN] = { 0x53, 0x61, 0x6E, 0x74,
                                                  0x6F, 0x73, 0x68, 0x20,
                                                  0x44, 0x65, 0x76, 0x61,
                                                  0x6C, 0x65, 0x20, 0x00
                                                };

    uint32_t l_len = (io_numBytes > sizeof(l_managedSystemGUID)) ?
                     sizeof(l_managedSystemGUID)
                     : io_numBytes;
    memcpy(i_buffer, l_managedSystemGUID, l_len);
}

