#include "comm_module.hpp"

#include <host-ipmid/ipmid-api.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <systemd/sd-bus.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>

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
            {(static_cast<uint32_t>(message::PayloadType::OPEN_SESSION_REQUEST) << 16)},
            &openSession, session::Privilege::PRIVILEGE_HIGHEST_MATCHING,  true
        },
        {
            {(static_cast<uint32_t>(message::PayloadType::RAKP1) << 16)},
            &RAKP12, session::Privilege::PRIVILEGE_HIGHEST_MATCHING, true
        },
        {
            {(static_cast<uint32_t>(message::PayloadType::RAKP3) << 16)},
            &RAKP34, session::Privilege::PRIVILEGE_HIGHEST_MATCHING, true
        },
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x38
            },
            &GetChannelCapabilities, session::Privilege::PRIVILEGE_HIGHEST_MATCHING, true
        },
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
                static_cast<uint16_t>(command::NetFns::APP) | 0x3B
            },
            &setSessionPrivilegeLevel, session::Privilege::PRIVILEGE_USER, false
        },
        {
            {
                (static_cast<uint32_t>(message::PayloadType::IPMI) << 16) |
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

    std::vector<uint8_t> outPayload(sizeof(GetChannelCapabilitiesResp_t));
    auto response = reinterpret_cast<GetChannelCapabilitiesResp_t*>
                    (outPayload.data());

    // A canned response, since there is no user and channel management.
    response->completionCode = IPMI_CC_OK ;

    // Channel Number 1 is arbitarily applied to primary LAN channel;
    response->channelNumber = 1;

    response->ipmiVersion = 1 ;     //IPMI v2.0 extended capabilities available.
    response->reserved1 = 0;
    response->oem = 0;
    response->straightKey = 0;
    response->reserved2 = 0;
    response->md5 = 0;
    response->md2 = 0;


    response->reserved3 = 0;
    response->KGStatus = 0;         //KG is set to default
    response->perMessageAuth = 0;   //Per-message Authentication is enabled
    response->userAuth = 0;         //User Level Authentication is enabled
    response->nonNullUsers = 1;     //Non-null usernames enabled
    response->nullUsers = 1;        //Null usernames enabled
    response->anonymousLogin = 0;   //Anonymous Login disabled

    response->reserved4 = 0;
    response->extCapabilities = 0x2;    //Channel supports IPMI v2.0 connections

    response->oemID[0] = 0;
    response->oemID[1] = 0;
    response->oemID[2] = 0;
    response->oemAuxillary = 0;

    std::cout << "<< GetChannelCapabilities\n";
    return outPayload;
}

std::vector<uint8_t> openSession(std::vector<uint8_t>& inPayload,
                                 MessageHandler& handler)
{
    std::cout << ">> openSession\n";

    std::vector<uint8_t> outPayload(sizeof(OpenSessionResponse_t));
    auto request = reinterpret_cast<OpenSessionRequest_t*>(inPayload.data());
    auto response = reinterpret_cast<OpenSessionResponse_t*>(outPayload.data());

    // Start an IPMI session
    session::Session* session = std::get<session::Manager&>
                                (singletonPool).startSession(
                                    request->remoteConsoleSessionID,
                                    static_cast<session::Privilege>(request->maxPrivLevel),
                                    request->authAlgo,
                                    request->intAlgo,
                                    request->confAlgo);

    response->messageTag = request->messageTag;

    if (session)
    {
        response->status_code = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
        response->maxPrivLevel = static_cast<uint8_t>(session->getPrivilegeLevel());
        response->remoteConsoleSessionID = request->remoteConsoleSessionID;
        response->managedSystemSessionID = endian::to_ipmi<uint32_t>
                                           (session->getBMCSessionID());

        response->authPayload = request->authPayload ;
        response->authPayloadLen = request->authPayloadLen ;
        response->authAlgo = request->authAlgo;

        response->intPayload = request->intPayload ;
        response->intPayloadLen = request->intPayloadLen ;
        response->intAlgo = request->intAlgo;

        response->confPayload = request->confPayload ;
        response->confPayloadLen = request->confPayloadLen ;
        response->confAlgo = request->confAlgo;

        session->updateLastTransactionTime();

        // Session state is Setup in progress
        session->setSessionState(session::State::SETUP_IN_PROGRESS);

    }
    else
    {
        response->status_code = static_cast<uint8_t>
                                (RAKP_ReturnCode::INSUFFICIENT_RESOURCE);
        std::cerr <<
                  "openSession : Problem opening a session (slots full or bad state)\n";
    }

    std::cout << "<< openSession\n";
    return outPayload;
}

std::vector<uint8_t> RAKP12(std::vector<uint8_t>& inPayload,
                            MessageHandler& handler)
{
    std::cout << ">> RAKP12\n";

    auto request = reinterpret_cast<RAKP1request_t*>(inPayload.data());
    std::vector<uint8_t> outPayload;

    auto session = std::get<session::Manager&>(singletonPool).getSession(
                       request->managedSystemSessionID);

    std::cout << "RAKP12: BMC Session ID: " << std::hex << std::setfill('0') <<
              std::setw(8) << std::uppercase << endian::from_ipmi<uint32_t>
              (request->managedSystemSessionID) << "\n";

    // Stop command execution if Session is not found or Session ID is zero which is reserved
    if (session == nullptr ||
        request->managedSystemSessionID == session::SESSION_ZERO)
    {
        std::cerr << "RAKP12: BMC invalid Session ID\n";
        return outPayload;
    }

    // Update transaction time
    session->updateLastTransactionTime();

    auto rcSessionID = endian::to_ipmi<uint32_t>(session->getRCSessionID());
    auto bmcSessionID = endian::to_ipmi<uint32_t>(session->getBMCSessionID());

    fprintf(stderr, "\nRAKP12 0x%X\n", rcSessionID);
    fprintf(stderr, "\nRAKP12 0x%X\n", bmcSessionID);

    auto authAlgo = session->getAuthAlgo();

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

    std::copy_n(input.data() + inSize, cipher::auth::BMC_RANDOM_NUMBER_LEN,
                bmcRandomNum.begin());
    inSize += cipher::auth::BMC_RANDOM_NUMBER_LEN;

    // Managed System GUID
    getSystemGUID(input.data() + inSize, BMC_GUID_LEN);
    inSize += BMC_GUID_LEN;

    // Requested Privilege Level
    session->setPrivilegeLevel(static_cast<session::Privilege>
                               (request->req_max_privilege_level));
    std::copy_n(&(request->req_max_privilege_level),
                sizeof(request->req_max_privilege_level), input.data() + inSize);
    inSize += sizeof(request->req_max_privilege_level);

    // Set Max Privilege to ADMIN
    session->setMaxPrivilegeLevel(session::Privilege::PRIVILEGE_ADMIN);

    // User Name Length Byte
    std::copy_n(&(request->user_name_len), sizeof(request->user_name_len),
                input.data() + inSize);

    // User Key - Hardcoded to PASSW0RD
    uint8_t l_userKey[cipher::auth::USER_KEY_MAX_LENGTH] = {'P', 'A', 'S', 'S', 'W', '0', 'R', 'D'};
    auto& userKey = authAlgo->getUserKey();
    std::copy_n(l_userKey, cipher::auth::USER_KEY_MAX_LENGTH, userKey.begin());

    // Generate Key Exchange Authentication Code - RAKP2
    auto output = authAlgo->generateHMAC(input);

    outPayload.resize(sizeof(RAKP2response_t));
    auto response = reinterpret_cast<RAKP2response_t*>(outPayload.data());

    response->messageTag = request->messageTag;
    response->rmcpStatusCode = 0;
    response->reserved = 0;
    response->remoteConsoleSessionID = rcSessionID ;

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
    outPayload.resize(sizeof(RAKP4response_t));
    auto request = reinterpret_cast<RAKP3request_t*>(inPayload.data());
    auto response = reinterpret_cast<RAKP4response_t*>(outPayload.data());

    auto session = std::get<session::Manager&>(singletonPool).getSession(le32toh(
                       request->managedSystemSessionID));

    // Session ID is zero is reserved for session setup, don't proceed
    // or if the session requested is not found
    if (session == nullptr ||
        request->managedSystemSessionID == session::SESSION_ZERO)
    {
        return outPayload;
    }
    session->updateLastTransactionTime();

    auto authAlgo = session->getAuthAlgo();
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
    auto rcSessionID = endian::to_ipmi<uint32_t>(session->getRCSessionID());

    // Session Privilege Level
    auto sessPrivLevel = static_cast<uint8_t>(session->getPrivilegeLevel());

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

    if (std::memcmp(output.data(), request->keyExchangeAuthCode , output.size()))
    {
        std::cerr << "mismatch in HMAC sent by remote console\n";

        response->messageTag = request->messageTag;
        response->rmcpStatusCode = 0x0F;
        response->reserved = 0;
        response->remoteConsoleSessionID = rcSessionID;

        //close the session
        std::get<session::Manager&>(singletonPool).stopSession(
            session->getBMCSessionID());

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
    auto bmcSessionID = endian::to_ipmi<uint32_t>(session->getBMCSessionID());

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


    outPayload.resize(sizeof(RAKP4response_t));

    response->messageTag = request->messageTag;
    response->rmcpStatusCode = 0;
    response->reserved = 0;
    response->remoteConsoleSessionID = rcSessionID;

    // Insert the HMAC output into the payload
    outPayload.insert(outPayload.end(), icv.begin(), icv.end());


    session->setSessionState(session::State::ACTIVE);

    std::cout << "<< RAKP34\n";
    return outPayload;
}
std::vector<uint8_t> setSessionPrivilegeLevel(std::vector<uint8_t>& inPayload,
        MessageHandler& handler)
{
    std::cout << ">> setSessionPrivilegeLevel\n";

    std::vector<uint8_t> outPayload(sizeof(SetSessionPrivilegeLevel_t));
    auto response = reinterpret_cast<SetSessionPrivilegeLevel_t*>
                    (outPayload.data());
    response->completionCode = IPMI_CC_OK;
    uint8_t reqPrivilegeLevel = *((uint8_t*)inPayload.data());

    auto session = std::get<session::Manager&>(singletonPool).getSession(
                       handler.getSessionID());

    if (reqPrivilegeLevel == 0) // Just return present privilege level
    {
        response->newPrivLevel = static_cast<uint8_t>(session->getPrivilegeLevel());
    }
    else if (reqPrivilegeLevel <= static_cast<uint8_t>
             (session->getMaxPrivilegeLevel()))
    {
        session->setPrivilegeLevel(static_cast<session::Privilege>(reqPrivilegeLevel));
        response->newPrivLevel = reqPrivilegeLevel;
    }
    else
    {
        // Requested level exceeds Channel and/or User Privilege Limit
        response->completionCode = IPMI_CC_EXCEEDS_USER_PRIV;
    }

    std::cout << "<< setSessionPrivilegeLevel\n";
    return outPayload;
}

std::vector<uint8_t> closeSession(std::vector<uint8_t>& inPayload,
                                  MessageHandler& handler)
{
    std::cout << ">> closeSession\n";

    std::vector<uint8_t> outPayload(sizeof(CloseSessionResponse));
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

