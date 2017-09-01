#include "rakp34.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>

#include "comm_module.hpp"
#include "endian.hpp"
#include "guid.hpp"
#include "main.hpp"

namespace command
{

void applyIntegrityAlgo(const uint32_t bmcSessionID)
{
    auto session = (std::get<session::Manager&>(singletonPool).getSession(
            bmcSessionID)).lock();

    auto authAlgo = session->getAuthAlgo();

    switch (authAlgo->intAlgo)
    {
        case cipher::integrity::Algorithms::HMAC_SHA1_96:
        {
            session->setIntegrityAlgo(
                    std::make_unique<cipher::integrity::AlgoSHA1>(
                        authAlgo->sessionIntegrityKey));
            break;
        }
        default:
            break;
    }
}

void applyCryptAlgo(const uint32_t bmcSessionID)
{
    auto session = (std::get<session::Manager&>(singletonPool).getSession(
            bmcSessionID)).lock();

    auto authAlgo = session->getAuthAlgo();

    switch (authAlgo->cryptAlgo)
    {
        case cipher::crypt::Algorithms::AES_CBC_128:
        {
            session->setCryptAlgo(std::make_unique<cipher::crypt::AlgoAES128>(
                                 authAlgo->sessionIntegrityKey));
            break;
        }
        default:
            break;
    }
}

std::vector<uint8_t> RAKP34(const std::vector<uint8_t>& inPayload,
                            const message::Handler& handler)
{
    std::cout << ">> RAKP34\n";

    std::vector<uint8_t> outPayload(sizeof(RAKP4response));
    auto request = reinterpret_cast<const RAKP3request*>(inPayload.data());
    auto response = reinterpret_cast<RAKP4response*>(outPayload.data());

    // Check if the RAKP3 Payload Length is as expected
    if(inPayload.size() != sizeof(RAKP3request))
    {
        std::cerr << "RAKP34: Invalid RAKP3 request\n";
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_INTEGRITY_VALUE);
        return outPayload;
    }

    // Session ID zero is reserved for Session Setup
    if(endian::from_ipmi(request->managedSystemSessionID) ==
                         session::SESSION_ZERO)
    {
        std::cerr << "RAKP34: BMC invalid Session ID\n";
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_SESSION_ID);
        return outPayload;
    }

    std::shared_ptr<session::Session> session;
    try
    {
        session = (std::get<session::Manager&>(singletonPool).getSession(
            endian::from_ipmi(request->managedSystemSessionID))).lock();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n";
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_SESSION_ID);
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

    // Remote Console Session ID
    auto rcSessionID = endian::to_ipmi(session->getRCSessionID());

    // Session Privilege Level
    auto sessPrivLevel = static_cast<uint8_t>(session->curPrivLevel);

    // User Name Length Byte
    uint8_t userLength = 0;

    std::vector<uint8_t> input;
    input.resize(cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN +
                 sizeof(rcSessionID) + sizeof(sessPrivLevel) +
                 sizeof(userLength));

    auto iter = input.begin();

    // Managed System Random Number
    std::copy(authAlgo->bmcRandomNum.begin(), authAlgo->bmcRandomNum.end(),
              iter);
    std::advance(iter, cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN);

    // Remote Console Session ID
    std::copy_n(reinterpret_cast<uint8_t*>(&rcSessionID), sizeof(rcSessionID),
                iter);
    std::advance(iter, sizeof(rcSessionID));

    // Session Privilege Level
    std::copy_n(reinterpret_cast<uint8_t*>(&sessPrivLevel),
                sizeof(sessPrivLevel), iter);
    std::advance(iter, sizeof(sessPrivLevel));

    // User Name Length Byte
    std::copy_n(&userLength, sizeof(userLength), iter);

    // Generate Key Exchange Authentication Code - RAKP2
    auto output = authAlgo->generateHMAC(input);

    if (std::memcmp(output.data(), request->keyExchangeAuthCode,
                    output.size()))
    {
        std::cerr << "Mismatch in HMAC sent by remote console\n";

        response->messageTag = request->messageTag;
        response->rmcpStatusCode = static_cast<uint8_t>
                                   (RAKP_ReturnCode::INVALID_INTEGRITY_VALUE);
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

    input.clear();

    input.resize(cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN +
                 cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN +
                 sizeof(sessPrivLevel) + sizeof(userLength));
    iter = input.begin();

    // Remote Console Random Number
    std::copy(authAlgo->rcRandomNum.begin(), authAlgo->rcRandomNum.end(),
              iter);
    std::advance(iter, cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN);

    // Managed Console Random Number
    std::copy(authAlgo->bmcRandomNum.begin(), authAlgo->bmcRandomNum.end(),
              iter);
    std::advance(iter, cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN);

    // Session Privilege Level
    std::copy_n(reinterpret_cast<uint8_t*>(&sessPrivLevel),
                sizeof(sessPrivLevel), iter);
    std::advance(iter, sizeof(sessPrivLevel));

    // User Name Length Byte
    std::copy_n(&userLength, sizeof(userLength), iter);

    // Generate Session Integrity Key
    auto sikOutput = authAlgo->generateHMAC(input);

    // Update the SIK in the Authentication Algo Interface
    authAlgo->sessionIntegrityKey.insert(authAlgo->sessionIntegrityKey.begin(),
                                         sikOutput.begin(), sikOutput.end());

    /*
     * Integrity Check Value
     *
     * 1) Remote Console Random Number - 16 bytes
     * 2) Managed System Session ID - 4 bytes
     * 3) Managed System GUID - 16 bytes
     */

    // Get Managed System Session ID
    auto bmcSessionID = endian::to_ipmi(session->getBMCSessionID());

    input.clear();

    input.resize(cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN +
                 sizeof(bmcSessionID) + BMC_GUID_LEN);
    iter = input.begin();

    // Remote Console Random Number
    std::copy(authAlgo->rcRandomNum.begin(), authAlgo->rcRandomNum.end(),
              iter);
    std::advance(iter, cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN);

    // Managed System Session ID
    std::copy_n(reinterpret_cast<uint8_t*>(&bmcSessionID), sizeof(bmcSessionID),
                iter);
    std::advance(iter, sizeof(bmcSessionID));

    // Managed System GUID
    std::copy_n(cache::guid.data(), cache::guid.size(), iter);

    // Integrity Check Value
    auto icv = authAlgo->generateICV(input);

    outPayload.resize(sizeof(RAKP4response));

    response->messageTag = request->messageTag;
    response->rmcpStatusCode = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
    response->reserved = 0;
    response->remoteConsoleSessionID = rcSessionID;

    // Insert the HMAC output into the payload
    outPayload.insert(outPayload.end(), icv.begin(), icv.end());

    // Set the Integrity Algorithm
    applyIntegrityAlgo(session->getBMCSessionID());

    // Set the Confidentiality Algorithm
    applyCryptAlgo(session->getBMCSessionID());

    session->state = session::State::ACTIVE;

    std::cout << "<< RAKP34\n";
    return outPayload;
}

} // namespace command
