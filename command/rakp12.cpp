#include "rakp12.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <iomanip>
#include <iostream>

#include "comm_module.hpp"
#include "endian.hpp"
#include "guid.hpp"
#include "main.hpp"

namespace command
{

std::vector<uint8_t> RAKP12(std::vector<uint8_t>& inPayload,
                            const message::Handler& handler)
{
    std::cout << ">> RAKP12\n";

    std::vector<uint8_t> outPayload(sizeof(RAKP2response_t));
    auto request = reinterpret_cast<RAKP1request_t*>(inPayload.data());
    auto response = reinterpret_cast<RAKP2response_t*>(outPayload.data());

    auto session = (std::get<session::Manager&>(singletonPool).getSession(
            endian::from_ipmi<uint32_t>
            (request->managedSystemSessionID))).lock();

    std::cout << "RAKP12: BMC Session ID: " << std::hex << std::setfill('0') <<
              std::setw(8) << std::uppercase << endian::from_ipmi<uint32_t>
              (request->managedSystemSessionID) << "\n";

    // Stop command execution if Session is not found or Session ID is zero
    // which is reserved
    if (session == nullptr ||
        request->managedSystemSessionID == session::SESSION_ZERO)
    {
        std::cerr << "RAKP12: BMC invalid Session ID\n";
        response->rmcpStatusCode =
            static_cast<uint8_t>(RAKP_ReturnCode::INVALID_SESSION_ID);
        return outPayload;
    }

    // Update transaction time
    session->updateLastTransactionTime();

    auto rcSessionID = endian::to_ipmi<uint32_t>(session->getRCSessionID());
    auto bmcSessionID = endian::to_ipmi<uint32_t>(session->getBMCSessionID());
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
                 cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN +
                 cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN +
                 BMC_GUID_LEN + sizeof(request->req_max_privilege_level) +
                 sizeof(request->user_name_len));

    // Remote Console Session ID
    std::copy_n((uint8_t*)(&rcSessionID), sizeof(rcSessionID), input.data());
    auto inSize = sizeof(rcSessionID);

    // Managed System Session ID
    std::copy_n((uint8_t*)(&bmcSessionID), sizeof(bmcSessionID),
                input.data() + inSize);
    inSize += sizeof(bmcSessionID);

    // Copy the Remote Console Random Number from the RAKP1 request to the
    // Authentication Algorithm
    std::copy_n((uint8_t*)request->remote_console_random_number,
                cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN,
                authAlgo->rcRandomNum.begin());

    std::copy(authAlgo->rcRandomNum.begin(), authAlgo->rcRandomNum.end(),
              input.data() + inSize);
    inSize += cipher::rakp_auth::REMOTE_CONSOLE_RANDOM_NUMBER_LEN;

    // Generate the Managed System Random Number
    RAND_bytes(input.data() + inSize, cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN);

    // Copy the Managed System Random Number to the Authentication Algorithm
    std::copy_n(input.data() + inSize, cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN,
                authAlgo->bmcRandomNum.begin());
    inSize += cipher::rakp_auth::BMC_RANDOM_NUMBER_LEN;

    // Managed System GUID
    getSystemGUID(input.data() + inSize, BMC_GUID_LEN);
    inSize += BMC_GUID_LEN;

    // Requested Privilege Level
    session->curPrivLevel = static_cast<session::Privilege>
                            (request->req_max_privilege_level);
    std::copy_n(&(request->req_max_privilege_level),
                sizeof(request->req_max_privilege_level), input.data() +
                inSize);
    inSize += sizeof(request->req_max_privilege_level);

    // Set Max Privilege to ADMIN
    session->maxPrivLevel = session::Privilege::ADMIN;

    // User Name Length Byte
    std::copy_n(&(request->user_name_len), sizeof(request->user_name_len),
                input.data() + inSize);

    // Generate Key Exchange Authentication Code - RAKP2
    auto output = authAlgo->generateHMAC(input);

    response->messageTag = request->messageTag;
    response->rmcpStatusCode = static_cast<uint8_t>(RAKP_ReturnCode::NO_ERROR);
    response->reserved = 0;
    response->remoteConsoleSessionID = rcSessionID ;

    // Copy Managed System Random Number to the Response
    std::copy(authAlgo->bmcRandomNum.begin(), authAlgo->bmcRandomNum.end(),
              response->managed_system_random_number);

    // Copy System GUID to the Response
    getSystemGUID(response->managed_system_guid,
                  sizeof(response->managed_system_guid));

    // Insert the HMAC output into the payload
    outPayload.insert(outPayload.end(), output.begin(), output.end());

    std::cout << "<< RAKP12\n";
    return outPayload;
}

} // namespace command
