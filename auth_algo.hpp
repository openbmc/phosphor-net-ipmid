#pragma once

#include <array>
#include <vector>

namespace cipher
{
namespace auth
{

constexpr size_t USER_KEY_MAX_LENGTH = 20;
constexpr size_t BMC_RANDOM_NUMBER_LEN = 16;
constexpr size_t REMOTE_CONSOLE_RANDOM_NUMBER_LEN = 16;

/*
 * @enum RAKP Authentication Algorithms
 *
 * RMCP+ Authenticated Key-Exchange Protocol (RAKP)
 *
 * RAKP-None is not supported as per the following recommendation
 * (https://www.us-cert.gov/ncas/alerts/TA13-207A)
 * ("cipher 0" is an option enabled by default on many IPMI enabled devices that allows
 * authentication to be bypassed.  Disable "cipher 0" to prevent attackers from bypassing
 * authentication and sending arbitrary IPMI commands.)
 */
enum class RAKPAuthAlgorithms : uint8_t
{
    RAKP_NONE = 0,  // Mandatory
    RAKP_HMAC_SHA1, // Mandatory
    RAKP_HMAC_MD5, // Optional
    RAKP_HMAC_SHA256, // Optional
    RAKP_HMAC_INVALID = 0xB0 // Reserved used to indicate an invalid authentication algorithm
};

/*
 * @class RAKPAlgoInterface
 *
 * RAKPAlgoInterface is the base class for the Authentication Algorithms.
 * The Authentication Algorithm specifies the type of authentication “handshake” process that is
 * used and identifies any particular variations of hashing or signature algorithm that is used as
 * part of the process.
 *
 */
class RAKPAlgoInterface
{
    public:
        RAKPAlgoInterface() = default;
        virtual ~RAKPAlgoInterface() = default;
        RAKPAlgoInterface(const RAKPAlgoInterface&) = delete;
        RAKPAlgoInterface& operator=(const RAKPAlgoInterface&) = delete;
        RAKPAlgoInterface(RAKPAlgoInterface&&) = delete;
        RAKPAlgoInterface& operator=(RAKPAlgoInterface&&) = delete;

        /*
         * @brief Generate the Hash Message Authentication Code
         *
         * This API is invoked to generate the Key Exchange Authentication Code in the
         * RAKP2 and RAKP4 sequence and for generating the Session Integrity Key.
         *
         * @param input message
         *
         * @return hash output
         *
         * @note The user key which is the secret key for the hash operation needs to be set
         *       before this operation.
         */
        std::vector<uint8_t> virtual generateHMAC(std::vector<uint8_t>& input) = 0;

        /*
         * @brief Generate the Integrity Check Value
         *
         * This API is invoked in the RAKP4 sequence for generating the Integrity Check Value.
         *
         * @param input message
         *
         * @return hash output
         *
         * @note The session integrity key which is the secret key for the hash operation needs to
         *       be set before this operation.
         */
        std::vector<uint8_t> virtual generateICV(std::vector<uint8_t>& input) = 0;

        std::array<uint8_t, USER_KEY_MAX_LENGTH>& getUserKey()
        {
            return userKey;
        }

        std::array<uint8_t, BMC_RANDOM_NUMBER_LEN>& getBMCRandomNum()
        {
            return bmcRandomNum;
        }

        std::array<uint8_t, REMOTE_CONSOLE_RANDOM_NUMBER_LEN>& getRCRandomNum()
        {
            return rcRandomNum;
        }

        /*
         * @function getSIK
         *
         * Get Session Integrity Key
         *
         */
        virtual std::vector<uint8_t>& getSIK() = 0;

    protected:
        // User Key
        std::array<uint8_t, USER_KEY_MAX_LENGTH> userKey;

        // Managed System Random Number
        std::array<uint8_t, BMC_RANDOM_NUMBER_LEN> bmcRandomNum;

        // Remote Console Random Number
        std::array<uint8_t, REMOTE_CONSOLE_RANDOM_NUMBER_LEN> rcRandomNum;
};

/*
 * @class RAKPAlgoSHA1
 *
 * RAKP-HMAC-SHA1 specifies the use of RAKP messages for the key exchange portion of
 * establishing the session, and that HMAC-SHA1 (per [RFC2104]) is used to create 20-byte Key
 * Exchange Authentication Code fields in RAKP Message 2 and RAKP Message 3. HMAC-SHA1-96
 * (per [RFC2404]) is used for generating a 12-byte Integrity Check Value field for RAKP Message 4.
 */

class RAKPAlgoSHA1 : public RAKPAlgoInterface
{
    public:

        RAKPAlgoSHA1() = default;
        ~RAKPAlgoSHA1() = default;
        RAKPAlgoSHA1(const RAKPAlgoSHA1&) = delete;
        RAKPAlgoSHA1& operator=(const RAKPAlgoSHA1&) = delete;
        RAKPAlgoSHA1(RAKPAlgoSHA1&&) = delete;
        RAKPAlgoSHA1& operator=(RAKPAlgoSHA1&&) = delete;

        std::vector<uint8_t> generateHMAC(std::vector<uint8_t>& input);

        std::vector<uint8_t> generateICV(std::vector<uint8_t>& input);

        std::vector<uint8_t>& getSIK()
        {
            return sessionIntegrityKey;
        }

    private:
        std::vector<uint8_t> sessionIntegrityKey; // Session Integrity Key
};

}// namespace auth

}// namespace cipher

