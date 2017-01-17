#pragma once

#include <array>
#include <vector>
#include "integrity_algo.hpp"

namespace cipher
{
namespace rakp_auth
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
 * ("cipher 0" is an option enabled by default on many IPMI enabled devices that
 * allows authentication to be bypassed.  Disable "cipher 0" to prevent
 * attackers from bypassing authentication and sending arbitrary IPMI commands.)
 */
enum class Algorithms : uint8_t
{
    RAKP_NONE = 0,              // Mandatory
    RAKP_HMAC_SHA1,             // Mandatory
    RAKP_HMAC_MD5,              // Optional
    RAKP_HMAC_SHA256,           // Optional
    // Reserved used to indicate an invalid authentication algorithm
    RAKP_HMAC_INVALID = 0xB0
};

/*
 * @class Interface
 *
 * Interface is the base class for the Authentication Algorithms.
 * The Authentication Algorithm specifies the type of authentication “handshake”
 * process that is used and identifies any particular variations of hashing or
 * signature algorithm that is used as part of the process.
 *
 */
class Interface
{
    public:
        explicit Interface(integrity::Algorithms intAlgo) : intAlgo(intAlgo) {}
        Interface() = delete;
        virtual ~Interface() = default;
        Interface(const Interface&) = default;
        Interface& operator=(const Interface&) = default;
        Interface(Interface&&) = default;
        Interface& operator=(Interface&&) = default;

        /*
         * @brief Generate the Hash Message Authentication Code
         *
         * This API is invoked to generate the Key Exchange Authentication Code
         * in the RAKP2 and RAKP4 sequence and for generating the Session
         * Integrity Key.
         *
         * @param input message
         *
         * @return hash output
         *
         * @note The user key which is the secret key for the hash operation
         *        needs to be set before this operation.
         */
        std::vector<uint8_t> virtual generateHMAC(
            std::vector<uint8_t>& input) const = 0;

        /*
         * @brief Generate the Integrity Check Value
         *
         * This API is invoked in the RAKP4 sequence for generating the
         * Integrity Check Value.
         *
         * @param input message
         *
         * @return hash output
         *
         * @note The session integrity key which is the secret key for the
         *        hash operation needs to be set before this operation.
         */
        std::vector<uint8_t> virtual generateICV(
            std::vector<uint8_t>& input) const = 0;

        // User Key is hardcoded to PASSW0RD till the IPMI User account
        // management is in place.
        std::array<uint8_t, USER_KEY_MAX_LENGTH> userKey = {"PASSW0RD"};

        // Managed System Random Number
        std::array<uint8_t, BMC_RANDOM_NUMBER_LEN> bmcRandomNum;

        // Remote Console Random Number
        std::array<uint8_t, REMOTE_CONSOLE_RANDOM_NUMBER_LEN> rcRandomNum;

        // Session Integrity Key
        std::vector<uint8_t> sessionIntegrityKey;

        /*
         * Integrity Algorithm is activated and set in the session data only
         * once the session setup is succeeded in the RAKP34 command. But the
         * integrity algorithm is negotiated in the Open Session Request command
         * . So the authentication algorithm successfully negotiated is stored
         * in the authentication algorithm.
         */
        integrity::Algorithms intAlgo;
};

/*
 * @class AlgoSHA1
 *
 * RAKP-HMAC-SHA1 specifies the use of RAKP messages for the key exchange
 * portion of establishing the session, and that HMAC-SHA1 (per [RFC2104]) is
 * used to create 20-byte Key Exchange Authentication Code fields in RAKP
 * Message 2 and RAKP Message 3. HMAC-SHA1-96(per [RFC2404]) is used for
 * generating a 12-byte Integrity Check Value field for RAKP Message 4.
 */

class AlgoSHA1 : public Interface
{
    public:
        explicit AlgoSHA1(integrity::Algorithms intAlgo) : Interface(intAlgo) {}
        AlgoSHA1() = delete;
        ~AlgoSHA1() = default;
        AlgoSHA1(const AlgoSHA1&) = default;
        AlgoSHA1& operator=(const AlgoSHA1&) = default;
        AlgoSHA1(AlgoSHA1&&) = default;
        AlgoSHA1& operator=(AlgoSHA1&&) = default;

        std::vector<uint8_t> generateHMAC(std::vector<uint8_t>& input) const
        override;

        std::vector<uint8_t> generateICV(std::vector<uint8_t>& input) const
        override;
};

}// namespace auth

}// namespace cipher

