#pragma once

#include "rmcp.hpp"

#include <array>
#include <cstddef>
#include <vector>

namespace cipher
{

namespace integrity
{

/**
 * @enum Integrity Algorithms
 *
 * The Integrity Algorithm Number specifies the algorithm used to generate the
 * contents for the AuthCode “signature” field that accompanies authenticated
 * IPMI v2.0/RMCP+ messages once the session has been established. If the
 * Integrity Algorithm is none the AuthCode value is not calculated and the
 * AuthCode field in the message is not present. Based on security
 * recommendations NONE will not be supported.
 */
enum class Algorithms : uint8_t
{
    NONE,            // Mandatory (implemented, not supported)
    HMAC_SHA1_96,    // Mandatory (implemented, default choice in ipmitool)
    HMAC_MD5_128,    // Optional (not implemented)
    MD5_128,         // Optional (not implemented)
    HMAC_SHA256_128, // Optional (implemented, best available)
};

/**
 * @class Interface
 *
 * Interface is the base class for the Integrity Algorithms.
 * Unless otherwise specified, the integrity algorithm is applied to the packet
 * data starting with the AuthType/Format field up to and including the field
 * that immediately precedes the AuthCode field itself.
 */
class Interface
{
  public:
    /**
     * @brief Constructor for Interface
     *
     * @param[in] - AuthCode length
     */
    explicit Interface(size_t authLength) : authCodeLength(authLength) {}

    Interface() = delete;
    virtual ~Interface() = default;
    Interface(const Interface&) = default;
    Interface& operator=(const Interface&) = default;
    Interface(Interface&&) = default;
    Interface& operator=(Interface&&) = default;

    /**
     * @brief Verify the integrity data of the packet
     *
     * @param[in] packet - Incoming IPMI packet
     * @param[in] packetLen - Packet length excluding authCode
     * @param[in] integrityDataBegin - Begin iterator to the authCode in the
     *                                 packet
     * @param[in] integrityDataEnd   - End to the authCode in the packet
     *
     * @return true if authcode in the packet is equal to one generated
     *         using integrity algorithm on the packet data, false otherwise
     */
    bool virtual verifyIntegrityData(
        const std::vector<uint8_t>& packet, const size_t packetLen,
        std::vector<uint8_t>::const_iterator integrityDataBegin,
        std::vector<uint8_t>::const_iterator integrityDataEnd) const = 0;

    /**
     * @brief Generate integrity data for the outgoing IPMI packet
     *
     * @param[in] input - Outgoing IPMI packet
     *
     * @return authcode for the outgoing IPMI packet
     *
     */
    std::vector<uint8_t> virtual generateIntegrityData(
        const std::vector<uint8_t>& input) const = 0;

    /**
     * @brief Check if the Integrity algorithm is supported
     *
     * @param[in] algo - integrity algorithm
     *
     * @return true if algorithm is supported else false
     *
     */
    static bool isAlgorithmSupported(Algorithms algo)
    {
        if (algo == Algorithms::HMAC_SHA256_128)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * @brief Generate additional keying material based on SIK
     *
     * @note
     * The IPMI 2.0 spec only states that the additional keying material is
     * generated by running HMAC(constN) using SIK as the key. It does not
     * state whether this is the integrity algorithm or the authentication
     * algorithm. Other implementations of the RMCP+ algorithm (ipmitool
     * and ipmiutil) are not consistent on this matter. But it does not
     * really matter because based on any of the defined cipher suites, the
     * integrity and authentication algorithms are both based on the same
     * digest method (integrity::Algorithms::HMAC_SHA1_96 uses SHA1 and
     * rakp_auth::Algorithms::RAKP_HMAC_SHA1 uses SHA1). None of the
     * defined cipher suites mix and match digests for integrity and
     * authentication. Generating Kn belongs in either the integrity or
     * authentication classes, so in this implementation, integrity has
     * been chosen.
     *
     * @param[in] sik - session integrity key
     * @param[in] data - 20-byte Const_n
     *
     * @return on success returns the Kn based on this integrity class
     *
     */
    std::vector<uint8_t> virtual generateKn(
        const std::vector<uint8_t>& sik, const rmcp::Const_n& data) const = 0;

    /** @brief Authcode field
     *
     *  AuthCode field length varies based on the integrity algorithm, for
     *  HMAC-SHA1-96 the authcode field is 12 bytes. For HMAC-SHA256-128 and
     *  HMAC-MD5-128 the authcode field is 16 bytes.
     */
    size_t authCodeLength;

  protected:
    /** @brief K1 key used to generated the integrity data. */
    std::vector<uint8_t> k1;
};

/**
 * @class AlgoSHA1
 *
 * @brief Implementation of the HMAC-SHA1-96 Integrity algorithm
 *
 * HMAC-SHA1-96 take the Session Integrity Key and use it to generate K1. K1 is
 * then used as the key for use in HMAC to produce the AuthCode field.
 * For “one-key” logins, the user’s key (password) is used in the creation of
 * the Session Integrity Key. When the HMAC-SHA1-96 Integrity Algorithm is used
 * the resulting AuthCode field is 12 bytes (96 bits).
 */
class AlgoSHA1 final : public Interface
{
  public:
    static constexpr size_t SHA1_96_AUTHCODE_LENGTH = 12;

    /**
     * @brief Constructor for AlgoSHA1
     *
     * @param[in] - Session Integrity Key
     */
    explicit AlgoSHA1(const std::vector<uint8_t>& sik);

    AlgoSHA1() = delete;
    ~AlgoSHA1() = default;
    AlgoSHA1(const AlgoSHA1&) = default;
    AlgoSHA1& operator=(const AlgoSHA1&) = default;
    AlgoSHA1(AlgoSHA1&&) = default;
    AlgoSHA1& operator=(AlgoSHA1&&) = default;

    /**
     * @brief Verify the integrity data of the packet
     *
     * @param[in] packet - Incoming IPMI packet
     * @param[in] length - Length of the data in the packet to calculate
     *                     the integrity data
     * @param[in] integrityDataBegin - Begin iterator to the authCode in the
     *                                 packet
     * @param[in] integrityDataEnd   - End to the authCode in the packet
     *
     * @return true if authcode in the packet is equal to one generated
     *         using integrity algorithm on the packet data, false otherwise
     */
    bool verifyIntegrityData(
        const std::vector<uint8_t>& packet, const size_t length,
        std::vector<uint8_t>::const_iterator integrityDataBegin,
        std::vector<uint8_t>::const_iterator integrityDataEnd) const override;

    /**
     * @brief Generate integrity data for the outgoing IPMI packet
     *
     * @param[in] input - Outgoing IPMI packet
     *
     * @return on success return the integrity data for the outgoing IPMI
     *         packet
     */
    std::vector<uint8_t> generateIntegrityData(
        const std::vector<uint8_t>& packet) const override;

    /**
     * @brief Generate additional keying material based on SIK
     *
     * @param[in] sik - session integrity key
     * @param[in] data - 20-byte Const_n
     *
     * @return on success returns the Kn based on HMAC-SHA1
     *
     */
    std::vector<uint8_t> generateKn(
        const std::vector<uint8_t>& sik,
        const rmcp::Const_n& const_n) const override;

  private:
    /**
     * @brief Generate HMAC based on HMAC-SHA1-96 algorithm
     *
     * @param[in] input - pointer to the message
     * @param[in] length - length of the message
     *
     * @return on success returns the message authentication code
     *
     */
    std::vector<uint8_t> generateHMAC(const uint8_t* input,
                                      const size_t len) const;
};

/**
 * @class AlgoSHA256
 *
 * @brief Implementation of the HMAC-SHA256-128 Integrity algorithm
 *
 * HMAC-SHA256-128 take the Session Integrity Key and use it to generate K1. K1
 * is then used as the key for use in HMAC to produce the AuthCode field.  For
 * “one-key” logins, the user’s key (password) is used in the creation of the
 * Session Integrity Key. When the HMAC-SHA256-128 Integrity Algorithm is used
 * the resulting AuthCode field is 16 bytes (128 bits).
 */
class AlgoSHA256 final : public Interface
{
  public:
    static constexpr size_t SHA256_128_AUTHCODE_LENGTH = 16;

    /**
     * @brief Constructor for AlgoSHA256
     *
     * @param[in] - Session Integrity Key
     */
    explicit AlgoSHA256(const std::vector<uint8_t>& sik);

    AlgoSHA256() = delete;
    ~AlgoSHA256() = default;
    AlgoSHA256(const AlgoSHA256&) = default;
    AlgoSHA256& operator=(const AlgoSHA256&) = default;
    AlgoSHA256(AlgoSHA256&&) = default;
    AlgoSHA256& operator=(AlgoSHA256&&) = default;

    /**
     * @brief Verify the integrity data of the packet
     *
     * @param[in] packet - Incoming IPMI packet
     * @param[in] length - Length of the data in the packet to calculate
     *                     the integrity data
     * @param[in] integrityDataBegin - Begin iterator to the authCode in the
     *                                 packet
     * @param[in] integrityDataEnd   - End to the authCode in the packet
     *
     * @return true if authcode in the packet is equal to one generated
     *         using integrity algorithm on the packet data, false otherwise
     */
    bool verifyIntegrityData(
        const std::vector<uint8_t>& packet, const size_t length,
        std::vector<uint8_t>::const_iterator integrityDataBegin,
        std::vector<uint8_t>::const_iterator integrityDataEnd) const override;

    /**
     * @brief Generate integrity data for the outgoing IPMI packet
     *
     * @param[in] packet - Outgoing IPMI packet
     *
     * @return on success return the integrity data for the outgoing IPMI
     *         packet
     */
    std::vector<uint8_t> generateIntegrityData(
        const std::vector<uint8_t>& packet) const override;

    /**
     * @brief Generate additional keying material based on SIK
     *
     * @param[in] sik - session integrity key
     * @param[in] data - 20-byte Const_n
     *
     * @return on success returns the Kn based on HMAC-SHA256
     *
     */
    std::vector<uint8_t> generateKn(
        const std::vector<uint8_t>& sik,
        const rmcp::Const_n& const_n) const override;

  private:
    /**
     * @brief Generate HMAC based on HMAC-SHA256-128 algorithm
     *
     * @param[in] input - pointer to the message
     * @param[in] len - length of the message
     *
     * @return on success returns the message authentication code
     *
     */
    std::vector<uint8_t> generateHMAC(const uint8_t* input,
                                      const size_t len) const;
};

} // namespace integrity

} // namespace cipher
