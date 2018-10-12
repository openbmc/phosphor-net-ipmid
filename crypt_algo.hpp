#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace cipher
{

namespace crypt
{

/**
 * @enum Confidentiality Algorithms
 *
 * The Confidentiality Algorithm Number specifies the encryption/decryption
 * algorithm field that is used for encrypted payload data under the session.
 * The ‘encrypted’ bit in the payload type field being set identifies packets
 * with payloads that include data that is encrypted per this specification.
 * When payload data is encrypted, there may be additional “Confidentiality
 * Header” and/or “Confidentiality Trailer” fields that are included within the
 * payload. The size and definition of those fields is specific to the
 * particular confidentiality algorithm. Based on security recommendations
 * encrypting IPMI traffic is preferred, so NONE is not supported.
 */
enum class Algorithms : uint8_t
{
    NONE,        /**< No encryption (mandatory , not supported) */
    AES_CBC_128, /**< AES-CBC-128 Algorithm (mandatory option) */
    xRC4_128,    /**< xRC4-128 Algorithm (optional option) */
    xRC4_40,     /**< xRC4-40 Algorithm (optional option) */
};

/**
 * @class Interface
 *
 * Interface is the base class for the Confidentiality Algorithms.
 */
class Interface
{
  public:
    /**
     * @brief Constructor for Interface
     */
    explicit Interface(const std::vector<uint8_t>& k2) : k2(k2)
    {
    }

    Interface() = delete;
    virtual ~Interface() = default;
    Interface(const Interface&) = default;
    Interface& operator=(const Interface&) = default;
    Interface(Interface&&) = default;
    Interface& operator=(Interface&&) = default;

    /**
     * @brief Decrypt the incoming payload
     *
     * @param[in] packet - Incoming IPMI packet
     * @param[in] sessHeaderLen - Length of the IPMI Session Header
     * @param[in] payloadLen - Length of the encrypted IPMI payload
     *
     * @return decrypted payload if the operation is successful
     */
    virtual std::vector<uint8_t>
        decryptPayload(const std::vector<uint8_t>& packet,
                       const size_t sessHeaderLen,
                       const size_t payloadLen) const = 0;

    /**
     * @brief Encrypt the outgoing payload
     *
     * @param[in] payload - plain payload for the outgoing IPMI packet
     *
     * @return encrypted payload if the operation is successful
     *
     */
    virtual std::vector<uint8_t>
        encryptPayload(std::vector<uint8_t>& payload) const = 0;

    /**
     * @brief Check if the Confidentiality algorithm is supported
     *
     * @param[in] algo - confidentiality algorithm
     *
     * @return true if algorithm is supported else false
     *
     */
    static bool isAlgorithmSupported(Algorithms algo)
    {
        if (algo == Algorithms::AES_CBC_128)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

  protected:
    /**
     * @brief The Cipher Key is the first 128-bits of key “K2”, K2 is
     * generated by processing a pre-defined constant keyed by Session
     * Integrity Key (SIK) that was created during session activation.
     */
    std::vector<uint8_t> k2;
};

/**
 * @class AlgoAES128
 *
 * @brief Implementation of the AES-CBC-128 Confidentiality algorithm
 *
 * AES-128 uses a 128-bit Cipher Key. The Cipher Key is the first 128-bits of
 * key “K2”.Once the Cipher Key has been generated it is used to encrypt
 * the payload data. The payload data is padded to make it an integral numbers
 * of blocks in length (a block is 16 bytes for AES). The payload is then
 * encrypted one block at a time from the lowest data offset to the highest
 * using Cipher_Key as specified in AES.
 */
class AlgoAES128 final : public Interface
{
  public:
    static constexpr size_t AESCBC128ConfHeader = 16;
    static constexpr size_t AESCBC128BlockSize = 16;

    /**
     * If confidentiality bytes are present, the value of the first byte is
     * one (01h). and all subsequent bytes shall have a monotonically
     * increasing value (e.g., 02h, 03h, 04h, etc). The receiver, as an
     * additional check for proper decryption, shall check the value of each
     * byte of Confidentiality Pad. For AES algorithm, the pad bytes will
     * range from 0 to 15 bytes. This predefined array would help in
     * doing the additional check.
     */
    static constexpr std::array<uint8_t, AESCBC128BlockSize - 1> confPadBytes =
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    /**
     * @brief Constructor for AlgoAES128
     *
     * @param[in] - Session Integrity key
     */
    explicit AlgoAES128(const std::vector<uint8_t>& k2) : Interface(k2)
    {
    }

    AlgoAES128() = delete;
    ~AlgoAES128() = default;
    AlgoAES128(const AlgoAES128&) = default;
    AlgoAES128& operator=(const AlgoAES128&) = default;
    AlgoAES128(AlgoAES128&&) = default;
    AlgoAES128& operator=(AlgoAES128&&) = default;

    /**
     * @brief Decrypt the incoming payload
     *
     * @param[in] packet - Incoming IPMI packet
     * @param[in] sessHeaderLen - Length of the IPMI Session Header
     * @param[in] payloadLen - Length of the encrypted IPMI payload
     *
     * @return decrypted payload if the operation is successful
     */
    std::vector<uint8_t> decryptPayload(const std::vector<uint8_t>& packet,
                                        const size_t sessHeaderLen,
                                        const size_t payloadLen) const override;

    /**
     * @brief Encrypt the outgoing payload
     *
     * @param[in] payload - plain payload for the outgoing IPMI packet
     *
     * @return encrypted payload if the operation is successful
     *
     */
    std::vector<uint8_t>
        encryptPayload(std::vector<uint8_t>& payload) const override;

  private:
    /**
     * @brief Decrypt the passed data
     *
     * @param[in] iv - Initialization vector
     * @param[in] input - Pointer to input data
     * @param[in] inputLen - Length of input data
     *
     * @return decrypted data if the operation is successful
     */
    std::vector<uint8_t> decryptData(const uint8_t* iv, const uint8_t* input,
                                     const int inputLen) const;

    /**
     * @brief Encrypt the passed data
     *
     * @param[in] input - Pointer to input data
     * @param[in] inputLen - Length of input data
     *
     * @return encrypted data if the operation is successful
     */
    std::vector<uint8_t> encryptData(const uint8_t* input,
                                     const int inputLen) const;
};

} // namespace crypt

} // namespace cipher
