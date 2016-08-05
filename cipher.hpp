#pragma once

#include <openssl/sha.h>

#include <array>

namespace cipher
{
struct Keys
{
    static constexpr size_t USER_KEY_MAX_LENGTH = 20;
    static constexpr size_t BMC_RANDOM_NUMBER_LEN = 16;
    static constexpr size_t REMOTE_CONSOLE_RANDOM_NUMBER_LEN = 16;
    static constexpr size_t SESSION_INTEGRITY_KEY_LENGTH = SHA_DIGEST_LENGTH;

    std::array<uint8_t, USER_KEY_MAX_LENGTH> userKey; // User Key
    std::array<uint8_t, BMC_RANDOM_NUMBER_LEN>
    bmcRandomNum; // Managed System Session ID
    std::array<uint8_t, REMOTE_CONSOLE_RANDOM_NUMBER_LEN>
    rcRandomNum; // Remote Console Random Number
    std::array<uint8_t, SESSION_INTEGRITY_KEY_LENGTH>
    sessionIntegrityKey; // Session Integrity Key
};

/** @class Base class for Cipher Implementation
 *
 *  @brief This is the base class for all cipher related implementations.
 *         The cipher related operations are Session Authentication Algorithm,
 *         Integrity Algorithm and Confidentiality Algorithm.
 */
class CipherAlgorithm
{
    public:

        virtual ~CipherAlgorithm() = default;
        CipherAlgorithm(const CipherAlgorithm&) = delete;
        CipherAlgorithm& operator=(const CipherAlgorithm&) = delete;
        CipherAlgorithm(CipherAlgorithm&&) = delete;
        CipherAlgorithm& operator=(CipherAlgorithm&&) = delete;

        /** @brief Set the state of the cipher implementation
         *
         *  @param[in] - enable/disable
         *
         */
        auto setState(bool i_enable)
        {
            enabled = i_enable;
            return enabled;
        }

        /** @brief Get the state of the cipher implementation
         *
         *  Returns the state of the implementation, whether it is enabled or enabled
         *
         */
        auto getState()
        {
            return enabled;
        }

        /** @brief Cipher Algorithm that was requested by the client as part of the RMCP Session setup.
         *
         *  @param[in] - Algorithm index
         *
         */
        auto setRequested(size_t i_algoIndex)
        {
            requested = i_algoIndex;
            return requested;
        }

        /** @brief Get the Cipher Algorithm that was requested by the client
         *
         */
        auto getRequested()
        {
            return requested;
        }

        /** @brief Cipher Algorithm that was applied after the negotiation at RMCP Session setup.
         *
         *  @param[in] - Algorithm index
         */
        auto setApplied(size_t i_algoIndex)
        {
            applied = i_algoIndex;
            return applied;
        }

        /** @brief Get the Cipher Algorithm that was applied
         *
         */
        auto getApplied()
        {
            return applied;
        }

    protected:
        CipherAlgorithm() = default;

        bool enabled;
        size_t requested;
        size_t applied;
};

} // name cipher
