#pragma once

#include "message.hpp"
#include "session.hpp"

namespace message
{

namespace parser
{

constexpr size_t RMCP_VERSION = 6;

// RMCP Messages with class=IPMI should be sent with an RMCP Sequence
// Number of FFh to indicate that an RMCP ACK message should not be
// generated by the message receiver.
constexpr size_t RMCP_SEQ = 0xFF;

// RMCP Message Class 7h is for IPMI
constexpr size_t RMCP_MESSAGE_CLASS_IPMI = 7;

// RMCP Session Header Size
constexpr size_t RMCP_SESSION_HEADER_SIZE = 4;

enum class SessionHeader
{
    IPMI15 = 0x00,
    IPMI20 = 0x06,
    INVALID = 0xFF,
};

struct BasicHeader_t
{
    // RMCP Header
    uint8_t version;
    uint8_t reserved;
    uint8_t rmcpSeqNum;
    uint8_t classOfMsg;

    // IPMI partial session header
    union
    {
        uint8_t reserved1: 4;
        uint8_t authType: 4;
        uint8_t formatType;
    } format;
} __attribute__((packed));

/*
 * @brief Unflatten an incoming packet and prepare the IPMI message
 *
 * @param[in] inPacket - Incoming IPMI packet
 *
 * @return A tuple with IPMI message and the session header type to sent the
 *         response packet. In case of success incoming message and session
 *         header type. In case of failure nullptr and session header type
 *         would be invalid.
 */
std::tuple<std::unique_ptr<Message>, SessionHeader> unflatten(
        std::vector<uint8_t>& inPacket);

/*
 * @brief Flatten an IPMI message and generate the IPMI packet with the
 *        session header
 *
 * @param[in] outMessage - IPMI message to be flattened
 * @param[in] authType - Session header type to be added to the IPMI
 *                       packet
 *
 * @return IPMI packet on success
 */
std::vector<uint8_t> flatten(Message& outMessage,
                             SessionHeader authType,
                             session::Session& session);

} // namespace parser

namespace ipmi15parser
{

struct SessionHeader_t
{
    struct parser::BasicHeader_t base;
    uint32_t sessSeqNum;
    uint32_t sessId;
    // <Optional Field: AuthCode>
    uint8_t payloadLength;
} __attribute__((packed));

struct SessionTrailer_t
{
    uint8_t legacyPad;
} __attribute__((packed));

/*
 * @brief Unflatten an incoming packet and prepare the IPMI message
 *
 * @param[in] inPacket - Incoming IPMI packet
 *
 * @return IPMI message in the packet on success
 */
std::unique_ptr<Message> unflatten(std::vector<uint8_t>& inPacket);

/*
 * @brief Flatten an IPMI message and generate the IPMI packet with the
 *        session header
 *
 * @param[in] outMessage - IPMI message to be flattened
 *
 * @return IPMI packet on success
 */
std::vector<uint8_t> flatten(Message& outMessage, session::Session& session);

} // namespace ipmi15parser

namespace ipmi20parser
{

constexpr size_t MAX_INTEGRITY_DATA_LENGTH = 12;
constexpr size_t PAYLOAD_ENCRYPT_MASK = 0x80;
constexpr size_t PAYLOAD_AUTH_MASK = 0x40;

struct SessionHeader_t
{
    struct parser::BasicHeader_t base;

    uint8_t payloadType;

    uint32_t sessId;
    uint32_t sessSeqNum;
    uint16_t payloadLength;
} __attribute__((packed));

struct SessionTrailer_t
{
    // Integrity Pad
    uint8_t padLength;
    uint8_t nextHeader;
} __attribute__((packed));

/*
 * @brief Unflatten an incoming packet and prepare the IPMI message
 *
 * @param[in] inPacket - Incoming IPMI packet
 *
 * @return IPMI message in the packet on success
 */
std::unique_ptr<Message> unflatten(std::vector<uint8_t>& inPacket);

/*
 * @brief Flatten an IPMI message and generate the IPMI packet with the
 *        session header
 *
 * @param[in] outMessage - IPMI message to be flattened
 *
 * @return IPMI packet on success
 */
std::vector<uint8_t> flatten(Message& outMessage, session::Session& session);

namespace internal
{

/*
 * @brief Add sequence number to the message
 *
 * @param[in] packet - outgoing packet to which to add sequence number
 * @param[in] session - session handle
 *
 */
void addSequenceNumber(std::vector<uint8_t>& packet, session::Session& session);

/*
 * @brief Verify the integrity data of the incoming IPMI packet
 *
 * @param[in] packet - Incoming IPMI packet
 * @param[in] message - IPMI Message populated from the incoming packet
 * @param[in] payloadLen - Length of the IPMI payload
 *
 */
bool verifyPacketIntegrity(const std::vector<uint8_t>& packet,
                           const Message& message,
                           const size_t payloadLen);

/*
 * @brief Add Integrity data to the outgoing IPMI packet
 *
 * @param[in] packet - Outgoing IPMI packet
 * @param[in] message - IPMI Message populated for the outgoing packet
 */
void addIntegrityData(std::vector<uint8_t>& packet,
                      const Message& message,
                      const size_t payloadLen);

/*
 * @brief Decrypt the encrypted payload in the incoming IPMI packet
 *
 * @param[in] packet - Incoming IPMI packet
 * @param[in] message - IPMI Message populated from the incoming packet
 * @param[in] payloadLen - Length of encrypted IPMI payload
 *
 * @return on successful completion, return the plain text payload
 */
std::vector<uint8_t> decryptPayload(const std::vector<uint8_t>& packet,
                                    const Message& message,
                                    const size_t payloadLen);

} // namespace internal

} // namespace ipmi20parser

} // namespace message
