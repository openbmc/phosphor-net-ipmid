#pragma once

#include "message.hpp"

namespace message
{

/*
 * @class Parser
 *
 * Parser is the base class for IPMI message parsers.There are two types of
 * IPMI session headers IPMI1.5 header and IPMI2.0 header
 */
class Parser
{
    public:
        static constexpr size_t RMCP_VERSION = 6;

        // RMCP Messages with class=IPMI should be sent with an RMCP Sequence
        // Number of FFh to indicate that an RMCP ACK message should not be
        // generated by the message receiver.
        static constexpr size_t RMCP_SEQ = 0xFF;

        // RMCP Message Class 7h is for IPMI
        static constexpr size_t RMCP_MESSAGE_CLASS_IPMI = 7;

        enum class SessionHeader
        {
            IPMI15 = 0x00,
            IPMI20 = 0x06,
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

        Parser() = delete;
        ~Parser() = delete;
        Parser(const Parser&) = delete;
        Parser& operator=(const Parser&) = delete;
        Parser(Parser&&) = delete;
        Parser& operator=(Parser&&) = delete;

        /*
         * @brief Unflatten an incoming packet and prepare the IPMI message
         *
         * @param [in] Incoming IPMI packet
         * @param [out] Session header type in the packet is passed to the
         *              Message handler to sent response packet
         *
         * @return IPMI message in the packet on success
         */
        static std::unique_ptr<Message> unflatten(
            std::vector<uint8_t>& inPacket, SessionHeader& authType);

        /*
         * @brief Flatten an IPMI message and generate the IPMI packet with the
         *        session header
         *
         * @param [in] IPMI message to be flattened
         * @param [in] Session header type to be added to the IPMI packet
         *
         * @return IPMI packet on success
         */
        static std::vector<uint8_t> flatten(Message* outMessage,
                                            SessionHeader authType);

        // Maximum packet size that we'll handle
        static constexpr uint32_t MESSAGE_MAX_PACKET_LENGTH = 512;
};

class Ipmi15Parser : public Parser
{
    public:
        struct SessionHeader_t
        {
            struct BasicHeader_t base;
            uint32_t sessSeqNum;
            uint32_t sessId;
            // <Optional Field: AuthCode>
            uint8_t payloadLength;
        } __attribute__((packed));

        struct SessionTrailer_t
        {
            uint8_t legacyPad;
        } __attribute__((packed));


        Ipmi15Parser() = delete;
        ~Ipmi15Parser() = delete;
        Ipmi15Parser(const Ipmi15Parser&) = delete;
        Ipmi15Parser& operator=(const Ipmi15Parser&) = delete;
        Ipmi15Parser(Ipmi15Parser&&) = delete;
        Ipmi15Parser& operator=(Ipmi15Parser&&) = delete;

        static std::unique_ptr<Message> unflatten(
            std::vector<uint8_t>& inPacket);

        static std::vector<uint8_t> flatten(Message* outMessage);
};

class Ipmi20Parser : public Parser
{
    public:
        static constexpr size_t MAX_INTEGRITY_DATA_LENGTH = 12;
        static constexpr size_t PAYLOAD_ENCRYPT_MASK = 0x80;
        static constexpr size_t PAYLOAD_AUTH_MASK = 0x40;

        struct SessionHeader_t
        {
            struct BasicHeader_t base;

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
            // AuthCode (Integrity Data)
            uint8_t authCode[MAX_INTEGRITY_DATA_LENGTH];
        } __attribute__((packed));

        Ipmi20Parser() = delete;
        ~Ipmi20Parser() = delete;
        Ipmi20Parser(const Ipmi20Parser&) = delete;
        Ipmi20Parser& operator=(const Ipmi20Parser&) = delete;
        Ipmi20Parser(Ipmi20Parser&&) = delete;
        Ipmi20Parser& operator=(Ipmi20Parser&&) = delete;

        static std::unique_ptr<Message> unflatten(
            std::vector<uint8_t>& inPacket);

        static std::vector<uint8_t> flatten(Message* outMessage);

    protected:
        /*
         * @brief Add sequence number to the message
         *
         */
        static bool addSequenceNumber(std::vector<uint8_t>& packet);
};

} // namespace message
