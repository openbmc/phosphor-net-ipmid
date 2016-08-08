#pragma once

#include "message.hpp"

class Ipmi15Parser : public MessageParser
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


        Ipmi15Parser() = default;
        ~Ipmi15Parser() = default;
        Ipmi15Parser(const Ipmi15Parser& right) = delete;
        Ipmi15Parser& operator=(const Ipmi15Parser& right) = delete;
        Ipmi15Parser(Ipmi15Parser&&) = delete;
        Ipmi15Parser& operator=(Ipmi15Parser&&) = delete;

        size_t getPacketSize(Message* i_msg);

        uint32_t getSessionID(Message* i_msg);

        bool unflatten(Message* i_msg);

        bool flatten(Message* i_msg);
};

class Ipmi20Parser : public MessageParser
{
    public:
        static constexpr size_t MAX_INTEGRITY_DATA_LENGTH = 12;

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
            uint8_t authCode[MAX_INTEGRITY_DATA_LENGTH];// AuthCode (Integrity Data)
        } __attribute__((packed));

        Ipmi20Parser() = default;
        ~Ipmi20Parser() = default;
        Ipmi20Parser(const Ipmi20Parser& right) = delete;
        Ipmi20Parser& operator=(const Ipmi20Parser& right) = delete;
        Ipmi20Parser(Ipmi20Parser&&) = delete;
        Ipmi20Parser& operator=(Ipmi20Parser&&) = delete;

        uint32_t getPacketSize(Message* i_msg);

        uint32_t getSessionID(Message* i_msg);

        bool unflatten(Message* i_msg);

        bool flatten(Message* i_msg);

    protected:
        /*
         * @brief Add sequence number to the message
         *
         */
        bool addSequenceNumber(Message* i_msg);

        /*
         * @brief Check Integrity data of the incoming IPMI message
         */
        bool checkPacketIntegrity(Message* i_msg);

        /*
         * @brief Add Integrity data for the outgoing message
         */
        bool addIntegrityData(Message* i_message);

        /*
         * @brief Decrypt the encrypted payload from the incoming message
         */
        bool decryptPayload(Message* i_msg);

        /*
         * @brief Encrypt the payload for the outgoing message
         */
        bool encryptPayload(Message* i_msg);
};
