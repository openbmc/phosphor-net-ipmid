#pragma once

#include "message.hpp"
#include "message_parsers.hpp"
#include "session.hpp"

class MessageHandler
{
    public:
        // IPMI Message Headers/Trailers
        struct LanMsgRequestHeader
        {
            uint8_t rsaddr;
            uint8_t netfn;
            uint8_t cs;
            uint8_t rqaddr;
            uint8_t rqseq;
            uint8_t cmd;
        } __attribute__((packed));

        struct LanMsgResponseHeader
        {
            uint8_t rqaddr;
            uint8_t netfn;
            uint8_t cs;
            uint8_t rsaddr;
            uint8_t rqseq;
            uint8_t cmd;
        } __attribute__((packed));

        struct LanMsgTrailer
        {
            uint8_t checksum2;
        } __attribute__((packed));


        MessageHandler(std::shared_ptr<SocketChannel> i_channel);

        MessageHandler() = delete;
        ~MessageHandler() = default;
        MessageHandler(const MessageHandler& right) = delete;
        MessageHandler& operator=(const MessageHandler& right) = delete;
        MessageHandler(MessageHandler&&) = delete;
        MessageHandler& operator=(MessageHandler&&) = delete;

        /*
         * @brief Receive the IPMI packet
         *
         * Read the data on the socket, get the parser based on the Session header type and
         * flatten the payload and generate the IPMI message
         *
         * @return IPMI Message on success and nullptr on failure
         *
         */
        std::unique_ptr<Message> receive();

        /*
         * @brief Process the incoming IPMI message
         *
         * The incoming message payload is handled and the command handler for the Network function
         * and Command is executed and the response message is returned
         *
         * @param [in] Incoming Message
         *
         * @return Outgoing message on success and nullptr on failure
         */
        std::unique_ptr<Message> executeCommand(Message* inMessage);


        /*
         * @brief Send the outgoing message
         *
         * The payload in the outgoing message is flattened and sent out on the socket
         */
        int send(Message* outMessage);

        auto getChannel()
        {
            return channel;
        }

    private:

        // Socket channel for communicating with the remote client
        std::shared_ptr<SocketChannel> channel;

        // BMC Session ID for the Channel
        uint32_t sessionID;

        // IPMI 1.5 or IPMI 2.0 Session Header
        MessageParser::SessionHeader sessionHeader;

        uint32_t getCommand(Message* message);

        /*
         * @brief Calculate 8 bit 2's complement checksum
         *
         * Initialize checksum to 0. For each byte, checksum = (checksum + byte) modulo 256.
         * Then checksum = - checksum. When the checksum and the bytes are added together,
         * modulo 256, the result should be 0.
         */

        uint8_t ipmiCrc8bit(const uint8_t* ptr, const int len);
};



