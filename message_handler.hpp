#pragma once

#include "message.hpp"
#include "message_parsers.hpp"
#include "session.hpp"

namespace message
{

class Handler
{
    public:

        Handler(std::shared_ptr<udpsocket::Channel> channel):
            channel(channel) {}

        Handler() = delete;
        ~Handler() = default;
        Handler(const Handler&) = default;
        Handler& operator=(const Handler&) = default;
        Handler(Handler&&) = default;
        Handler& operator=(Handler&&) = default;

        /*
         * @brief Receive the IPMI packet
         *
         * Read the data on the socket, get the parser based on the Session
         * header type and flatten the payload and generate the IPMI message
         *
         * @return IPMI Message on success and nullptr on failure
         *
         */
        std::unique_ptr<Message> receive();

        /*
         * @brief Process the incoming IPMI message
         *
         * The incoming message payload is handled and the command handler for
         * the Network function and Command is executed and the response message
         * is returned
         *
         * @param[in] inMessage - Incoming Message
         *
         * @return Outgoing message on success and nullptr on failure
         */
        std::unique_ptr<Message> executeCommand(Message* inMessage);

        /*
         * @brief Send the outgoing message
         *
         * The payload in the outgoing message is flattened and sent out on the
         * socket
         *
         * @param[in] outMessage - Outgoing Message
         *
         * @return Zero on success and <0 on failure
         */
        int send(Message* outMessage);

        // BMC Session ID for the Channel
        uint32_t sessionID;
    private:
        // Socket channel for communicating with the remote client
        std::shared_ptr<udpsocket::Channel> channel;

        // IPMI 1.5 or IPMI 2.0 Session Header
        Parser::SessionHeader sessionHeader;

        /*
         * @brief Extract the command from the IPMI payload
         *
         * @param[in] message - Incoming message
         */
        uint32_t getCommand(Message* message);

        /*
         * @brief Calculate 8 bit 2's complement checksum
         *
         * Initialize checksum to 0. For each byte, checksum = (checksum + byte)
         * modulo 256. Then checksum = - checksum. When the checksum and the
         * bytes are added together, modulo 256, the result should be 0.
         */
        uint8_t ipmiCrc8bit(const uint8_t* ptr, const int len);

};

} //namespace message



