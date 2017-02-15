#pragma once

#include <map>
#include <memory>
#include "console_buffer.hpp"
#include "session.hpp"
#include "sol_context.hpp"

namespace sol
{

constexpr size_t MAX_SOL_PAYLOADS = 16;
constexpr size_t MAX_PAYLOAD_SIZE = 255;

constexpr auto CONSOLE_SOCKET_PATH = "\0obmc-console";
const size_t CONSOLE_SOCKET_PATH_LEN = sizeof(CONSOLE_SOCKET_PATH) - 1;

/**
 * @class Manager
 *
 * Manager class acts a manager for the SOL payload instances and provides
 * interfaces to start a payload instance, stop a payload instance and get
 * reference to the context object.
 */
class Manager
{
    public:

        /**
         * SOL Payload Instance is the key for the map, the value is the SOL
         * context
         */
        using SOLPayloadMap = std::map<uint8_t, std::unique_ptr<Context>>;

        Manager() = default;
        ~Manager()
        {
            if (!fd)
            {
                close(fd);
            }
        }
        Manager(const Manager&) = delete;
        Manager& operator=(const Manager&) = delete;
        Manager(Manager&&) = default;
        Manager& operator=(Manager&&) = default;

        /** Host Console Buffer */
        ConsoleData buffer;

        /** Character Accumulate Interval */
        uint8_t accumulateInterval;

        /** Character Send Threshold */
        uint8_t sendThreshold;

        /** Retry Count */
        uint8_t retryCount;

        /** Retry Interval */
        uint8_t retryThreshold;

        /**
         * @brief Start a SOL Payload Instance
         *
         * Starting a payload instance involves creating the Context object, add the
         * accumulate interval timer and retry interval timer to the event loop.
         *
         * @param[in] payloadInstance - SOL payload instance
         * @param[in] sessionID - BMC Session ID
         *
         */
        void startSOLPayload(uint8_t payloadInstance, uint32_t sessionID);

        /**
         * @brief Stop SOL Payload Instance
         *
         * @param[in] payloadInstance - SOL payload instance
         *
         */
        void stopSOLPayload(uint8_t payloadInstance);

        /**
         * @brief Get SOL Context Data
         *
         * @param[in] payloadInstance - SOL payload instance
         *
         * @return reference to the SOL payload context
         */
        Context& getSOLContext(uint8_t payloadInstance)
        {
            auto iter = payloadMap.find(payloadInstance);
            if (iter != payloadMap.end())
            {
                return *(iter->second);
            }
            else
            {
                throw std::runtime_error("Invalid payload instance");
            }
        }

        /**
         * @brief Check if SOL payload is active
         *
         * @param[in] payloadInstance - SOL payload instance
         *
         * @return true if the instance is active and false it is not active
         */
        auto checkPayloadInst(uint8_t payloadInstance)
        {
            auto search = payloadMap.find(payloadInstance);
            if (search != payloadMap.end())
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /**
         * @brief Write data to the Host Console Unix socket
         *
         * @param[in] input - Data from the remote console
         */
        int writeConsoleSocket(const sol::buffer& input);

    private:

        SOLPayloadMap payloadMap;

        /** File descriptor for the Host Console */
        int fd;

        int initHostConsoleFd();

};

} //namespace sol
