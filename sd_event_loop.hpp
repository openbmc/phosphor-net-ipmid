#pragma once

#include "main.hpp"
#include "sol/sol_manager.hpp"

#include <systemd/sd-event.h>

#include <boost/asio/io_context.hpp>
#include <chrono>
#include <map>
#include <sdbusplus/asio/connection.hpp>
#include <string>

namespace ipmi
{
namespace rmcpp
{
constexpr uint16_t defaultPort = 623;
} // namespace rmcpp
} // namespace ipmi

namespace eventloop
{
// VLANs are a 12-bit value
constexpr auto MAPPER_BUS_NAME = "xyz.openbmc_project.ObjectMapper";
constexpr auto MAPPER_OBJ = "/xyz/openbmc_project/object_mapper";
constexpr auto MAPPER_INTF = "xyz.openbmc_project.ObjectMapper";
constexpr auto PATH_ROOT = "/xyz/openbmc_project/network";
constexpr auto INTF_VLAN = "xyz.openbmc_project.Network.VLAN";
constexpr auto INTF_ETHERNET = "xyz.openbmc_project.Network.EthernetInterface";

class EventLoop
{
  private:
    struct Private
    {
    };

  public:
    EventLoop(std::shared_ptr<boost::asio::io_context>& io, const Private&) :
        io(io)
    {
    }
    EventLoop() = delete;
    ~EventLoop() = default;
    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) = delete;
    EventLoop& operator=(EventLoop&&) = delete;

    /**
     * @brief Get a reference to the singleton EventLoop
     *
     * @return EventLoop reference
     */
    static EventLoop& get()
    {
        static std::shared_ptr<EventLoop> ptr = nullptr;
        if (!ptr)
        {
            std::shared_ptr<boost::asio::io_context> io = getIo();
            ptr = std::make_shared<EventLoop>(io, Private());
        }
        return *ptr;
    }

    /** @brief Initialise the event loop and add the handler for incoming
     *         IPMI packets.
     *
     *  @return EXIT_SUCCESS on success and EXIT_FAILURE on failure.
     */
    int startEventLoop();

    /** @brief Set up the socket (if systemd has not already) and
     *         make sure that the bus name matches the specified channel
     */
    int setupSocket(std::shared_ptr<sdbusplus::asio::connection>& bus,
                    std::string iface,
                    uint16_t reqPort = ipmi::rmcpp::defaultPort);

  private:
    /** @brief async handler for incoming udp packets */
    void handleRmcpPacket();

    /** @brief register the async handler for incoming udp packets */
    void startRmcpReceive();

    /** @brief get vlanid  */
    int getVLANID(const std::string channel);

    /** @brief boost::asio io context to run with
     */
    std::shared_ptr<boost::asio::io_context> io;

    /** @brief boost::asio udp socket
     */
    std::shared_ptr<boost::asio::ip::udp::socket> udpSocket = nullptr;
};

} // namespace eventloop
