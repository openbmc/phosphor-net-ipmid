#include "sd_event_loop.hpp"

#include "main.hpp"
#include "message_handler.hpp"

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <systemd/sd-daemon.h>

#include <boost/asio/io_context.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/sd_event.hpp>
#include <user_channel/channel_layer.hpp>

namespace eventloop
{
using namespace phosphor::logging;

void EventLoop::handleRmcpPacket()
{
    try
    {
        auto channelPtr = std::make_shared<udpsocket::Channel>(udpSocket);

        // Initialize the Message Handler with the socket channel
        auto msgHandler = std::make_shared<message::Handler>(channelPtr, io);

        msgHandler->processIncoming();
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Executing the IPMI message failed",
                        entry("EXCEPTION=%s", e.what()));
    }
}

void EventLoop::startRmcpReceive()
{
    udpSocket->async_wait(boost::asio::socket_base::wait_read,
                          [this](const boost::system::error_code& ec) {
                              if (!ec)
                              {
                                  io->post([this]() { startRmcpReceive(); });
                                  handleRmcpPacket();
                              }
                          });
}

int EventLoop::getVLANID()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    auto IpmiServerCall = bus.new_method_call(
        "xyz.openbmc_project.Ipmi.Host", "/xyz/openbmc_project/Ipmi",
        "xyz.openbmc_project.Ipmi.Server", "execute");
    static constexpr uint8_t netfnTransport = 0x0C;
    static constexpr uint8_t LUN0 = 0x00;
    static constexpr uint8_t cmdGetLanConfigParameters = 0x02;
    IpmiServerCall.append(netfnTransport);
    IpmiServerCall.append(LUN0);
    IpmiServerCall.append(cmdGetLanConfigParameters);

    uint8_t channel = getInterfaceIndex();
    static constexpr uint8_t vlan_parameter = 20;
    static constexpr uint8_t set_seletor = 0x0;
    static constexpr uint8_t block_seletor = 0x0;
    std::vector<uint8_t> data{channel, vlan_parameter, set_seletor,
                              block_seletor};
    IpmiServerCall.append(data);

    // non-session still need to pass an empty options map
    std::map<std::string, sdbusplus::message::variant<int>> options;
    IpmiServerCall.append(options);

    // the response is a tuple because dbus can only return a single value
    std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>
        ipmi_response;
    try
    {
        auto dbus_response = bus.call(IpmiServerCall);
        try
        {
            dbus_response.read(ipmi_response);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            log<level::ERR>("getVLANID: failed to unpack");
            return 0;
        }
    }
    catch (std::exception& e)
    {
        log<level::ERR>("getVLANID: failed to execute IPMI command");
        return 0;
    }

    int vlanid = 0;
    const auto& [netfn, lun, cmd, cc, payload] = ipmi_response;

    log<level::DEBUG>("getVLANID: Get VLANID result", entry("CC=%d", cc),
                      entry("PAYLOAD0=0x%x", payload[0] & 0xff),
                      entry("PAYLOAD1=0x%x", payload[1] & 0xff),
                      entry("PAYLOAD2=0x%x", payload[2] & 0xff));

    static constexpr uint8_t VLANID_ENABLE_MASK = 0x80;
    static constexpr uint8_t VLANID_ENABLE_OFFSET = 2;
    if (IPMI_CC_OK == cc &&
        (payload[VLANID_ENABLE_OFFSET] & VLANID_ENABLE_MASK))
    {
        static constexpr uint8_t VLANID_LSB_OFFSET = 1;
        static constexpr uint8_t VLANID_MSB_OFFSET = 2;
        static constexpr uint8_t VLANID_MSB_MASK = 0xF;

        vlanid =
            ((int)payload[VLANID_LSB_OFFSET]) +
            (((int)(payload[VLANID_MSB_OFFSET] & VLANID_MSB_MASK)) << 8);
    }

    return vlanid;
}

int EventLoop::setupSocket(std::shared_ptr<sdbusplus::asio::connection>& bus,
                           std::string channel, uint16_t reqPort)
{
    std::string iface = channel;
    static constexpr const char* unboundIface = "rmcpp";
    if (channel == "")
    {
        iface = channel = unboundIface;
    }
    else
    {
        // If VLANID of this channel is set, bind the socket to this
        // VLAN logic device
        auto vlanid = getVLANID();
        if (vlanid)
        {
            iface = iface + "." + std::to_string(vlanid);
            log<level::DEBUG>("This channel has VLAN id",
                              entry("VLANID=%d", vlanid));
        }
    }
    // Create our own socket if SysD did not supply one.
    int listensFdCount = sd_listen_fds(0);
    if (listensFdCount > 1)
    {
        log<level::ERR>("Too many file descriptors received");
        return EXIT_FAILURE;
    }
    if (listensFdCount == 1)
    {
        int openFd = SD_LISTEN_FDS_START;
        if (!sd_is_socket(openFd, AF_UNSPEC, SOCK_DGRAM, -1))
        {
            log<level::ERR>("Failed to set up systemd-passed socket");
            return EXIT_FAILURE;
        }
        udpSocket = std::make_shared<boost::asio::ip::udp::socket>(
            *io, boost::asio::ip::udp::v6(), openFd);
    }
    else
    {
        // asio does not natively offer a way to bind to an interface
        // so it must be done in steps
        boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v6(), reqPort);
        udpSocket = std::make_shared<boost::asio::ip::udp::socket>(*io);
        udpSocket->open(ep.protocol());
        // bind
        udpSocket->set_option(
            boost::asio::ip::udp::socket::reuse_address(true));
        udpSocket->bind(ep);
    }
    // SO_BINDTODEVICE
    char nameout[IFNAMSIZ];
    unsigned int lenout = sizeof(nameout);
    if ((::getsockopt(udpSocket->native_handle(), SOL_SOCKET, SO_BINDTODEVICE,
                      nameout, &lenout) == -1))
    {
        log<level::ERR>("Failed to read bound device",
                        entry("ERROR=%s", strerror(errno)));
    }
    if (iface != nameout && iface != unboundIface)
    {
        // SO_BINDTODEVICE
        if ((::setsockopt(udpSocket->native_handle(), SOL_SOCKET,
                          SO_BINDTODEVICE, iface.c_str(),
                          iface.size() + 1) == -1))
        {
            log<level::ERR>("Failed to bind to requested interface",
                            entry("ERROR=%s", strerror(errno)));
            return EXIT_FAILURE;
        }
        log<level::INFO>("Bind to interfae",
                         entry("INTERFACE=%s", iface.c_str()));
    }
    // cannot be constexpr because it gets passed by address
    const int option_enabled = 1;
    // common socket stuff; set options to get packet info (DST addr)
    ::setsockopt(udpSocket->native_handle(), IPPROTO_IP, IP_PKTINFO,
                 &option_enabled, sizeof(option_enabled));
    ::setsockopt(udpSocket->native_handle(), IPPROTO_IPV6, IPV6_RECVPKTINFO,
                 &option_enabled, sizeof(option_enabled));

    // set the dbus name
    std::string busName = "xyz.openbmc_project.Ipmi.Channel." + channel;
    try
    {
        bus->request_name(busName.c_str());
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to acquire D-Bus name",
                        entry("NAME=%s", busName.c_str()),
                        entry("ERROR=%s", e.what()));
        return EXIT_FAILURE;
    }
    return 0;
}

int EventLoop::startEventLoop()
{
    // set up boost::asio signal handling
    boost::asio::signal_set signals(*io, SIGINT, SIGTERM);
    signals.async_wait(
        [this](const boost::system::error_code& error, int signalNumber) {
            udpSocket->cancel();
            udpSocket->close();
            io->stop();
        });

    startRmcpReceive();

    io->run();

    return EXIT_SUCCESS;
}

} // namespace eventloop
