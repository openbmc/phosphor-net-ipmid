#include "sol_manager.hpp"

#include "main.hpp"
#include "sol_context.hpp"

#include <sys/socket.h>
#include <sys/un.h>

#include <boost/asio/basic_stream_socket.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/write.hpp>
#include <chrono>
#include <cmath>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>

constexpr const char* solInterface = "xyz.openbmc_project.Ipmi.SOL";
constexpr const char* solPath = "/xyz/openbmc_project/ipmi/sol/";
constexpr const char* PROP_INTF = "org.freedesktop.DBus.Properties";

namespace sol
{

using namespace phosphor::logging;

void Manager::initConsoleSocket()
{
    // explicit length constructor for NUL-prefixed abstract path
    std::string path(CONSOLE_SOCKET_PATH, CONSOLE_SOCKET_PATH_LEN);
    boost::asio::local::stream_protocol::endpoint ep(path);
    consoleSocket =
        std::make_unique<boost::asio::local::stream_protocol::socket>(*io);
    consoleSocket->connect(ep);
}

void Manager::consoleInputHandler()
{
    boost::system::error_code ec;
    boost::asio::socket_base::bytes_readable cmd(true);
    consoleSocket->io_control(cmd, ec);
    size_t readSize;
    if (!ec)
    {
        readSize = cmd.get();
    }
    else
    {
        log<level::ERR>("Reading ready count from host console socket failed:",
                        entry("EXCEPTION=%s", ec.message().c_str()));
        return;
    }
    std::vector<uint8_t> buffer(readSize);
    ec.clear();
    size_t readDataLen =
        consoleSocket->read_some(boost::asio::buffer(buffer), ec);
    if (ec)
    {
        log<level::ERR>("Reading from host console socket failed:",
                        entry("EXCEPTION=%s", ec.message().c_str()));
        return;
    }

    // Update the Console buffer with data read from the socket
    buffer.resize(readDataLen);
    dataBuffer.write(buffer);
}

int Manager::writeConsoleSocket(const std::vector<uint8_t>& input) const
{
    boost::system::error_code ec;
    boost::asio::write(*consoleSocket, boost::asio::buffer(input), ec);
    return ec.value();
}

void Manager::startHostConsole()
{
    if (!consoleSocket)
    {
        initConsoleSocket();
    }
    consoleSocket->async_wait(boost::asio::socket_base::wait_read,
                              [this](const boost::system::error_code& ec) {
                                  if (!ec)
                                  {
                                      consoleInputHandler();
                                      startHostConsole();
                                  }
                              });
} // namespace sol

void Manager::stopHostConsole()
{
    if (consoleSocket)
    {
        consoleSocket->cancel();
        consoleSocket.reset();
    }
}

std::string getService(sdbusplus::bus::bus& bus, const std::string& intf,
                       const std::string& path)
{
    auto mapperCall =
        bus.new_method_call("xyz.openbmc_project.ObjectMapper",
                            "/xyz/openbmc_project/object_mapper",
                            "xyz.openbmc_project.ObjectMapper", "GetObject");

    mapperCall.append(path);
    mapperCall.append(std::vector<std::string>({intf}));

    std::map<std::string, std::vector<std::string>> mapperResponse;

    try
    {
        auto mapperResponseMsg = bus.call(mapperCall);
        mapperResponseMsg.read(mapperResponse);
    }
    catch (sdbusplus::exception_t&)
    {
        throw std::runtime_error("ERROR in mapper call");
    }

    if (mapperResponse.begin() == mapperResponse.end())
    {
        throw std::runtime_error("ERROR in reading the mapper response");
    }

    return mapperResponse.begin()->first;
}

ipmi::PropertyMap getAllDbusProperties(sdbusplus::bus::bus& bus,
                                       const std::string& service,
                                       const std::string& objPath,
                                       const std::string& interface)
{
    ipmi::PropertyMap properties;

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), objPath.c_str(), PROP_INTF, "GetAll");

    method.append(interface);

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(properties);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get all properties",
            phosphor::logging::entry("PATH=%s", objPath.c_str()),
            phosphor::logging::entry("INTERFACE=%s", interface.c_str()));
        throw std::runtime_error("ERROR in reading proerties");
    }

    return properties;
}

void Manager::updateSOLParameter(uint8_t channelNum)
{
    std::variant<uint8_t, bool> value;
    sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());
    static std::string solService{};
    ipmi::PropertyMap properties;
    std::string ethdevice = ipmi::getChannelName(channelNum);
    std::string solPathWitheEthName = solPath + ethdevice;
    if (solService.empty())
    {
        try
        {
            solService = getService(dbus, solInterface, solPathWitheEthName);
        }
        catch (const std::runtime_error& e)
        {
            solService.clear();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error: get SOL service failed");
            return;
        }
    }
    try
    {
        properties = getAllDbusProperties(dbus, solService, solPathWitheEthName,
                                          solInterface);
    }
    catch (const std::runtime_error&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error setting sol parameter");
        return;
    }

    progress = std::get<uint8_t>(properties["Progress"]);

    enable = std::get<bool>(properties["Enable"]);

    forceEncrypt = std::get<bool>(properties["ForceEncryption"]);

    forceAuth = std::get<bool>(properties["ForceAuthentication"]);

    solMinPrivilege = static_cast<session::Privilege>(
        std::get<uint8_t>(properties["Privilege"]));

    accumulateInterval =
        std::get<uint8_t>((properties["AccumulateIntervalMS"])) *
        sol::accIntervalFactor * 1ms;

    sendThreshold = std::get<uint8_t>(properties["Threshold"]);

    retryCount = std::get<uint8_t>(properties["RetryCount"]);

    retryInterval = std::get<uint8_t>(properties["RetryIntervalMS"]) *
                    sol::retryIntervalFactor * 1ms;

    return;
}

void Manager::startPayloadInstance(uint8_t payloadInstance,
                                   session::SessionID sessionID)
{
    if (payloadMap.empty())
    {
        try
        {
            startHostConsole();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Encountered exception when starting host console. "
                            "Hence stopping host console.",
                            entry("EXCEPTION=%s", e.what()));
            stopHostConsole();
            throw;
        }
    }

    // Create the SOL Context data for payload instance
    auto context = std::make_unique<Context>(io, retryCount, sendThreshold,
                                             payloadInstance, sessionID);

    payloadMap.emplace(payloadInstance, std::move(context));
}

void Manager::stopPayloadInstance(uint8_t payloadInstance)
{
    auto iter = payloadMap.find(payloadInstance);
    if (iter == payloadMap.end())
    {
        throw std::runtime_error("SOL Payload instance not found ");
    }

    payloadMap.erase(iter);

    if (payloadMap.empty())
    {
        stopHostConsole();

        dataBuffer.erase(dataBuffer.size());
    }
}

} // namespace sol
