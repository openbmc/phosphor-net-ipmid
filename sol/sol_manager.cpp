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
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>

constexpr const char* solInterface = "xyz.openbmc_project.Network.SOL";
constexpr const char* solPath = "/xyz/openbmc_project/network/host0/sol";
constexpr const char* PROP_INTF = "org.freedesktop.DBus.Properties";
constexpr const char* METHOD_GET = "Get";

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
}

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

    auto mapperResponseMsg = bus.call(mapperCall);

    if (mapperResponseMsg.is_method_error())
    {
        throw std::runtime_error("ERROR in mapper call");
    }

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        throw std::runtime_error("ERROR in reading the mapper response");
    }

    return mapperResponse.begin()->first;
}

std::variant<uint8_t, bool> getDbusProperty(sdbusplus::bus::bus& bus,
                                            const std::string& service,
                                            const std::string& objPath,
                                            const std::string& interface,
                                            const std::string& property)
{
    std::variant<uint8_t, bool> value;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, METHOD_GET);

    method.append(interface, property);

    auto reply = bus.call(method);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to get property",
                        entry("PROPERTY=%s", property.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
    }

    reply.read(value);

    return value;
}

void Manager::updateSOLParameter()
{
    std::variant<uint8_t, bool> value;
    sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());
    static std::string solService{};
    if (solService.empty())
    {
        try
        {
            solService = getService(dbus, solInterface, solPath);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            solService.clear();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error: get SOL service failed");
            return;
        }
    }
    try
    {
        value = getDbusProperty(dbus, solService, solPath, solInterface,
                                "Progress");
        progress = std::get<uint8_t>(value);

        value =
            getDbusProperty(dbus, solService, solPath, solInterface, "Enable");
        enable = std::get<bool>(value);

        value = getDbusProperty(dbus, solService, solPath, solInterface,
                                "Authentication");
        solMinPrivilege =
            static_cast<session::Privilege>(std::get<uint8_t>(value));

        value = getDbusProperty(dbus, solService, solPath, solInterface,
                                "Accumulate");
        accumulateInterval =
            std::get<uint8_t>(value) * sol::accIntervalFactor * 1ms;

        value = getDbusProperty(dbus, solService, solPath, solInterface,
                                "Threshold");
        sendThreshold = std::get<uint8_t>(value);

        value = getDbusProperty(dbus, solService, solPath, solInterface,
                                "RetryCount");
        retryCount = std::get<uint8_t>(value);

        value = getDbusProperty(dbus, solService, solPath, solInterface,
                                "RetryInterval");
        retryInterval =
            std::get<uint8_t>(value) * sol::retryIntervalFactor * 1ms;
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error setting sol parameter");
    }
    return;
}

void Manager::startPayloadInstance(uint8_t payloadInstance,
                                   session::SessionID sessionID)
{
    if (payloadMap.empty())
    {
        startHostConsole();
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
