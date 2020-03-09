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
            solService =
                ipmi::getService(dbus, solInterface, solPathWitheEthName);
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
        properties = ipmi::getAllDbusProperties(
            dbus, solService, solPathWitheEthName, solInterface);
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
