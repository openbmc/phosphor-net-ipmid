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

namespace sol
{

using namespace phosphor::logging;

std::unique_ptr<sdbusplus::bus::match_t> matchPtrSOL(nullptr);

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

    // Register callback to close SOL session for disable SSH SOL
    if (matchPtrSOL == nullptr)
    {
        registerSOLServiceChangeCallback();
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
    std::shared_ptr<Context> context = Context::makeContext(
        io, retryCount, sendThreshold, payloadInstance, sessionID);

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

void Manager::stopAllPayloadInstance()
{
    // Erase all payload instance
    payloadMap.erase(payloadMap.begin(), payloadMap.end());

    stopHostConsole();

    dataBuffer.erase(dataBuffer.size());
}

void registerSOLServiceChangeCallback()
{
    using namespace sdbusplus::bus::match::rules;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
    try
    {
        auto servicePath = ipmi::getDbusObject(
            bus, "xyz.openbmc_project.Control.Service.Attributes",
            "/xyz/openbmc_project/control/service", "obmc_2dconsole");

        if (!std::empty(servicePath.first))
        {
            matchPtrSOL = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                path_namespace(servicePath.first) +
                    "arg0namespace='xyz.openbmc_project.Control.Service."
                    "Attributes'"
                    ", " +
                    type::signal() + member("PropertiesChanged") +
                    interface("org.freedesktop.DBus.Properties"),
                [](sdbusplus::message::message& msg) {
                    std::string intfName;
                    std::map<std::string, std::variant<bool>> properties;
                    msg.read(intfName, properties);

                    const auto it = properties.find("Enabled");
                    if (it != properties.end())
                    {
                        const bool* state = std::get_if<bool>(&it->second);

                        if (state != nullptr && *state == false)
                        {
                            // Stop all the payload session.
                            std::get<sol::Manager&>(singletonPool)
                                .stopAllPayloadInstance();
                        }
                    }
                });
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        log<level::ERR>(
            "Failed to get service path in registerSOLServiceChangeCallback");
    }
}

} // namespace sol
