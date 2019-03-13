#include "main.hpp"

#include "comm_module.hpp"
#include "command/guid.hpp"
#include "command_table.hpp"
#include "message.hpp"
#include "message_handler.hpp"
#include "socket_channel.hpp"
#include "sol_module.hpp"

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <ipmid/api.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <unistd.h>

#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/timer.hpp>
#include <tuple>

using namespace phosphor::logging;

// Tuple of Global Singletons
static auto io = std::make_shared<boost::asio::io_context>();
session::Manager manager;
command::Table table;
eventloop::EventLoop loop(io);
sol::Manager solManager(io);

// D-Bus root for session manager
constexpr auto SESSION_MANAGER_ROOT = "/xyz/openbmc_project/Session";

std::tuple<session::Manager&, command::Table&, eventloop::EventLoop&,
           sol::Manager&>
    singletonPool(manager, table, loop, solManager);

sd_bus* bus = nullptr;

std::shared_ptr<sdbusplus::asio::connection> sdbusp;

/*
 * @brief Required by apphandler IPMI Provider Library
 */
sd_bus* ipmid_get_sd_bus_connection()
{
    return bus;
}

/*
 * @brief mechanism to get at sdbusplus object
 */
std::shared_ptr<sdbusplus::asio::connection> getSdBus()
{
    return sdbusp;
}

EInterfaceIndex getInterfaceIndex(void)
{
    return interfaceLAN1;
}

int main()
{
    // Connect to system bus
    auto rc = sd_bus_default_system(&bus);
    if (rc < 0)
    {
        log<level::ERR>("Failed to connect to system bus",
                        entry("ERROR=%s", strerror(-rc)));
        return rc;
    }

    sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus);
    auto objManager = std::make_unique<sdbusplus::server::manager::manager>(
        *sdbusp, SESSION_MANAGER_ROOT);
    rc = sd_bus_request_name(bus, "xyz.openbmc_project.netipmid", 0);
    if (rc < 0)
    {
        log<level::ERR>("Failure in bus request",
                        entry("ERROR=%s", strerror(-rc)));
        return EXIT_FAILURE;
    }

    // Register callback to update cache for a GUID change and cache the GUID
    command::registerGUIDChangeCallback();
    cache::guid = command::getSystemGUID();

    // Register the phosphor-net-ipmid session setup commands
    command::sessionSetupCommands();

    // Register the phosphor-net-ipmid SOL commands
    sol::command::registerCommands();

    // Start Event Loop
    return std::get<eventloop::EventLoop&>(singletonPool).startEventLoop();
}
