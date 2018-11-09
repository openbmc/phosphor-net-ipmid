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
#include <host-ipmid/ipmid-api.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <unistd.h>

#include <iostream>
#include <sdbusplus/asio/connection.hpp>
#include <tuple>

// Tuple of Global Singletons
static auto io = std::make_shared<boost::asio::io_context>();
session::Manager manager;
command::Table table;
eventloop::EventLoop loop(io);
sol::Manager solManager(io);

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

int main()
{
    // Connect to system bus
    auto rc = sd_bus_default_system(&bus);
    if (rc < 0)
    {
        std::cerr << "Failed to connect to system bus:" << strerror(-rc)
                  << "\n";
        return rc;
    }

    sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus);

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
