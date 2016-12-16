#include "guid.hpp"

#include <iostream>
#include <sstream>
#include <string>

#include <host-ipmid/ipmid-api.h>
#include <mapper.h>

namespace command
{

std::array<uint8_t, BMC_GUID_LEN> getSystemGUID()
{
    // Canned System GUID for QEMU where the Chassis DBUS object is not
    // populated
    std::array<uint8_t, BMC_GUID_LEN> guid = { 0x01, 0x02, 0x03, 0x04,
                                               0x05, 0x06, 0x07, 0x08,
                                               0x09, 0x0A, 0x0B, 0x0C,
                                               0x0D, 0x0E, 0x0F, 0x10
                                             };

    constexpr auto objname = "/org/openbmc/control/chassis0";
    constexpr auto interface = "org.freedesktop.DBus.Properties";
    constexpr auto chassisIntf = "org.openbmc.control.Chassis";

    sd_bus_message* reply = nullptr;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus* bus = ipmid_get_sd_bus_connection();
    int rc = 0;
    char* uuid = nullptr;
    char* busname = nullptr;

    do
    {
        rc = mapper_get_service(bus, objname, &busname);
        if (rc < 0)
        {
            std::cerr << "Failed to get " << objname << " bus name: "
                      << strerror(-rc) << "\n";
            break;
        }

        rc = sd_bus_call_method(bus, busname, objname, interface, "Get", &error,
                                &reply, "ss", chassisIntf, "uuid");
        if (rc < 0)
        {
            std::cerr << "Failed to call Get Method:" << strerror(-rc) << "\n";
            break;
        }

        rc = sd_bus_message_read(reply, "v", "s", &uuid);
        if (rc < 0 || uuid == NULL)
        {
            std::cerr << "Failed to get a response:" << strerror(-rc) << "\n";
            break;
        }

        std::string readUUID(uuid);
        auto len = readUUID.length();

        for (size_t iter = 0, inc = 0;
             iter < len && inc < BMC_GUID_LEN; iter += 2, inc++)
        {
            uint8_t hexVal = std::strtoul(readUUID.substr(iter, 2).c_str(),
                                          NULL, 16);
            guid[inc] = hexVal;
        }
    }
    while (0);

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);

    return guid;
}

} // namespace command
