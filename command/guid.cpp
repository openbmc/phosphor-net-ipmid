#include "guid.hpp"

#include <iostream>
#include <sstream>
#include <string>

#include <host-ipmid/ipmid-api.h>
#include <mapper.h>

void getSystemGUID(uint8_t* buffer, size_t numBytes)
{
    // Canned System GUID for QEMU where the Chassis DBUS object is not
    // populated
    uint8_t guid[BMC_GUID_LEN] = { 0x01, 0x02, 0x03, 0x04,
                                   0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0A, 0x0B, 0x0C,
                                   0x0D, 0x0E, 0x0F, 0x11
                                 };

    constexpr auto objname = "/org/openbmc/control/chassis0";
    constexpr auto iface = "org.freedesktop.DBus.Properties";
    constexpr auto chassis_iface = "org.openbmc.control.Chassis";

    sd_bus_message* reply = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus* bus = ipmid_get_sd_bus_connection();
    int r = 0;
    char* uuid = NULL;
    char* busname = NULL;
    int i = 0;
    int loc = 0;
    std::string readUUID;

    r = mapper_get_service(bus, objname, &busname);
    if (r < 0)
    {
        std::cerr << "Failed to get " << objname << " bus name: "
                  << strerror(-r) << "\n";
        goto finish;
    }

    r = sd_bus_call_method(bus, busname, objname, iface, "Get", &error, &reply,
                           "ss",
                           chassis_iface, "uuid");
    if (r < 0)
    {
        std::cerr << "Failed to call Get Method:" << strerror(-r) << "\n";
        goto finish;
    }

    r = sd_bus_message_read(reply, "v", "s", &uuid);
    if (r < 0 || uuid == NULL)
    {
        std::cerr << "Failed to get a response:" << strerror(-r) << "\n";
        goto finish;
    }

    readUUID.append(uuid);

    for (i = 0; i < readUUID.size(); i += 2)
    {
        char temp[2] = {0}; // Holder of the 2 chars that will become a byte
        strncpy(temp, &readUUID[i], 2); // 2 chars at a time

        auto loc = strtoul(temp, NULL, 16); // Convert to hex byte
        memcpy((void*)&guid[loc++], &loc, 1);
    }

finish:
    memcpy(buffer, &guid, numBytes);

    sd_bus_error_free(&error);
    reply = sd_bus_message_unref(reply);
    free(busname);
}
