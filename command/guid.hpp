#pragma once

#include <cstddef>

#include "comm_module.hpp"

constexpr size_t BMC_GUID_LEN = 16;

/*
 * @brief Get System GUID
 *
 * @param[in] buffer - Buffer to be populated with the GUID
 * @param[in] numBytes - The number of bytes allotted for populating GUID
 *
 * @return If UUID is successfully read from the Chassis DBUS object, then the
 *         buffer is populated with GUID.
 */
void getSystemGUID(uint8_t* buffer, size_t numBytes = BMC_GUID_LEN);
