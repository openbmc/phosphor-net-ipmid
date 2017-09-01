#pragma once

#include <cstddef>
#include <vector>

#include "comm_module.hpp"

namespace command
{

constexpr size_t BMC_GUID_LEN = 16;

using Guid = std::array<uint8_t, BMC_GUID_LEN>;

/**
 * @brief Get System GUID
 *
 * @return If UUID is successfully read from the Chassis DBUS object, then the
 *         GUID is returned, else a canned GUID is returned
 */
Guid getSystemGUID();

} // namespace command
