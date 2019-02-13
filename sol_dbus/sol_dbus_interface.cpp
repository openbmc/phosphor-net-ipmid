/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "sol_dbus_interface.hpp"

namespace sol
{

uint8_t DBusInterface::progress(uint8_t value)
{
    inProgress = value;
    return sdbusplus::xyz::openbmc_project::SOL::server::SOL::progress(value);
}

uint8_t DBusInterface::progress() const
{
    return inProgress;
}

bool DBusInterface::enable(bool value)
{
    isEnable = value;
    return sdbusplus::xyz::openbmc_project::SOL::server::SOL::enable(value);
}

bool DBusInterface::enable() const
{
    return isEnable;
}

uint8_t DBusInterface::authentication(uint8_t value)
{
    solMinPrivilege = value;
    return sdbusplus::xyz::openbmc_project::SOL::server::SOL::authentication(
        value);
}

uint8_t DBusInterface::authentication() const
{
    return solMinPrivilege;
}

uint8_t DBusInterface::accumulate(uint8_t value)
{
    accumulateInterval = value;
    return sdbusplus::xyz::openbmc_project::SOL::server::SOL::accumulate(value);
}

uint8_t DBusInterface::accumulate() const
{
    return accumulateInterval;
}

uint8_t DBusInterface::threshold(uint8_t value)
{
    sendThreshold = value;
    return sdbusplus::xyz::openbmc_project::SOL::server::SOL::threshold(value);
}

uint8_t DBusInterface::threshold() const
{
    return sendThreshold;
}

uint8_t DBusInterface::retryCount(uint8_t value)
{
    retry = value;
    return sdbusplus::xyz::openbmc_project::SOL::server::SOL::retryCount(value);
}

uint8_t DBusInterface::retryCount() const
{
    return retry;
}

uint8_t DBusInterface::retryInterval(uint8_t value)
{
    retryInter = value;
    return sdbusplus::xyz::openbmc_project::SOL::server::SOL::retryInterval(
        value);
}

uint8_t DBusInterface::retryInterval() const
{
    return retryInter;
}

} // namespace sol
