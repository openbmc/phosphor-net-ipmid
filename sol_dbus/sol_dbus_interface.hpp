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

#pragma once

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/timer.hpp>
#include <xyz/openbmc_project/SOL/SOL/server.hpp>

constexpr const char* SOL_BUSNAME = "xyz.openbmc_project.Network.SOL";
constexpr const char* SOL_OBJPATH = "/xyz/openbmc_project/SOL";
constexpr const uint8_t userPrivilege = 2;

namespace sol
{

class DBusInterface : sdbusplus::xyz::openbmc_project::SOL::server::SOL
{
  public:
    DBusInterface() = delete;
    DBusInterface(const DBusInterface&) = delete;
    DBusInterface& operator=(const DBusInterface&) = delete;
    DBusInterface(DBusInterface&&) = delete;
    DBusInterface& operator=(DBusInterface&&) = delete;
    ~DBusInterface() = default;

    DBusInterface(sdbusplus::bus::bus& bus, const char* path) :
        sdbusplus::xyz::openbmc_project::SOL::server::SOL(bus, path)
    {
    }

    virtual uint8_t progress() const override;
    virtual uint8_t progress(uint8_t value) override;

    virtual bool enable() const override;
    virtual bool enable(bool value) override;

    virtual uint8_t authentication() const override;
    virtual uint8_t authentication(uint8_t value) override;

    virtual uint8_t accumulate() const override;
    virtual uint8_t accumulate(uint8_t value) override;

    virtual uint8_t threshold() const override;
    virtual uint8_t threshold(uint8_t value) override;

    virtual uint8_t retryCount() const override;
    virtual uint8_t retryCount(uint8_t value) override;

    virtual uint8_t retryInterval() const override;
    virtual uint8_t retryInterval(uint8_t value) override;

  private:
    uint8_t inProgress = 0;
    bool isEnable = true;
    uint8_t solMinPrivilege = userPrivilege;
    uint8_t accumulateInterval = 20; // 100ms
    uint8_t sendThreshold = 1;
    uint8_t retry = 7;
    uint8_t retryInter = 10; // 100ms
};

} // namespace sol
