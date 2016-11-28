#pragma once

#include <tuple>

#include <command_table.hpp>
#include <sessions_manager.hpp>

extern std::tuple<session::Manager&, command::Table&> singletonPool;

// Select call timeout is set arbitarily set to 30 sec
static constexpr size_t SELECT_CALL_TIMEOUT = 30;
static const auto IPMI_STD_PORT = 623;
