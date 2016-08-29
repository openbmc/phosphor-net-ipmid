#pragma once

#include <tuple>

#include <command_table.hpp>
#include <sessions_manager.hpp>

extern std::tuple<session::Manager&, command::Table& > singletonPool;
