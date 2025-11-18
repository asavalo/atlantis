// This file is part of the SymCC runtime.
//
// The SymCC runtime is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// The SymCC runtime is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the SymCC runtime. If not, see <https://www.gnu.org/licenses/>.

#include "Config.h"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>

#include <fcntl.h>

namespace {

bool checkFlagString(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  if (value == "1" || value == "on" || value == "yes")
    return true;

  if (value.empty() || value == "0" || value == "off" || value == "no")
    return false;

  std::stringstream msg;
  msg << "Unknown flag value " << value;
  throw std::runtime_error(msg.str());
}

} // namespace

Config g_config;

void loadConfig() {
  // always make input memory input
  g_config.input = MemoryInput{};

  auto *garbageCollectionThreshold = getenv("SYMCC_GC_THRESHOLD");
  if (garbageCollectionThreshold != nullptr) {
    try {
      g_config.garbageCollectionThreshold =
          std::stoul(garbageCollectionThreshold);
    } catch (std::invalid_argument &) {
      std::stringstream msg;
      msg << "Can't convert " << garbageCollectionThreshold << " to an integer";
      throw std::runtime_error(msg.str());
    } catch (std::out_of_range &) {
      std::stringstream msg;
      msg << "The GC threshold must be between 0 and "
          << std::numeric_limits<size_t>::max();
      throw std::runtime_error(msg.str());
    }
  }

  auto *fullTrace = getenv("SYMCC_ENABLE_FULL_TRACE");
  if (fullTrace != nullptr)
    g_config.fullTrace = checkFlagString(fullTrace);
  if (g_config.fullTrace) {
    // If full trace is enabled, SYMCC_SEMAPHORE must also be set
    auto *semName = getenv("SYMCC_SEM_KEY");
    if (semName == nullptr) {
      std::cerr << "SYMCC_SEM_KEY must be set when SYMCC_ENABLE_FULL_TRACE is "
                   "enabled"
                << std::endl;
      exit(1);
    }
    g_config.semName = semName;
  }
  auto *symbolizeDataLength = getenv("SYMCC_SYMBOLIZE_DATA_LENGTH");
  if (symbolizeDataLength != nullptr)
    g_config.symbolizeDataLength = checkFlagString(symbolizeDataLength);
}
