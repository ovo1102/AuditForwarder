#pragma once
// Windows platform entry: forwards the create function for agent startup.

#include "auditforwarder/agent.h"
#include <vector>
#include <memory>

namespace af {

void create_windows_collectors(std::vector<std::unique_ptr<Collector>>& out, Agent& /*agent*/);

}  // namespace af
