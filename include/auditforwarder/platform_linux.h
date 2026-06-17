#pragma once
// Linux platform entry: forwards the create function for agent startup.

#include "auditforwarder/agent.h"
#include <vector>
#include <memory>

namespace af::collector {
class LinuxFileCollector;
class LinuxProcessCollector;
class LinuxNetworkCollector;
class LinuxCommandCollector;
class LinuxAuditCollector;
}

namespace af {

inline void create_linux_collectors(std::vector<std::unique_ptr<Collector>>& out, Agent& /*agent*/) {
    out.emplace_back(std::make_unique<af::collector::LinuxFileCollector>());
    out.emplace_back(std::make_unique<af::collector::LinuxProcessCollector>());
    out.emplace_back(std::make_unique<af::collector::LinuxNetworkCollector>());
    out.emplace_back(std::make_unique<af::collector::LinuxCommandCollector>());
    out.emplace_back(std::make_unique<af::collector::LinuxAuditCollector>());
}

}  // namespace af
