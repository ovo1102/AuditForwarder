// AuditForwarder - main entry point.
//
// Usage:
//   auditforwarderd [options]
//
// Options:
//   -c, --config <path>   Load configuration file (YAML or JSON)
//   -d, --data <dir>      Data directory
//   -l, --log <file>      Log file
//   -L, --level <level>   Log level: debug|info|notice|warning|error|critical
//       --no-manager      Disable the manager admin interface
//       --no-selfprotect  Disable self-protection
//       --install         Install as a system service (Linux systemd / Windows service)
//       --uninstall       Uninstall the system service
//       --version         Show version
//   -h, --help            Show help
//
// All settings can also be supplied via the configuration file.

#include "auditforwarder/agent.h"
#include "auditforwarder/process.h"
#include "auditforwarder/config.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/build_config.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <csignal>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

extern "C" int install_service(const std::string& data_dir, const std::string& config_path);
extern "C" int uninstall_service();

namespace {

void print_help() {
    std::cout <<
R"(AuditForwarder v1.0.0 - Enterprise Security Audit Agent

Usage:
  auditforwarderd [options]

Options:
  -c, --config <path>   Load configuration file (YAML or JSON)
  -d, --data <dir>      Data directory (default: /var/lib/auditforwarder or
                        C:\ProgramData\AuditForwarder)
  -l, --log <file>      Log file path
  -L, --level <level>   Log level: debug|info|notice|warning|error|critical
      --agent-id <id>   Set the agent identifier
      --server <url>    Server URL (can be repeated for failover)
      --no-manager      Disable the manager admin interface
      --no-selfprotect  Disable self-protection
      --install         Install as a system service
      --uninstall       Uninstall the system service
      --version         Show version information
  -h, --help            Show this help
)";
}

std::string get_arg(int argc, char** argv, int& i, const std::string& opt) {
    if (i + 1 >= argc) {
        std::cerr << "Missing argument for " << opt << "\n";
        std::exit(2);
    }
    return argv[++i];
}

}  // namespace

int main(int argc, char** argv) {
    using namespace af;

    AgentConfig cfg;
    cfg.agent_id = proc::hostname() + "-" + std::to_string(proc::current_pid());
    cfg.data_dir = AF_DEFAULT_DATA_DIR;
    cfg.config_path = AF_DEFAULT_CONFIG_PATH;

    bool do_install = false, do_uninstall = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { print_help(); return 0; }
        else if (a == "--version") {
            std::cout << "auditforwarderd " << AF_VERSION_STRING << "\n";
            return 0;
        }
        else if (a == "-c" || a == "--config") cfg.config_path = get_arg(argc, argv, i, a);
        else if (a == "-d" || a == "--data")   cfg.data_dir   = get_arg(argc, argv, i, a);
        else if (a == "-l" || a == "--log")    cfg.log_file   = get_arg(argc, argv, i, a);
        else if (a == "-L" || a == "--level")  cfg.log_level  = severity_from_string(get_arg(argc, argv, i, a));
        else if (a == "--agent-id")            cfg.agent_id   = get_arg(argc, argv, i, a);
        else if (a == "--server")              cfg.server_urls.push_back(get_arg(argc, argv, i, a));
        else if (a == "--no-manager")          cfg.manager_enabled = false;
        else if (a == "--no-selfprotect")      cfg.self_protect_enabled = false;
        else if (a == "--install")             do_install = true;
        else if (a == "--uninstall")           do_uninstall = true;
        else {
            std::cerr << "Unknown option: " << a << "\n";
            print_help();
            return 2;
        }
    }

    if (do_install)   return install_service(cfg.data_dir, cfg.config_path);
    if (do_uninstall) return uninstall_service();

    Agent agent;
    auto r = agent.init(cfg);
    if (r.is_err()) {
        std::cerr << "init failed: " << r.error().message() << "\n";
        return 1;
    }
    r = agent.start();
    if (r.is_err()) {
        std::cerr << "start failed: " << r.error().message() << "\n";
        return 1;
    }

    AF_LOG_INFO("auditforwarderd " << AF_VERSION_STRING << " running. Ctrl+C to stop.");

    // Idle main thread
    while (agent.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    agent.stop();
    return 0;
}
