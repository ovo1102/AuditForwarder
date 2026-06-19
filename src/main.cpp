// AuditForwarder - 主入口点。
//
// 用法:
//   auditforwarderd [选项]
//
// 选项:
//   -c, --config <path>   加载配置文件 (YAML 或 JSON)
//   -d, --data <dir>      数据目录
//   -l, --log <file>      日志文件
//   -L, --level <level>   日志级别: debug|info|notice|warning|error|critical
//       --no-manager      禁用管理后台接口
//       --no-selfprotect  禁用自我保护
//       --install         安装为系统服务 (Linux systemd / Windows 服务)
//       --uninstall       卸载系统服务
//       --version         显示版本
//   -h, --help            显示帮助
//
// 所有设置也可以通过配置文件提供。

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
R"(AuditForwarder v1.0.0 - 企业级安全审计代理

用法:
  auditforwarderd [选项]

选项:
  -c, --config <path>   加载配置文件 (YAML 或 JSON)
  -d, --data <dir>      数据目录 (默认: /var/lib/auditforwarder 或
                        C:\ProgramData\AuditForwarder)
  -l, --log <file>      日志文件路径
  -L, --level <level>   日志级别: debug|info|notice|warning|error|critical
      --agent-id <id>   设置代理标识符
      --server <url>    服务器 URL (可重复指定用于故障转移)
      --no-manager      禁用管理后台接口
      --no-selfprotect  禁用自我保护
      --install         安装为系统服务
      --uninstall       卸载系统服务
      --version         显示版本信息
  -h, --help            显示此帮助
)";
}

std::string get_arg(int argc, char** argv, int& i, const std::string& opt) {
    if (i + 1 >= argc) {
        std::cerr << "选项 " << opt << " 缺少参数\n";
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
            std::cerr << "未知选项: " << a << "\n";
            print_help();
            return 2;
        }
    }

    if (do_install)   return install_service(cfg.data_dir, cfg.config_path);
    if (do_uninstall) return uninstall_service();

    Agent agent;
    auto r = agent.init(cfg);
    if (r.is_err()) {
        std::cerr << "初始化失败: " << r.error().message() << "\n";
        return 1;
    }
    r = agent.start();
    if (r.is_err()) {
        std::cerr << "启动失败: " << r.error().message() << "\n";
        return 1;
    }

    AF_LOG_INFO("auditforwarderd " << AF_VERSION_STRING << " 正在运行。按 Ctrl+C 停止。");

    // 主线程空闲等待
    while (agent.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    agent.stop();
    return 0;
}
