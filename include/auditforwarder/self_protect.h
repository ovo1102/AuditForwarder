#pragma once
// AuditForwarder - 自我保护：完整性检查、看门狗、防篡改。

#include "auditforwarder/agent.h"
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace af {

struct SelfProtectConfig {
    std::string install_path;        // 代理二进制文件路径
    std::string data_dir;
    std::string config_path;
    std::string known_good_hash;     // 二进制文件的预期 SHA-256
    std::string policy_path;         // 包含关键进程路径的文件
    std::vector<std::string> watch_processes;
    int         check_interval_sec { 5 };
    bool        lock_files          { true };
    bool        watchdog            { true };
};

class DefaultSelfProtect : public SelfProtect {
public:
    explicit DefaultSelfProtect(SelfProtectConfig cfg);
    ~DefaultSelfProtect() override;
    Result<void> start(Agent& agent) override;
    void         stop() override;
    bool         healthy() const override { return healthy_.load(); }
    std::string  status() const override;

private:
    void worker_loop();
    bool check_integrity();
    void ensure_install_dir_protected();
    void reexec_if_needed();

    SelfProtectConfig       cfg_;
    std::atomic<bool>       running_ { false };
    std::atomic<bool>       healthy_ { true };
    std::thread             thr_;
    Agent*                  agent_   { nullptr };
    int                     restart_count_ { 0 };
    std::string             last_audit_hash_;
};

}  // namespace af
