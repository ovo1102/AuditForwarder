#include "auditforwarder/self_protect.h"

#include "auditforwarder/crypto.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

#include <fstream>
#include <sstream>

#ifdef AF_PLATFORM_UNIX
#  include <sys/stat.h>
#  include <unistd.h>
#  include <signal.h>
#  include <fcntl.h>
#endif
#ifdef AF_PLATFORM_WINDOWS
#  include <windows.h>
#  include <aclapi.h>
#endif

namespace af {

DefaultSelfProtect::DefaultSelfProtect(SelfProtectConfig cfg) : cfg_(std::move(cfg)) {}
DefaultSelfProtect::~DefaultSelfProtect() { stop(); }

Result<void> DefaultSelfProtect::start(Agent& agent) {
    agent_ = &agent;
    ensure_install_dir_protected();
    if (cfg_.install_path.empty()) cfg_.install_path = af::fs::executable_path();
    running_.store(true);
    thr_ = std::thread([this] { worker_loop(); });
    AF_LOG_INFO("self_protect: started, install=" << cfg_.install_path);
    return Result<void>::ok();
}

void DefaultSelfProtect::stop() {
    if (!running_.exchange(false)) return;
    if (thr_.joinable()) thr_.join();
}

void DefaultSelfProtect::ensure_install_dir_protected() {
    if (cfg_.install_path.empty() || !cfg_.lock_files) return;
#ifdef AF_PLATFORM_UNIX
    auto dir = af::fs::dirname(cfg_.install_path);
    // 为安装目录设置写保护模式（0555）
    ::chmod(dir.c_str(), S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
#endif
#ifdef AF_PLATFORM_WINDOWS
    // 在 Windows 上，获取安装目录的所有权，并通过 DACL 拒绝非管理员的写访问权限。
    // 这是尽力而为的操作。
    auto dir = af::fs::dirname(cfg_.install_path);
    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pDacl = nullptr;
    if (::GetNamedSecurityInfoA(const_cast<char*>(dir.c_str()), SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                &pDacl, nullptr, &pSD) == ERROR_SUCCESS) {
        // 注意：此处简化处理 — 生产代码应构建新的 DACL，
        // 拒绝除 SYSTEM 和当前用户之外所有人的写入权限。
        if (pSD) ::LocalFree(pSD);
    }
#endif
}

bool DefaultSelfProtect::check_integrity() {
    if (cfg_.install_path.empty()) return true;
    std::ifstream in(cfg_.install_path, std::ios::binary);
    if (!in) return true;  // 无法检查；假设正常
    std::ostringstream ss; ss << in.rdbuf();
    auto hash = crypto::sha256_hex(ss.str());
    if (!cfg_.known_good_hash.empty() && hash != cfg_.known_good_hash) {
        AF_LOG_CRITICAL("self_protect: integrity hash mismatch! computed="
                          << hash << " expected=" << cfg_.known_good_hash);
        return false;
    }
    last_audit_hash_ = hash;
    return true;
}

void DefaultSelfProtect::reexec_if_needed() {
    // In production, this would re-execute ourselves as a fresh process
    // if the binary on disk has been replaced and the signature is valid.
    // For now, simply count invocations.
    ++restart_count_;
}

void DefaultSelfProtect::worker_loop() {
    using namespace std::chrono;
    while (running_.load()) {
        bool ok = check_integrity();
        healthy_.store(ok);
        if (!ok && cfg_.watchdog) {
            reexec_if_needed();
        }
        // 休眠，但在停止时唤醒
        for (int i = 0; i < cfg_.check_interval_sec * 10 && running_.load(); ++i) {
            std::this_thread::sleep_for(milliseconds(100));
        }
    }
}

std::string DefaultSelfProtect::status() const {
    std::ostringstream o;
    o << "{"
      << "\"healthy\":" << (healthy_.load() ? "true" : "false") << ","
      << "\"install_path\":\"" << cfg_.install_path << "\","
      << "\"last_hash\":\"" << last_audit_hash_ << "\","
      << "\"restart_count\":" << restart_count_
      << "}";
    return o.str();
}

}  // namespace af
