#include "auditforwarder/agent.h"

#include "auditforwarder/chain.h"
#include "auditforwarder/config.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/manager.h"
#include "auditforwarder/processor.h"
#include "auditforwarder/process.h"
#include "auditforwarder/self_protect.h"
#include "auditforwarder/transport.h"
#include "auditforwarder/detector.h"
#ifdef AF_PLATFORM_LINUX
#  include "auditforwarder/platform_linux.h"
#endif
#ifdef AF_PLATFORM_WINDOWS
#  include "auditforwarder/platform_windows.h"
#endif

#include <chrono>
#include <csignal>
#include <fstream>
#include <sstream>

#ifdef AF_PLATFORM_WINDOWS
#  include <windows.h>
#endif

namespace af {

// 全局代理指针，用于信号处理
namespace {
Agent* g_agent = nullptr;
void on_signal(int sig) {
    if (g_agent) g_agent->stop();
    (void)sig;
}
}  // namespace

Agent::Agent() = default;
Agent::~Agent() { stop(); }

Result<void> Agent::init(const AgentConfig& cfg) {
    cfg_ = cfg;

    // 配置日志器
    LogConfig lcfg;
    lcfg.level       = cfg_.log_level;
    lcfg.file_path   = cfg_.log_file;
    lcfg.max_bytes   = cfg_.log_max_bytes;
    lcfg.targets     = static_cast<u8>(LogTarget::Console);
    if (!cfg_.log_file.empty()) {
        lcfg.targets = static_cast<u8>(static_cast<LogTarget>(lcfg.targets) | LogTarget::File);
    }
#ifdef AF_PLATFORM_UNIX
    lcfg.targets = static_cast<u8>(static_cast<LogTarget>(lcfg.targets) | LogTarget::Syslog);
#endif
    Logger::instance().configure(lcfg);

    // 确保数据目录存在
    if (!cfg_.data_dir.empty()) {
        auto r = fs::create_directories(cfg_.data_dir);
        if (r.is_err()) return r;
    }

    // Load config file if present
    if (!cfg_.config_path.empty() && fs::exists(cfg_.config_path)) {
        auto r = Config::instance().load_from_file(cfg_.config_path);
        if (r.is_err()) AF_LOG_WARN("config: load failed: " << r.error().message());
    }

    // 初始化链
    chain::ChainConfig cc;
    cc.data_dir      = cfg_.data_dir;
    cc.batch_size    = cfg_.chain_batch_size;
    cc.auto_persist  = true;
    chain_ = std::make_unique<chain::Chain>(cc);
    chain_->start();
    if (!cfg_.chain_signing_key.empty()) {
        auto kp = crypto::KeyPair::load_pem(cfg_.chain_signing_key);
        if (kp.is_ok()) chain_->set_signer(std::move(kp).value());
    } else if (!cfg_.chain_hmac_key.empty()) {
        chain_->set_hmac_key(cfg_.chain_hmac_key);
    }
    // Register batch callback to forward to the transport once it is set.
    chain_->on_batch([this](const chain::EventBatch& b) {
        if (transport_) transport_->send_batch(b);
    });

    // 构建默认处理器链
    processors_.emplace_back(std::make_unique<processor::Enricher>(proc::hostname(), cfg_.agent_id));
    processors_.emplace_back(std::make_unique<processor::PIIMasker>());
    processors_.emplace_back(std::make_unique<processor::Deduper>());

    // 检测器
    auto det = std::make_unique<detector::RuleEngine>();
    if (!cfg_.rules_path.empty() && fs::exists(cfg_.rules_path)) {
        auto r = det->load_rules(cfg_.rules_path);
        if (r.is_err()) AF_LOG_WARN("detector: " << r.error().message());
    } else {
        // Add a few sensible defaults
        detector::Rule r1;
        r1.id = "R-PROC-001";
        r1.name = "Sensitive file read";
        r1.severity = Severity::Warning;
        r1.categories = {"file"};
        r1.actions = {"read"};
        r1.path_match = {"/etc/shadow", "/etc/passwd", "/etc/sudoers", "C:\\\\Windows\\\\System32\\\\config\\\\SAM"};
        r1.responses = {"alert"};
        det->add_rule(r1);

        detector::Rule r2;
        r2.id = "R-NET-001";
        r2.name = "Outbound to suspicious TLD";
        r2.severity = Severity::Warning;
        r2.categories = {"network"};
        r2.actions = {"connect"};
        r2.path_match = {".*\\.(ru|cn|tk|xyz|top)$"};
        r2.responses = {"alert"};
        det->add_rule(r2);

        detector::Rule r3;
        r3.id = "R-CMD-001";
        r3.name = "Potential reverse shell";
        r3.severity = Severity::Critical;
        r3.categories = {"command"};
        r3.cmd_match = {"bash\\s+-i.*>&?\\s*/dev/tcp/", "nc\\s+-e\\s+/bin/bash", "nc\\s+-e\\s+/bin/sh", "python.*-c.*socket\\.socket"};
        r3.responses = {"alert", "kill"};
        det->add_rule(r3);
    }
    detector_ = std::move(det);

    // 传输模块
    TransportConfig tc;
    tc.server_urls     = cfg_.server_urls;
    tc.mode            = cfg_.transport_mode;
    tc.interval_sec    = cfg_.transport_interval_sec;
    tc.max_backoff_sec = cfg_.transport_max_backoff_sec;
    tc.compress        = cfg_.transport_compress;
    tc.encrypt_payload = cfg_.transport_encrypt;
    tc.client_cert     = cfg_.client_cert;
    tc.client_key      = cfg_.client_key;
    tc.ca_cert         = cfg_.ca_cert;
    tc.agent_id        = cfg_.agent_id;
    tc.data_dir        = cfg_.data_dir;
    transport_ = std::make_unique<HttpsTransport>(tc);

    // Self protect
    if (cfg_.self_protect_enabled) {
        SelfProtectConfig sp;
        sp.install_path     = fs::executable_path();
        sp.data_dir         = cfg_.data_dir;
        sp.config_path      = cfg_.config_path;
        sp.check_interval_sec = 5;
        sp.lock_files       = true;
        sp.watchdog         = true;
        self_protect_ = std::make_unique<DefaultSelfProtect>(sp);
    }

    // Manager
    if (cfg_.manager_enabled) {
        ManagerConfig mc;
        mc.listen     = cfg_.manager_listen;
        mc.auth_token = cfg_.manager_token;
        mc.data_dir   = cfg_.data_dir;
        manager_ = std::make_unique<SimpleHttpManager>(mc);
    }

    pool_.start(std::max<std::size_t>(4u, std::thread::hardware_concurrency()));
    AF_LOG_INFO("agent: init complete, id=" << cfg_.agent_id);
    return Result<void>::ok();
}

Result<void> Agent::start() {
    if (running_.exchange(true)) return Result<void>::ok();
    start_tp_ = Clock::now();

    // 构建平台特定的采集器
    std::vector<std::unique_ptr<Collector>> created;
    if (collectors_.empty()) {
#ifdef AF_PLATFORM_LINUX
        create_linux_collectors(created, *this);
#elif defined(AF_PLATFORM_WINDOWS)
        create_windows_collectors(created, *this);
#endif
        collectors_ = std::move(created);
    }
    for (auto& c : collectors_) {
        auto r = c->start(*this);
        if (r.is_err()) AF_LOG_ERROR("collector: " << c->name() << " start failed: " << r.error().message());
        else AF_LOG_INFO("collector: " << c->name() << " started");
    }

    if (self_protect_) {
        auto r = self_protect_->start(*this);
        if (r.is_err()) AF_LOG_ERROR("self_protect: " << r.error().message());
    }
    if (manager_) {
        auto r = manager_->start(*this);
        if (r.is_err()) AF_LOG_ERROR("manager: " << r.error().message());
    }
    if (detector_) detector_->start(*this);
    if (transport_) transport_->start(*this);

    install_signal_handlers();
    g_agent = this;

    AF_LOG_INFO("agent: started, collectors=" << collectors_.size());
    return Result<void>::ok();
}

void Agent::stop() {
    if (!running_.exchange(false)) return;
    AF_LOG_INFO("agent: stopping");
    if (transport_) transport_->stop();
    if (manager_)   manager_->stop();
    if (detector_)  detector_->stop();
    for (auto& c : collectors_) c->stop();
    if (self_protect_) self_protect_->stop();
    if (chain_) chain_->stop();
    pool_.shutdown(true);
    Logger::instance().flush();
}

void Agent::submit(AuditEvent& ev) {
    if (ev.host.empty())     ev.host     = proc::hostname();
    if (ev.agent_id.empty()) ev.agent_id = cfg_.agent_id;
    if (ev.actor.pid == 0)   ev.actor.pid = proc::current_pid();
    if (ev.actor.user.empty()) ev.actor.user = proc::current_username();

    // 运行处理器管道
    for (auto& p : processors_) {
        if (!p->process(ev)) {
            std::lock_guard<std::mutex> lk(stats_mtx_);
            stats_.events_dropped++;
            return;
        }
    }

    // 检测
    if (detector_ && !detector_->inspect(ev)) {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        stats_.events_dropped++;
        return;
    }
    if (!ev.rule_id.empty()) {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        stats_.alerts++;
    }

    // 添加到链
    if (chain_) chain_->submit(ev);
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        stats_.events_collected++;
    }

    // 转发到传输模块
    if (transport_ && !cfg_.server_urls.empty()) {
        // 批量转发由 chain.flush() 消费者完成
    }
}

void Agent::record_uploaded(u64 event_count, u64 bytes) {
    std::lock_guard<std::mutex> lk(stats_mtx_);
    stats_.events_uploaded += event_count;
    stats_.bytes_uploaded  += bytes;
}

void Agent::record_failed(u64 event_count) {
    std::lock_guard<std::mutex> lk(stats_mtx_);
    stats_.events_failed += event_count;
}

AgentStats Agent::stats() const {
    AgentStats s;
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        s = stats_;
    }
    s.started_at = start_tp_;
    if (running_.load()) {
        s.uptime_seconds = static_cast<u64>(
            std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - start_tp_).count());
    }
    return s;
}

Result<void> Agent::reload_config() {
    if (cfg_.config_path.empty()) return Result<void>(Error::Code::InvalidArgument, "no config path");
    return Config::instance().load_from_file(cfg_.config_path);
}

void Agent::install_signal_handlers() {
#ifdef AF_PLATFORM_UNIX
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
#endif
#ifdef AF_PLATFORM_WINDOWS
    SetConsoleCtrlHandler([](DWORD type) -> BOOL {
        if (g_agent) g_agent->stop();
        return TRUE;
    }, TRUE);
#endif
}

}  // namespace af
