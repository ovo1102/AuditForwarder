#pragma once
// AuditForwarder - 核心代理，整合采集器、处理器、链和传输模块。

#include "auditforwarder/event.h"
#include "auditforwarder/chain.h"
#include "auditforwarder/thread_pool.h"
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace af {

// 前置声明
class Collector;
class Processor;
class Transport;
class Detector;
class ManagerServer;
class SelfProtect;

struct AgentConfig {
    std::string agent_id;
    std::string data_dir;
    std::string config_path;

    // 日志配置
    Severity    log_level { Severity::Info };
    std::string log_file;
    std::size_t log_max_bytes { 50 * 1024 * 1024 };

    // 链配置
    std::size_t chain_batch_size { 256 };
    std::string chain_signing_key;     // PEM 格式
    std::string chain_hmac_key;        // 备选方案

    // 传输配置
    std::vector<std::string> server_urls;
    std::string transport_mode {"realtime"}; // realtime | batch
    int transport_interval_sec { 30 };
    int transport_max_backoff_sec { 600 };
    bool transport_compress { true };
    bool transport_encrypt { true };
    std::string client_cert;
    std::string client_key;
    std::string ca_cert;

    // 自我保护
    bool self_protect_enabled { true };

    // 管理后台接口
    bool manager_enabled { true };
    std::string manager_listen {"127.0.0.1:8443"};
    std::string manager_token;

    // 检测规则
    std::string rules_path;

    // 隐藏安装 / 系统级操作
    bool elevate_required { false };
};

struct AgentStats {
    u64 events_collected { 0 };
    u64 events_dropped   { 0 };
    u64 events_uploaded  { 0 };
    u64 events_failed    { 0 };
    u64 alerts           { 0 };
    u64 bytes_uploaded   { 0 };
    u64 uptime_seconds   { 0 };
    TimePoint started_at;
};

class Agent {
public:
    Agent();
    ~Agent();

    // 加载配置、准备目录等。必须在 start() 之前调用。
    Result<void> init(const AgentConfig& cfg);

    // 启动所有子系统
    Result<void> start();
    void         stop();
    bool         is_running() const { return running_.load(); }

    // 直接事件注入（由采集器和 IPC 使用）
    void submit(AuditEvent& ev);

    // 记录成功批量上传
    void record_uploaded(u64 event_count, u64 bytes);

    // 记录失败批量上传
    void record_failed(u64 event_count);

    // 获取运行时统计信息
    AgentStats stats() const;

    // 从磁盘重新加载配置
    Result<void> reload_config();

    // 访问子系统
    chain::Chain&          chain_module()   { return *chain_; }
    ThreadPool&            pool()           { return pool_; }

private:
    void install_signal_handlers();

    AgentConfig             cfg_;
    std::atomic<bool>       running_ { false };
    std::atomic<bool>       stopping_{ false };
    TimePoint               start_tp_;
    mutable std::mutex              stats_mtx_;
    AgentStats             stats_;

    ThreadPool              pool_;
    std::unique_ptr<chain::Chain>          chain_;
    std::vector<std::unique_ptr<Collector>> collectors_;
    std::vector<std::unique_ptr<Processor>> processors_;
    std::unique_ptr<Transport>              transport_;
    std::unique_ptr<Detector>               detector_;
    std::unique_ptr<ManagerServer>          manager_;
    std::unique_ptr<SelfProtect>            self_protect_;
};

// ---- 采集器基类 ----
class Collector {
public:
    virtual ~Collector() = default;
    virtual Result<void> start(class Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual std::string  name() const = 0;
    virtual EventCategory category() const = 0;
    virtual bool         is_running() const = 0;
};

// ---- 处理器基类（过滤/增强/聚合）----
class Processor {
public:
    virtual ~Processor() = default;
    // 返回 true 保留事件，返回 false 丢弃事件。
    virtual bool process(AuditEvent& ev) = 0;
    virtual std::string name() const = 0;
};

// ---- 传输模块（前置声明）----
class Transport {
public:
    virtual ~Transport() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual Result<void> send_batch(const chain::EventBatch& b) = 0;
    virtual bool         is_running() const = 0;
    virtual std::string  name() const = 0;
};

// ---- 检测器（前置声明）----
class Detector {
public:
    virtual ~Detector() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    // 检查新创建的事件；可以修改事件（如添加 rule_id、severity）
    // 并排队自动响应。返回 false 将事件从管道中丢弃。
    virtual bool         inspect(AuditEvent& ev) = 0;
    virtual std::string  name() const = 0;
};

// ---- 自我保护（前置声明）----
class SelfProtect {
public:
    virtual ~SelfProtect() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual bool         healthy() const = 0;
    virtual std::string  status() const = 0;
};

// ---- 管理服务器（前置声明）----
class ManagerServer {
public:
    virtual ~ManagerServer() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual std::string  endpoint() const = 0;
};

}  // namespace af
