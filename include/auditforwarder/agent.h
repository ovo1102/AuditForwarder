#pragma once
// AuditForwarder - 核心代理，整合采集器、处理器、链和传输模块。

#include "auditforwarder/collector_filter.h"
#include "auditforwarder/event.h"
#include "auditforwarder/chain.h"
#include "auditforwarder/security_adapter.h"
#include "auditforwarder/thread_pool.h"
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace af {

// 前置声明
class Collector;
class Processor;
class Transport;
class Detector;
class ManagerServer;
class SelfProtect;
class RemoteAgentClient;

struct AgentConfig {
    std::string agent_id;
    std::string data_dir;
    std::string config_path;

    // 操作员身份贯通（M5）：本机操作员标识与显示名，随心跳/事件/日志上报，
    // 服务端据此登记「操作员 ↔ 主机」绑定关系（operators 台账）。
    std::string operator_id;
    std::string operator_name;

    // 日志配置
    Severity    log_level { Severity::Info };
    std::string log_file;
    std::size_t log_max_bytes { 50 * 1024 * 1024 };

    // 链配置
    std::size_t chain_batch_size { 256 };
    std::string chain_signing_key;     // PEM 格式
    std::string chain_hmac_key;        // 备选方案
    std::size_t chain_super_batch_k { 8 };  // 超级批次容量（0=禁用）
    // 是否把批次落盘到 <data_dir>/batches。
    // 注意：开着它时，如果本机文件采集器也在采 data_dir，就会出现
    //   采集事件 -> 落盘 -> 文件采集器采到这次写入 -> 再落盘
    // 的自激回路（实测每秒数百批，真实业务事件会被淹没，表现为合谋告警迟迟不出）。
    // 实验机应显式设为 false。
    bool chain_auto_persist { true };

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
    std::string transport_auth_token;
    bool transport_verify_tls { true };

    // Agent 主动连接中心服务：心跳、资源指标、批次摘要、远控命令轮询。
    bool remote_enabled { true };
    std::vector<std::string> remote_server_urls;
    std::string remote_host_id;
    int remote_heartbeat_interval_sec { 30 };
    int remote_command_poll_interval_sec { 10 };
    int remote_audit_summary_interval_sec { 30 };
    bool remote_production_mode { false };
    bool remote_require_tls { false };
    bool remote_crl_check { false };
    std::string remote_enrollment_key;
    std::vector<std::string> remote_allowed_commands { "collect_status", "echo" };

    // 自我保护
    bool self_protect_enabled { true };

    // 管理后台接口
    bool manager_enabled { true };
    std::string manager_listen {"127.0.0.1:8443"};
    std::string manager_token;
    bool        manager_use_tls { false };
    std::string manager_tls_cert;
    std::string manager_tls_key;
    std::string manager_tls_ca_cert;
    bool        manager_require_client_cert { false };
    bool        manager_tls_crl_check { false };
    std::string manager_enrollment_key;
    std::size_t manager_max_host_count { 1000 };
    u64         manager_status_timeout_seconds { 30 };
    std::string manager_login_username { "admin" };
    std::string manager_login_password_sha256;

    // 检测规则
    std::string rules_path;

    // 是否启动本机采集器。服务端单独运行时应关闭采集器，只保留管理接口。
    bool collectors_enabled { true };

    // 本地 HTTP 代理行为采集（M5-3）：未配置时默认关闭，可被服务端远程开启。
    bool        http_proxy_enabled { false };
    std::string http_proxy_bind { "127.0.0.1" };
    int         http_proxy_listen_port { 8888 };
    std::vector<std::string> http_proxy_target_hosts;  // 空 = 采集全部主机
    bool        http_proxy_capture_body { false };     // 请求体验存（下游 PIIMasker 脱敏）
    // 操作员身份提取：HTTP 事件的操作员不再取客户端配置的写死值，而是从请求中解析。
    // 一台机器上多个管理员轮流登录时，只有这样才能区分"谁做的"。
    std::string http_proxy_identity_header { "x-af-operator" };  // 显式身份头（脚本/网关）
    std::string http_proxy_identity_cookie { "af_operator" };    // 身份 Cookie（业务系统下发）
    bool        http_proxy_identity_from_bearer { true };      // 解 Bearer token 里的 username
    bool        http_proxy_identity_from_body { true };         // 登录请求体 username 兜底

    // 采集器降噪过滤（collectors.filter.*，见 collector_filter.h）：
    // 路径/进程/网络/ETW 四类过滤，未配置时使用内置默认值（已按噪声经验调优）。
    collector::CollectorFilterConfig collector_filter = collector::default_collector_filter();

    // 高权限操作检测（Windows 提权令牌/SYSTEM，Linux uid=0）
    bool privilege_detect_enabled { true };

    // 测试注入开关（仅测试环境，生产必须关闭）
    bool test_injection_enabled { false };
    int  test_injection_interval_ms { 1000 };

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

    // 高权限检测开关（采集器据此决定是否标注提权事件）
    bool        privilege_detect_enabled() const { return cfg_.privilege_detect_enabled; }

    // 数据目录（采集器用于排除自身落盘文件，避免自采集死循环）
    const std::string& data_dir() const { return cfg_.data_dir; }

    // 采集器降噪配置（采集器启动/运行中读取）
    const collector::CollectorFilterConfig& collector_filter() const { return cfg_.collector_filter; }

    // 某采集器当前是否在运行（用于避免多个采集器重复上报同一事件）
    bool collector_running(const std::string& name) const;

    // 查询某 PID 的高权限级别（带 5 秒 TTL 缓存，避免重复令牌查询）。
    // 返回 "" 表示检测关闭；否则为 logmeta::priv 中的 system/elevated/root/none。
    std::string privilege_level_for_pid(u32 pid);

    // 获取运行时统计信息
    AgentStats stats() const;

    // 从磁盘重新加载配置
    Result<void> reload_config();

    // 动态启停指定名称的采集器（由服务端远程开关，名称见 Collector::name()）。
    // 返回 false 表示不存在该名称的采集器。
    bool set_collector_enabled(const std::string& name, bool enabled);

    // 返回全部采集器的名称与运行状态，JSON 数组格式：[{"name":"...","running":true}]。
    std::string collector_states_json() const;

    // 用服务端下发的规则 JSON 热加载检测器规则（无需重启、无需本地规则文件）。
    Result<void> load_remote_rules(const std::string& rules_json);

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
    std::unique_ptr<RemoteAgentClient>       remote_client_;
    std::unique_ptr<Detector>               detector_;
    std::unique_ptr<ManagerServer>          manager_;
    std::unique_ptr<SelfProtect>            self_protect_;

    // 高权限级别查询缓存：pid -> {级别, 缓存时刻}
    mutable std::mutex                              priv_cache_mtx_;
    std::unordered_map<u32, std::pair<std::string, TimePoint>> priv_cache_;

    // 测试注入线程（cfg_.test_injection_enabled 时启动）
    std::thread       injector_;
    std::atomic<bool> injecting_ { false };
    void injector_loop();

    // 安全产品适配器（Syslog/DB 审计/堡垒机）
    std::vector<std::unique_ptr<SecurityAdapter>> security_adapters_;
    std::vector<std::thread>                      adapter_threads_;
    std::atomic<bool> adapters_running_ { false };
    void adapter_poll_loop(SecurityAdapter* adapter);
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
