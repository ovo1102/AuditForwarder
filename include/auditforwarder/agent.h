#pragma once
// AuditForwarder - Core agent that wires up collectors, processors, chain, transport.

#include "auditforwarder/event.h"
#include "auditforwarder/chain.h"
#include "auditforwarder/thread_pool.h"
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace af {

// Forward declarations
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

    // Logging
    Severity    log_level { Severity::Info };
    std::string log_file;
    std::size_t log_max_bytes { 50 * 1024 * 1024 };

    // Chain
    std::size_t chain_batch_size { 256 };
    std::string chain_signing_key;     // PEM
    std::string chain_hmac_key;        // fallback

    // Transport
    std::vector<std::string> server_urls;
    std::string transport_mode {"realtime"}; // realtime | batch
    int transport_interval_sec { 30 };
    int transport_max_backoff_sec { 600 };
    bool transport_compress { true };
    bool transport_encrypt { true };
    std::string client_cert;
    std::string client_key;
    std::string ca_cert;

    // Self protection
    bool self_protect_enabled { true };

    // Manager (admin interface)
    bool manager_enabled { true };
    std::string manager_listen {"127.0.0.1:8443"};
    std::string manager_token;

    // Detection
    std::string rules_path;

    // Hidden install / system-level operation
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

    // Load configuration, prepare directories, etc.  Must be called before start().
    Result<void> init(const AgentConfig& cfg);

    // Start all subsystems
    Result<void> start();
    void         stop();
    bool         is_running() const { return running_.load(); }

    // Direct event injection (used by collectors and IPC)
    void submit(AuditEvent& ev);

    // Mark a successful batch upload
    void record_uploaded(u64 event_count, u64 bytes);

    // Mark a failed batch upload
    void record_failed(u64 event_count);

    // Get runtime statistics
    AgentStats stats() const;

    // Configuration reload from disk
    Result<void> reload_config();

    // Access to subsystems
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

// ---- Collector base ----
class Collector {
public:
    virtual ~Collector() = default;
    virtual Result<void> start(class Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual std::string  name() const = 0;
    virtual EventCategory category() const = 0;
    virtual bool         is_running() const = 0;
};

// ---- Processor base (filter / enrich / aggregate) ----
class Processor {
public:
    virtual ~Processor() = default;
    // Return true to keep the event, false to drop.
    virtual bool process(AuditEvent& ev) = 0;
    virtual std::string name() const = 0;
};

// ---- Transport (forward decl) ----
class Transport {
public:
    virtual ~Transport() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual Result<void> send_batch(const chain::EventBatch& b) = 0;
    virtual bool         is_running() const = 0;
    virtual std::string  name() const = 0;
};

// ---- Detector (forward decl) ----
class Detector {
public:
    virtual ~Detector() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    // Inspect a freshly created event; may mutate it (e.g. add rule_id, severity)
    // and queue an auto-response. Returning false drops the event from the pipeline.
    virtual bool         inspect(AuditEvent& ev) = 0;
    virtual std::string  name() const = 0;
};

// ---- Self protect (forward decl) ----
class SelfProtect {
public:
    virtual ~SelfProtect() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual bool         healthy() const = 0;
    virtual std::string  status() const = 0;
};

// ---- Manager (forward decl) ----
class ManagerServer {
public:
    virtual ~ManagerServer() = default;
    virtual Result<void> start(Agent& agent) = 0;
    virtual void         stop() = 0;
    virtual std::string  endpoint() const = 0;
};

}  // namespace af
