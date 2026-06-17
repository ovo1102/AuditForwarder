#pragma once
// AuditForwarder - Detection engine: rule-based + behavior-based detection
// with automatic response actions.

#include "auditforwarder/event.h"
#include "auditforwarder/agent.h"
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace af::detector {

// ---- Rule definition (YAML/JSON loadable) ----
struct Rule {
    std::string id;
    std::string name;
    std::string description;
    Severity    severity { Severity::Warning };
    bool        enabled  { true };
    std::vector<std::string> categories;     // match any
    std::vector<std::string> actions;        // match any
    std::map<std::string, std::string> match; // exact field match
    std::vector<std::string> actor_match;    // regex on actor.name/path
    std::vector<std::string> path_match;     // regex on target.path
    std::vector<std::string> cmd_match;      // regex on command
    int         threshold { 1 };             // occurrences within window
    std::chrono::seconds window { 10 };
    std::vector<std::string> responses;      // alert, block, kill, quarantine
};

// ---- Behavior baseline (simple moving average / frequency) ----
struct BehaviorKey {
    std::string actor;
    std::string path;
    std::string cmd;
    bool operator==(const BehaviorKey& o) const { return actor == o.actor && path == o.path && cmd == o.cmd; }
    bool operator<(const BehaviorKey& o) const {
        if (actor != o.actor) return actor < o.actor;
        if (path != o.path) return path < o.path;
        return cmd < o.cmd;
    }
};

struct BehaviorStat {
    u64 hits { 0 };
    u64 last_unix { 0 };
    u64 first_unix { 0 };
    double avg_interval_ms { 0 };
};

class BehaviorTracker {
public:
    void observe(const BehaviorKey& k, u64 ts_unix);
    bool is_anomalous(const BehaviorKey& k, u64 ts_unix, double sigma = 3.0);
    std::size_t size() const;
private:
    std::map<BehaviorKey, std::vector<u64>> samples_;
    mutable std::mutex mtx_;
};

// ---- Auto response actions ----
class ResponseDispatcher {
public:
    ResponseDispatcher(class Agent* agent, std::function<void(const AuditEvent&)> alert_cb);
    void dispatch(const std::vector<std::string>& responses, const AuditEvent& trigger);
private:
    Agent* agent_ { nullptr };
    std::function<void(const AuditEvent&)> alert_cb_;
};

class RuleEngine : public Detector {
public:
    RuleEngine();
    ~RuleEngine() override;

    Result<void> start(Agent& agent) override;
    void         stop() override;
    bool         inspect(AuditEvent& ev) override;
    std::string  name() const override { return "rule_engine"; }

    // Load rules from a file (JSON or YAML)
    Result<void> load_rules(const std::string& path);
    Result<void> add_rule(const Rule& r);
    void clear_rules();
    std::size_t rule_count() const;
    const std::vector<Rule>& rules() const { return rules_; }

    // Behavior tracker
    BehaviorTracker& behavior() { return behavior_; }

private:
    void on_alert(const AuditEvent& ev);

    std::vector<Rule>         rules_;
    mutable std::mutex        mtx_;
    Agent*                    agent_ { nullptr };
    std::atomic<bool>         running_{ false };
    BehaviorTracker           behavior_;
    std::map<std::string, std::vector<u64>> hits_;  // rule_id -> timestamps
    ResponseDispatcher*       responder_ { nullptr };
    std::function<void(const AuditEvent&)> alert_cb_;
};

}  // namespace af::detector
