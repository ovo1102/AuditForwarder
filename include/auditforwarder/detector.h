#pragma once
// AuditForwarder - 检测引擎：基于规则 + 基于行为的检测
// 并自动执行响应动作。

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

// ---- 规则定义（可通过 YAML/JSON 加载）----
struct Rule {
    std::string id;
    std::string name;
    std::string description;
    Severity    severity { Severity::Warning };
    bool        enabled  { true };
    std::vector<std::string> categories;     // 匹配任意
    std::vector<std::string> actions;        // 匹配任意
    std::map<std::string, std::string> match; // 精确字段匹配
    std::vector<std::string> actor_match;    // actor.name/path 正则匹配
    std::vector<std::string> path_match;     // target.path 正则匹配
    std::vector<std::string> cmd_match;      // command 正则匹配
    int         threshold { 1 };             // 时间窗口内的出现次数
    std::chrono::seconds window { 10 };
    std::vector<std::string> responses;      // alert, block, kill, quarantine
};

// ---- 行为基线（简单移动平均 / 频率）----
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

// ---- 自动响应动作 ----
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

    // 从文件加载规则（JSON 或 YAML）
    Result<void> load_rules(const std::string& path);
    Result<void> add_rule(const Rule& r);
    void clear_rules();
    std::size_t rule_count() const;
    const std::vector<Rule>& rules() const { return rules_; }

    // 行为追踪器
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
