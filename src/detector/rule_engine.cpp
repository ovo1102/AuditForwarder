#include "auditforwarder/detector.h"

#include "auditforwarder/config.h"
#include "auditforwarder/crypto.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>

namespace af::detector {

// ===========================================================================
// BehaviorTracker
// ===========================================================================
void BehaviorTracker::observe(const BehaviorKey& k, u64 ts_unix) {
    std::lock_guard<std::mutex> lk(mtx_);
    samples_[k].push_back(ts_unix);
    if (samples_[k].size() > 1024) samples_[k].erase(samples_[k].begin());
}

bool BehaviorTracker::is_anomalous(const BehaviorKey& k, u64 ts_unix, double sigma) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = samples_.find(k);
    if (it == samples_.end() || it->second.size() < 30) return false;
    auto& v = it->second;
    // compute inter-arrival intervals
    std::vector<double> iv;
    iv.reserve(v.size() - 1);
    for (std::size_t i = 1; i < v.size(); ++i)
        iv.push_back(static_cast<double>(v[i] - v[i - 1]));
    double mean = 0; for (auto x : iv) mean += x; mean /= std::max<std::size_t>(1, iv.size());
    double var  = 0; for (auto x : iv) var += (x - mean) * (x - mean); var /= std::max<std::size_t>(1, iv.size());
    double sd = std::sqrt(var);
    if (sd <= 0) return false;
    if (v.size() < 2) return false;
    double last_iv = static_cast<double>(ts_unix - v[v.size() - 2]);
    return std::abs(last_iv - mean) > sigma * sd;
}

std::size_t BehaviorTracker::size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return samples_.size();
}

// ===========================================================================
// ResponseDispatcher
// ===========================================================================
ResponseDispatcher::ResponseDispatcher(Agent* agent, std::function<void(const AuditEvent&)> alert_cb)
    : agent_(agent), alert_cb_(std::move(alert_cb)) {}

void ResponseDispatcher::dispatch(const std::vector<std::string>& responses, const AuditEvent& ev) {
    for (const auto& r : responses) {
        if (r == "alert") {
            AuditEvent a = ev;
            a.action  = EventAction::Alert;
            a.severity = ev.severity;
            a.message = "DETECTION ALERT: " + ev.message;
            a.attrs["response"] = "alert";
            if (alert_cb_) alert_cb_(a);
            AF_LOG_WARN("detector: ALERT rule_id=" << ev.rule_id << " " << ev.message);
        } else if (r == "block") {
            AF_LOG_WARN("detector: BLOCK actor=" << ev.actor.name << " cmd=" << ev.command);
            // Mark the original event outcome as denied
            // (a blocking hook into the kernel/usercall would be invoked here)
        } else if (r == "kill") {
            if (ev.actor.pid != 0) {
                AF_LOG_WARN("detector: KILL pid=" << ev.actor.pid);
                (void)proc::terminate(ev.actor.pid, 1);
            }
        } else if (r == "quarantine") {
            AF_LOG_WARN("detector: QUARANTINE path=" << ev.target.path);
            // The actual quarantine (move to encrypted vault) is performed by
            // the file collector on the next observation.
        }
    }
}

// ===========================================================================
// RuleEngine
// ===========================================================================
RuleEngine::RuleEngine()  = default;
RuleEngine::~RuleEngine() { delete responder_; }

Result<void> RuleEngine::start(Agent& agent) {
    agent_ = &agent;
    alert_cb_ = [this](const AuditEvent& e) {
        if (agent_) agent_->submit(const_cast<AuditEvent&>(e));
    };
    responder_ = new ResponseDispatcher(agent_, alert_cb_);
    running_.store(true);
    AF_LOG_INFO("detector: rule engine started, rules=" << rules_.size());
    return Result<void>::ok();
}

void RuleEngine::stop() { running_.store(false); }

void RuleEngine::clear_rules() {
    std::lock_guard<std::mutex> lk(mtx_);
    rules_.clear();
    hits_.clear();
}

std::size_t RuleEngine::rule_count() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return rules_.size();
}

Result<void> RuleEngine::add_rule(const Rule& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    rules_.push_back(r);
    return Result<void>::ok();
}

namespace {
bool any_match(const std::vector<std::string>& patterns, const std::string& s) {
    for (const auto& p : patterns) {
        try { if (std::regex_search(s, std::regex(p))) return true; } catch (...) {}
    }
    return false;
}
bool in_list(const std::vector<std::string>& list, const std::string& s) {
    return std::find(list.begin(), list.end(), s) != list.end();
}
}  // namespace

bool RuleEngine::inspect(AuditEvent& ev) {
    if (!running_.load()) return true;
    std::vector<Rule> rules_snapshot;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        rules_snapshot = rules_;
    }
    auto now_unix = static_cast<u64>(
        std::chrono::duration_cast<std::chrono::seconds>(ev.timestamp.time_since_epoch()).count());

    bool keep = true;
    for (const auto& r : rules_snapshot) {
        if (!r.enabled) continue;
        if (!r.categories.empty() && !in_list(r.categories, to_string(ev.category))) continue;
        if (!r.actions.empty()    && !in_list(r.actions,    to_string(ev.action)))   continue;
        if (!r.actor_match.empty() && !any_match(r.actor_match, ev.actor.name + " " + ev.actor.path)) continue;
        if (!r.path_match.empty()  && !any_match(r.path_match, ev.target.path)) continue;
        if (!r.cmd_match.empty()   && !any_match(r.cmd_match, ev.command)) continue;
        bool exact = true;
        for (const auto& [k, v] : r.match) {
            auto it = ev.attrs.find(k);
            std::string actual = (it != ev.attrs.end()) ? it->second : std::string();
            if (k == "actor.name") actual = ev.actor.name;
            else if (k == "actor.user") actual = ev.actor.user;
            else if (k == "target.path") actual = ev.target.path;
            else if (k == "command") actual = ev.command;
            if (actual != v) { exact = false; break; }
        }
        if (!exact) continue;

        // Threshold / window tracking
        if (r.threshold > 1) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto& h = hits_[r.id];
            h.push_back(now_unix);
            while (!h.empty() && (now_unix - h.front()) > r.window.count()) h.erase(h.begin());
            if (static_cast<int>(h.size()) < r.threshold) continue;
        }

        // Match!  Promote severity, set rule_id, dispatch responses.
        ev.severity = r.severity;
        ev.rule_id  = r.id;
        if (!r.responses.empty() && responder_) {
            responder_->dispatch(r.responses, ev);
        }
        // Action 'block' and 'kill' in responses => drop event from normal pipeline
        if (std::find(r.responses.begin(), r.responses.end(), "block") != r.responses.end() ||
            std::find(r.responses.begin(), r.responses.end(), "kill")  != r.responses.end()) {
            keep = false;
        }
    }

    // Update behavior baseline
    BehaviorKey bk{ ev.actor.name, ev.target.path, ev.command };
    behavior().observe(bk, now_unix);
    if (behavior().is_anomalous(bk, now_unix)) {
        ev.attrs["behavior_anomaly"] = "true";
        if (ev.severity < Severity::Warning) ev.severity = Severity::Warning;
    }
    return keep;
}

Result<void> RuleEngine::load_rules(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open())
        return Result<void>(Error::Code::NotFound, "rules file: " + path);
    std::ostringstream ss; ss << in.rdbuf();
    ConfigValue v;
    auto r = parse_minimal(ss.str(), path, v);
    if (r.is_err()) return r;
    if (v.type() != ConfigValue::Type::Map)
        return Result<void>(Error::Code::Parse, "rules must be a map");
    auto& rules = v.at("rules");
    if (rules.type() != ConfigValue::Type::List)
        return Result<void>(Error::Code::Parse, "expected rules: [...]");
    std::lock_guard<std::mutex> lk(mtx_);
    rules_.clear();
    hits_.clear();
    for (const auto& rv : rules.as_list()) {
        Rule r;
        r.id          = rv.at("id").as_string();
        r.name        = rv.at("name").as_string();
        r.description = rv.at("description").as_string();
        r.severity    = severity_from_string(rv.at("severity").as_string("warning"));
        r.enabled     = rv.at("enabled").as_bool(true);
        for (const auto& c : rv.at("categories").as_list()) r.categories.push_back(c.as_string());
        for (const auto& c : rv.at("actions").as_list())    r.actions.push_back(c.as_string());
        for (const auto& c : rv.at("actor_match").as_list()) r.actor_match.push_back(c.as_string());
        for (const auto& c : rv.at("path_match").as_list())  r.path_match.push_back(c.as_string());
        for (const auto& c : rv.at("cmd_match").as_list())   r.cmd_match.push_back(c.as_string());
        for (const auto& c : rv.at("responses").as_list())   r.responses.push_back(c.as_string());
        for (const auto& [k, val] : rv.at("match").as_map()) r.match[k] = val.as_string();
        r.threshold   = static_cast<int>(rv.at("threshold").as_int(1));
        r.window      = std::chrono::seconds(rv.at("window_sec").as_int(10));
        rules_.push_back(std::move(r));
    }
    AF_LOG_INFO("detector: loaded " << rules_.size() << " rules from " << path);
    return Result<void>::ok();
}

}  // namespace af::detector
