#include "auditforwarder/processor.h"

#include "auditforwarder/logger.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>

namespace af::processor {

// =====================================================================
// RegexFilter
// =====================================================================
namespace {
const std::string& pick_field(const AuditEvent& ev, RegexFilter::Field f) {
    switch (f) {
        case RegexFilter::Field::ActorName:   return ev.actor.name;
        case RegexFilter::Field::ActorPath:   return ev.actor.path;
        case RegexFilter::Field::ActorUser:   return ev.actor.user;
        case RegexFilter::Field::TargetPath:  return ev.target.path;
        case RegexFilter::Field::Command:     return ev.command;
        case RegexFilter::Field::Message:     return ev.message;
        case RegexFilter::Field::Any: {
            static const std::string empty;
            (void)ev;
            return empty;
        }
    }
    static const std::string empty;
    return empty;
}
}  // namespace

RegexFilter::RegexFilter(Field f, std::string pattern, bool allow_when_match)
    : f_(f), pattern_(std::move(pattern)), allow_(allow_when_match) {
    try { re_ = new std::regex(pattern_); } catch (...) { re_ = nullptr; }
}
RegexFilter::~RegexFilter() { delete static_cast<std::regex*>(re_); }

bool RegexFilter::process(AuditEvent& ev) {
    auto* re = static_cast<std::regex*>(re_);
    if (!re) return true;
    if (f_ == Field::Any) {
        if (std::regex_search(ev.actor.name,   *re) ||
            std::regex_search(ev.actor.path,   *re) ||
            std::regex_search(ev.actor.user,   *re) ||
            std::regex_search(ev.target.path,  *re) ||
            std::regex_search(ev.command,      *re) ||
            std::regex_search(ev.message,      *re)) {
            return allow_;
        }
        return !allow_;
    }
    const std::string& s = pick_field(ev, f_);
    bool match = std::regex_search(s, *re);
    return match ? allow_ : !allow_;
}

// =====================================================================
// Sampler
// =====================================================================
Sampler::Sampler(double keep_ratio) : keep_(std::min(1.0, std::max(0.0, keep_ratio))) {}
bool Sampler::process(AuditEvent&) {
    if (keep_ >= 1.0) return true;
    if (keep_ <= 0.0) return false;
    auto n = counter_.fetch_add(1, std::memory_order_relaxed);
    double r = static_cast<double>(n % 1000) / 1000.0;
    return r < keep_;
}

// =====================================================================
// Deduper
// =====================================================================
Deduper::Deduper(std::chrono::milliseconds window) : window_(window) {}

bool Deduper::process(AuditEvent& ev) {
    std::lock_guard<std::mutex> lk(mtx_);
    std::string key = ev.actor.name + "|" + ev.actor.path + "|" +
                      std::to_string(static_cast<int>(ev.action)) + "|" +
                      ev.target.path + "|" + ev.command;
    auto now = Clock::now();
    auto it = seen_.find(key);
    if (it != seen_.end() && (now - it->second) < window_) {
        return false;
    }
    seen_[key] = now;
    // GC old entries
    for (auto i = seen_.begin(); i != seen_.end();) {
        if ((now - i->second) > window_ * 10) i = seen_.erase(i); else ++i;
    }
    return true;
}

// =====================================================================
// Enricher
// =====================================================================
Enricher::Enricher(std::string host, std::string agent_id)
    : host_(std::move(host)), agent_id_(std::move(agent_id)) {}

bool Enricher::process(AuditEvent& ev) {
    if (ev.host.empty())     ev.host = host_;
    if (ev.agent_id.empty()) ev.agent_id = agent_id_;
    if (ev.actor.user.empty()) {
#ifdef AF_PLATFORM_WINDOWS
        // best-effort: leave empty if unknown
#else
        if (char* l = std::getenv("USER"); l) ev.actor.user = l;
#endif
    }
    return true;
}

// =====================================================================
// Aggregator
// =====================================================================
Aggregator::Aggregator(std::chrono::seconds window, std::size_t max)
    : window_(window), max_(max) {}

static std::string agg_key(const AuditEvent& ev) {
    return std::to_string(static_cast<int>(ev.category)) + "|" +
           std::to_string(static_cast<int>(ev.action)) + "|" +
           ev.actor.name + "|" + ev.target.path;
}

bool Aggregator::process(AuditEvent& ev) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto k = agg_key(ev);
    auto it = buckets_.find(k);
    auto now = Clock::now();
    if (it == buckets_.end() || (now - it->second.first) > window_) {
        if (it != buckets_.end() && !it->second.events.empty()) {
            // Emit a summary now
            AuditEvent sum = it->second.events.front();
            sum.message = "[aggregated " + std::to_string(it->second.events.size()) + " events] " + sum.message;
            sum.attrs["aggregated_count"] = std::to_string(it->second.events.size());
            if (sum.command.empty()) sum.command = it->second.events.back().command;
            ev = std::move(sum);
            buckets_.erase(it);
        }
        buckets_[k] = { {ev}, now, now };
        return true;
    }
    it->second.events.push_back(ev);
    it->second.last = now;
    if (it->second.events.size() >= max_) {
        AuditEvent sum = it->second.events.front();
        sum.message = "[aggregated " + std::to_string(it->second.events.size()) + " events] " + sum.message;
        sum.attrs["aggregated_count"] = std::to_string(it->second.events.size());
        ev = std::move(sum);
        buckets_.erase(it);
    }
    return true;
}

void Aggregator::flush(std::function<void(AuditEvent&&)> emit) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& [k, b] : buckets_) {
        if (b.events.empty()) continue;
        AuditEvent sum = b.events.front();
        sum.message = "[aggregated " + std::to_string(b.events.size()) + " events] " + sum.message;
        sum.attrs["aggregated_count"] = std::to_string(b.events.size());
        emit(std::move(sum));
    }
    buckets_.clear();
}

// =====================================================================
// PIIMasker
// =====================================================================
PIIMasker::PIIMasker() {
    re_ = new std::regex(
        R"((password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token)\s*[=:]\s*['"]?([^\s'";,]+))",
        std::regex_constants::icase);
}
PIIMasker::~PIIMasker() { delete static_cast<std::regex*>(re_); }

bool PIIMasker::process(AuditEvent& ev) {
    auto* re = static_cast<std::regex*>(re_);
    if (!ev.command.empty()) {
        ev.command = std::regex_replace(ev.command, *re, "$1=***REDACTED***");
    }
    if (!ev.message.empty()) {
        ev.message = std::regex_replace(ev.message, *re, "$1=***REDACTED***");
    }
    for (auto& [k, v] : ev.attrs) {
        v = std::regex_replace(v, *re, "$1=***REDACTED***");
    }
    return true;
}

}  // namespace af::processor
