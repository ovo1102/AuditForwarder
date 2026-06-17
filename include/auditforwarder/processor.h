#pragma once
// AuditForwarder - Event processors: filter, enrich, aggregate.

#include "auditforwarder/agent.h"
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace af::processor {

// Drop events that match a regex on a given field.
class RegexFilter : public Processor {
public:
    enum class Field { ActorName, ActorPath, ActorUser, TargetPath, Command, Message, Any };
    RegexFilter(Field f, std::string pattern, bool allow_when_match = false);
    ~RegexFilter() override;
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "regex_filter"; }
private:
    Field f_;
    std::string pattern_;
    bool allow_;
    void* re_ { nullptr }; // compiled regex (opaque)
};

// Drop a percentage of events for high-volume debug streams.
class Sampler : public Processor {
public:
    explicit Sampler(double keep_ratio);
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "sampler"; }
private:
    double keep_;
    std::atomic<u64> counter_{0};
};

// Deduplicate identical events within a short time window.
class Deduper : public Processor {
public:
    explicit Deduper(std::chrono::milliseconds window = std::chrono::milliseconds(50));
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "deduper"; }
private:
    std::chrono::milliseconds window_;
    std::mutex mtx_;
    std::unordered_map<std::string, TimePoint> seen_;
};

// Enrich an event with hostname / agent_id / OS info.
class Enricher : public Processor {
public:
    Enricher(std::string host, std::string agent_id);
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "enricher"; }
private:
    std::string host_;
    std::string agent_id_;
};

// Aggregate repeated low-severity events into a single summary event.
class Aggregator : public Processor {
public:
    Aggregator(std::chrono::seconds window = std::chrono::seconds(10),
               std::size_t max_per_window = 100);
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "aggregator"; }
    // Drain all pending aggregates now, emitting one summary event per bucket
    void flush(std::function<void(AuditEvent&&)> emit);
private:
    struct Bucket { std::vector<AuditEvent> events; TimePoint first; TimePoint last; };
    std::chrono::seconds window_;
    std::size_t max_;
    std::mutex mtx_;
    std::map<std::string, Bucket> buckets_;
};

// Mask sensitive values in command line / message (passwords, tokens).
class PIIMasker : public Processor {
public:
    PIIMasker();
    ~PIIMasker() override;
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "pii_masker"; }
private:
    void* re_ { nullptr };
};

}  // namespace af::processor
