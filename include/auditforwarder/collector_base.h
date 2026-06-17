#pragma once
// AuditForwarder - Collector base utilities (path filter, file watcher helpers).

#include "auditforwarder/agent.h"
#include <string>
#include <vector>

namespace af::collector {

// Filter a candidate path against include/exclude glob patterns.
class PathFilter {
public:
    void include(const std::vector<std::string>& patterns);
    void exclude(const std::vector<std::string>& patterns);
    bool allows(const std::string& path) const;
    std::size_t include_count() const { return includes_.size(); }
    std::size_t exclude_count() const { return excludes_.size(); }
private:
    std::vector<std::string> includes_;
    std::vector<std::string> excludes_;
};

// Watch a set of paths/dirs for file system events.
class FileWatchSource {
public:
    virtual ~FileWatchSource() = default;
    virtual Result<void> open(const std::vector<std::string>& paths) = 0;
    virtual void         close() = 0;
    // Poll events, returns number of events emitted via the callback
    virtual int          poll(std::function<bool(const std::string& path,
                                                 const std::string& op,
                                                 u64 timestamp_us)> cb) = 0;
};

// Construct a platform-specific source.
std::unique_ptr<FileWatchSource> make_file_watch_source();

}  // namespace af::collector
