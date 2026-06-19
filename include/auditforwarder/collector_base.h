#pragma once
// AuditForwarder - 采集器基础工具（路径过滤、文件监控辅助）。

#include "auditforwarder/agent.h"
#include <string>
#include <vector>

namespace af::collector {

// 根据包含/排除 glob 模式过滤候选路径。
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

// 监控一组路径/目录的文件系统事件。
class FileWatchSource {
public:
    virtual ~FileWatchSource() = default;
    virtual Result<void> open(const std::vector<std::string>& paths) = 0;
    virtual void         close() = 0;
    // 轮询事件，返回通过回调发出的事件数量
    virtual int          poll(std::function<bool(const std::string& path,
                                                 const std::string& op,
                                                 u64 timestamp_us)> cb) = 0;
};

// 构建平台特定的监控源。
std::unique_ptr<FileWatchSource> make_file_watch_source();

}  // namespace af::collector
