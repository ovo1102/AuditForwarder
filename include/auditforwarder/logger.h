#pragma once
// AuditForwarder - Cross-platform thread-safe logger.

#include "auditforwarder/types.h"
#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

namespace af {

enum class LogTarget : u8 {
    Console = 1 << 0,
    File    = 1 << 1,
    Syslog  = 1 << 2,
    Journal = 1 << 3,
};

inline LogTarget operator|(LogTarget a, LogTarget b) {
    return static_cast<LogTarget>(static_cast<u8>(a) | static_cast<u8>(b));
}

inline LogTarget operator&(LogTarget a, LogTarget b) {
    return static_cast<LogTarget>(static_cast<u8>(a) & static_cast<u8>(b));
}

struct LogConfig {
    Severity    level       { Severity::Info };
    std::string file_path   {};
    std::size_t  max_bytes  { 50 * 1024 * 1024 };  // 50 MiB rotation
    int         max_backups { 5 };
    bool        async       { true };
    u8          targets     { static_cast<u8>(LogTarget::Console) };
    bool        include_pid { true };
    bool        include_tid { true };
};

class Logger {
public:
    static Logger& instance();

    void configure(const LogConfig& cfg);
    void shutdown();

    void write(Severity sev, const char* file, int line, std::string_view msg);

    void flush();

private:
    Logger() = default;
    ~Logger();

    void rotate_if_needed_locked(std::size_t incoming);
    void write_to_targets_locked(const std::string& line, Severity sev);
    void write_to_console(const std::string& line, Severity sev);
    void write_to_file(const std::string& line);
    void write_to_syslog(const std::string& line, Severity sev);

    LogConfig              cfg_;
    std::mutex             mtx_;
    std::ofstream          file_stream_;
    std::atomic<bool>      configured_ { false };
    std::atomic<bool>      stopped_    { false };

#ifdef AF_PLATFORM_UNIX
    int syslog_fd_ { -1 };
#endif
};

// ---- Macros ----
#define AF_LOG(sev, expr)                                                       \
    do {                                                                        \
        std::ostringstream _af_oss;                                             \
        _af_oss << expr;                                                        \
        ::af::Logger::instance().write((sev), __FILE__, __LINE__,               \
            _af_oss.str());                                                     \
    } while (0)

#define AF_LOG_DEBUG(expr)   AF_LOG(::af::Severity::Debug,   expr)
#define AF_LOG_INFO(expr)    AF_LOG(::af::Severity::Info,    expr)
#define AF_LOG_NOTICE(expr)  AF_LOG(::af::Severity::Notice,  expr)
#define AF_LOG_WARN(expr)    AF_LOG(::af::Severity::Warning, expr)
#define AF_LOG_ERROR(expr)   AF_LOG(::af::Severity::Error,   expr)
#define AF_LOG_CRITICAL(expr) AF_LOG(::af::Severity::Critical, expr)

}  // namespace af
