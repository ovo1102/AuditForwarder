#include "auditforwarder/logger.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#ifdef AF_PLATFORM_UNIX
#  include <sys/stat.h>
#  include <syslog.h>
#  include <unistd.h>
#endif

#ifdef AF_PLATFORM_WINDOWS
#  include <windows.h>
#endif

namespace af {

namespace {
const char* level_str(Severity s) {
    switch (s) {
        case Severity::Debug:     return "DEBUG";
        case Severity::Info:      return "INFO ";
        case Severity::Notice:    return "NOTE ";
        case Severity::Warning:   return "WARN ";
        case Severity::Error:     return "ERROR";
        case Severity::Critical:  return "CRIT ";
        case Severity::Alert:     return "ALERT";
        case Severity::Emergency: return "EMERG";
    }
    return "?    ";
}

int syslog_priority(Severity s) {
#ifdef AF_PLATFORM_UNIX
    switch (s) {
        case Severity::Debug:     return LOG_DEBUG;
        case Severity::Info:      return LOG_INFO;
        case Severity::Notice:    return LOG_NOTICE;
        case Severity::Warning:   return LOG_WARNING;
        case Severity::Error:     return LOG_ERR;
        case Severity::Critical:  return LOG_CRIT;
        case Severity::Alert:     return LOG_ALERT;
        case Severity::Emergency: return LOG_EMERG;
    }
#endif
    return 0;
}

std::string basename(const char* path) {
    if (!path) return "";
    const char* p = std::strrchr(path, AF_PATH_SEPARATOR);
    return p ? std::string(p + 1) : std::string(path);
}

std::string iso8601_now() {
    using namespace std::chrono;
    auto now    = system_clock::now();
    auto t      = system_clock::to_time_t(now);
    auto millis = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::tm tm_buf{};
#ifdef AF_PLATFORM_WINDOWS
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[40];
    std::snprintf(buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02d.%03lld",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
        static_cast<long long>(millis.count()));
    return buf;
}

}  // namespace

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::~Logger() {
    shutdown();
}

void Logger::configure(const LogConfig& cfg) {
    std::lock_guard<std::mutex> lk(mtx_);
    cfg_ = cfg;
    if ((cfg_.targets & static_cast<u8>(LogTarget::File)) != 0 && !cfg_.file_path.empty()) {
        file_stream_.open(cfg_.file_path, std::ios::app | std::ios::binary);
        if (!file_stream_.is_open()) {
            std::fprintf(stderr, "logger: failed to open log file: %s\n",
                         cfg_.file_path.c_str());
        }
    }
#ifdef AF_PLATFORM_UNIX
    if (static_cast<LogTarget>(cfg_.targets) & LogTarget::Syslog) {
        if (syslog_fd_ < 0) {
            openlog("auditforwarder", LOG_PID | LOG_NDELAY, LOG_DAEMON);
            syslog_fd_ = 1;
        }
    }
#endif
    configured_.store(true);
}

void Logger::shutdown() {
    if (stopped_.exchange(true)) return;
    std::lock_guard<std::mutex> lk(mtx_);
    if (file_stream_.is_open()) file_stream_.close();
#ifdef AF_PLATFORM_UNIX
    if (syslog_fd_ >= 0) {
        closelog();
        syslog_fd_ = -1;
    }
#endif
}

void Logger::write(Severity sev, const char* file, int line, std::string_view msg) {
    if (!configured_.load()) return;
    if (static_cast<int>(sev) < static_cast<int>(cfg_.level)) return;

    std::ostringstream oss;
    oss << iso8601_now() << " [" << level_str(sev) << "]";
    if (cfg_.include_pid) {
#ifdef AF_PLATFORM_WINDOWS
        oss << " pid=" << ::GetCurrentProcessId();
#else
        oss << " pid=" << ::getpid();
#endif
    }
    if (cfg_.include_tid) {
        std::ostringstream tss;
        tss << std::this_thread::get_id();
        oss << " tid=" << tss.str();
    }
    oss << " " << basename(file) << ":" << line << " - " << msg << "\n";
    std::string line_str = oss.str();

    std::lock_guard<std::mutex> lk(mtx_);
    write_to_targets_locked(line_str, sev);
}

void Logger::write_to_targets_locked(const std::string& line, Severity sev) {
    auto tgts = static_cast<u8>(cfg_.targets);
    if (tgts & static_cast<u8>(LogTarget::Console)) write_to_console(line, sev);
    if (tgts & static_cast<u8>(LogTarget::File))    write_to_file(line);
    if (tgts & static_cast<u8>(LogTarget::Syslog))  write_to_syslog(line, sev);
}

void Logger::write_to_console(const std::string& line, Severity sev) {
    FILE* out = (sev >= Severity::Error) ? stderr : stdout;
    std::fwrite(line.data(), 1, line.size(), out);
    std::fflush(out);
}

void Logger::rotate_if_needed_locked(std::size_t incoming) {
    if (!file_stream_.is_open()) return;
    auto pos = file_stream_.tellp();
    if (pos < 0) return;
    if (static_cast<std::size_t>(pos) + incoming > cfg_.max_bytes) {
        file_stream_.close();
        for (int i = cfg_.max_backups; i > 0; --i) {
            std::string from = cfg_.file_path + "." + std::to_string(i);
            std::string to   = cfg_.file_path + "." + std::to_string(i + 1);
            std::rename(from.c_str(), to.c_str());
        }
        std::string first = cfg_.file_path + ".1";
        std::rename(cfg_.file_path.c_str(), first.c_str());
        file_stream_.open(cfg_.file_path, std::ios::app | std::ios::binary);
    }
}

void Logger::write_to_file(const std::string& line) {
    rotate_if_needed_locked(line.size());
    if (file_stream_.is_open()) {
        file_stream_.write(line.data(), static_cast<std::streamsize>(line.size()));
        file_stream_.flush();
    }
}

void Logger::write_to_syslog(const std::string& line, Severity sev) {
#ifdef AF_PLATFORM_UNIX
    if (syslog_fd_ < 0) return;
    // syslog 会自动添加时间戳，去除前导 ISO 时间戳以避免重复
    auto p = line.find(' ');
    std::string body = (p != std::string::npos) ? line.substr(p + 1) : line;
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r')) body.pop_back();
    ::syslog(syslog_priority(sev), "%s", body.c_str());
#endif
}

void Logger::flush() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (file_stream_.is_open()) file_stream_.flush();
}

}  // namespace af
