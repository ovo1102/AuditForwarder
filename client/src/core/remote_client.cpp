#include "auditforwarder/remote_client.h"

#include "auditforwarder/agent.h"
#include "auditforwarder/crypto.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <fstream>
#include <sstream>
#include <thread>
#include <utility>

#ifdef AF_PLATFORM_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <iphlpapi.h>
#  define AF_CLOSE_SOCKET closesocket
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <sys/statvfs.h>
#  include <unistd.h>
#  define AF_CLOSE_SOCKET close
#endif

namespace af {

namespace {

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

std::string json_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c != '\\' || i + 1 >= s.size()) {
            out.push_back(c);
            continue;
        }
        char n = s[++i];
        switch (n) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default:
                out.push_back('\\');
                out.push_back(n);
                break;
        }
    }
    return out;
}

std::string json_string_field(const std::string& json, const std::string& key) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return {};
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return {};
    p = json.find('"', p + 1);
    if (p == std::string::npos) return {};
    std::string raw;
    bool esc = false;
    for (++p; p < json.size(); ++p) {
        char c = json[p];
        if (esc) {
            raw.push_back('\\');
            raw.push_back(c);
            esc = false;
            continue;
        }
        if (c == '\\') {
            esc = true;
            continue;
        }
        if (c == '"') break;
        raw.push_back(c);
    }
    return json_unescape(raw);
}

// 从 [{"name":"a","enabled":true}, ...] 形式的 JSON 数组中粗解析采集器开关对。
// 前端生成的字段固定；不做完整 JSON 解析，避免引入额外依赖。
std::vector<std::pair<std::string, bool>> parse_collector_toggles(const std::string& json) {
    std::vector<std::pair<std::string, bool>> out;
    std::size_t pos = 0;
    while (pos < json.size()) {
        auto kn = json.find("\"name\"", pos);
        if (kn == std::string::npos) break;
        std::string tail = json.substr(kn);
        std::string name = json_string_field(tail, "name");
        auto en = tail.find("\"enabled\"");
        bool on = en != std::string::npos && json_string_field(tail.substr(en), "enabled") == "true";
        if (!name.empty()) out.emplace_back(std::string(name), on);
        pos = kn + 6;
    }
    return out;
}

std::uint64_t epoch_seconds() {
    return static_cast<std::uint64_t>(std::time(nullptr));
}

std::string iso_time(std::uint64_t epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
#ifdef AF_PLATFORM_WINDOWS
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> lines;
    std::istringstream in(s);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
}

struct ParsedUrl {
    std::string scheme;
    std::string host;
    int port { 0 };
    std::string path;
};

bool parse_url(const std::string& url, ParsedUrl& out) {
    auto sep = url.find("://");
    if (sep == std::string::npos) return false;
    out.scheme = lower(url.substr(0, sep));
    std::string rest = url.substr(sep + 3);
    auto slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    out.path = slash == std::string::npos ? "/" : rest.substr(slash);
    auto colon = authority.rfind(':');
    if (colon == std::string::npos) {
        out.host = authority;
        out.port = out.scheme == "https" ? 443 : 80;
    } else {
        out.host = authority.substr(0, colon);
        try {
            out.port = std::stoi(authority.substr(colon + 1));
        } catch (...) {
            return false;
        }
    }
    return (out.scheme == "http" || out.scheme == "https") && !out.host.empty();
}

bool socket_send_all(int fd, SSL* ssl, const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        int n = ssl ? SSL_write(ssl, data.data() + sent, static_cast<int>(data.size() - sent))
                    : send(fd, data.data() + sent, static_cast<int>(data.size() - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

std::string first_local_ipv4() {
    char host[256]{};
    if (gethostname(host, sizeof(host)) != 0) return {};
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return {};
    char ip[INET_ADDRSTRLEN]{};
    auto* addr = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    freeaddrinfo(res);
    return ip;
}

struct ResourceMetrics {
    double cpu_percent { 0.0 };
    std::uint64_t memory_total_bytes { 0 };
    std::uint64_t memory_used_bytes { 0 };
    double memory_percent { 0.0 };
    std::uint64_t disk_total_bytes { 0 };
    std::uint64_t disk_free_bytes { 0 };
    double disk_percent { 0.0 };
    std::uint64_t network_rx_bytes { 0 };
    std::uint64_t network_tx_bytes { 0 };
};

#ifdef AF_PLATFORM_WINDOWS
std::uint64_t filetime_to_u64(const FILETIME& ft) {
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}
#endif

ResourceMetrics collect_metrics(const std::string& data_dir) {
    ResourceMetrics m;
#ifdef AF_PLATFORM_WINDOWS
    static std::uint64_t prev_idle = 0;
    static std::uint64_t prev_total = 0;
    FILETIME idle_ft{}, kernel_ft{}, user_ft{};
    if (GetSystemTimes(&idle_ft, &kernel_ft, &user_ft)) {
        auto idle = filetime_to_u64(idle_ft);
        auto total = filetime_to_u64(kernel_ft) + filetime_to_u64(user_ft);
        if (prev_total != 0 && total > prev_total) {
            auto total_delta = total - prev_total;
            auto idle_delta = idle - prev_idle;
            m.cpu_percent = 100.0 * static_cast<double>(total_delta - idle_delta) /
                            static_cast<double>(total_delta);
        }
        prev_idle = idle;
        prev_total = total;
    }

    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        m.memory_total_bytes = mem.ullTotalPhys;
        m.memory_used_bytes = mem.ullTotalPhys - mem.ullAvailPhys;
        m.memory_percent = static_cast<double>(mem.dwMemoryLoad);
    }

    ULARGE_INTEGER free_avail{}, total{}, free_total{};
    std::string root = data_dir.empty() ? "C:\\" : data_dir.substr(0, 3);
    if (GetDiskFreeSpaceExA(root.c_str(), &free_avail, &total, &free_total)) {
        m.disk_total_bytes = total.QuadPart;
        m.disk_free_bytes = free_total.QuadPart;
        if (m.disk_total_bytes > 0) {
            m.disk_percent = 100.0 * static_cast<double>(m.disk_total_bytes - m.disk_free_bytes) /
                             static_cast<double>(m.disk_total_bytes);
        }
    }

    MIB_IF_TABLE2* table = nullptr;
    if (GetIfTable2(&table) == NO_ERROR && table) {
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto& row = table->Table[i];
            if (row.OperStatus == IfOperStatusUp) {
                m.network_rx_bytes += row.InOctets;
                m.network_tx_bytes += row.OutOctets;
            }
        }
        FreeMibTable(table);
    }
#else
    static std::uint64_t prev_total = 0;
    static std::uint64_t prev_idle = 0;
    std::ifstream stat("/proc/stat");
    if (stat) {
        std::string cpu;
        std::uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0;
        stat >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
        auto idle_all = idle + iowait;
        auto total = user + nice + system + idle + iowait + irq + softirq + steal;
        if (prev_total != 0 && total > prev_total) {
            auto total_delta = total - prev_total;
            auto idle_delta = idle_all - prev_idle;
            m.cpu_percent = 100.0 * static_cast<double>(total_delta - idle_delta) /
                            static_cast<double>(total_delta);
        }
        prev_total = total;
        prev_idle = idle_all;
    }

    std::ifstream meminfo("/proc/meminfo");
    if (meminfo) {
        std::string k, unit;
        std::uint64_t v = 0, total_kb = 0, avail_kb = 0;
        while (meminfo >> k >> v >> unit) {
            if (k == "MemTotal:") total_kb = v;
            if (k == "MemAvailable:") avail_kb = v;
        }
        m.memory_total_bytes = total_kb * 1024;
        m.memory_used_bytes = (total_kb > avail_kb ? total_kb - avail_kb : 0) * 1024;
        if (m.memory_total_bytes > 0) {
            m.memory_percent = 100.0 * static_cast<double>(m.memory_used_bytes) /
                               static_cast<double>(m.memory_total_bytes);
        }
    }

    struct statvfs vfs {};
    std::string path = data_dir.empty() ? "/" : data_dir;
    if (statvfs(path.c_str(), &vfs) == 0) {
        m.disk_total_bytes = static_cast<std::uint64_t>(vfs.f_blocks) * vfs.f_frsize;
        m.disk_free_bytes = static_cast<std::uint64_t>(vfs.f_bavail) * vfs.f_frsize;
        if (m.disk_total_bytes > 0) {
            m.disk_percent = 100.0 * static_cast<double>(m.disk_total_bytes - m.disk_free_bytes) /
                             static_cast<double>(m.disk_total_bytes);
        }
    }

    std::ifstream net("/proc/net/dev");
    std::string line;
    while (std::getline(net, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        if (name.find("lo") != std::string::npos) continue;
        std::istringstream vals(line.substr(colon + 1));
        std::uint64_t rx = 0, tx = 0, tmp = 0;
        vals >> rx;
        for (int i = 0; i < 7; ++i) vals >> tmp;
        vals >> tx;
        m.network_rx_bytes += rx;
        m.network_tx_bytes += tx;
    }
#endif
    return m;
}

}  // namespace

RemoteAgentClient::RemoteAgentClient(RemoteClientConfig cfg) : cfg_(std::move(cfg)) {}
RemoteAgentClient::~RemoteAgentClient() { stop(); }

Result<void> RemoteAgentClient::start(Agent& agent) {
    agent_ = &agent;
    if (!cfg_.enabled || cfg_.server_urls.empty()) {
        return Result<void>::ok();
    }
    if (cfg_.host_id.empty()) cfg_.host_id = proc::hostname();
    if (cfg_.production_mode && cfg_.require_tls) {
        for (const auto& url : cfg_.server_urls) {
            if (url.rfind("https://", 0) != 0) {
                return Result<void>(Error::Code::InvalidArgument,
                                    "production remote reporting requires https server URLs");
            }
        }
    }
#ifdef AF_PLATFORM_WINDOWS
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    running_.store(true);
    stopping_.store(false);
    worker_ = std::thread([this] { worker_loop(); });
    audit_worker_ = std::thread([this] { audit_loop(); });
    AF_LOG_INFO("remote_client: started, servers=" << cfg_.server_urls.size()
                << " host_id=" << cfg_.host_id);
    return Result<void>::ok();
}

void RemoteAgentClient::stop() {
    if (stopping_.exchange(true)) return;
    running_.store(false);
    cv_.notify_all();
    audit_cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    if (audit_worker_.joinable()) audit_worker_.join();
#ifdef AF_PLATFORM_WINDOWS
    WSACleanup();
#endif
}

void RemoteAgentClient::enqueue_batch_summary(const chain::EventBatch& batch) {
    // 每 100 个批次打一条，用来判断"操作日志发不出去"到底是
    // 没入队（回调没触发 / running_ 为 false）还是发了没成功。
    static std::atomic<std::uint64_t> enq_count{0};
    auto seq = enq_count.fetch_add(1);
    if (seq % 100 == 0) {
        AF_LOG_INFO("remote_client[" << cfg_.host_id << "]: enqueue batch #" << seq
                    << " events=" << batch.events.size()
                    << " running=" << (running_.load() ? 1 : 0));
    }
    if (!running_.load()) return;
    // 拷贝补盖客户端时间戳（用于服务端传输延迟统计），并按内容分流
    chain::EventBatch b = batch;
    for (auto& ev : b.events) {
        if (ev.attrs.find(logmeta::attr::kClientTs) == ev.attrs.end())
            logmeta::stamp_client_ts(ev);
    }
    const bool high = logmeta::batch_is_high_priority(b);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto& q = high ? hi_audit_queue_ : audit_queue_;
        q.push_back(std::move(b));
        if (q.size() > 1000) q.erase(q.begin());
    }
    if (high) audit_cv_.notify_one();  // 唤醒审计线程的紧急发送
}

void RemoteAgentClient::worker_loop() {
    AF_LOG_INFO("remote_client: worker_loop started, heartbeat=" << cfg_.heartbeat_interval_sec
                << "s command_poll=" << cfg_.command_poll_interval_sec
                << "s audit_summary=" << cfg_.audit_summary_interval_sec << "s");
    auto last_heartbeat = Clock::now() - std::chrono::seconds(cfg_.heartbeat_interval_sec);
    auto last_command_poll = Clock::now() - std::chrono::seconds(cfg_.command_poll_interval_sec);
    while (running_.load()) {
        auto now = Clock::now();
        if (now - last_heartbeat >= std::chrono::seconds(cfg_.heartbeat_interval_sec)) {
            send_heartbeat();
            last_heartbeat = Clock::now();
        }
        if (now - last_command_poll >= std::chrono::seconds(cfg_.command_poll_interval_sec)) {
            poll_commands();
            last_command_poll = Clock::now();
        }
        send_pending_results();
        // 500ms 周期；审计摘要发送已移至 audit_loop，本循环只做心跳/命令/结果回传
        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait_for(lk, std::chrono::milliseconds(500), [this] { return !running_.load(); });
    }
}

// 审计摘要独立发送线程：定时通道（先高后普通）+ 高优先级紧急通道。
// 与心跳/命令轮询隔离，避免大体积 operation-logs 上传阻塞拖垮心跳周期。
void RemoteAgentClient::audit_loop() {
    auto last_audit = Clock::now() - std::chrono::seconds(cfg_.audit_summary_interval_sec);
    while (running_.load()) {
        auto now = Clock::now();
        if (now - last_audit >= std::chrono::seconds(cfg_.audit_summary_interval_sec)) {
            send_audit_summaries();  // 定时通道：先高后普通
            last_audit = Clock::now();
            continue;
        }
        bool has_high = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            has_high = !hi_audit_queue_.empty();
        }
        if (has_high) {
            // 合并 100ms 内到达的其他高优先级批次，再一次性发出
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            send_audit_summaries(true);
            continue;
        }
        // 等待下一个检查点；高优先级批次入队会 notify 即时唤醒
        std::unique_lock<std::mutex> lk(mtx_);
        audit_cv_.wait_for(lk, std::chrono::milliseconds(100), [this] {
            return !running_.load() || !hi_audit_queue_.empty();
        });
    }
}

std::string RemoteAgentClient::endpoint(const std::string& base, const std::string& path) const {
    if (base.empty()) return path;
    if (base.back() == '/' && !path.empty() && path.front() == '/') return base.substr(0, base.size() - 1) + path;
    if (base.back() != '/' && !path.empty() && path.front() != '/') return base + "/" + path;
    return base + path;
}

bool RemoteAgentClient::command_allowed(const std::string& command_type) const {
    return std::find(cfg_.allowed_commands.begin(), cfg_.allowed_commands.end(), command_type) != cfg_.allowed_commands.end();
}

std::string RemoteAgentClient::build_metrics_json() {
    auto m = collect_metrics(cfg_.data_dir);
    std::ostringstream o;
    o << "{"
      << "\"timestamp\":\"" << iso_time(epoch_seconds()) << "\","
      << "\"host_id\":\"" << json_escape(cfg_.host_id) << "\","
      << "\"cpu\":{\"usage_percent\":" << m.cpu_percent << ",\"unit\":\"percent\"},"
      << "\"memory\":{\"total_bytes\":" << m.memory_total_bytes
      << ",\"used_bytes\":" << m.memory_used_bytes
      << ",\"usage_percent\":" << m.memory_percent << ",\"unit\":\"bytes\"},"
      << "\"disk\":{\"total_bytes\":" << m.disk_total_bytes
      << ",\"free_bytes\":" << m.disk_free_bytes
      << ",\"usage_percent\":" << m.disk_percent << ",\"unit\":\"bytes\"},"
      << "\"network\":{\"rx_bytes\":" << m.network_rx_bytes
      << ",\"tx_bytes\":" << m.network_tx_bytes << ",\"unit\":\"bytes\"}"
      << "}";
    return o.str();
}

std::string RemoteAgentClient::build_heartbeat_json() {
    auto metrics = collect_metrics(cfg_.data_dir);
    std::ostringstream hardware;
    hardware << "cpu_threads=" << std::thread::hardware_concurrency();
    std::ostringstream o;
    o << "{"
      << "\"host_id\":\"" << json_escape(cfg_.host_id) << "\","
      << "\"operator_id\":\"" << json_escape(cfg_.operator_id) << "\","
      << "\"operator_name\":\"" << json_escape(cfg_.operator_name) << "\","
      << "\"name\":\"" << json_escape(proc::hostname()) << "\","
      << "\"ip_address\":\"" << json_escape(first_local_ipv4()) << "\","
      << "\"hardware\":\"" << json_escape(hardware.str()) << "\","
      << "\"os_version\":\"" << json_escape(proc::os_version()) << "\","
      << "\"network_status\":\"online\","
      << "\"enrollment_key\":\"" << json_escape(cfg_.enrollment_key) << "\","
      << "\"cpu_usage_percent\":" << static_cast<unsigned>(metrics.cpu_percent + 0.5) << ","
      << "\"memory_usage_percent\":" << static_cast<unsigned>(metrics.memory_percent + 0.5) << ","
      << "\"metrics\":" << build_metrics_json() << ","
      // 各采集器名称与运行状态，供服务端 Web 界面渲染开关面板。
      << "\"collectors\":" << (agent_ ? agent_->collector_states_json() : "[]") << ","
      << "\"permissions\":[";
    for (std::size_t i = 0; i < cfg_.allowed_commands.size(); ++i) {
        if (i) o << ",";
        o << "\"" << json_escape(cfg_.allowed_commands[i]) << "\"";
    }
    o << "]"
      << "}";
    return o.str();
}

std::string RemoteAgentClient::build_batch_summary_json(const chain::EventBatch& batch) {
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        batch.created_at.time_since_epoch()).count();
    const bool high = logmeta::batch_is_high_priority(batch);
    std::ostringstream o;
    o << "{"
      << "\"host_id\":\"" << json_escape(cfg_.host_id) << "\","
      << "\"operator_id\":\"" << json_escape(cfg_.operator_id) << "\","
      << "\"timestamp\":\"" << iso_time(epoch_seconds()) << "\","
      << "\"batch_id\":\"" << json_escape(batch.id) << "\","
      << "\"event_count\":" << batch.events.size() << ","
      << "\"priority\":\"" << (high ? logmeta::priority::kHigh : logmeta::priority::kNormal) << "\","
      << "\"created_at_us\":" << us << ","
      << "\"merkle_root\":\"" << json_escape(batch.merkle_root) << "\","
      << "\"signature_present\":" << (!batch.signature.empty() ? "true" : "false") << ","
      // 批次签名（HMAC-SHA256 或非对称签名字节），服务端据此验签，构成防篡改闭环。
      << "\"signature\":\"" << json_escape(batch.signature) << "\","
      << "\"activities\":[";
    for (std::size_t i = 0; i < batch.events.size() && i < 20; ++i) {
        const auto& ev = batch.events[i];
        if (i) o << ",";
        o << "{"
          << "\"id\":" << ev.id << ","
          << "\"seq\":" << ev.seq << ","
          << "\"category\":\"" << to_string(ev.category) << "\","
          << "\"action\":\"" << to_string(ev.action) << "\","
          << "\"outcome\":\"" << to_string(ev.outcome) << "\","
          << "\"severity\":\"" << to_string(ev.severity) << "\","
          << "\"actor\":\"" << json_escape(ev.actor.name) << "\","
          << "\"target\":\"" << json_escape(ev.target.path.empty() ? ev.target.address : ev.target.path) << "\","
          << "\"message\":\"" << json_escape(ev.message) << "\""
          << "}";
    }
    o << "]"
      << "}";
    return o.str();
}

void RemoteAgentClient::send_heartbeat() {
    auto body = build_heartbeat_json();
    for (const auto& base : cfg_.server_urls) {
        auto url = endpoint(base, "/hosts/heartbeat");
        auto r = http_request("POST", url, body, "application/json");
        if (r.ok) {
            AF_LOG_INFO("remote_client: heartbeat ok -> " << url);
            (void)http_request("POST", endpoint(base, "/agent/metrics"), build_metrics_json(), "application/json");
            return;
        }
        AF_LOG_WARN("remote_client: heartbeat failed: " << url << " err=" << r.error << " status=" << r.status);
    }
}

void RemoteAgentClient::send_audit_summaries(bool high_only) {
    // 单次最多取这么多批次。
    //
    // 原来的写法是把两个队列整批 swap 出来，队列堆到 1000 条时会构造出
    // 几十 MB 的 body：发送超时 → 整批塞回队列 → 下次更大，形成"永远发不出去"
    // 的死锁。表现出来的现象非常迷惑人：
    //   心跳一直 ok、chain 通道的批次一直在 upload status=200，
    //   但 operation-logs 一条都到不了服务端，合谋检测自然是空的。
    // 分批发送才能把积压慢慢消化掉。
    //
    // 实验环境把单次上限从 40 提到 120：http_proxy 会把浏览器的轮询请求也采成
    // 操作日志，队列很容易堆到几百条，新产生的三条合谋动作只能排在队尾，
    // 表现为"操作完要等十几秒才出告警"。加大单次批量能让队列更快被清空。
    constexpr std::size_t kMaxPerSend = 120;
    std::vector<chain::EventBatch> pending;
    auto take = [&pending](std::vector<chain::EventBatch>& q, std::size_t want) {
        std::size_t n = want < q.size() ? want : q.size();
        pending.insert(pending.end(),
                       std::make_move_iterator(q.begin()),
                       std::make_move_iterator(q.begin() + static_cast<std::ptrdiff_t>(n)));
        q.erase(q.begin(), q.begin() + static_cast<std::ptrdiff_t>(n));
    };
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (high_only) {
            take(hi_audit_queue_, kMaxPerSend);
        } else {
            take(hi_audit_queue_, kMaxPerSend);              // 高优先级先走
            take(audit_queue_, kMaxPerSend - pending.size()); // 剩余额度给普通
        }
    }
    if (pending.empty()) {
        static std::atomic<std::uint32_t> idle{0};
        if ((idle.fetch_add(1) % 30) == 0) {
            AF_LOG_INFO("remote_client[" << cfg_.host_id << "]: audit queue empty, nothing to send");
        }
        return;
    }
    const char* channel_priority = high_only ? "high" : "normal";
    std::ostringstream body;
    body << "{"
         << "\"host_id\":\"" << json_escape(cfg_.host_id) << "\","
         << "\"priority\":\"" << channel_priority << "\","
         << "\"timestamp\":\"" << iso_time(epoch_seconds()) << "\","
         << "\"summaries\":[";
    for (std::size_t i = 0; i < pending.size(); ++i) {
        if (i) body << ",";
        body << build_batch_summary_json(pending[i]);
    }
    body << "]}";

    // 同时把批次内的每条事件展开为操作日志，供服务端「操作日志/安全监控」展示与规则匹配
    auto attr_str = [](const AuditEvent& ev, const std::string& key, const std::string& dflt) -> std::string {
        auto it = ev.attrs.find(key);
        return it == ev.attrs.end() ? dflt : it->second;
    };
    std::ostringstream logs_body;
    logs_body << "{\"host_id\":\"" << json_escape(cfg_.host_id) << "\","
              << "\"priority\":\"" << channel_priority << "\",\"logs\":[";
    std::size_t log_count = 0;
    for (const auto& batch : pending) {
        auto batch_sec = static_cast<u64>(
            std::chrono::duration_cast<std::chrono::seconds>(batch.created_at.time_since_epoch()).count());
        std::string ts = iso_time(batch_sec);
        for (const auto& ev : batch.events) {
            if (log_count) logs_body << ",";
            // 操作员身份：优先取事件 attrs 中由 Enricher 注入的 operator_id，
            // 缺失时回退到客户端配置的操作员（M5 身份贯通）。
            std::string op_id = attr_str(ev, logmeta::attr::kOperatorId, "");
            if (op_id.empty()) op_id = cfg_.operator_id;
            std::string op_name = attr_str(ev, logmeta::attr::kOperatorName, "");
            if (op_name.empty()) op_name = cfg_.operator_name;
            logs_body << "{"
                      << "\"host_id\":\"" << json_escape(cfg_.host_id) << "\","
                      << "\"operator_id\":\"" << json_escape(op_id) << "\","
                      << "\"operator_name\":\"" << json_escape(op_name) << "\","
                      << "\"timestamp\":\"" << ts << "\","
                      << "\"batch_id\":\"" << json_escape(batch.id) << "\","
                      << "\"seq\":" << ev.seq << ","
                      << "\"operation_type\":\"" << to_string(ev.category) << "\","
                      << "\"event_type\":\"" << to_string(ev.action) << "\","
                      << "\"outcome\":\"" << to_string(ev.outcome) << "\","
                      << "\"severity\":\"" << to_string(ev.severity) << "\","
                      << "\"actor\":\"" << json_escape(ev.actor.name) << "\","
                      << "\"target\":\"" << json_escape(ev.target.path.empty() ? ev.target.address : ev.target.path) << "\","
                      // —— 日志分类与优先级元数据（采集器类型/来源/优先级/权限标注/客户端时间戳）——
                      << "\"collector\":\"" << json_escape(attr_str(ev, logmeta::attr::kCollector, logmeta::collector::kUnknown)) << "\","
                      << "\"source\":\"" << json_escape(attr_str(ev, logmeta::attr::kSource, "")) << "\","
                      << "\"priority\":\"" << json_escape(attr_str(ev, logmeta::attr::kPriority, logmeta::priority::kNormal)) << "\","
                      << "\"priv_level\":\"" << json_escape(attr_str(ev, logmeta::attr::kPrivLevel, "")) << "\","
                      << "\"priv_operation\":\"" << json_escape(attr_str(ev, logmeta::attr::kPrivOperation, "")) << "\","
                      << "\"priv_ts\":\"" << json_escape(attr_str(ev, logmeta::attr::kPrivTs, "")) << "\","
                      << "\"client_ts\":" << attr_str(ev, logmeta::attr::kClientTs, "0") << ","
                      << "\"message\":\"" << json_escape(ev.message) << "\","
                      // 动作归一化结果（<verb>.<object>）：服务端合谋规则按此精确匹配，
                      // 避免 "delete" 裸词把"删除一本书"误判为"删除备份"。
                      << "\"action_norm\":\"" << json_escape(attr_str(ev, logmeta::attr::kActionNorm, "")) << "\","
                      // 完整 attrs 原样上送（含 ETW raw_xml/event_id 等富字段），
                      // 服务端按采集器过滤策略（strict/lenient）决定保留范围
                      << "\"attrs\":{";
            bool first_attr = true;
            for (const auto& kv : ev.attrs) {
                if (!first_attr) logs_body << ",";
                first_attr = false;
                logs_body << "\"" << json_escape(kv.first) << "\":\""
                          << json_escape(kv.second) << "\"";
            }
            logs_body << "}"
                      << "}";
            ++log_count;
        }
    }
    logs_body << "]}";

    bool sent = false;
    bool logs_sent = false;
    for (const auto& base : cfg_.server_urls) {
        if (!sent) {
            auto r = http_request("POST", endpoint(base, "/agent/audit-summaries"), body.str(), "application/json");
            if (r.ok) sent = true;
            else AF_LOG_WARN("remote_client: audit summary upload failed: " << r.error);
        }
        if (!logs_sent && log_count > 0) {
            auto r2 = http_request("POST", endpoint(base, "/agent/operation-logs"), logs_body.str(), "application/json");
            if (r2.ok) logs_sent = true;
            else AF_LOG_WARN("remote_client: operation logs upload failed: " << r2.error);
        }
        if (sent && (logs_sent || log_count == 0)) break;
    }
    if (logs_sent) {
        AF_LOG_INFO("remote_client[" << cfg_.host_id << "]: operation-logs sent batches="
                    << pending.size() << " logs=" << log_count);
    }
    if (!sent) {
        // 失败批次塞回各自优先级队列头部，高优先级不降级
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
            auto& q = logmeta::batch_is_high_priority(*it) ? hi_audit_queue_ : audit_queue_;
            q.insert(q.begin(), std::move(*it));
        }
    }
}

std::string RemoteAgentClient::execute_command(const std::string& command_id,
                                               const std::string& command_type,
                                               const std::string& payload) {
    auto started = Clock::now();
    bool success = false;
    std::string output;
    std::string error;

    if (!command_allowed(command_type)) {
        error = "command type is not allowed by this Agent";
    } else if (command_type == "collect_status") {
        // 返回运行指标 + 各采集器开关状态，供 Web 面板渲染。
        success = true;
        output = std::string("{\"metrics\":") + build_metrics_json()
               + ",\"collectors\":" + (agent_ ? agent_->collector_states_json() : "[]") + "}";
    } else if (command_type == "echo") {
        success = true;
        output = payload;
    } else if (command_type == "set_collector") {
        // payload: {"name":"file_win","enabled":true}
        std::string name = json_string_field(payload, "name");
        bool on = json_string_field(payload, "enabled") == "true";
        if (name.empty()) {
            error = "set_collector: missing 'name' in payload";
        } else if (!agent_) {
            error = "set_collector: agent not running";
        } else {
            success = agent_->set_collector_enabled(name, on);
            if (!success) error = "set_collector: collector not found or failed: " + name;
            else output = agent_->collector_states_json();
        }
    } else if (command_type == "set_collectors") {
        // payload: [{"name":"...","enabled":...}, ...]
        if (!agent_) {
            error = "set_collectors: agent not running";
        } else {
            auto toggles = parse_collector_toggles(payload);
            int applied = 0;
            for (const auto& [name, on] : toggles) {
                if (agent_->set_collector_enabled(name, on)) ++applied;
            }
            success = applied > 0;
            if (success) {
                std::ostringstream os;
                os << "applied " << applied << " of " << toggles.size() << " collectors";
                output = os.str() + ";" + agent_->collector_states_json();
            } else {
                error = "set_collectors: no matching collector on this host";
            }
        }
    } else if (command_type == "load_rules") {
        // payload payload 为服务端下发的完整规则 JSON 文本。
        if (!agent_) {
            error = "load_rules: agent not running";
        } else {
            auto r2 = agent_->load_remote_rules(payload);
            if (r2.is_err()) {
                error = "load_rules: " + r2.error().message();
            } else {
                success = true;
                output = "rules hot-loaded";
            }
        }
    } else {
        error = "command type is recognized by permission list but has no local executor";
    }

    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
    std::ostringstream result;
    result << "{"
           << "\"host_id\":\"" << json_escape(cfg_.host_id) << "\","
           << "\"command_id\":\"" << json_escape(command_id) << "\","
           << "\"command_type\":\"" << json_escape(command_type) << "\","
           << "\"status\":\"" << (success ? "success" : "failure") << "\","
           << "\"success\":" << (success ? "true" : "false") << ","
           << "\"output\":\"" << json_escape(output) << "\","
           << "\"error_message\":\"" << json_escape(error) << "\","
           << "\"duration_ms\":" << duration_ms << ","
           << "\"completed_at\":\"" << iso_time(epoch_seconds()) << "\""
           << "}";
    AF_LOG_INFO("remote_client: command " << command_id << " type=" << command_type
                << " status=" << (success ? "success" : "failure"));
    return result.str();
}

void RemoteAgentClient::poll_commands() {
    for (const auto& base : cfg_.server_urls) {
        auto r = http_request("GET", endpoint(base, "/hosts/commands?host_id=" + cfg_.host_id), {}, "application/json");
        if (!r.ok) {
            AF_LOG_WARN("remote_client: command poll failed: " << r.error);
            continue;
        }
        auto jsonl = json_string_field(r.body, "commands_jsonl");
        if (jsonl.empty()) continue;
        auto key = crypto::sha256((cfg_.auth_token.empty() ? "auditforwarder-local-command-key" : cfg_.auth_token) + "|" + cfg_.host_id);
        for (const auto& line : split_lines(jsonl)) {
            std::string command_id = json_string_field(line, "command_id");
            if (command_id.empty() || executed_commands_.count(command_id)) continue;
            crypto::AeadResult enc;
            enc.iv = crypto::from_hex(json_string_field(line, "iv"));
            enc.ciphertext = crypto::from_hex(json_string_field(line, "ciphertext"));
            auto plain = crypto::aes_gcm_decrypt(key, enc, ByteBuffer(cfg_.host_id.begin(), cfg_.host_id.end()));
            if (plain.is_err()) {
                AF_LOG_WARN("remote_client: cannot decrypt command " << command_id);
                continue;
            }
            std::string command_json(plain.value().begin(), plain.value().end());
            std::string command_type = json_string_field(command_json, "command_type");
            std::string payload = json_string_field(command_json, "payload");
            auto result = execute_command(command_id, command_type, payload);
            executed_commands_.insert(command_id);
            std::lock_guard<std::mutex> lk(mtx_);
            pending_results_.push_back(std::move(result));
        }
    }
}

void RemoteAgentClient::send_pending_results() {
    std::vector<std::string> pending;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        pending.swap(pending_results_);
    }
    if (pending.empty()) return;

    std::vector<std::string> failed;
    for (const auto& result : pending) {
        bool sent = false;
        for (const auto& base : cfg_.server_urls) {
            auto r = http_request("POST", endpoint(base, "/hosts/command-results"), result, "application/json");
            if (r.ok) {
                sent = true;
                break;
            }
        }
        if (!sent) failed.push_back(result);
    }
    if (!failed.empty()) {
        std::lock_guard<std::mutex> lk(mtx_);
        pending_results_.insert(pending_results_.end(), failed.begin(), failed.end());
    }
}

RemoteAgentClient::HttpResponse RemoteAgentClient::http_request(const std::string& method,
                                                                const std::string& url,
                                                                const std::string& body,
                                                                const std::string& content_type) {
    HttpResponse out;
    ParsedUrl u;
    if (!parse_url(url, u)) {
        out.error = "bad url: " + url;
        return out;
    }
    if ((cfg_.production_mode || cfg_.require_tls) && u.scheme != "https") {
        out.error = "TLS is required for remote communication";
        return out;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    auto port = std::to_string(u.port);
    if (getaddrinfo(u.host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        out.error = "resolve failed";
        return out;
    }

    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = static_cast<int>(socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) break;
        AF_CLOSE_SOCKET(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        out.error = "connect failed";
        return out;
    }

    // 设置发送/接收超时，防止 recv() 永久阻塞
    {
#ifdef AF_PLATFORM_WINDOWS
        DWORD tv = 10000;  // 10 秒
#else
        struct timeval tv { 10, 0 };
#endif
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    }

    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    if (u.scheme == "https") {
        const SSL_METHOD* ssl_method = TLS_client_method();
        ctx = SSL_CTX_new(ssl_method);
        if (!ctx) {
            AF_CLOSE_SOCKET(fd);
            out.error = "tls context failed";
            return out;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4:!3DES");
        if (cfg_.verify_tls) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
            if (!cfg_.ca_cert.empty()) SSL_CTX_load_verify_locations(ctx, cfg_.ca_cert.c_str(), nullptr);
            else SSL_CTX_set_default_verify_paths(ctx);
            if (cfg_.crl_check) {
                auto* param = SSL_CTX_get0_param(ctx);
                X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            }
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        }
        if (!cfg_.client_cert.empty() && !cfg_.client_key.empty()) {
            if (SSL_CTX_use_certificate_file(ctx, cfg_.client_cert.c_str(), SSL_FILETYPE_PEM) != 1 ||
                SSL_CTX_use_PrivateKey_file(ctx, cfg_.client_key.c_str(), SSL_FILETYPE_PEM) != 1) {
                SSL_CTX_free(ctx);
                AF_CLOSE_SOCKET(fd);
                out.error = "client certificate load failed";
                return out;
            }
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, u.host.c_str());
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            AF_CLOSE_SOCKET(fd);
            out.error = "tls handshake failed";
            return out;
        }
        if (cfg_.verify_tls && SSL_get_verify_result(ssl) != X509_V_OK) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            AF_CLOSE_SOCKET(fd);
            out.error = "tls verify failed";
            return out;
        }
    }

    std::ostringstream req;
    req << method << " " << u.path << " HTTP/1.1\r\n"
        << "Host: " << u.host << "\r\n"
        << "User-Agent: AuditForwarder-Agent/1.0\r\n"
        << "Accept: application/json\r\n"
        << "Connection: close\r\n";
    if (!cfg_.auth_token.empty()) req << "Authorization: Bearer " << cfg_.auth_token << "\r\n";
    if (method == "POST" || method == "PUT") {
        req << "Content-Type: " << content_type << "\r\n"
            << "Content-Length: " << body.size() << "\r\n";
        // 请求级完整性签名：服务端配置了同一 hmac_key 时强制验签，防止传输篡改
        if (!cfg_.hmac_key.empty()) {
            req << "X-Signature: " << crypto::hmac_sha256_hex(cfg_.hmac_key, body) << "\r\n";
        }
    }
    req << "\r\n";
    std::string raw = req.str() + body;
    if (!socket_send_all(fd, ssl, raw)) {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
        AF_CLOSE_SOCKET(fd);
        out.error = "write failed";
        return out;
    }

    // 读响应：解析 Content-Length，读够响应体就停。
    // 不能等 EOF：服务端若保持 keep-alive，recv/SSL_read 会一直阻塞，
    // audit_loop 线程整个卡死（现象：只有第一条 audit-summaries 能发出，
    // 之后所有 operation-logs 都堆在队列里，服务端收不到任何事件）。
    std::string response;
    char buf[4096];
    int n = 0;
    std::size_t need = 0;  // 响应总长度（含头）；0=暂未知
    while (true) {
        n = ssl ? SSL_read(ssl, buf, sizeof(buf)) : recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        response.append(buf, n);
        if (need == 0) {
            auto hdr_end = response.find("\r\n\r\n");
            if (hdr_end != std::string::npos) {
                std::string heads = response.substr(0, hdr_end);
                std::size_t cl_pos = heads.find("Content-Length:");
                if (cl_pos == std::string::npos) cl_pos = heads.find("content-length:");
                if (cl_pos != std::string::npos) {
                    try {
                        need = hdr_end + 4 + static_cast<std::size_t>(std::stoul(heads.substr(cl_pos + 15)));
                    } catch (...) { need = 0; }
                }
            }
        }
        if (need != 0 && response.size() >= need) break;
    }
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) SSL_CTX_free(ctx);
    AF_CLOSE_SOCKET(fd);

    auto line_end = response.find("\r\n");
    if (line_end == std::string::npos) {
        out.error = "bad response";
        return out;
    }
    std::string status = response.substr(0, line_end);
    auto sp1 = status.find(' ');
    auto sp2 = status.find(' ', sp1 + 1);
    if (sp1 != std::string::npos && sp2 != std::string::npos) {
        try { out.status = std::stoi(status.substr(sp1 + 1, sp2 - sp1 - 1)); } catch (...) {}
    }
    auto body_pos = response.find("\r\n\r\n");
    out.body = body_pos == std::string::npos ? "" : response.substr(body_pos + 4);
    out.ok = out.status >= 200 && out.status < 300;
    if (!out.ok) out.error = "http " + std::to_string(out.status);
    return out;
}

}  // namespace af
