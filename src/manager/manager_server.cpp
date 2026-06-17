#include "auditforwarder/manager.h"

#include "auditforwarder/config.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>

#ifdef AF_PLATFORM_UNIX
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif
#ifdef AF_PLATFORM_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  define close closesocket
#endif

namespace af {

namespace {
std::string url_decode(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '+') o.push_back(' ');
        else if (c == '%' && i + 2 < s.size()) {
            char hi = s[i + 1], lo = s[i + 2];
            auto h = [](char x) {
                if (x >= '0' && x <= '9') return x - '0';
                if (x >= 'a' && x <= 'f') return x - 'a' + 10;
                if (x >= 'A' && x <= 'F') return x - 'A' + 10;
                return 0;
            };
            o.push_back(static_cast<char>((h(hi) << 4) | h(lo)));
            i += 2;
        } else o.push_back(c);
    }
    return o;
}
std::string status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
    }
    return "OK";
}
}  // namespace

SimpleHttpManager::SimpleHttpManager(ManagerConfig cfg) : cfg_(std::move(cfg)) {}
SimpleHttpManager::~SimpleHttpManager() { stop(); }

Result<void> SimpleHttpManager::start(Agent& agent) {
    agent_ = &agent;
#ifdef AF_PLATFORM_WINDOWS
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    auto colon = cfg_.listen.find(':');
    if (colon == std::string::npos)
        return Result<void>(Error::Code::InvalidArgument, "bad listen address");
    std::string host = cfg_.listen.substr(0, colon);
    int port = std::stoi(cfg_.listen.substr(colon + 1));

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return Result<void>(Error::Code::IoError, "socket");
    int one = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<u16>(port));
    if (host.empty() || host == "0.0.0.0") addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        // Try DNS
        addrinfo hints{}; hints.ai_family = AF_INET;
        addrinfo* res = nullptr;
        if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
            return Result<void>(Error::Code::NotFound, "bad host: " + host);
        }
        std::memcpy(&addr.sin_addr, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, sizeof(in_addr));
        freeaddrinfo(res);
    }
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        return Result<void>(Error::Code::IoError, std::string("bind: ") + strerror(errno));
    }
    if (::listen(listen_fd_, 32) < 0) {
        return Result<void>(Error::Code::IoError, std::string("listen: ") + strerror(errno));
    }
    running_.store(true);
    thr_ = std::thread([this] { accept_loop(); });
    AF_LOG_INFO("manager: listening on " << cfg_.listen);
    return Result<void>::ok();
}

void SimpleHttpManager::stop() {
    if (!running_.exchange(false)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, 2);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (thr_.joinable()) thr_.join();
#ifdef AF_PLATFORM_WINDOWS
    WSACleanup();
#endif
}

void SimpleHttpManager::accept_loop() {
    while (running_.load()) {
        sockaddr_in cli{}; socklen_t cl = sizeof(cli);
        int cfd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&cli), &cl);
        if (cfd < 0) {
            if (!running_.load()) return;
            continue;
        }
        // For simplicity, handle one client per thread (no thread pool dependency here)
        std::thread([this, cfd] { handle_client(cfd); ::close(cfd); }).detach();
    }
}

void SimpleHttpManager::handle_client(int fd) {
    std::string req;
    char buf[4096];
    int n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0) {
        req.append(buf, n);
        if (req.find("\r\n\r\n") != std::string::npos) break;
    }
    if (req.empty()) return;

    // Parse request line
    std::istringstream iss(req);
    std::string method, target, version;
    iss >> method >> target >> version;

    // Body (after \r\n\r\n)
    std::string body;
    auto bp = req.find("\r\n\r\n");
    if (bp != std::string::npos) body = req.substr(bp + 4);

    // Headers (auth check)
    bool auth_ok = cfg_.auth_token.empty();
    {
        std::istringstream hl(req.substr(0, bp == std::string::npos ? req.size() : bp));
        std::string line;
        std::getline(hl, line);
        while (std::getline(hl, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.size() > 14 && line.substr(0, 14) == "Authorization:") {
                std::string v = line.substr(15);
                // trim
                while (!v.empty() && v.front() == ' ') v.erase(0, 1);
                if (v.size() > 7 && v.substr(0, 7) == "Bearer ") v = v.substr(7);
                if (v == cfg_.auth_token) auth_ok = true;
            }
            if (line.empty()) break;
        }
    }

    std::string path = target;
    std::string query;
    auto q = path.find('?');
    if (q != std::string::npos) { query = path.substr(q + 1); path = path.substr(0, q); }

    std::string content_type = "application/json";
    int status = 200;
    std::string resp_body;
    if (!auth_ok) {
        status = 401;
        resp_body = "{\"error\":\"unauthorized\"}";
    } else {
        resp_body = route(method, path, query, body, content_type, status);
    }

    std::ostringstream resp;
    resp << "HTTP/1.1 " << status << " " << status_text(status) << "\r\n"
         << "Content-Type: " << content_type << "\r\n"
         << "Content-Length: " << resp_body.size() << "\r\n"
         << "Connection: close\r\n"
         << "Server: AuditForwarder/1.0\r\n"
         << "\r\n"
         << resp_body;
    auto s = resp.str();
    ::send(fd, s.data(), s.size(), 0);
}

std::string SimpleHttpManager::route(const std::string& method, const std::string& path,
                                     const std::string& query, const std::string& body,
                                     std::string& content_type, int& status) {
    if (path == "/health" || path == "/status") {
        if (!agent_) { status = 503; return "{}"; }
        auto s = agent_->stats();
        std::ostringstream o;
        o << "{"
          << "\"running\":" << (agent_->is_running() ? "true" : "false") << ","
          << "\"events_collected\":" << s.events_collected << ","
          << "\"events_uploaded\":" << s.events_uploaded << ","
          << "\"events_failed\":" << s.events_failed << ","
          << "\"events_dropped\":" << s.events_dropped << ","
          << "\"alerts\":" << s.alerts << ","
          << "\"bytes_uploaded\":" << s.bytes_uploaded << ","
          << "\"uptime_seconds\":" << s.uptime_seconds
          << "}";
        return o.str();
    }
    if (path == "/config" && method == "GET") {
        content_type = "text/plain";
        return af::Config::instance().dump_json();
    }
    if (path == "/config/reload" && method == "POST") {
        auto r = agent_->reload_config();
        if (r.is_err()) { status = 500; return "{\"error\":\"" + r.error().message() + "\"}"; }
        return "{\"status\":\"reloaded\"}";
    }
    if (path == "/batches" && method == "GET") {
        auto lst = agent_->chain_module().recent_batches(50);
        if (lst.is_err()) { status = 500; return "{}"; }
        std::ostringstream o;
        o << "{\"batches\":[";
        bool first = true;
        for (const auto& b : lst.value()) {
            if (!first) o << ',';
            first = false;
            o << "{\"id\":\"" << b.id << "\","
              << "\"merkle_root\":\"" << b.merkle_root << "\","
              << "\"signature\":\"" << b.signature << "\"}";
        }
        o << "]}";
        return o.str();
    }
    if (path == "/upgrade" && method == "POST") {
        // body is URL of new binary
        AF_LOG_INFO("manager: remote upgrade requested: " << body);
        status = 202;
        return "{\"accepted\":true}";
    }
    status = 404;
    return "{\"error\":\"not found\"}";
}

}  // namespace af
