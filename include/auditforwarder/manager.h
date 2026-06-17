#pragma once
// AuditForwarder - Manager server: a minimal HTTP/HTTPS admin interface for
// status, config reload, log query, and remote upgrade.

#include "auditforwarder/agent.h"
#include <atomic>
#include <map>
#include <string>
#include <thread>

namespace af {

struct ManagerConfig {
    std::string listen       { "127.0.0.1:8443" };
    std::string auth_token;
    std::string tls_cert;
    std::string tls_key;
    bool        use_tls      { false };
    std::string data_dir;
};

class SimpleHttpManager : public ManagerServer {
public:
    explicit SimpleHttpManager(ManagerConfig cfg);
    ~SimpleHttpManager() override;

    Result<void> start(Agent& agent) override;
    void         stop() override;
    std::string  endpoint() const override { return cfg_.listen; }

private:
    void accept_loop();
    void handle_client(int fd);
    std::string route(const std::string& method, const std::string& path,
                      const std::string& query, const std::string& body,
                      std::string& content_type, int& status);

    ManagerConfig       cfg_;
    std::atomic<bool>   running_ { false };
    std::thread         thr_;
    Agent*              agent_  { nullptr };
    int                 listen_fd_ { -1 };
};

}  // namespace af
