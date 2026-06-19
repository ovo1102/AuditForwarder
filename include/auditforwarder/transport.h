#pragma once
// AuditForwarder - HTTPS 传输模块，支持压缩、加密和断点续传。

#include "auditforwarder/agent.h"
#include "auditforwarder/event.h"
#include "auditforwarder/chain.h"
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace af {

struct TransportConfig {
    std::vector<std::string> server_urls;
    std::string mode {"realtime"};  // realtime | batch
    int interval_sec { 30 };
    int max_backoff_sec { 600 };
    bool compress { true };
    bool encrypt_payload { true };
    std::string client_cert;
    std::string client_key;
    std::string ca_cert;
    std::string auth_token;
    std::string agent_id;
    int  request_timeout_sec { 30 };
    bool verify_tls { true };
    std::string data_dir;     // for resume index
};

struct UploadResult {
    bool     success { false };
    int      http_status { 0 };
    std::string error;
    u64      bytes_sent { 0 };
};

class HttpsTransport : public Transport {
public:
    explicit HttpsTransport(TransportConfig cfg);
    ~HttpsTransport() override;

    Result<void> start(Agent& agent) override;
    void         stop() override;
    Result<void> send_batch(const chain::EventBatch& b) override;
    bool         is_running() const override { return running_.load(); }
    std::string  name() const override { return "https"; }

    // 压缩 + （可选）加密批次为传输格式
    ByteBuffer encode_batch(const chain::EventBatch& b, const std::string& sym_key = {});

    // 解析服务器响应以提取检查点信息
    static std::string extract_checkpoint(const std::string& body);

private:
    void worker_loop();
    UploadResult do_upload(const std::string& url, const ByteBuffer& body, const std::string& batch_id);
    void persist_index();
    void load_index();

    TransportConfig       cfg_;
    std::atomic<bool>     running_{ false };
    std::atomic<bool>     stopping_{ false };
    std::thread           worker_;
    Agent*                agent_ { nullptr };
    std::mutex            mtx_;
    std::vector<chain::EventBatch> queue_;
    std::map<std::string, std::string> resume_index_;  // batch_id -> last_error/url

    std::string           sym_key_;   // 用于载荷加密的对称密钥
    std::string           checkpoint_path_;
};

}  // namespace af
