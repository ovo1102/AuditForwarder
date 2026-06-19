#pragma once
// AuditForwarder - 证据链：将事件链接到哈希链中，批量构建
// Merkle 树，并对批次签名。

#include "auditforwarder/event.h"
#include "auditforwarder/crypto.h"
#include <atomic>
#include <functional>
#include <mutex>
#include <string>

namespace af::chain {

using EventBatch = af::EventBatch;

// 链配置
struct ChainConfig {
    std::string data_dir;            // 签名批次的本地存储
    std::size_t batch_size { 256 };  // 每批次事件数
    bool        sign_batches { true };
    bool        auto_persist { true };
};

// 当新批次构建并持久化后调用的回调函数。
// 用于桥接到传输模块。
using BatchCallback = std::function<void(const EventBatch&)>;

// 处理原始事件：分配 ID、计算哈希、链接 prev_hash、追加到批次。
class Chain {
public:
    explicit Chain(ChainConfig cfg);
    ~Chain();

    void start();
    void stop();

    // 设置用于签名批次的密钥。如未设置，则使用 HMAC-SHA256。
    void set_signer(crypto::KeyPair kp);
    void set_hmac_key(const std::string& key);

    // 注册每次成功构建批次后调用的回调。
    void on_batch(BatchCallback cb);

    // 提交单个事件进行哈希计算并添加到当前批次。
    void submit(AuditEvent& ev);

    // 强制刷新当前批次。
    Result<EventBatch> flush();

    // 读取最近 N 个已签名批次（用于审计）。
    Result<std::vector<EventBatch>> recent_batches(std::size_t n = 10) const;

    // 统计信息
    u64  total_events() const   { return total_events_.load(); }
    u64  total_batches() const  { return total_batches_.load(); }
    u64  last_event_seq() const { return last_seq_.load(); }
    std::string last_batch_id() const;
    std::string last_merkle_root() const;

    // 验证批次的签名和哈希链。
    static bool verify_batch(const EventBatch& b, const std::string& hmac_key = {});
    static bool verify_batch_with_key(const EventBatch& b, const crypto::KeyPair& kp);

private:
    void persist_batch(const EventBatch& b);
    EventBatch build_batch(std::vector<AuditEvent>&& events);

    ChainConfig                cfg_;
    std::mutex                 mtx_;
    std::vector<AuditEvent>    pending_;
    crypto::KeyPair            signer_;
    std::string                hmac_key_;
    bool                       has_signer_  { false };
    bool                       has_hmac_    { false };
    BatchCallback              batch_cb_;
    std::atomic<bool>          running_     { false };
    std::atomic<u64>           total_events_{ 0 };
    std::atomic<u64>           total_batches_{ 0 };
    std::atomic<u64>           last_seq_    { 0 };
    std::string                last_batch_id_;
    std::string                last_merkle_;
    std::string                last_event_hash_;
};

}  // namespace af::chain
