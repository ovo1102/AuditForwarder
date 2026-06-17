#pragma once
// AuditForwarder - Chain of custody: links events in hash chain, batches into
// Merkle trees, signs batches.

#include "auditforwarder/event.h"
#include "auditforwarder/crypto.h"
#include <atomic>
#include <functional>
#include <mutex>
#include <string>

namespace af::chain {

using EventBatch = af::EventBatch;

// Configuration for the chain
struct ChainConfig {
    std::string data_dir;            // local storage of signed batches
    std::size_t batch_size { 256 };  // events per batch
    bool        sign_batches { true };
    bool        auto_persist { true };
};

// Callback invoked whenever a new batch has been built and persisted.
// Useful for bridging to the transport.
using BatchCallback = std::function<void(const EventBatch&)>;

// Process raw events: assign id, compute hash, link prev_hash, append to batch.
class Chain {
public:
    explicit Chain(ChainConfig cfg);
    ~Chain();

    void start();
    void stop();

    // Set the key used for signing batches. If not set, HMAC-SHA256 is used.
    void set_signer(crypto::KeyPair kp);
    void set_hmac_key(const std::string& key);

    // Register a callback invoked after each successful batch build.
    void on_batch(BatchCallback cb);

    // Submit a single event to be hashed and added to the current batch.
    void submit(AuditEvent& ev);

    // Force flush of the current batch.
    Result<EventBatch> flush();

    // Read back the most recent N signed batches (for audit).
    Result<std::vector<EventBatch>> recent_batches(std::size_t n = 10) const;

    // Statistics
    u64  total_events() const   { return total_events_.load(); }
    u64  total_batches() const  { return total_batches_.load(); }
    u64  last_event_seq() const { return last_seq_.load(); }
    std::string last_batch_id() const;
    std::string last_merkle_root() const;

    // Verify a batch's signature and hash chain.
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
