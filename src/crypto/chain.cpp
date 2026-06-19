#include "auditforwarder/chain.h"

#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>

#ifdef AF_PLATFORM_WINDOWS
#  include <windows.h>
#endif

namespace af::chain {

namespace {
std::string proc_hostname() {
    char buf[256] = {0};
#ifdef AF_PLATFORM_WINDOWS
    DWORD n = sizeof(buf);
    ::GetComputerNameA(buf, &n);
#else
    gethostname(buf, sizeof(buf) - 1);
#endif
    return std::string(buf);
}
}  // namespace

Chain::Chain(ChainConfig cfg) : cfg_(std::move(cfg)) {}
Chain::~Chain() { stop(); }

void Chain::start() {
    if (running_.exchange(true)) return;
    if (cfg_.auto_persist && !cfg_.data_dir.empty()) {
        fs::create_directories(cfg_.data_dir + "/batches");
    }
    if (!has_signer_ && !has_hmac_) {
        // Default: use HMAC with a machine-derived key
        hmac_key_ = "auditforwarder-default-" + proc_hostname();
        has_hmac_ = true;
    }
}

void Chain::stop() { running_.store(false); }

void Chain::set_signer(crypto::KeyPair kp) { signer_ = std::move(kp); has_signer_ = signer_.is_valid(); }
void Chain::set_hmac_key(const std::string& k) { hmac_key_ = k; has_hmac_ = !k.empty(); }
void Chain::on_batch(BatchCallback cb) { batch_cb_ = std::move(cb); }

void Chain::submit(AuditEvent& ev) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        ev.seq       = ++last_seq_;
        ev.timestamp = SysClock::now();
        ev.ts_micros = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
                                          ev.timestamp.time_since_epoch()).count());
        // Compute the canonical hash payload
        ev.compute_hash();
        // The hash field after compute_hash() is the canonicalization string.
        // Replace it with a SHA-256 of that string for compactness.
        ev.hash = crypto::sha256_hex(ev.hash);
        // Link to previous event (across all threads; protected by mtx_)
        ev.prev_hash = last_event_hash_;
        last_event_hash_ = ev.hash;

        pending_.push_back(ev);
        total_events_++;
    }
    if (pending_.size() >= cfg_.batch_size) {
        flush();
    }
}

EventBatch Chain::build_batch(std::vector<AuditEvent>&& events) {
    EventBatch b;
    auto now = SysClock::now();
    b.created_at = now;
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    b.id = crypto::to_hex(crypto::sha256(std::to_string(micros) + "-" + std::to_string(events.size()))).substr(0, 16);
    b.events = std::move(events);

    // 构建 Merkle 树
    std::vector<ByteBuffer> leaves;
    leaves.reserve(b.events.size());
    for (const auto& e : b.events) {
        leaves.push_back(ByteBuffer(e.hash.begin(), e.hash.end()));
    }
    crypto::MerkleTree tree(std::move(leaves));
    b.merkle_root = tree.root_hex();

    // 签名
    std::string payload = b.id + "|" + std::to_string(b.created_at.time_since_epoch().count()) + "|" + b.merkle_root;
    if (has_signer_) {
        auto sig = signer_.sign(ByteBuffer(payload.begin(), payload.end()));
        b.signature = crypto::to_hex(sig);
    } else if (has_hmac_) {
        b.signature = crypto::hmac_sha256_hex(hmac_key_, payload);
    }
    return b;
}

Result<EventBatch> Chain::flush() {
    std::vector<AuditEvent> events;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (pending_.empty()) return Result<EventBatch>(Error::Code::InvalidArgument, "no events");
        events.swap(pending_);
    }
    auto b = build_batch(std::move(events));
    if (cfg_.auto_persist) persist_batch(b);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        last_batch_id_ = b.id;
        last_merkle_   = b.merkle_root;
        total_batches_++;
    }
    AF_LOG_INFO("chain: flushed batch id=" << b.id << " events=" << b.events.size()
                  << " merkle=" << b.merkle_root.substr(0, 16) << "...");
    if (batch_cb_) {
        try { batch_cb_(b); } catch (...) {}
    }
    return b;
}

void Chain::persist_batch(const EventBatch& b) {
    if (cfg_.data_dir.empty()) return;
    std::string path = cfg_.data_dir + "/batches/" + b.id + ".json";
    std::ofstream o(path, std::ios::binary);
    if (!o) return;
    o << "{\"id\":\"" << b.id << "\","
      << "\"merkle_root\":\"" << b.merkle_root << "\","
      << "\"signature\":\"" << b.signature << "\","
      << "\"count\":" << b.events.size() << ",";
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                  b.created_at.time_since_epoch()).count();
    o << "\"created_at\":" << us << ",";
    o << "\"events\":[";
    for (std::size_t i = 0; i < b.events.size(); ++i) {
        if (i) o << ',';
        o << b.events[i].to_json();
    }
    o << "]}";
}

Result<std::vector<EventBatch>> Chain::recent_batches(std::size_t n) const {
    std::vector<EventBatch> out;
    if (cfg_.data_dir.empty()) return out;
    auto lst = fs::list_directory(cfg_.data_dir + "/batches");
    if (lst.is_err()) return Result<std::vector<EventBatch>>(lst.error());
    auto& files = lst.value();
    std::sort(files.rbegin(), files.rend());
    for (std::size_t i = 0; i < std::min(n, files.size()); ++i) {
        std::ifstream in(files[i], std::ios::binary);
        if (!in) continue;
        std::ostringstream ss; ss << in.rdbuf();
        // 最小化重建：暂时不解析回 EventBatch，
        // 但记录元数据以便远程验证者可以拉取文件。
        EventBatch b;
        std::string content = ss.str();
        auto get_str = [&](const std::string& key) -> std::string {
            auto pos = content.find("\"" + key + "\":\"");
            if (pos == std::string::npos) return {};
            pos += key.size() + 4;
            auto end = content.find('"', pos);
            return end == std::string::npos ? std::string() : content.substr(pos, end - pos);
        };
        b.id          = get_str("id");
        b.merkle_root = get_str("merkle_root");
        b.signature   = get_str("signature");
        out.push_back(std::move(b));
    }
    return out;
}

bool Chain::verify_batch(const EventBatch& b, const std::string& hmac_key) {
    if (hmac_key.empty()) return false;
    std::string payload = b.id + "|" + std::to_string(b.created_at.time_since_epoch().count()) + "|" + b.merkle_root;
    return b.signature == crypto::hmac_sha256_hex(hmac_key, payload);
}

bool Chain::verify_batch_with_key(const EventBatch& b, const crypto::KeyPair& kp) {
    if (!kp.is_valid()) return false;
    std::string payload = b.id + "|" + std::to_string(b.created_at.time_since_epoch().count()) + "|" + b.merkle_root;
    return kp.verify(ByteBuffer(payload.begin(), payload.end()),
                     crypto::from_hex(b.signature));
}

std::string Chain::last_batch_id() const { return last_batch_id_; }
std::string Chain::last_merkle_root() const { return last_merkle_; }

}  // namespace af::chain
