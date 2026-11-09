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

Chain::Chain(ChainConfig cfg) : cfg_(std::move(cfg)) {
    super_batch_k_ = cfg_.super_batch_k;
}
Chain::~Chain() { stop(); }

void Chain::start() {
    if (running_.exchange(true)) return;
    if (cfg_.auto_persist && !cfg_.data_dir.empty()) {
        fs::create_directories(cfg_.data_dir + "/batches");
        if (super_batch_k_ > 0) {
            fs::create_directories(cfg_.data_dir + "/super_batches");
        }
    }
    if (!has_signer_ && !has_hmac_) {
        // 安全红线：绝不使用任何硬编码/机器派生的弱默认密钥。
        // 未配置签名私钥或 HMAC 密钥时，批次保持“无签名”状态；
        // 服务端在配置了验签密钥的情况下会拒绝这类批次（只记录不告警的部署除外）。
        AF_LOG_WARN("chain: 未配置任何签名密钥（chain.signer_key / chain.hmac_key），"
                      "批次将不签名；生产环境必须配置共享 HMAC 密钥，否则服务端验签会失败");
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
    // 使用微秒粒度（与 audit-summary 中 created_at_us 字段一致），保证服务端验签 payload 与客户端签名 payload 完全相同。
    auto sig_us = std::chrono::duration_cast<std::chrono::microseconds>(b.created_at.time_since_epoch()).count();
    std::string payload = b.id + "|" + std::to_string(sig_us) + "|" + b.merkle_root;
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

    // 检查是否达到超级批次阈值
    bool need_super = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        last_batch_id_ = b.id;
        last_merkle_   = b.merkle_root;
        total_batches_++;
        if (super_batch_k_ > 0) {
            pending_batch_ids_.push_back(b.id);
            pending_batch_roots_.push_back(b.merkle_root);
            if (pending_batch_roots_.size() >= super_batch_k_) {
                need_super = true;
            }
        }
    }
    // 超级批次构建在锁外完成（涉及 Merkle 树 + 签名，耗时操作）
    if (need_super) {
        std::vector<std::string> sb_ids;
        std::vector<std::string> sb_roots;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            sb_ids.swap(pending_batch_ids_);
            sb_roots.swap(pending_batch_roots_);
        }
        auto sb = build_super_batch(std::move(sb_ids), std::move(sb_roots));
        if (cfg_.auto_persist) persist_super_batch(sb);
        AF_LOG_INFO("chain: super batch id=" << sb.id
                      << " batches=" << sb.batch_ids.size()
                      << " super_root=" << sb.super_root.substr(0, 16) << "...");
    }
    AF_LOG_INFO("chain: flushed batch id=" << b.id << " events=" << b.events.size()
                  << " merkle=" << b.merkle_root.substr(0, 16) << "...");
    if (batch_cb_) {
        // 注意：这里不能静默吞异常。回调负责把批次交给 transport / remote_client，
        // 一旦抛异常，这批事件就永远丢了（表现为"客户端采集正常但服务端收不到"）。
        try { batch_cb_(b); }
        catch (const std::exception& e) {
            AF_LOG_ERROR("chain: batch callback threw: " << e.what());
        }
        catch (...) {
            AF_LOG_ERROR("chain: batch callback threw unknown exception");
        }
    }
    return b;
}

void Chain::persist_batch(const EventBatch& b) {
    if (cfg_.data_dir.empty()) return;
    std::string path = cfg_.data_dir + "/batches/" + b.id + ".json";
    std::ofstream o(path, std::ios::binary);
    if (!o) return;
    o << "{\n"
      << "  \"id\": \"" << b.id << "\",\n"
      << "  \"merkle_root\": \"" << b.merkle_root << "\",\n"
      << "  \"signature\": \"" << b.signature << "\",\n"
      << "  \"count\": " << b.events.size() << ",\n";
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                  b.created_at.time_since_epoch()).count();
    o << "  \"created_at\": " << us << ",\n";
    o << "  \"events\": [\n";
    for (std::size_t i = 0; i < b.events.size(); ++i) {
        o << "    " << b.events[i].to_json();
        if (i + 1 < b.events.size()) o << ',';
        o << "\n";
    }
    o << "  ]\n"
      << "}\n";
    o.close();
    if (!o) {
        AF_LOG_WARN("chain: failed to persist batch file " << path);
        return;
    }
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
    // 与 build_batch 签名 payload 保持一致：微秒粒度
    auto verify_us = std::chrono::duration_cast<std::chrono::microseconds>(b.created_at.time_since_epoch()).count();
    std::string payload = b.id + "|" + std::to_string(verify_us) + "|" + b.merkle_root;
    return b.signature == crypto::hmac_sha256_hex(hmac_key, payload);
}

bool Chain::verify_batch_with_key(const EventBatch& b, const crypto::KeyPair& kp) {
    if (!kp.is_valid()) return false;
    // 与 build_batch 签名 payload 保持一致：微秒粒度
    auto verify_us = std::chrono::duration_cast<std::chrono::microseconds>(b.created_at.time_since_epoch()).count();
    std::string payload = b.id + "|" + std::to_string(verify_us) + "|" + b.merkle_root;
    return kp.verify(ByteBuffer(payload.begin(), payload.end()),
                     crypto::from_hex(b.signature));
}

std::string Chain::last_batch_id() const { return last_batch_id_; }
std::string Chain::last_merkle_root() const { return last_merkle_; }

// ---------------- 超级批次实现 ----------------

std::string Chain::super_batch_payload(const SuperBatch& sb) {
    // 与 EventBatch 签名 payload 模式一致：微秒粒度
    // 含 prev_super_root 实现跨超级批次的链式锚定
    return sb.id + "|" + std::to_string(sb.created_at_us) + "|" +
           sb.super_root + "|" + sb.prev_super_root;
}

SuperBatch Chain::build_super_batch(std::vector<std::string>&& batch_ids,
                                    std::vector<std::string>&& batch_roots) {
    SuperBatch sb;
    sb.batch_ids   = std::move(batch_ids);
    sb.batch_roots = std::move(batch_roots);

    // 生成超级批次 ID（与 EventBatch ID 生成方式一致）
    auto now = SysClock::now();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
                      now.time_since_epoch()).count();
    sb.created_at_us = static_cast<u64>(micros);
    sb.id = crypto::to_hex(crypto::sha256(
        std::to_string(micros) + "-" + std::to_string(sb.batch_ids.size()))).substr(0, 16);

    // 将各批次的 merkle_root（hex 字符串）转为 ByteBuffer 作为叶子
    std::vector<ByteBuffer> leaves;
    leaves.reserve(sb.batch_roots.size());
    for (const auto& root : sb.batch_roots) {
        leaves.push_back(ByteBuffer(root.begin(), root.end()));
    }
    crypto::MerkleTree tree(std::move(leaves));
    sb.super_root = tree.root_hex();

    // 链式锚定：记录前一个超级批次根
    sb.prev_super_root = last_super_root_;

    // 签名（与 EventBatch 签名逻辑一致：优先 Ed25519，回退 HMAC）
    std::string payload = super_batch_payload(sb);
    if (has_signer_) {
        auto sig = signer_.sign(ByteBuffer(payload.begin(), payload.end()));
        sb.signature = crypto::to_hex(sig);
    } else if (has_hmac_) {
        sb.signature = crypto::hmac_sha256_hex(hmac_key_, payload);
    }

    // 更新链式锚定根
    last_super_root_ = sb.super_root;
    return sb;
}

void Chain::persist_super_batch(const SuperBatch& sb) {
    if (cfg_.data_dir.empty()) return;
    std::string path = cfg_.data_dir + "/super_batches/" + sb.id + ".json";
    std::ofstream o(path, std::ios::binary);
    if (!o) return;
    o << "{\n"
      << "  \"id\": \"" << sb.id << "\",\n"
      << "  \"super_root\": \"" << sb.super_root << "\",\n"
      << "  \"prev_super_root\": \"" << sb.prev_super_root << "\",\n"
      << "  \"signature\": \"" << sb.signature << "\",\n"
      << "  \"batch_count\": " << sb.batch_ids.size() << ",\n"
      << "  \"created_at\": " << sb.created_at_us << ",\n"
      << "  \"batch_ids\": [";
    for (std::size_t i = 0; i < sb.batch_ids.size(); ++i) {
        o << "\"" << sb.batch_ids[i] << "\"";
        if (i + 1 < sb.batch_ids.size()) o << ", ";
    }
    o << "],\n  \"batch_roots\": [";
    for (std::size_t i = 0; i < sb.batch_roots.size(); ++i) {
        o << "\"" << sb.batch_roots[i] << "\"";
        if (i + 1 < sb.batch_roots.size()) o << ", ";
    }
    o << "]\n}\n";
    o.close();
    if (!o) {
        AF_LOG_WARN("chain: failed to persist super batch file " << path);
    }
}

bool Chain::verify_super_batch(const SuperBatch& sb, const std::string& hmac_key) {
    if (hmac_key.empty()) return false;
    std::string payload = super_batch_payload(sb);
    return sb.signature == crypto::hmac_sha256_hex(hmac_key, payload);
}

bool Chain::verify_super_batch_with_key(const SuperBatch& sb, const crypto::KeyPair& kp) {
    if (!kp.is_valid()) return false;
    std::string payload = super_batch_payload(sb);
    return kp.verify(ByteBuffer(payload.begin(), payload.end()),
                     crypto::from_hex(sb.signature));
}

Result<std::vector<SuperBatch>> Chain::recent_super_batches(std::size_t n) const {
    std::vector<SuperBatch> out;
    if (cfg_.data_dir.empty()) return out;
    auto lst = fs::list_directory(cfg_.data_dir + "/super_batches");
    if (lst.is_err()) return Result<std::vector<SuperBatch>>(lst.error());
    auto& files = lst.value();

    // 先解析全部文件，再按 created_at_us 降序排列（最新在前），最后截取 n 条
    for (const auto& f : files) {
        std::ifstream in(f, std::ios::binary);
        if (!in) continue;
        std::ostringstream ss; ss << in.rdbuf();
        std::string content = ss.str();

        // 最小化重建：提取元数据字段
        SuperBatch sb;
        auto get_str = [&](const std::string& key) -> std::string {
            auto marker = "\"" + key + "\":";
            auto pos = content.find(marker);
            if (pos == std::string::npos) return {};
            pos += marker.size();
            // 跳过冒号后的空白字符
            while (pos < content.size() && (content[pos] == ' ' || content[pos] == '\t')) ++pos;
            if (pos >= content.size() || content[pos] != '"') return {};
            ++pos;
            auto end = content.find('"', pos);
            return end == std::string::npos ? std::string() : content.substr(pos, end - pos);
        };
        auto get_u64 = [&](const std::string& key) -> u64 {
            auto marker = "\"" + key + "\":";
            auto pos = content.find(marker);
            if (pos == std::string::npos) return 0;
            pos += marker.size();
            while (pos < content.size() && (content[pos] == ' ' || content[pos] == '\t')) ++pos;
            u64 val = 0;
            while (pos < content.size() && content[pos] >= '0' && content[pos] <= '9') {
                val = val * 10 + static_cast<u64>(content[pos] - '0');
                ++pos;
            }
            return val;
        };
        sb.id              = get_str("id");
        sb.super_root      = get_str("super_root");
        sb.prev_super_root = get_str("prev_super_root");
        sb.signature      = get_str("signature");
        sb.created_at_us  = get_u64("created_at");
        out.push_back(std::move(sb));
    }
    // 按创建时间降序排列（最新在前）
    std::sort(out.begin(), out.end(),
              [](const SuperBatch& a, const SuperBatch& b) {
                  return a.created_at_us > b.created_at_us;
              });
    // 截取最近 n 条
    if (out.size() > n) out.resize(n);
    return out;
}

}  // namespace af::chain
