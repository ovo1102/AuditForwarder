#include "auditforwarder/transport.h"

#include "auditforwarder/agent.h"
#include "auditforwarder/crypto.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <sys/stat.h>
#include <sys/types.h>
#ifdef AF_PLATFORM_UNIX
#  include <sys/stat.h>
#  include <unistd.h>
#  include <dirent.h>
#endif
#ifdef AF_PLATFORM_WINDOWS
#  include <direct.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <thread>
#include <zlib.h>

namespace af {

namespace {

// Zlib 压缩/解压缩辅助函数
ByteBuffer zlib_compress(const ByteBuffer& in) {
    z_stream s{};
    deflateInit(&s, Z_DEFAULT_COMPRESSION);
    ByteBuffer out(in.size() + 64);
    s.next_in  = const_cast<ByteBuffer::value_type*>(in.data());
    s.avail_in = static_cast<u32>(in.size());
    s.next_out  = out.data();
    s.avail_out = static_cast<u32>(out.size());
    while (s.avail_in > 0) {
        if (deflate(&s, Z_NO_FLUSH) != Z_OK) { deflateEnd(&s); return {}; }
        if (s.avail_out == 0) {
            std::size_t used = out.size();
            out.resize(used * 2);
            s.next_out = out.data() + used;
            s.avail_out = static_cast<u32>(out.size() - used);
        }
    }
    int r = deflate(&s, Z_FINISH);
    deflateEnd(&s);
    if (r != Z_STREAM_END) return {};
    out.resize(s.total_out);
    return out;
}

ByteBuffer zlib_decompress(const ByteBuffer& in) {
    z_stream s{};
    inflateInit(&s);
    s.next_in  = const_cast<ByteBuffer::value_type*>(in.data());
    s.avail_in = static_cast<u32>(in.size());
    ByteBuffer out(in.size() * 3 + 64);
    s.next_out  = out.data();
    s.avail_out = static_cast<u32>(out.size());
    while (s.avail_in > 0) {
        int r = inflate(&s, Z_NO_FLUSH);
        if (r == Z_STREAM_END) break;
        if (r != Z_OK) { inflateEnd(&s); return {}; }
        if (s.avail_out == 0) {
            std::size_t used = out.size();
            out.resize(used * 2);
            s.next_out = out.data() + used;
            s.avail_out = static_cast<u32>(out.size() - used);
        }
    }
    inflateEnd(&s);
    out.resize(s.total_out);
    return out;
}

std::string event_batch_to_canonical_json(const chain::EventBatch& b) {
    std::ostringstream o;
    o << "{\"id\":\"" << b.id << "\","
      << "\"merkle_root\":\"" << b.merkle_root << "\","
      << "\"signature\":\"" << b.signature << "\","
      << "\"count\":" << b.events.size() << ",";
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                  b.created_at.time_since_epoch()).count();
    o << "\"created_at\":" << us << ","
      << "\"events\":[";
    for (std::size_t i = 0; i < b.events.size(); ++i) {
        if (i) o << ',';
        o << b.events[i].to_json();
    }
    o << "]}";
    return o.str();
}

}  // namespace

HttpsTransport::HttpsTransport(TransportConfig cfg) : cfg_(std::move(cfg)) {}
HttpsTransport::~HttpsTransport() { stop(); }

Result<void> HttpsTransport::start(Agent& agent) {
    agent_ = &agent;
    if (cfg_.data_dir.empty()) cfg_.data_dir = ".";
    auto dir_r = af::fs::create_directories(cfg_.data_dir);
    (void)dir_r;
    checkpoint_path_ = cfg_.data_dir + "/transport.index";
    load_index();
    // Derive a stable per-agent symmetric key for payload encryption
    sym_key_ = crypto::sha256_hex("af-sym:" + cfg_.agent_id);
    running_.store(true);
    worker_ = std::thread([this] { worker_loop(); });
    AF_LOG_INFO("transport: started, mode=" << cfg_.mode
                  << " servers=" << cfg_.server_urls.size());
    return Result<void>::ok();
}

void HttpsTransport::stop() {
    if (stopping_.exchange(true)) return;
    running_.store(false);
    if (worker_.joinable()) worker_.join();
    persist_index();
}

Result<void> HttpsTransport::send_batch(const chain::EventBatch& b) {
    std::lock_guard<std::mutex> lk(mtx_);
    queue_.push_back(b);
    return Result<void>::ok();
}

ByteBuffer HttpsTransport::encode_batch(const chain::EventBatch& b, const std::string& sym_key) {
    std::string json = event_batch_to_canonical_json(b);
    ByteBuffer raw(json.begin(), json.end());
    if (cfg_.compress) raw = zlib_compress(raw);
    if (cfg_.encrypt_payload || !sym_key.empty()) {
        auto key = sym_key.empty() ? sym_key_ : sym_key;
        crypto::AeadResult r = crypto::aes_gcm_encrypt(
            ByteBuffer(key.begin(), key.end()),
            raw,
            ByteBuffer(b.id.begin(), b.id.end()));
        ByteBuffer out;
        // header: "AE1" || iv_len(1) || iv || cipher_len(4) || cipher
        out.push_back('A'); out.push_back('E'); out.push_back('1');
        out.push_back(static_cast<u8>(r.iv.size()));
        out.insert(out.end(), r.iv.begin(), r.iv.end());
        u32 cl = static_cast<u32>(r.ciphertext.size());
        out.push_back(static_cast<u8>(cl & 0xFF));
        out.push_back(static_cast<u8>((cl >> 8) & 0xFF));
        out.push_back(static_cast<u8>((cl >> 16) & 0xFF));
        out.push_back(static_cast<u8>((cl >> 24) & 0xFF));
        out.insert(out.end(), r.ciphertext.begin(), r.ciphertext.end());
        return out;
    }
    return raw;
}

std::string HttpsTransport::extract_checkpoint(const std::string& body) {
    auto pos = body.find("\"checkpoint\":\"");
    if (pos == std::string::npos) return {};
    pos += 14;
    auto end = body.find('"', pos);
    return end == std::string::npos ? std::string() : body.substr(pos, end - pos);
}

namespace {
void fs_create_dir_or_throw(const std::string& p) {
    (void)p;  // placeholder kept for source compatibility
}
}  // namespace

// ------------------------------------------------------------------
// Worker loop: drains the in-memory queue and uploads with retry.
// ------------------------------------------------------------------
void HttpsTransport::worker_loop() {
    int backoff = 1;
    while (running_.load()) {
        chain::EventBatch batch;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (queue_.empty()) {
                if (cfg_.mode == "batch") {
                    std::this_thread::sleep_for(std::chrono::seconds(cfg_.interval_sec));
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                continue;
            }
            batch = std::move(queue_.front());
            queue_.erase(queue_.begin());
        }
        if (cfg_.server_urls.empty()) {
            AF_LOG_WARN("transport: no server configured, dropping batch " << batch.id);
            continue;
        }
        bool uploaded = false;
        for (const auto& url : cfg_.server_urls) {
            ByteBuffer body = encode_batch(batch);
            auto r = do_upload(url, body, batch.id);
            if (r.success) {
                AF_LOG_INFO("transport: uploaded batch " << batch.id
                              << " bytes=" << r.bytes_sent << " status=" << r.http_status);
                if (agent_) {
                    agent_->record_uploaded(batch.events.size(), r.bytes_sent);
                }
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    resume_index_.erase(batch.id);
                }
                uploaded = true;
                backoff = 1;
                break;
            } else {
                AF_LOG_WARN("transport: upload to " << url << " failed: " << r.error);
                if (agent_) agent_->record_failed(batch.events.size());
            }
        }
        if (!uploaded) {
            // 放回队列头部并进行限流
            {
                std::lock_guard<std::mutex> lk(mtx_);
                resume_index_[batch.id] = "failed";
                queue_.insert(queue_.begin(), std::move(batch));
            }
            int sleep_s = std::min(backoff, cfg_.max_backoff_sec);
            std::this_thread::sleep_for(std::chrono::seconds(sleep_s));
            backoff = std::min(backoff * 2, cfg_.max_backoff_sec);
        }
        if (cfg_.mode == "batch") {
            std::this_thread::sleep_for(std::chrono::seconds(cfg_.interval_sec));
        }
    }
}

// ------------------------------------------------------------------
// do_upload: perform a single HTTPS POST using OpenSSL BIO.
// ------------------------------------------------------------------
UploadResult HttpsTransport::do_upload(const std::string& url, const ByteBuffer& body, const std::string& batch_id) {
    UploadResult r;
    if (url.size() < 8 || url.substr(0, 8) != "https://") {
        r.error = "unsupported scheme: " + url;
        return r;
    }
    // Parse URL: https://host[:port]/path
    std::string rest = url.substr(8);
    auto slash = rest.find('/');
    std::string authority = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    std::string path = (slash == std::string::npos) ? "/" : rest.substr(slash);

    std::string host; int port = 443;
    auto colon = authority.find(':');
    if (colon == std::string::npos) { host = authority; }
    else { host = authority.substr(0, colon); port = std::stoi(authority.substr(colon + 1)); }

    OpenSSL_add_all_algorithms();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { r.error = "ctx"; return r; }

    if (cfg_.verify_tls) {
        if (!cfg_.ca_cert.empty()) {
            if (SSL_CTX_load_verify_locations(ctx, cfg_.ca_cert.c_str(), nullptr) != 1) {
                r.error = "load ca"; SSL_CTX_free(ctx); return r;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    if (!cfg_.client_cert.empty() && !cfg_.client_key.empty()) {
        if (SSL_CTX_use_certificate_file(ctx, cfg_.client_cert.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, cfg_.client_key.c_str(), SSL_FILETYPE_PEM) != 1) {
            r.error = "client key/cert"; SSL_CTX_free(ctx); return r;
        }
    }

    // 连接 TCP
    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) { r.error = "bio"; SSL_CTX_free(ctx); return r; }
    std::string hostport = host + ":" + std::to_string(port);
    BIO_set_conn_hostname(bio, hostport.c_str());

    if (BIO_do_connect(bio) <= 0) {
        r.error = "connect failed"; BIO_free_all(bio); SSL_CTX_free(ctx); return r;
    }
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) { r.error = "ssl null"; BIO_free_all(bio); SSL_CTX_free(ctx); return r; }
    if (cfg_.verify_tls && SSL_get_verify_result(ssl) != X509_V_OK) {
        r.error = "tls verify failed"; BIO_free_all(bio); SSL_CTX_free(ctx); return r;
    }

    // Build HTTP/1.1 request
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: AuditForwarder/1.0\r\n"
        << "Content-Type: application/octet-stream\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "X-AuditForwarder-Batch: " << batch_id << "\r\n"
        << "X-AuditForwarder-Agent: " << cfg_.agent_id << "\r\n"
        << "Connection: close\r\n";
    if (!cfg_.auth_token.empty()) req << "Authorization: Bearer " << cfg_.auth_token << "\r\n";
    req << "\r\n";

    std::string hdr = req.str();
    if (BIO_write(bio, hdr.data(), static_cast<int>(hdr.size())) <= 0) {
        r.error = "write header failed"; BIO_free_all(bio); SSL_CTX_free(ctx); return r;
    }
    if (!body.empty()) {
        int sent = 0;
        while (sent < static_cast<int>(body.size())) {
            int n = BIO_write(bio, body.data() + sent, static_cast<int>(body.size() - sent));
            if (n <= 0) { r.error = "write body failed"; BIO_free_all(bio); SSL_CTX_free(ctx); return r; }
            sent += n;
        }
    }

    // Read response
    std::string response;
    char buf[4096];
    int n;
    while ((n = BIO_read(bio, buf, sizeof(buf))) > 0) {
        response.append(buf, n);
    }
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    r.bytes_sent = body.size();
    // Parse status line
    auto line_end = response.find("\r\n");
    if (line_end == std::string::npos) { r.error = "bad response"; return r; }
    std::string status = response.substr(0, line_end);
    auto sp1 = status.find(' ');
    auto sp2 = status.find(' ', sp1 + 1);
    if (sp1 != std::string::npos && sp2 != std::string::npos) {
        r.http_status = std::stoi(status.substr(sp1 + 1, sp2 - sp1 - 1));
    }
    r.success = (r.http_status >= 200 && r.http_status < 300);
    if (!r.success) r.error = "http " + std::to_string(r.http_status);
    return r;
}

// 辅助函数保留以保持源码兼容性（不再使用）
static void* ssl_via_bio(BIO* bio) { (void)bio; return nullptr; }

void HttpsTransport::persist_index() {
    if (checkpoint_path_.empty()) return;
    std::ofstream o(checkpoint_path_, std::ios::binary);
    if (!o) return;
    o << "{\"resumed\":[";
    bool first = true;
    std::lock_guard<std::mutex> lk(mtx_);
    for (const auto& [k, v] : resume_index_) {
        if (!first) o << ',';
        first = false;
        o << '"' << k << '"';
    }
    o << "]}";
}

void HttpsTransport::load_index() {
    if (checkpoint_path_.empty()) return;
    std::ifstream in(checkpoint_path_, std::ios::binary);
    if (!in) return;
    std::ostringstream ss; ss << in.rdbuf();
    auto body = ss.str();
    auto pos = body.find("\"resumed\":[");
    if (pos == std::string::npos) return;
    pos += 11;
    auto end = body.find(']', pos);
    if (end == std::string::npos) return;
    std::string list = body.substr(pos, end - pos);
    std::size_t i = 0;
    while (i < list.size()) {
        if (list[i] != '"') { ++i; continue; }
        auto j = list.find('"', i + 1);
        if (j == std::string::npos) break;
        std::string id = list.substr(i + 1, j - i - 1);
        resume_index_[id] = "persisted";
        i = j + 1;
    }
    AF_LOG_INFO("transport: loaded " << resume_index_.size() << " resume checkpoints");
}

}  // namespace af
