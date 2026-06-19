#pragma once
// AuditForwarder - 用于日志完整性、签名、加密的密码学原语。

#include "auditforwarder/types.h"
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace af::crypto {

// ---- 编码辅助函数 ----
std::string to_hex(const ByteBuffer& data);
std::string to_hex(const u8* data, std::size_t len);
ByteBuffer  from_hex(const std::string& s);
std::string to_base64(const ByteBuffer& data);
std::string to_base64(const u8* data, std::size_t len);
ByteBuffer  from_base64(const std::string& s);

// ---- 哈希函数 ----
// 计算给定数据的 SHA-256，返回 32 字节。
ByteBuffer sha256(const ByteBuffer& data);
ByteBuffer sha256(const u8* data, std::size_t len);
ByteBuffer sha256(const std::string& s);
std::string sha256_hex(const std::string& s);

// 使用密钥的 HMAC-SHA-256。
ByteBuffer hmac_sha256(const ByteBuffer& key, const ByteBuffer& data);
std::string hmac_sha256_hex(const std::string& key, const std::string& data);

// 增量 SHA-256。
class Sha256 {
public:
    Sha256();
    ~Sha256();
    void update(const u8* data, std::size_t len);
    void update(const ByteBuffer& data);
    void update(const std::string& s);
    void finalize(ByteBuffer& out);   // 32 字节
    void finalize_hex(std::string& out);
    void reset();
private:
    struct Impl;
    Impl* impl_;
};

// ---- 随机数 ----
ByteBuffer random_bytes(std::size_t len);
std::string random_hex(std::size_t bytes);
std::string random_base64(std::size_t bytes);

// ---- 对称加密 (AES-256-GCM) ----
struct AeadResult {
    ByteBuffer ciphertext;   // 密文 || 标签
    ByteBuffer iv;           // 12 字节
    int        error { 0 };
};

AeadResult aes_gcm_encrypt(const ByteBuffer& key, const ByteBuffer& plaintext,
                           const ByteBuffer& aad = {});
AeadResult aes_gcm_encrypt(const std::string& key, const std::string& plaintext,
                           const std::string& aad = {});

Result<ByteBuffer> aes_gcm_decrypt(const ByteBuffer& key, const AeadResult& r,
                                   const ByteBuffer& aad = {});
Result<std::string> aes_gcm_decrypt(const std::string& key, const AeadResult& r,
                                     const std::string& aad = {});

// ---- 非对称签名 (Ed25519) ----
class KeyPair {
public:
    enum class Algorithm { Ed25519, RSA2048 };
    KeyPair();
    ~KeyPair();
    KeyPair(KeyPair&& o) noexcept;
    KeyPair& operator=(KeyPair&& o) noexcept;
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;

    static Result<KeyPair> generate(Algorithm alg = Algorithm::Ed25519);
    static Result<KeyPair> load_pem(const std::string& priv_pem, const std::string& password = {});
    Result<std::string>    public_pem() const;
    Result<std::string>    private_pem(const std::string& password = {}) const;
    std::string            fingerprint() const;
    const std::string&     algorithm_name() const { return alg_name_; }
    bool                    is_valid() const;

    ByteBuffer sign(const ByteBuffer& msg) const;
    bool      verify(const ByteBuffer& msg, const ByteBuffer& sig) const;

    std::string sign_hex(const std::string& msg) const;
    bool        verify_hex(const std::string& msg, const std::string& sig_hex) const;

private:
    struct Impl;
    Impl*        impl_;
    std::string  alg_name_;
};

// 使用外部提供的公钥 (PEM) 验证签名。
Result<bool> verify_with_public_pem(const std::string& pem,
                                    const ByteBuffer& msg,
                                    const ByteBuffer& sig);

// ---- Merkle 树（二进制 SHA-256）----
class MerkleTree {
public:
    explicit MerkleTree(std::vector<ByteBuffer> leaves);
    std::string root_hex() const;
    std::size_t size() const { return leaves_.size(); }
    std::vector<std::string> proof(std::size_t index) const;
    static bool verify(const std::string& root_hex,
                       const ByteBuffer& leaf,
                       std::size_t index,
                       const std::vector<std::string>& proof);
private:
    std::vector<ByteBuffer> leaves_;
    std::vector<std::string> layers_hex_;
    void build();
};

}  // namespace af::crypto
