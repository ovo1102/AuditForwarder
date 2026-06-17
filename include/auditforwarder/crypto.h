#pragma once
// AuditForwarder - Cryptographic primitives for log integrity, signing, encryption.

#include "auditforwarder/types.h"
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace af::crypto {

// ---- Encoding helpers ----
std::string to_hex(const ByteBuffer& data);
std::string to_hex(const u8* data, std::size_t len);
ByteBuffer  from_hex(const std::string& s);
std::string to_base64(const ByteBuffer& data);
std::string to_base64(const u8* data, std::size_t len);
ByteBuffer  from_base64(const std::string& s);

// ---- Hashing ----
// Compute SHA-256 of the given data, returning 32 bytes.
ByteBuffer sha256(const ByteBuffer& data);
ByteBuffer sha256(const u8* data, std::size_t len);
ByteBuffer sha256(const std::string& s);
std::string sha256_hex(const std::string& s);

// HMAC-SHA-256 with a key.
ByteBuffer hmac_sha256(const ByteBuffer& key, const ByteBuffer& data);
std::string hmac_sha256_hex(const std::string& key, const std::string& data);

// Incremental SHA-256.
class Sha256 {
public:
    Sha256();
    ~Sha256();
    void update(const u8* data, std::size_t len);
    void update(const ByteBuffer& data);
    void update(const std::string& s);
    void finalize(ByteBuffer& out);   // 32 bytes
    void finalize_hex(std::string& out);
    void reset();
private:
    struct Impl;
    Impl* impl_;
};

// ---- Random ----
ByteBuffer random_bytes(std::size_t len);
std::string random_hex(std::size_t bytes);
std::string random_base64(std::size_t bytes);

// ---- Symmetric encryption (AES-256-GCM) ----
struct AeadResult {
    ByteBuffer ciphertext;   // ciphertext || tag
    ByteBuffer iv;           // 12 bytes
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

// ---- Asymmetric signing (Ed25519) ----
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

// Verify a signature using an externally supplied public key (PEM).
Result<bool> verify_with_public_pem(const std::string& pem,
                                    const ByteBuffer& msg,
                                    const ByteBuffer& sig);

// ---- Merkle tree (binary SHA-256) ----
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
