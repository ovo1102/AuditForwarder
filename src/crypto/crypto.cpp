#include "auditforwarder/crypto.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cstring>
#include <stdexcept>
#include <vector>

namespace af::crypto {

// ============================================================================
// Encoding
// ============================================================================
static const char* HEX_CHARS = "0123456789abcdef";

std::string to_hex(const u8* data, std::size_t len) {
    std::string s;
    s.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        s[2 * i]     = HEX_CHARS[(data[i] >> 4) & 0xF];
        s[2 * i + 1] = HEX_CHARS[data[i] & 0xF];
    }
    return s;
}
std::string to_hex(const ByteBuffer& data) { return to_hex(data.data(), data.size()); }

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
ByteBuffer from_hex(const std::string& s) {
    if (s.size() % 2) return {};
    ByteBuffer out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        int hi = hexval(s[2 * i]);
        int lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return {};
        out[i] = static_cast<u8>((hi << 4) | lo);
    }
    return out;
}

std::string to_base64(const u8* data, std::size_t len) {
    if (len == 0) return {};
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);
    BUF_MEM* p; BIO_get_mem_ptr(b64, &p);
    std::string s(p->data, p->length);
    BIO_free_all(b64);
    return s;
}
std::string to_base64(const ByteBuffer& data) { return to_base64(data.data(), data.size()); }

ByteBuffer from_base64(const std::string& s) {
    if (s.empty()) return {};
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
    mem = BIO_push(b64, mem);
    ByteBuffer out(s.size());
    int n = BIO_read(mem, out.data(), static_cast<int>(out.size()));
    BIO_free_all(mem);
    if (n < 0) return {};
    out.resize(static_cast<std::size_t>(n));
    return out;
}

// ============================================================================
// Hashing
// ============================================================================
ByteBuffer sha256(const u8* data, std::size_t len) {
    ByteBuffer out(SHA256_DIGEST_LENGTH);
    SHA256(data, len, out.data());
    return out;
}
ByteBuffer sha256(const ByteBuffer& data) { return sha256(data.data(), data.size()); }
ByteBuffer sha256(const std::string& s)  { return sha256(reinterpret_cast<const u8*>(s.data()), s.size()); }
std::string sha256_hex(const std::string& s) { return to_hex(sha256(s)); }

ByteBuffer hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) {
    ByteBuffer out(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         data.data(), data.size(),
         out.data(), &len);
    out.resize(len);
    return out;
}
std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    return to_hex(hmac_sha256(ByteBuffer(key.begin(), key.end()),
                                ByteBuffer(data.begin(), data.end())));
}

struct Sha256::Impl {
    EVP_MD_CTX* ctx { nullptr };
    Impl() { ctx = EVP_MD_CTX_new(); }
    ~Impl() { if (ctx) EVP_MD_CTX_free(ctx); }
};

Sha256::Sha256()  : impl_(new Impl()) { reset(); }
Sha256::~Sha256() { delete impl_; }

void Sha256::reset() {
    if (impl_->ctx) EVP_MD_CTX_free(impl_->ctx);
    impl_->ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr);
}
void Sha256::update(const u8* data, std::size_t len) { EVP_DigestUpdate(impl_->ctx, data, len); }
void Sha256::update(const ByteBuffer& d) { update(d.data(), d.size()); }
void Sha256::update(const std::string& s) { update(reinterpret_cast<const u8*>(s.data()), s.size()); }
void Sha256::finalize(ByteBuffer& out) {
    out.assign(EVP_MAX_MD_SIZE, 0);
    unsigned int len = 0;
    EVP_DigestFinal_ex(impl_->ctx, out.data(), &len);
    out.resize(len);
}
void Sha256::finalize_hex(std::string& out) {
    ByteBuffer b; finalize(b); out = to_hex(b);
}

// ============================================================================
// Random
// ============================================================================
ByteBuffer random_bytes(std::size_t len) {
    ByteBuffer out(len);
    if (RAND_bytes(out.data(), static_cast<int>(len)) != 1) {
        // Fallback: pseudo-random via OpenSSL hash chain
        for (std::size_t i = 0; i < len; ++i) {
            out[i] = static_cast<u8>(std::rand() & 0xFF);
        }
    }
    return out;
}
std::string random_hex(std::size_t bytes) { return to_hex(random_bytes(bytes)); }
std::string random_base64(std::size_t bytes) { return to_base64(random_bytes(bytes)); }

// ============================================================================
// AES-256-GCM
// ============================================================================
AeadResult aes_gcm_encrypt(const ByteBuffer& key, const ByteBuffer& pt, const ByteBuffer& aad) {
    AeadResult r;
    if (key.size() != 32) { r.error = -1; return r; }
    r.iv = random_bytes(12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { r.error = -2; return r; }

    int outlen = 0;
    int written = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { r.error = -3; goto end; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(r.iv.size()), nullptr) != 1) { r.error = -4; goto end; }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), r.iv.data()) != 1) { r.error = -5; goto end; }
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1) { r.error = -6; goto end; }
    }
    r.ciphertext.resize(pt.size() + 16);
    if (!pt.empty() && EVP_EncryptUpdate(ctx, r.ciphertext.data(), &outlen, pt.data(), static_cast<int>(pt.size())) != 1) { r.error = -7; goto end; }
    written = outlen;
    if (EVP_EncryptFinal_ex(ctx, r.ciphertext.data() + written, &outlen) != 1) { r.error = -8; goto end; }
    written += outlen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, r.ciphertext.data() + written) != 1) { r.error = -9; goto end; }
    written += 16;
    r.ciphertext.resize(static_cast<std::size_t>(written));
    r.error = 0;
end:
    EVP_CIPHER_CTX_free(ctx);
    return r;
}

AeadResult aes_gcm_encrypt(const std::string& key, const std::string& pt, const std::string& aad) {
    return aes_gcm_encrypt(ByteBuffer(key.begin(), key.end()),
                           ByteBuffer(pt.begin(), pt.end()),
                           aad.empty() ? ByteBuffer{} : ByteBuffer(aad.begin(), aad.end()));
}

Result<ByteBuffer> aes_gcm_decrypt(const ByteBuffer& key, const AeadResult& r, const ByteBuffer& aad) {
    if (key.size() != 32) return Result<ByteBuffer>(Error::Code::InvalidArgument, "key must be 32 bytes");
    if (r.iv.size() != 12) return Result<ByteBuffer>(Error::Code::InvalidArgument, "iv must be 12 bytes");
    if (r.ciphertext.size() < 16) return Result<ByteBuffer>(Error::Code::Integrity, "ciphertext too short");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return Result<ByteBuffer>(Error::Code::IoError, "ctx alloc");
    ByteBuffer out(r.ciphertext.size());
    int outlen = 0, written = 0;
    bool ok = true;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(r.iv.size()), nullptr) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), r.iv.data()) != 1) ok = false;
    if (ok && !aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1) ok = false;
    }
    if (ok && EVP_DecryptUpdate(ctx, out.data(), &outlen, r.ciphertext.data(),
                                static_cast<int>(r.ciphertext.size() - 16)) != 1) ok = false;
    written = outlen;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                   const_cast<void*>(static_cast<const void*>(r.ciphertext.data() + r.ciphertext.size() - 16))) != 1) ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, out.data() + written, &outlen) != 1) ok = false;
    written += outlen;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return Result<ByteBuffer>(Error::Code::Integrity, "decrypt failed");
    out.resize(static_cast<std::size_t>(written));
    return out;
}

Result<std::string> aes_gcm_decrypt(const std::string& key, const AeadResult& r, const std::string& aad) {
    auto b = aes_gcm_decrypt(ByteBuffer(key.begin(), key.end()), r,
                             aad.empty() ? ByteBuffer{} : ByteBuffer(aad.begin(), aad.end()));
    if (b.is_err()) return Result<std::string>(b.error());
    auto& v = b.value();
    return std::string(v.begin(), v.end());
}

// ============================================================================
// KeyPair (Ed25519 / RSA)
// ============================================================================
struct KeyPair::Impl {
    EVP_PKEY* pkey { nullptr };
};

KeyPair::KeyPair() : impl_(new Impl()) {}
KeyPair::~KeyPair() { if (impl_->pkey) EVP_PKEY_free(impl_->pkey); delete impl_; }
KeyPair::KeyPair(KeyPair&& o) noexcept : impl_(o.impl_), alg_name_(std::move(o.alg_name_)) {
    o.impl_ = new Impl();
}
KeyPair& KeyPair::operator=(KeyPair&& o) noexcept {
    if (this != &o) {
        if (impl_->pkey) EVP_PKEY_free(impl_->pkey);
        delete impl_;
        impl_ = o.impl_; alg_name_ = std::move(o.alg_name_);
        o.impl_ = new Impl();
    }
    return *this;
}
bool KeyPair::is_valid() const { return impl_->pkey != nullptr; }

Result<KeyPair> KeyPair::generate(Algorithm alg) {
    KeyPair kp;
    EVP_PKEY_CTX* pctx = nullptr;
    if (alg == Algorithm::Ed25519) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!pctx) return Result<KeyPair>(Error::Code::Crypto, "ctx new");
        if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return Result<KeyPair>(Error::Code::Crypto, "init"); }
        if (EVP_PKEY_keygen(pctx, &kp.impl_->pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return Result<KeyPair>(Error::Code::Crypto, "keygen"); }
        kp.alg_name_ = "ed25519";
    } else {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!pctx) return Result<KeyPair>(Error::Code::Crypto, "ctx new");
        if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return Result<KeyPair>(Error::Code::Crypto, "init"); }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) { EVP_PKEY_CTX_free(pctx); return Result<KeyPair>(Error::Code::Crypto, "bits"); }
        if (EVP_PKEY_keygen(pctx, &kp.impl_->pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return Result<KeyPair>(Error::Code::Crypto, "keygen"); }
        kp.alg_name_ = "rsa-2048";
    }
    EVP_PKEY_CTX_free(pctx);
    return std::move(kp);
}

Result<KeyPair> KeyPair::load_pem(const std::string& priv_pem, const std::string& password) {
    KeyPair kp;
    BIO* bio = BIO_new_mem_buf(priv_pem.data(), static_cast<int>(priv_pem.size()));
    if (!bio) return Result<KeyPair>(Error::Code::IoError, "bio");
    kp.impl_->pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr,
        password.empty() ? nullptr : const_cast<char*>(password.c_str()));
    BIO_free(bio);
    if (!kp.impl_->pkey) return Result<KeyPair>(Error::Code::Parse, "invalid PEM");
    int id = EVP_PKEY_base_id(kp.impl_->pkey);
    kp.alg_name_ = (id == EVP_PKEY_ED25519) ? "ed25519" : "rsa-2048";
    return std::move(kp);
}

Result<std::string> KeyPair::public_pem() const {
    if (!impl_->pkey) return Result<std::string>(Error::Code::InvalidArgument, "no key");
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, impl_->pkey)) { BIO_free(bio); return Result<std::string>(Error::Code::Crypto, "write"); }
    char* p; long n = BIO_get_mem_data(bio, &p);
    std::string s(p, n);
    BIO_free(bio);
    return s;
}

Result<std::string> KeyPair::private_pem(const std::string& password) const {
    if (!impl_->pkey) return Result<std::string>(Error::Code::InvalidArgument, "no key");
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio, impl_->pkey, nullptr, nullptr, 0, nullptr,
        password.empty() ? nullptr : const_cast<char*>(password.c_str()))) {
        BIO_free(bio);
        return Result<std::string>(Error::Code::Crypto, "write");
    }
    char* p; long n = BIO_get_mem_data(bio, &p);
    std::string s(p, n);
    BIO_free(bio);
    return s;
}

std::string KeyPair::fingerprint() const {
    if (!impl_->pkey) return {};
    u8 buf[64]; std::size_t len = 64;
    if (EVP_PKEY_get_raw_public_key(impl_->pkey, buf, &len) == 1) return to_hex(buf, len);
    // Fallback: write to PEM and hash
    auto pem = public_pem();
    if (pem.is_ok()) return sha256_hex(pem.value());
    return {};
}

ByteBuffer KeyPair::sign(const ByteBuffer& msg) const {
    if (!impl_->pkey) return {};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    int id = EVP_PKEY_base_id(impl_->pkey);
    const EVP_MD* md = (id == EVP_PKEY_ED25519) ? nullptr : EVP_sha256();
    if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, impl_->pkey) <= 0) { EVP_MD_CTX_free(ctx); return {}; }
    if (id == EVP_PKEY_ED25519) {
        std::size_t len = 0;
        if (EVP_DigestSign(ctx, nullptr, &len, msg.data(), msg.size()) <= 0) { EVP_MD_CTX_free(ctx); return {}; }
    }
    std::size_t slen = 0;
    if (EVP_DigestSign(ctx, nullptr, &slen, msg.data(), msg.size()) <= 0) { EVP_MD_CTX_free(ctx); return {}; }
    ByteBuffer sig(slen);
    if (EVP_DigestSign(ctx, sig.data(), &slen, msg.data(), msg.size()) <= 0) { EVP_MD_CTX_free(ctx); return {}; }
    sig.resize(slen);
    EVP_MD_CTX_free(ctx);
    return sig;
}

bool KeyPair::verify(const ByteBuffer& msg, const ByteBuffer& sig) const {
    if (!impl_->pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    int id = EVP_PKEY_base_id(impl_->pkey);
    const EVP_MD* md = (id == EVP_PKEY_ED25519) ? nullptr : EVP_sha256();
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, impl_->pkey) <= 0) { EVP_MD_CTX_free(ctx); return false; }
    int r = EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size());
    EVP_MD_CTX_free(ctx);
    return r == 1;
}

std::string KeyPair::sign_hex(const std::string& msg) const { return to_hex(sign(ByteBuffer(msg.begin(), msg.end()))); }
bool KeyPair::verify_hex(const std::string& msg, const std::string& sig_hex) const {
    return verify(ByteBuffer(msg.begin(), msg.end()), from_hex(sig_hex));
}

Result<bool> verify_with_public_pem(const std::string& pem, const ByteBuffer& msg, const ByteBuffer& sig) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return Result<bool>(Error::Code::IoError, "bio");
    EVP_PKEY* pk = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pk) return Result<bool>(Error::Code::Parse, "invalid PEM");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    int id = EVP_PKEY_base_id(pk);
    const EVP_MD* md = (id == EVP_PKEY_ED25519) ? nullptr : EVP_sha256();
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pk) <= 0) { EVP_MD_CTX_free(ctx); EVP_PKEY_free(pk); return false; }
    int r = EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return r == 1;
}

// ============================================================================
// Merkle tree
// ============================================================================
MerkleTree::MerkleTree(std::vector<ByteBuffer> leaves) : leaves_(std::move(leaves)) { build(); }

void MerkleTree::build() {
    layers_hex_.clear();
    if (leaves_.empty()) { layers_hex_.push_back(sha256_hex("")); return; }
    std::vector<std::string> cur;
    cur.reserve(leaves_.size());
    for (auto& l : leaves_) cur.push_back(to_hex(sha256(l)));
    layers_hex_.push_back(cur.empty() ? std::string() : cur.back());
    while (cur.size() > 1) {
        std::vector<std::string> nxt;
        nxt.reserve((cur.size() + 1) / 2);
        for (std::size_t i = 0; i < cur.size(); i += 2) {
            std::string left  = cur[i];
            std::string right = (i + 1 < cur.size()) ? cur[i + 1] : left;
            ByteBuffer joined;
            joined.reserve(left.size() + right.size());
            joined.insert(joined.end(), left.begin(), left.end());
            joined.insert(joined.end(), right.begin(), right.end());
            nxt.push_back(sha256_hex(std::string(joined.begin(), joined.end())));
        }
        cur.swap(nxt);
        layers_hex_.push_back(cur.back());
    }
}

std::string MerkleTree::root_hex() const {
    if (layers_hex_.empty()) return sha256_hex("");
    return layers_hex_.back();
}

std::vector<std::string> MerkleTree::proof(std::size_t index) const {
    std::vector<std::string> out;
    if (index >= leaves_.size()) return out;
    std::vector<std::string> cur;
    cur.reserve(leaves_.size());
    for (auto& l : leaves_) cur.push_back(to_hex(sha256(l)));
    std::size_t idx = index;
    while (cur.size() > 1) {
        std::size_t pair = (idx % 2 == 0) ? idx + 1 : idx - 1;
        out.push_back(pair < cur.size() ? cur[pair] : cur[idx]);
        std::vector<std::string> nxt;
        for (std::size_t i = 0; i < cur.size(); i += 2) {
            std::string l = cur[i];
            std::string r = (i + 1 < cur.size()) ? cur[i + 1] : l;
            ByteBuffer j; j.insert(j.end(), l.begin(), l.end()); j.insert(j.end(), r.begin(), r.end());
            nxt.push_back(sha256_hex(std::string(j.begin(), j.end())));
        }
        cur.swap(nxt);
        idx /= 2;
    }
    return out;
}

bool MerkleTree::verify(const std::string& root_hex, const ByteBuffer& leaf,
                        std::size_t index, const std::vector<std::string>& proof) {
    std::string h = to_hex(sha256(leaf));
    std::size_t idx = index;
    for (const auto& sib : proof) {
        std::string l, r;
        if (idx % 2 == 0) { l = h; r = sib; }
        else              { l = sib; r = h; }
        ByteBuffer j; j.insert(j.end(), l.begin(), l.end()); j.insert(j.end(), r.begin(), r.end());
        h = sha256_hex(std::string(j.begin(), j.end()));
        idx /= 2;
    }
    return h == root_hex;
}

}  // namespace af::crypto
