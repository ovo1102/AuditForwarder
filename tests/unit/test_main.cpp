// Unit tests for AuditForwarder core utilities.

#include "auditforwarder/agent.h"
#include "auditforwarder/build_config.h"
#include "auditforwarder/chain.h"
#include "auditforwarder/config.h"
#include "auditforwarder/crypto.h"
#include "auditforwarder/event.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"
#include "auditforwarder/thread_pool.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

namespace {

int passed = 0, failed = 0;

#define AF_EXPECT(cond)                                                      \
    do {                                                                      \
        if (cond) { ++passed; std::printf("[ok]   %s\n", #cond); }            \
        else      { ++failed; std::printf("[FAIL] %s (line %d)\n",            \
                                  #cond, __LINE__); }                         \
    } while (0)

#define AF_EXPECT_EQ(a, b)                                                   \
    do {                                                                      \
        auto _a = (a); auto _b = (b);                                         \
        if (_a == _b) { ++passed; std::printf("[ok]   %s == %s\n",            \
            #a, #b); }                                                       \
        else { ++failed; std::printf("[FAIL] %s != %s (line %d)\n",           \
            #a, #b, __LINE__); }                                              \
    } while (0)

void test_types_and_string_conversion() {
    using namespace af;
    AF_EXPECT_EQ(af::to_string(Severity::Info), std::string("info"));
    AF_EXPECT_EQ(severity_from_string("warning"), Severity::Warning);
    AF_EXPECT_EQ(af::to_string(EventCategory::Process), std::string("process"));
    AF_EXPECT_EQ(category_from_string("network"), EventCategory::Network);
    AF_EXPECT_EQ(af::to_string(EventAction::Execute), std::string("execute"));
    AF_EXPECT_EQ(action_from_string("kill"), EventAction::Kill);
    AF_EXPECT_EQ(af::to_string(EventOutcome::Success), std::string("success"));
}

void test_crypto_hash_and_sign() {
    using namespace af::crypto;
    auto h1 = sha256_hex("hello");
    auto h2 = sha256_hex("hello");
    AF_EXPECT_EQ(h1, h2);
    AF_EXPECT_EQ(h1.size(), (std::size_t)64);

    auto kp = KeyPair::generate(KeyPair::Algorithm::Ed25519);
    AF_EXPECT(kp.is_ok());
    auto msg = std::string("the quick brown fox");
    auto sig = kp.value().sign_hex(msg);
    AF_EXPECT(kp.value().verify_hex(msg, sig));
    AF_EXPECT(!kp.value().verify_hex(msg + "X", sig));
}

void test_crypto_aead_roundtrip() {
    using namespace af::crypto;
    auto key = random_bytes(32);
    std::string pt_string = "classified payload";
    af::ByteBuffer pt(pt_string.begin(), pt_string.end());
    auto enc = aes_gcm_encrypt(key, pt);
    AF_EXPECT_EQ(enc.error, 0);
    auto dec = aes_gcm_decrypt(key, enc);
    AF_EXPECT(dec.is_ok());
    AF_EXPECT_EQ(std::string(dec.value().begin(), dec.value().end()), pt_string);

    // Tamper with ciphertext -> should fail
    enc.ciphertext[0] ^= 0x55;
    auto dec2 = aes_gcm_decrypt(key, enc);
    AF_EXPECT(dec2.is_err());
}

void test_crypto_merkle_proof() {
    using namespace af::crypto;
    std::vector<af::ByteBuffer> leaves;
    for (int i = 0; i < 8; ++i) {
        std::string s = std::to_string(i);
        leaves.emplace_back(s.begin(), s.end());
    }
    MerkleTree tree(std::move(leaves));
    auto root = tree.root_hex();
    AF_EXPECT_EQ(root.size(), (std::size_t)64);
    auto proof = tree.proof(3);
    std::string s3 = std::to_string(3);
    std::string s4 = std::to_string(4);
    AF_EXPECT(MerkleTree::verify(root, af::ByteBuffer(s3.begin(), s3.end()), 3, proof));
    AF_EXPECT(!MerkleTree::verify(root, af::ByteBuffer(s4.begin(), s4.end()), 3, proof));
}

void test_config_load_yaml() {
    using namespace af;
    std::string yaml = R"(
agent:
  id: test-1
  data_dir: /var/lib/af
log:
  level: debug
server:
  urls:
    - https://a.example.com
    - https://b.example.com
)";
    auto r = Config::instance().load_from_string(yaml, "yaml");
    AF_EXPECT(r.is_ok());
    AF_EXPECT_EQ(Config::instance().get_string("agent.id"), std::string("test-1"));
    AF_EXPECT_EQ(Config::instance().get_string("log.level"), std::string("debug"));
    AF_EXPECT_EQ(Config::instance().get_int("server.urls.size"), 0);
}

void test_config_load_json() {
    using namespace af;
    std::string json = R"({"a":{"b":{"c":42}},"list":[1,2,3]})";
    auto r = Config::instance().load_from_string(json, "json");
    AF_EXPECT(r.is_ok());
    AF_EXPECT_EQ(Config::instance().get_int("a.b.c"), 42);
    AF_EXPECT_EQ(Config::instance().get_int("list.size"), 0);
}

void test_event_json_roundtrip() {
    using namespace af;
    AuditEvent ev;
    ev.id = 42;
    ev.seq = 1;
    ev.category = EventCategory::File;
    ev.action   = EventAction::Write;
    ev.outcome  = EventOutcome::Success;
    ev.host     = "host-1";
    ev.actor.pid = 1234;
    ev.actor.name = "bash";
    ev.actor.user = "root";
    ev.target.path = "/etc/passwd";
    ev.command = "echo hi";
    ev.message = "file write /etc/passwd";
    auto s = ev.to_json();
    AF_EXPECT(s.find("\"file\"") != std::string::npos);
    AF_EXPECT(s.find("\"bash\"") != std::string::npos);
    AF_EXPECT(s.find("\"root\"") != std::string::npos);
    AF_EXPECT(s.find("\"write\"") != std::string::npos);
}

void test_thread_pool_priority() {
    using namespace af;
    ThreadPool pool(2);
    pool.start(2);
    std::atomic<int> order{0};
    std::vector<int> seq;
    std::mutex m;
    auto a = pool.submit([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lk(m);
        seq.push_back(1);
    });
    auto b = pool.submit([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lk(m);
        seq.push_back(2);
    }, ThreadPool::Priority::High);
    a.wait(); b.wait();
    AF_EXPECT_EQ(seq.size(), (std::size_t)2);
    AF_EXPECT_EQ(seq[0], 2);  // high priority task should run first or concurrently
    pool.shutdown();
}

void test_chain_submission_and_signing() {
    using namespace af;
    chain::ChainConfig cfg;
    cfg.data_dir = ".";
    cfg.batch_size = 4;
    cfg.auto_persist = false;
    chain::Chain ch(cfg);
    ch.start();
    ch.set_hmac_key("test-key");

    for (int i = 0; i < 5; ++i) {
        AuditEvent ev;
        ev.category = EventCategory::Process;
        ev.action   = EventAction::Spawn;
        ev.actor.pid = 1000 + i;
        ev.target.path = "/usr/bin/test";
        ch.submit(ev);
    }
    auto b = ch.flush();
    AF_EXPECT(b.is_ok());
    AF_EXPECT_EQ(b.value().events.size(), (std::size_t)5);
    AF_EXPECT(ch.verify_batch(b.value(), "test-key"));
    AF_EXPECT(!ch.verify_batch(b.value(), "wrong-key"));
}

void test_path_utilities() {
    using namespace af::fs;
    AF_EXPECT_EQ(basename("/etc/hosts"), std::string("hosts"));
    AF_EXPECT_EQ(basename("C:\\Windows\\hosts"), std::string("hosts"));
    AF_EXPECT_EQ(dirname("/etc/hosts"), std::string("/etc"));
    AF_EXPECT_EQ(extension("a.tar.gz"), std::string(".gz"));
    AF_EXPECT_EQ(normalize("/a//b/../c/"), std::string("/a/c"));
}

}  // namespace

int main() {
    std::printf("AuditForwarder unit tests\n");
    test_types_and_string_conversion();
    test_crypto_hash_and_sign();
    test_crypto_aead_roundtrip();
    test_crypto_merkle_proof();
    test_config_load_yaml();
    test_config_load_json();
    test_event_json_roundtrip();
    test_thread_pool_priority();
    test_chain_submission_and_signing();
    test_path_utilities();

    std::printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
