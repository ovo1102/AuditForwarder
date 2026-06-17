#pragma once
// AuditForwarder - Audit event model and processing pipeline.

#include "auditforwarder/types.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace af {

// ---- Event category (top-level classification) ----
enum class EventCategory : u8 {
    System      = 0,  // boot/shutdown, kernel events
    Process     = 1,  // exec, fork, exit
    File        = 2,  // create/read/write/delete/rename/chmod
    Network     = 3,  // connect, listen, send, recv
    Registry    = 4,  // Windows registry
    Command     = 5,  // shell command line
    Gui         = 6,  // GUI interactions (window focus, clipboard)
    Auth        = 7,  // login, logout, sudo, UAC
    Privilege   = 8,  // privilege changes
    Driver      = 9,  // kernel driver load/unload
    Syscall     = 10, // low-level syscall tracing
    Config      = 11, // agent config changes
    Update      = 12, // agent upgrade
    Other       = 255,
};

const char* to_string(EventCategory c) noexcept;
EventCategory category_from_string(const std::string& s) noexcept;

// ---- Action performed (verb) ----
enum class EventAction : u16 {
    Unknown       = 0,
    Create        = 1,
    Read          = 2,
    Write         = 3,
    Delete        = 4,
    Rename        = 5,
    Chmod         = 6,
    Execute       = 7,
    Spawn         = 8,
    Exit          = 9,
    Connect       = 10,
    Disconnect    = 11,
    Listen        = 12,
    Send          = 13,
    Receive       = 14,
    Login         = 20,
    Logout        = 21,
    AuthFail      = 22,
    PrivilegeEsc  = 23,
    KeyEvent      = 30,  // keyboard event (privacy filtered)
    MouseEvent    = 31,
    WindowFocus   = 32,
    Clipboard     = 33,
    Screenshot    = 34,
    Set           = 40,  // registry / config set
    Get           = 41,  // registry / config get
    Load          = 50,  // driver / module load
    Unload        = 51,
    Alert         = 100, // detection alert
    Block         = 101, // policy block
    Quarantine    = 102,
    Kill          = 103,
    Annotate      = 200,
    SystemStart   = 210,
    SystemStop    = 211,
};

const char* to_string(EventAction a) noexcept;
EventAction action_from_string(const std::string& s) noexcept;

// ---- Outcome ----
enum class EventOutcome : u8 {
    Unknown = 0,
    Success = 1,
    Failure = 2,
    Denied  = 3,
};

const char* to_string(EventOutcome o) noexcept;

// ---- Actor (who did it) ----
struct Actor {
    u32         pid     { 0 };
    u32         tid     { 0 };
    std::string name;
    std::string path;
    std::string user;
    std::string sid;     // Windows SID / Linux uid:gid
    std::string session; // session id
    std::string remote;  // remote address if remote actor
};

// ---- Target (what was affected) ----
struct Target {
    std::string kind;     // file, registry-key, socket, process...
    std::string path;     // file path or key
    std::string address;  // network address
    u16         port      { 0 };
    std::string protocol; // tcp/udp/icmp...
};

// ---- Single audit event ----
struct AuditEvent {
    u64                 id            { 0 }; // assigned globally
    u64                 seq           { 0 }; // monotonic seq
    SysTime             timestamp     {};   // wall clock
    u64                 ts_micros     { 0 };
    EventCategory       category      { EventCategory::Other };
    EventAction         action        { EventAction::Unknown };
    EventOutcome        outcome       { EventOutcome::Unknown };
    Severity            severity      { Severity::Info };
    std::string         host;
    std::string         agent_id;
    std::string         rule_id;      // detection rule id
    Actor               actor;
    Target              target;
    std::string         command;      // executed command line
    std::string         message;      // human readable
    std::map<std::string, std::string> attrs;  // additional attributes
    ByteBuffer          raw_payload;  // optional raw evidence (encrypted)
    std::string         hash;         // computed after normalization
    std::string         prev_hash;    // chain link
    std::string         signature;    // signed payload
    std::string         batch_id;     // batch this event belongs to
    u32                 schema_ver    { 1 };

    std::string to_json() const;
    static AuditEvent from_json(const std::string& s);
    void compute_hash();
};

// ---- Event sink interface ----
class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void on_event(const AuditEvent& ev) = 0;
    virtual void flush() {}
    virtual void shutdown() {}
};

using EventSinkPtr = std::shared_ptr<EventSink>;

// ---- Batched event container ----
struct EventBatch {
    std::string         id;
    SysTime             created_at;
    std::vector<AuditEvent> events;
    std::string         merkle_root;
    std::string         signature;
    u64                 prev_batch_id { 0 };
    std::string         prev_merkle;
};

}  // namespace af
