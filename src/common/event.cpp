#include "auditforwarder/event.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace af {

const char* to_string(EventCategory c) noexcept {
    switch (c) {
        case EventCategory::System:    return "system";
        case EventCategory::Process:   return "process";
        case EventCategory::File:      return "file";
        case EventCategory::Network:   return "network";
        case EventCategory::Registry:  return "registry";
        case EventCategory::Command:   return "command";
        case EventCategory::Gui:       return "gui";
        case EventCategory::Auth:      return "auth";
        case EventCategory::Privilege: return "privilege";
        case EventCategory::Driver:    return "driver";
        case EventCategory::Syscall:   return "syscall";
        case EventCategory::Config:    return "config";
        case EventCategory::Update:    return "update";
        case EventCategory::Other:     return "other";
    }
    return "other";
}

EventCategory category_from_string(const std::string& s) noexcept {
    if (s == "system")    return EventCategory::System;
    if (s == "process")   return EventCategory::Process;
    if (s == "file")      return EventCategory::File;
    if (s == "network")   return EventCategory::Network;
    if (s == "registry")  return EventCategory::Registry;
    if (s == "command")   return EventCategory::Command;
    if (s == "gui")       return EventCategory::Gui;
    if (s == "auth")      return EventCategory::Auth;
    if (s == "privilege") return EventCategory::Privilege;
    if (s == "driver")    return EventCategory::Driver;
    if (s == "syscall")   return EventCategory::Syscall;
    if (s == "config")    return EventCategory::Config;
    if (s == "update")    return EventCategory::Update;
    return EventCategory::Other;
}

const char* to_string(EventAction a) noexcept {
    switch (a) {
        case EventAction::Unknown:      return "unknown";
        case EventAction::Create:       return "create";
        case EventAction::Read:         return "read";
        case EventAction::Write:        return "write";
        case EventAction::Delete:       return "delete";
        case EventAction::Rename:       return "rename";
        case EventAction::Chmod:        return "chmod";
        case EventAction::Execute:      return "execute";
        case EventAction::Spawn:        return "spawn";
        case EventAction::Exit:         return "exit";
        case EventAction::Connect:      return "connect";
        case EventAction::Disconnect:   return "disconnect";
        case EventAction::Listen:       return "listen";
        case EventAction::Send:         return "send";
        case EventAction::Receive:      return "receive";
        case EventAction::Login:        return "login";
        case EventAction::Logout:       return "logout";
        case EventAction::AuthFail:     return "auth_fail";
        case EventAction::PrivilegeEsc: return "privilege_escalation";
        case EventAction::KeyEvent:     return "key_event";
        case EventAction::MouseEvent:   return "mouse_event";
        case EventAction::WindowFocus:  return "window_focus";
        case EventAction::Clipboard:    return "clipboard";
        case EventAction::Screenshot:   return "screenshot";
        case EventAction::Set:          return "set";
        case EventAction::Get:          return "get";
        case EventAction::Load:         return "load";
        case EventAction::Unload:       return "unload";
        case EventAction::Alert:        return "alert";
        case EventAction::Block:        return "block";
        case EventAction::Quarantine:   return "quarantine";
        case EventAction::Kill:         return "kill";
        case EventAction::Annotate:     return "annotate";
        case EventAction::SystemStart:  return "system_start";
        case EventAction::SystemStop:   return "system_stop";
    }
    return "unknown";
}

EventAction action_from_string(const std::string& s) noexcept {
    if (s == "unknown")             return EventAction::Unknown;
    if (s == "create")              return EventAction::Create;
    if (s == "read")                return EventAction::Read;
    if (s == "write")               return EventAction::Write;
    if (s == "delete")              return EventAction::Delete;
    if (s == "rename")              return EventAction::Rename;
    if (s == "chmod")               return EventAction::Chmod;
    if (s == "execute")             return EventAction::Execute;
    if (s == "spawn")               return EventAction::Spawn;
    if (s == "exit")                return EventAction::Exit;
    if (s == "connect")             return EventAction::Connect;
    if (s == "disconnect")          return EventAction::Disconnect;
    if (s == "listen")              return EventAction::Listen;
    if (s == "send")                return EventAction::Send;
    if (s == "receive")             return EventAction::Receive;
    if (s == "login")               return EventAction::Login;
    if (s == "logout")              return EventAction::Logout;
    if (s == "auth_fail")           return EventAction::AuthFail;
    if (s == "privilege_escalation") return EventAction::PrivilegeEsc;
    if (s == "key_event")           return EventAction::KeyEvent;
    if (s == "mouse_event")         return EventAction::MouseEvent;
    if (s == "window_focus")        return EventAction::WindowFocus;
    if (s == "clipboard")           return EventAction::Clipboard;
    if (s == "screenshot")          return EventAction::Screenshot;
    if (s == "set")                 return EventAction::Set;
    if (s == "get")                 return EventAction::Get;
    if (s == "load")                return EventAction::Load;
    if (s == "unload")              return EventAction::Unload;
    if (s == "alert")               return EventAction::Alert;
    if (s == "block")               return EventAction::Block;
    if (s == "quarantine")          return EventAction::Quarantine;
    if (s == "kill")                return EventAction::Kill;
    if (s == "annotate")            return EventAction::Annotate;
    if (s == "system_start")        return EventAction::SystemStart;
    if (s == "system_stop")         return EventAction::SystemStop;
    return EventAction::Unknown;
}

const char* to_string(EventOutcome o) noexcept {
    switch (o) {
        case EventOutcome::Unknown: return "unknown";
        case EventOutcome::Success: return "success";
        case EventOutcome::Failure: return "failure";
        case EventOutcome::Denied:  return "denied";
    }
    return "unknown";
}

namespace {
std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8]; std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else o.push_back(c);
        }
    }
    return o;
}

void write_kv(std::ostringstream& o, const char* k, const std::string& v, bool first) {
    if (!first) o << ',';
    o << '"' << k << "\":\"" << json_escape(v) << '"';
}
}  // namespace

std::string AuditEvent::to_json() const {
    std::ostringstream o;
    o << '{';
    o << "\"id\":" << id
      << ",\"seq\":" << seq
      << ",\"ts_micros\":" << ts_micros
      << ",\"schema_ver\":" << schema_ver;
    write_kv(o, "category", to_string(category), false);
    write_kv(o, "action",   to_string(action),   false);
    write_kv(o, "outcome",  to_string(outcome),  false);
    write_kv(o, "severity", to_string(severity), false);
    write_kv(o, "host",     host,    false);
    write_kv(o, "agent_id", agent_id, false);
    write_kv(o, "rule_id",  rule_id, false);
    write_kv(o, "command",  command, false);
    write_kv(o, "message",  message, false);
    write_kv(o, "hash",     hash,    false);
    write_kv(o, "prev_hash", prev_hash, false);
    write_kv(o, "signature", signature, false);
    write_kv(o, "batch_id", batch_id, false);
    o << ",\"actor\":{";
    bool first = true;
    auto w = [&](const char* k, const std::string& v) {
        if (!first) o << ',';
        first = false;
        o << '"' << k << "\":\"" << json_escape(v) << '"';
    };
    o << "\"pid\":" << actor.pid << ",\"tid\":" << actor.tid;
    w("name",    actor.name);
    w("path",    actor.path);
    w("user",    actor.user);
    w("sid",     actor.sid);
    w("session", actor.session);
    w("remote",  actor.remote);
    o << "},\"target\":{";
    first = true;
    o << "\"port\":" << target.port;
    w("kind",     target.kind);
    w("path",     target.path);
    w("address",  target.address);
    w("protocol", target.protocol);
    o << "},\"attrs\":{";
    first = true;
    for (const auto& [k, v] : attrs) {
        if (!first) o << ',';
        first = false;
        o << '"' << json_escape(k) << "\":\"" << json_escape(v) << '"';
    }
    o << '}';
    if (!raw_payload.empty()) {
        o << ",\"raw_b64\":\"";
        static const char* hex = "0123456789ABCDEF";
        for (auto b : raw_payload) { o << hex[(b >> 4) & 0xF] << hex[b & 0xF]; }
        o << '"';
    }
    o << '}';
    return o.str();
}

void AuditEvent::compute_hash() {
    // Defer to crypto module; here we just produce a deterministic string.
    std::ostringstream o;
    o << seq << '|' << ts_micros << '|' << to_string(category) << '|'
      << to_string(action) << '|' << to_string(outcome) << '|'
      << actor.pid << '|' << actor.user << '|' << actor.name << '|'
      << target.path << '|' << target.address << '|' << target.port << '|'
      << command << '|' << message << '|';
    for (const auto& [k, v] : attrs) o << k << '=' << v << ';';
    hash = o.str();
    // SHA-256 will be applied in crypto/chain.cpp
}

AuditEvent AuditEvent::from_json(const std::string& /*s*/) {
    // Full JSON deserialization is handled by the JSON transport sink
    // when nlohmann_json is available. Without it, return empty.
    return AuditEvent{};
}

}  // namespace af
