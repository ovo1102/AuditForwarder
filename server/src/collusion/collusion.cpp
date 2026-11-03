// AuditForwarder - 跨操作员合谋协同检测模块实现。
// 数据流：操作日志流 → 事件清洗 → 资产组+时间窗口聚合（不按操作员分组）
//        → 双路检测（规则引擎 + 行为画像引擎）→ 风险评分 → 分级告警与处置闭环。
// 详见《跨操作员合谋协同行为检测子系统-系统设计方案》与 include/auditforwarder/collusion.h。

#include "auditforwarder/collusion.h"

#include "auditforwarder/crypto.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/onnx_inference.h"      // M3: ONNX 推理封装
#include "auditforwarder/feature_extractor.h"   // M3: 行为特征工程
#include "auditforwarder/behavior_graph.h"      // M4: 轻量级图算法替代 GNN
#include "manager/log_policy_util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <sstream>

namespace af::collusion {

namespace {

// ---------------- 基础工具 ----------------

constexpr std::size_t kMaxRawEvidence = 4096;      // 单条证据链原文截断
constexpr std::size_t kMaxStoredEvents = 5000;     // 风险事件文件行数上限

u64 now_ms() {
    return static_cast<u64>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

u64 now_epoch() {
    return static_cast<u64>(std::time(nullptr));
}

std::string iso_time_epoch(u64 epoch) {
    if (epoch == 0) return {};
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
#ifdef AF_PLATFORM_WINDOWS
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string iso_time_ms(u64 ms) {
    if (ms == 0) return {};
    return iso_time_epoch(ms / 1000);
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

std::string json_array_of_strings(const std::vector<std::string>& v) {
    std::string o = "[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) o += ",";
        o += "\"" + json_escape(v[i]) + "\"";
    }
    o += "]";
    return o;
}

std::string to_lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool json_has_field(const std::string& json, const std::string& key) {
    return json.find("\"" + key + "\"") != std::string::npos;
}

// 提取 JSON 中某个对象字段的原文（含花括号），如 "dispose":{...}；深度感知字符串
std::string json_object_text(const std::string& json, const std::string& key) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return {};
    auto start = json.find('{', p + marker.size());
    if (start == std::string::npos) return {};
    int depth = 0;
    bool in_str = false, esc = false;
    for (std::size_t i = start; i < json.size(); ++i) {
        char c = json[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{') ++depth;
        else if (c == '}') {
            --depth;
            if (depth == 0) return json.substr(start, i - start + 1);
        }
    }
    return {};
}

bool json_bool_field(const std::string& json, const std::string& key, bool def) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return def;
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return def;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (json.compare(p, 4, "true") == 0) return true;
    if (json.compare(p, 5, "false") == 0) return false;
    return def;
}

// 读取文件全部文本；失败返回空串
std::string read_file_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool write_file_text(const std::string& path, const std::string& text) {
    auto dir = fs::dirname(path);
    if (!dir.empty()) (void)fs::create_directories(dir);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << text;
    out.flush();
    return static_cast<bool>(out);
}

std::vector<std::string> read_jsonl(const std::string& path) {
    std::vector<std::string> lines;
    auto content = read_file_text(path);
    if (content.empty()) return lines;
    std::istringstream in(content);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
}

// 在 JSON 对象中替换 "key":{...} 的整个对象值（深度感知字符串，用于处置状态更新）
bool json_replace_object_field(std::string& json, const std::string& key, const std::string& new_obj) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return false;
    p = json.find('{', p + marker.size());
    if (p == std::string::npos) return false;
    int depth = 0;
    bool in_str = false, esc = false;
    for (std::size_t i = p; i < json.size(); ++i) {
        char c = json[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{') ++depth;
        else if (c == '}') {
            --depth;
            if (depth == 0) {
                json = json.substr(0, p) + new_obj + json.substr(i + 1);
                return true;
            }
        }
    }
    return false;
}

// ---------------- 存储路径 ----------------

std::string collusion_dir(const std::string& data_dir) {
    return fs::join(data_dir.empty() ? "data" : data_dir, "collusion");
}
std::string events_path(const std::string& data_dir) {
    return fs::join(collusion_dir(data_dir), "events.jsonl");
}
std::string audit_path(const std::string& data_dir) {
    return fs::join(collusion_dir(data_dir), "audit.jsonl");
}
std::string profile_path(const std::string& data_dir) {
    return fs::join(collusion_dir(data_dir), "profiles.json");
}
std::string policy_dir(const std::string& data_dir) {
    return fs::join(data_dir.empty() ? "data" : data_dir, "policies");
}
std::string config_path(const std::string& data_dir) {
    return fs::join(policy_dir(data_dir), "collusion_config.json");
}
std::string rules_path(const std::string& data_dir) {
    return fs::join(policy_dir(data_dir), "collusion_rules.json");
}
std::string workorders_path(const std::string& data_dir) {
    return fs::join(policy_dir(data_dir), "collusion_workorders.json");
}

// 告警落盘路径：与 manager 侧写入保持一致，按天分片到 alerts/<YYYY-MM-DD>/<host>.jsonl，
// 这样才能被归档线程统一搬移/压缩/清理（原先写 alerts/<host>.jsonl 会绕过分层体系）。
std::string alert_day_dir(const std::string& data_dir, u64 epoch_sec) {
    std::time_t t = static_cast<std::time_t>(epoch_sec);
    std::tm tm{};
#ifdef AF_PLATFORM_WINDOWS
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[16];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
    return fs::join(fs::join(data_dir.empty() ? "data" : data_dir, "alerts"), buf);
}

// ---------------- 默认配置 / 规则 / 工单桩（首次运行自动生成，支持热更新） ----------------

std::string default_config_json() {
    return R"({
  "enabled": true,
  "note": "跨操作员合谋协同检测配置（热更新）；asset_groups.patterns 支持通配符 * 与 ?",
  "short_window_minutes": 15,
  "long_window_hours": 4,
  "flush_grace_seconds": 10,
  "rule_max_factor": 40,
  "profile_max_factor": 25,
  "work_order_deduct": 40,
  "forged_ticket_bonus": 10,
  "score_high": 80,
  "score_mid": 40,
  "alert_dedup_seconds": 300,
  "chain_dedup_seconds": 300,
  "chain_mode": true,
  "chain_span_minutes": 10080,
  "chain_max_events": 200,
  "span_decay_start_minutes": 60,
  "span_decay_per_hour": 1,
  "span_decay_max": 15,
  "eager_eval": false,
  "emergency_mode": false,
  "emergency_until_epoch": 0,
  "profile_enabled": true,
  "ml_enabled": false,
  "ml_high_threshold_pct": 70,
  "ml_max_factor": 30,
  "ml_model_path": "models/isolation_forest.onnx",
  "graph_enabled": false,
  "graph_threshold_pct": 30,
  "graph_max_factor": 25,
  "graph_window_minutes": 15,
  "graph_density_threshold_pct": 30,
  "complementary_action_pairs": [
    { "label": "备份破坏", "first": ["delete_backup", "delete", "remove", "rm", "删除", "删备份"],
      "second": ["unmount", "diskpart", "format", "卸载", "磁盘"] },
    { "label": "提权外泄", "first": ["grant", "privilege", "elevat", "提权", "授权"],
      "second": ["export", "download", "dump", "导出", "下载"] }
  ],
  "asset_groups": [
    { "name": "backup-group",    "patterns": ["*backup*", "*snapshot*", "*快照*", "*.bak", "*备份*", "*storage*", "*volume*"],
      "note": "存储卷/挂载点与备份、快照同属备份链资产：R-001 的卸载步骤落在 volume 上，不纳入本组会断链" },
    { "name": "key-mgmt-group",  "patterns": ["*key*", "*secret*", "*cert*", "*.pem", "*密钥*"] },
    { "name": "sys-config-group","patterns": ["*config*", "*.conf", "*.ini", "*.yaml", "*.yml", "*.service", "*service*", "*hosts*", "*system*", "*log*"],
      "note": "服务名与日志端点纳入：R-003 的重启/清日志步骤按 /system/service、/system/logs 形式出现" },
    { "name": "db-group",        "patterns": ["*database*", "*.db", "*.sql", "*mysql*", "*postgres*", "*oracle*", "*redis*", "*book*", "*user*"],
      "note": "业务库表与账号对象纳入：R-004 的授权/导出/清审计落在 /users 与 /books 资源上" },
    { "name": "general-group",   "patterns": ["*"], "note": "兜底资产组：仅产生低风险线索，可按需删除" }
  ],
  "whitelist_groups": [
    { "name": "示例-数据库协同组", "operators": ["op_dba1", "op_dba2"], "valid_until_epoch": 0,
      "note": "预登记合法协同小组示例：请替换为实际操作员清单，0 表示长期有效" }
  ]
}
)";
}

std::string default_rules_json() {
    // 预置合谋规则：sequence 为按时间有序的操作子序列，每一步任一关键词命中即完成该步骤。
    //
    // 关键词一律使用动作归一化后的精确形式 <verb>.<object>（如 delete.backup）。
    // 不要写裸词 "delete"：严格模式下裸词会被忽略；而在未归一化的事件上裸词又会
    // 把"删除一本书"误判成"删除备份"。精确形式的来源见客户端 ActionNormalizer。
    return R"({
  "rules": [
    { "rule_id": "R-001", "name": "备份销毁合谋", "enabled": true,
      "asset_group": "backup-group", "min_operator_cnt": 2, "base_score": 85,
      "op_sequence": [
        { "any_of": ["delete.backup"] },
        { "any_of": ["unmount.volume", "detach.volume"] },
        { "any_of": ["delete.snapshot"] }
      ] },
    // 只约束「有几个人分担了这条链」，不约束「谁做哪一步」：
    // 甲做前两步、丙做第三步，与甲/乙/丙各做一步，同样命中。
    { "rule_id": "R-002", "name": "密钥权限拆分绕过", "enabled": true,
      "asset_group": "key-mgmt-group", "min_operator_cnt": 2, "base_score": 75,
      "op_sequence": [
        { "any_of": ["create.key"] },
        { "any_of": ["distribute.key"] },
        { "any_of": ["clear.key_audit"] }
      ] },
    { "rule_id": "R-003", "name": "配置篡改链路", "enabled": true,
      "asset_group": "sys-config-group", "min_operator_cnt": 2, "base_score": 70,
      "op_sequence": [
        { "any_of": ["update.config"] },
        { "any_of": ["restart.service"] },
        { "any_of": ["clear.logs"] }
      ] },
    { "rule_id": "R-004", "name": "数据批量外泄", "enabled": true,
      "asset_group": "db-group", "min_operator_cnt": 2, "base_score": 82,
      "op_sequence": [
        { "any_of": ["grant.user", "grant.privilege"] },
        { "any_of": ["export.book", "export.db"] },
        { "any_of": ["clear.book_audit", "clear.db_audit"] }
      ] },
    { "rule_id": "R-005", "name": "权限晋升合谋", "enabled": true,
      "asset_group": "*", "min_operator_cnt": 3, "base_score": 75,
      "op_sequence": [
        { "any_of": ["create.user"] },
        { "any_of": ["assign.user", "grant.admin"] },
        { "any_of": ["exec.purge_books", "exec.*"] }
      ] },
    { "rule_id": "R-006", "name": "同一操作员导出后清除", "enabled": false,
      "group_by": "operator", "timespan_us": 600000000,
      "min_operator_cnt": 1, "base_score": 80,
      "note": "单人规则，与“只研究管理员合谋”的边界冲突，作为负样本禁用",
      "op_sequence": [
        { "any_of": ["export.book", "export.db"] },
        { "any_of": ["clear.book_audit", "clear.db_audit"] }
      ] },
    { "rule_id": "R-007", "name": "同对象提权后外泄", "enabled": false,
      "group_by": "object", "timespan_us": 300000000,
      "min_operator_cnt": 2, "base_score": 82,
      "note": "按 res_key 全等分组，提权与导出落在不同 URL，规则不可达",
      "op_sequence": [
        { "any_of": ["grant.user"] },
        { "any_of": ["export.book"] }
      ] }
  ]
}
)";
}

std::string default_workorders_json() {
    // 外部工单系统 API 的本地桩：生产环境应替换为对接外部工单系统核验接口。
    // 不采信日志内自带工单号，只有登记于此（模拟外部核验通过）的工单才能触发减分。
    return R"({
  "workorders": [
    { "work_order_id": "WO-2026-0001", "status": "执行中",
      "allowed_operators": ["op_dba1", "op_dba2"],
      "valid_from_epoch": 0, "valid_until_epoch": 0,
      "note": "示例工单：合谋演示环境使用" }
  ]
}
)";
}

// ---------------- 结构化读写 ----------------

std::string patterns_json(const std::vector<std::string>& patterns) {
    return json_array_of_strings(patterns);
}

std::string config_to_json(const EngineConfig& c) {
    std::ostringstream o;
    o << "{\n"
      << "  \"enabled\": " << (c.enabled ? "true" : "false") << ",\n"
      << "  \"short_window_minutes\": " << (c.short_window_ms / 60000) << ",\n"
      << "  \"long_window_hours\": " << (c.long_window_ms / 3600000) << ",\n"
      << "  \"flush_grace_seconds\": " << (c.flush_grace_ms / 1000) << ",\n"
      << "  \"rule_max_factor\": " << c.rule_max_factor << ",\n"
      << "  \"profile_max_factor\": " << c.profile_max_factor << ",\n"
      << "  \"work_order_deduct\": " << c.work_order_deduct << ",\n"
      << "  \"forged_ticket_bonus\": " << c.forged_ticket_bonus << ",\n"
      << "  \"score_high\": " << c.score_high << ",\n"
      << "  \"score_mid\": " << c.score_mid << ",\n"
      << "  \"alert_dedup_seconds\": " << c.alert_dedup_seconds << ",\n"
      << "  \"chain_dedup_seconds\": " << c.chain_dedup_seconds << ",\n"
      << "  \"chain_mode\": " << (c.chain_mode ? "true" : "false") << ",\n"
      << "  \"chain_span_minutes\": " << (c.chain_span_ms / 60000) << ",\n"
      << "  \"chain_max_events\": " << c.chain_max_events << ",\n"
      << "  \"span_decay_start_minutes\": " << (c.span_decay_start_ms / 60000) << ",\n"
      << "  \"span_decay_per_hour\": " << c.span_decay_per_hour << ",\n"
      << "  \"span_decay_max\": " << c.span_decay_max << ",\n"
      << "  \"eager_eval\": " << (c.eager_eval ? "true" : "false") << ",\n"
      << "  \"emergency_mode\": " << (c.emergency_mode ? "true" : "false") << ",\n"
      << "  \"emergency_until_epoch\": " << c.emergency_until_epoch << ",\n"
      << "  \"profile_enabled\": " << (c.profile_enabled ? "true" : "false") << ",\n"
      << "  \"ml_enabled\": " << (c.ml_enabled ? "true" : "false") << ",\n"
      << "  \"ml_high_threshold_pct\": " << static_cast<int>(c.ml_high_threshold * 100) << ",\n"
      << "  \"ml_max_factor\": " << c.ml_max_factor << ",\n"
      << "  \"ml_model_path\": \"" << json_escape(c.ml_model_path) << "\",\n"
      << "  \"graph_enabled\": " << (c.graph_enabled ? "true" : "false") << ",\n"
      << "  \"graph_threshold_pct\": " << static_cast<int>(c.graph_threshold * 100) << ",\n"
      << "  \"graph_max_factor\": " << c.graph_max_factor << ",\n"
      << "  \"graph_window_minutes\": " << (c.graph_window_us / 60000000ull) << ",\n"
      << "  \"graph_density_threshold_pct\": " << static_cast<int>(c.graph_density_threshold * 100) << ",\n"
      << "  \"complementary_action_pairs\": [\n";
    for (std::size_t i = 0; i < c.complement_pairs.size(); ++i) {
        const auto& p = c.complement_pairs[i];
        o << "    { \"label\": \"" << json_escape(p.label)
          << "\", \"first\": " << json_array_of_strings(p.first)
          << ", \"second\": " << json_array_of_strings(p.second) << " }";
        if (i + 1 < c.complement_pairs.size()) o << ",";
        o << "\n";
    }
    o << "  ],\n  \"asset_groups\": [\n";
    for (std::size_t i = 0; i < c.asset_groups.size(); ++i) {
        o << "    { \"name\": \"" << json_escape(c.asset_groups[i].name)
          << "\", \"patterns\": " << patterns_json(c.asset_groups[i].patterns) << " }";
        if (i + 1 < c.asset_groups.size()) o << ",";
        o << "\n";
    }
    o << "  ],\n  \"whitelist_groups\": [\n";
    for (std::size_t i = 0; i < c.whitelist_groups.size(); ++i) {
        const auto& w = c.whitelist_groups[i];
        o << "    { \"name\": \"" << json_escape(w.name)
          << "\", \"operators\": " << json_array_of_strings(w.operators)
          << ", \"valid_until_epoch\": " << w.valid_until_epoch << " }";
        if (i + 1 < c.whitelist_groups.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}\n";
    return o.str();
}

std::vector<af::graph::ComplementPair> default_complement_pairs() {
    af::graph::ComplementPair backup;
    backup.label = "备份破坏";
    backup.first = { "delete_backup", "delete", "remove", "rm", "删除", "删备份" };
    backup.second = { "unmount", "diskpart", "format", "卸载", "磁盘" };
    af::graph::ComplementPair leak;
    leak.label = "提权外泄";
    leak.first = { "grant", "privilege", "elevat", "提权", "授权" };
    leak.second = { "export", "download", "dump", "导出", "下载" };
    return { backup, leak };
}

EngineConfig config_from_json(const std::string& j) {
    EngineConfig c;
    c.enabled = json_bool_field(j, "enabled", true);
    u64 short_min = static_cast<u64>(logpolicy::json_size_field(j, "short_window_minutes", 15));
    short_min = std::min<u64>(std::max<u64>(short_min, 5), 30);     // 设计约束：5~30 分钟
    c.short_window_ms = short_min * 60000;
    u64 long_hours = static_cast<u64>(logpolicy::json_size_field(j, "long_window_hours", 4));
    long_hours = std::min<u64>(std::max<u64>(long_hours, 1), 24);
    c.long_window_ms = long_hours * 3600000;
    u64 grace = static_cast<u64>(logpolicy::json_size_field(j, "flush_grace_seconds", 10));
    c.flush_grace_ms = std::min<u64>(grace, 300) * 1000;
    c.rule_max_factor = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "rule_max_factor", 40)), 10), 60);
    c.profile_max_factor = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "profile_max_factor", 25)), 5), 40);
    c.work_order_deduct = std::min(static_cast<int>(logpolicy::json_size_field(j, "work_order_deduct", 40)), 100);
    c.forged_ticket_bonus = std::min(static_cast<int>(logpolicy::json_size_field(j, "forged_ticket_bonus", 10)), 40);
    c.score_high = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "score_high", 80)), 50), 100);
    c.score_mid = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "score_mid", 40)), 10), c.score_high - 1);
    c.alert_dedup_seconds = static_cast<u64>(logpolicy::json_size_field(j, "alert_dedup_seconds", 300));
    // 链式指纹降噪：缺省沿用 alert_dedup_seconds，上限 1 小时（与旧的固定行为一致）
    c.chain_dedup_seconds = static_cast<u64>(
        logpolicy::json_size_field(j, "chain_dedup_seconds", c.alert_dedup_seconds));
    c.chain_dedup_seconds = std::min<u64>(std::max<u64>(c.chain_dedup_seconds, 10), 3600);
    // ---- 链式滑动匹配（不再按固定窗口切分事件集）----
    c.chain_mode = json_bool_field(j, "chain_mode", true);
    // chain_span_minutes = 0 表示不限跨度（只受 chain_max_events 容量约束）
    c.chain_span_ms = static_cast<u64>(logpolicy::json_size_field(j, "chain_span_minutes", 10080)) * 60000ull;
    c.chain_max_events = static_cast<std::size_t>(logpolicy::json_size_field(j, "chain_max_events", 200));
    c.chain_max_events = std::min<std::size_t>(std::max<std::size_t>(c.chain_max_events, 20), 2000);
    c.span_decay_start_ms =
        static_cast<u64>(logpolicy::json_size_field(j, "span_decay_start_minutes", 60)) * 60000ull;
    c.span_decay_per_hour =
        std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "span_decay_per_hour", 1)), 0), 10);
    c.span_decay_max =
        std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "span_decay_max", 15)), 0), 40);
    c.eager_eval = json_bool_field(j, "eager_eval", false);
    c.emergency_mode = json_bool_field(j, "emergency_mode", false);
    c.emergency_until_epoch = static_cast<u64>(logpolicy::json_size_field(j, "emergency_until_epoch", 0));
    c.profile_enabled = json_bool_field(j, "profile_enabled", true);
    // ---- ML 配置解析（M3 措施3）----
    c.ml_enabled = json_bool_field(j, "ml_enabled", false);
    // 阈值存为整数百分比（70 = 0.70），避免引入 float JSON 解析
    int ml_pct = static_cast<int>(logpolicy::json_size_field(j, "ml_high_threshold_pct", 70));
    c.ml_high_threshold = std::min(std::max(ml_pct, 0), 100) / 100.f;
    c.ml_max_factor = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "ml_max_factor", 30)), 0), 50);
    c.ml_model_path = logpolicy::json_string_field(j, "ml_model_path");
    // ---- 图算法配置解析（M4 措施4）----
    c.graph_enabled = json_bool_field(j, "graph_enabled", false);
    int g_pct = static_cast<int>(logpolicy::json_size_field(j, "graph_threshold_pct", 30));
    c.graph_threshold = std::min(std::max(g_pct, 0), 100) / 100.f;
    c.graph_max_factor = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "graph_max_factor", 25)), 0), 50);
    // ---- 操作员合谋图谱配置（M7）----
    u64 gwin_min = static_cast<u64>(logpolicy::json_size_field(j, "graph_window_minutes", 15));
    gwin_min = std::min<u64>(std::max<u64>(gwin_min, 1), 120);
    c.graph_window_us = gwin_min * 60000000ull;
    int gd_pct = static_cast<int>(logpolicy::json_size_field(j, "graph_density_threshold_pct", 30));
    c.graph_density_threshold = std::min(std::max(gd_pct, 0), 100) / 100.f;
    if (j.find("\"complementary_action_pairs\"") == std::string::npos) {
        c.complement_pairs = default_complement_pairs();   // 旧配置文件缺省时使用内置组合
    } else {
        for (const auto& rec : logpolicy::json_object_array_field(j, "complementary_action_pairs")) {
            af::graph::ComplementPair p;
            p.label = logpolicy::json_string_field(rec, "label");
            p.first = logpolicy::json_string_array_field(rec, "first");
            p.second = logpolicy::json_string_array_field(rec, "second");
            if (!p.first.empty() && !p.second.empty()) c.complement_pairs.push_back(std::move(p));
        }
    }
    for (const auto& rec : logpolicy::json_object_array_field(j, "asset_groups")) {
        AssetGroup g;
        g.name = logpolicy::json_string_field(rec, "name");
        if (g.name.empty()) continue;
        g.patterns = logpolicy::json_string_array_field(rec, "patterns");
        c.asset_groups.push_back(std::move(g));
    }
    for (const auto& rec : logpolicy::json_object_array_field(j, "whitelist_groups")) {
        WhitelistGroup w;
        w.name = logpolicy::json_string_field(rec, "name");
        if (w.name.empty()) continue;
        w.operators = logpolicy::json_string_array_field(rec, "operators");
        w.valid_until_epoch = static_cast<u64>(logpolicy::json_size_field(rec, "valid_until_epoch", 0));
        c.whitelist_groups.push_back(std::move(w));
    }
    return c;
}

std::string rules_to_json(const std::vector<Rule>& rules) {
    std::ostringstream o;
    o << "{\n  \"rules\": [\n";
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& r = rules[i];
        o << "    { \"rule_id\": \"" << json_escape(r.rule_id)
          << "\", \"name\": \"" << json_escape(r.name)
          << "\", \"enabled\": " << (r.enabled ? "true" : "false")
          << ", \"asset_group\": \"" << json_escape(r.asset_group)
          << ", \"min_operator_cnt\": " << r.min_operator_cnt
          << ", \"base_score\": " << r.base_score
          << ", \"group_by\": \"" << json_escape(r.group_by) << "\""
          << ", \"timespan_us\": " << r.timespan_us
          << ",\n      \"op_sequence\": [\n";
        for (std::size_t k = 0; k < r.sequence.size(); ++k) {
            o << "        { \"any_of\": " << json_array_of_strings(r.sequence[k].any_of) << " }";
            if (k + 1 < r.sequence.size()) o << ",";
            o << "\n";
        }
        o << "      ] }";
        if (i + 1 < rules.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}\n";
    return o.str();
}

std::vector<Rule> rules_from_json(const std::string& j) {
    std::vector<Rule> out;
    for (const auto& rec : logpolicy::json_object_array_field(j, "rules")) {
        Rule r;
        r.rule_id = logpolicy::json_string_field(rec, "rule_id");
        if (r.rule_id.empty()) r.rule_id = logpolicy::json_string_field(rec, "id");
        if (r.rule_id.empty()) continue;
        r.name = logpolicy::json_string_field(rec, "name");
        r.enabled = json_bool_field(rec, "enabled", true);
        r.asset_group = logpolicy::json_string_field(rec, "asset_group");
        if (r.asset_group.empty()) r.asset_group = "*";
        // Sigma correlation 扩展（M6-3）：分组维度与微秒时间窗
        auto group_by = to_lower_copy(logpolicy::json_string_field(rec, "group_by"));
        if (group_by == "operator" || group_by == "object" || group_by == "asset_group") {
            r.group_by = group_by;
        } else if (!group_by.empty() && group_by != "assetgroup") {
            r.group_by = "asset_group";   // 未识别的分组维度回落到资产组（兼容旧规则文件）
        }
        r.timespan_us = static_cast<u64>(logpolicy::json_size_field(rec, "timespan_us", 0));
        // 按操作员分组的序列是单人多事件，允许 min_operator_cnt=1；其余默认 2
        int min_op_def = (r.group_by == "operator") ? 1 : 2;
        r.min_operator_cnt = std::max(1, static_cast<int>(
            logpolicy::json_size_field(rec, "min_operator_cnt", static_cast<std::size_t>(min_op_def))));
        r.base_score = std::min(std::max(static_cast<int>(logpolicy::json_size_field(rec, "base_score", 80)), 1), 100);
        for (const auto& step : logpolicy::json_object_array_field(rec, "op_sequence")) {
            RuleStep s;
            s.any_of = logpolicy::json_string_array_field(step, "any_of");
            if (!s.any_of.empty()) r.sequence.push_back(std::move(s));
        }
        if (!r.sequence.empty()) out.push_back(std::move(r));
    }
    return out;
}

std::string workorders_to_json(const std::vector<WorkOrder>& wos) {
    std::ostringstream o;
    o << "{\n  \"workorders\": [\n";
    for (std::size_t i = 0; i < wos.size(); ++i) {
        const auto& w = wos[i];
        o << "    { \"work_order_id\": \"" << json_escape(w.work_order_id)
          << "\", \"status\": \"" << json_escape(w.status)
          << "\", \"allowed_operators\": " << json_array_of_strings(w.allowed_operators)
          << ", \"valid_from_epoch\": " << w.valid_from_epoch
          << ", \"valid_until_epoch\": " << w.valid_until_epoch << " }";
        if (i + 1 < wos.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}\n";
    return o.str();
}

std::vector<WorkOrder> workorders_from_json(const std::string& j) {
    std::vector<WorkOrder> out;
    for (const auto& rec : logpolicy::json_object_array_field(j, "workorders")) {
        WorkOrder w;
        w.work_order_id = logpolicy::json_string_field(rec, "work_order_id");
        if (w.work_order_id.empty()) continue;
        w.status = logpolicy::json_string_field(rec, "status");
        w.allowed_operators = logpolicy::json_string_array_field(rec, "allowed_operators");
        w.valid_from_epoch = static_cast<u64>(logpolicy::json_size_field(rec, "valid_from_epoch", 0));
        w.valid_until_epoch = static_cast<u64>(logpolicy::json_size_field(rec, "valid_until_epoch", 0));
        out.push_back(std::move(w));
    }
    return out;
}

std::string pair_key(const std::string& a, const std::string& b) {
    return a < b ? a + "|" + b : b + "|" + a;
}

}  // namespace

// ---------------- 纯逻辑函数 ----------------

bool wildcard_match(const std::string& pattern, const std::string& text) {
    std::string p = to_lower_copy(pattern);
    std::string t = to_lower_copy(text);
    // 迭代式通配符匹配（* 与 ?），避免递归在长文本上退化
    std::size_t pi = 0, ti = 0, star = std::string::npos, mark = 0;
    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == t[ti])) { ++pi; ++ti; }
        else if (pi < p.size() && p[pi] == '*') { star = pi++; mark = ti; }
        else if (star != std::string::npos) { pi = star + 1; ti = ++mark; }
        else return false;
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

bool any_keyword_hit(const std::vector<std::string>& keywords, const std::string& text) {
    if (keywords.empty()) return false;
    std::string t = to_lower_copy(text);
    for (const auto& k : keywords) {
        if (k.empty()) continue;
        if (t.find(to_lower_copy(k)) != std::string::npos) return true;
    }
    return false;
}

// 规则步骤命中判定（动作归一化优先）。
//
// 背景：旧实现用裸词子串匹配 "delete"，"删除一本书"与"删除备份"无法区分，
// 正常业务也会命中"备份销毁"剧本 → 误报。归一化后动作形如 delete.backup。
//
// 规则：
//   1) 日志无 action_norm → 沿用原子串匹配（兼容非 HTTP / 旧客户端）。
//   2) 关键词里出现带 "." 的精确动作名 → 进入严格模式：只认带 "." 的关键词，
//      与 action_norm 全等或按通配符匹配；裸词一律忽略（避免又退回宽泛匹配）。
//   3) 关键词全是裸词（旧规则集）→ 仍走子串匹配，保证老配置不至于全部哑火。
//
// 若要精确区分对象，规则必须写成 "<verb>.<object>"，例如 delete.backup。
bool step_hit(const std::vector<std::string>& keywords, const CleanEvent& e) {
    if (keywords.empty()) return false;
    const std::string searchable = e.op_type + " " + e.res_key + " " + e.op_param;
    if (e.action_norm.empty()) return any_keyword_hit(keywords, searchable);

    bool has_dotted = false;
    for (const auto& k : keywords) {
        if (k.find('.') != std::string::npos) { has_dotted = true; break; }
    }
    if (!has_dotted) return any_keyword_hit(keywords, searchable);

    const std::string norm = to_lower_copy(e.action_norm);
    for (const auto& k : keywords) {
        if (k.empty()) continue;
        const std::string kw = to_lower_copy(k);
        if (kw.find('.') == std::string::npos) continue;   // 严格模式忽略裸词
        if (kw == norm) return true;
        if (wildcard_match(kw, norm)) return true;
    }
    return false;
}

// 把事件按"发生时间"插入聚合集合，而不是按到达顺序追加。
//
// 为什么必须这样：规则里的 op_sequence 描述的是"先做什么、再做什么"，
// is_subsequence() 是顺着 events 的顺序去比对的。单机时代客户端按操作顺序
// 逐条上报，push_back 恰好等于时间序；一旦变成多台上报（两台管理员机器
// 各跑一个采集器），到达顺序就由网络和批次节奏决定，A 机先操作却后上报
// 是很常见的情况。此时集合里变成 [第2步, 第3步, 第1步]，
// 本来成立的三步合谋会被判成"序列不成立"——告警直接丢失，而且不报错。
//
// 插入排序在窗口内的几十条事件上开销可以忽略，换来的是与证据时间线一致的语义。
void append_event_ordered(std::vector<CleanEvent>& events, const CleanEvent& e) {
    auto pos = events.end();
    while (pos != events.begin() && (pos - 1)->ts_ms > e.ts_ms) --pos;
    events.insert(pos, e);
}

bool is_subsequence(const std::vector<RuleStep>& sequence, const std::vector<CleanEvent>& events) {
    if (sequence.empty()) return false;
    std::size_t si = 0;
    for (const auto& e : events) {
        if (si >= sequence.size()) break;
        if (step_hit(sequence[si].any_of, e)) ++si;
    }
    return si == sequence.size();
}

// 最小时间跨度匹配窗口。
//
// 为什么需要：链式滑动聚合会把「最近 N 天、同一资产组」的事件全放进一个集合。
// 集合里必然混着大量与规则无关的历史事件，如果直接拿集合首末事件算跨度，
// 会得到"跨了 7 天"的假跨度，时间衰减被误触发；证据链里也会塞满无关操作。
//
// 算法（两遍）：
//   1) 正向贪心：找到最早能凑齐整条序列的末事件位置 e；
//   2) 从 e 反向贪心：每一步都取"不晚于当前锚点、且最晚"的那条匹配事件，
//      得到在末事件固定时的最晚起点 s。区间 [s, e] 即最小跨度窗口。
// 这是子序列最短窗口问题的经典解法，O(n·k)。
bool minimal_match_window(const Rule& rule, const std::vector<CleanEvent>& events,
                          std::size_t& out_begin, std::size_t& out_end) {
    const auto& seq = rule.sequence;
    if (seq.empty() || events.empty()) return false;

    // 1) 正向贪心：取得最早完成的末事件下标
    std::size_t si = 0;
    std::size_t end_idx = events.size();
    for (std::size_t i = 0; i < events.size(); ++i) {
        if (si >= seq.size()) break;
        if (step_hit(seq[si].any_of, events[i])) {
            ++si;
            if (si == seq.size()) { end_idx = i; break; }
        }
    }
    if (end_idx == events.size()) return false;

    // 2) 反向贪心：在 [0, end_idx] 内为每一步找最晚的可用匹配
    std::size_t anchor = end_idx;
    std::size_t begin_idx = 0;
    for (std::size_t k = seq.size(); k-- > 0;) {
        std::size_t found = anchor + 1;          // 初值 = 未找到
        std::size_t i = anchor + 1;
        while (i-- > 0) {
            if (step_hit(seq[k].any_of, events[i])) { found = i; break; }
        }
        if (found > anchor) return false;        // 理论上不会发生（正向已证明有解）
        begin_idx = found;
        if (k == 0) break;
        if (found == 0) return false;            // 前面已无位置容纳剩余步骤
        anchor = found - 1;
    }
    out_begin = begin_idx;
    out_end = end_idx;
    return true;
}

std::string correlation_group_key(const std::string& group_by, const CleanEvent& e,
                                  const std::vector<AssetGroup>& groups) {
    if (group_by == "operator") return e.oper_id;
    if (group_by == "object") return e.res_key;
    return match_asset_group(groups, e.res_key);   // asset_group（默认）
}

bool match_correlation_rule(const Rule& rule, const std::vector<CleanEvent>& events,
                            const std::vector<AssetGroup>& groups, CorrelationMatch& out) {
    if (rule.sequence.empty()) return false;
    const std::string group_by = rule.group_by.empty() ? "asset_group" : rule.group_by;

    // 按微秒时间戳升序稳定排序，保证“有序序列”语义（乱序接入/跨主机时钟偏差可容忍）
    std::vector<CleanEvent> sorted = events;
    std::stable_sort(sorted.begin(), sorted.end(), [](const CleanEvent& a, const CleanEvent& b) {
        u64 au = a.ts_us ? a.ts_us : a.ts_ms * 1000;
        u64 bu = b.ts_us ? b.ts_us : b.ts_ms * 1000;
        return au < bu;
    });

    for (std::size_t i = 0; i < sorted.size(); ++i) {
        const std::string gk = correlation_group_key(group_by, sorted[i], groups);
        if (gk.empty()) continue;
        const u64 start_us = sorted[i].ts_us ? sorted[i].ts_us : sorted[i].ts_ms * 1000;
        std::size_t si = 0;
        std::vector<CleanEvent> matched;
        for (std::size_t j = i; j < sorted.size() && si < rule.sequence.size(); ++j) {
            if (correlation_group_key(group_by, sorted[j], groups) != gk) continue;
            const u64 ts_us = sorted[j].ts_us ? sorted[j].ts_us : sorted[j].ts_ms * 1000;
            // timespan 从序列首事件起算；超窗即停止（后续事件更晚，无需继续）
            if (rule.timespan_us > 0 && ts_us > start_us + rule.timespan_us) break;
            if (!step_hit(rule.sequence[si].any_of, sorted[j])) continue;
            matched.push_back(sorted[j]);
            ++si;
        }
        if (si < rule.sequence.size()) continue;

        // 最少操作员数校验（跨操作员规则依赖此项；operator 分组通常为 1）
        std::vector<std::string> ops;
        for (const auto& m : matched) {
            if (std::find(ops.begin(), ops.end(), m.oper_id) == ops.end()) ops.push_back(m.oper_id);
        }
        if (static_cast<int>(ops.size()) < rule.min_operator_cnt) continue;

        out = CorrelationMatch{};
        out.rule_id = rule.rule_id;
        out.name = rule.name;
        out.group_by = group_by;
        out.group_key = gk;
        out.operator_ids = std::move(ops);
        out.events = std::move(matched);
        out.window_start_us = out.events.front().ts_us ? out.events.front().ts_us
                                                       : out.events.front().ts_ms * 1000;
        out.window_end_us = out.events.back().ts_us ? out.events.back().ts_us
                                                    : out.events.back().ts_ms * 1000;
        return true;
    }
    return false;
}

std::string match_asset_group(const std::vector<AssetGroup>& groups, const std::string& res_key) {
    if (res_key.empty()) return {};
    for (const auto& g : groups) {
        for (const auto& p : g.patterns) {
            if (wildcard_match(p, res_key)) return g.name;
        }
    }
    return {};
}

bool clean_event_json(const std::string& json, CleanEvent& out) {
    // 字段映射：优先设计文档原生字段，兼容现有审计日志字段；
    // 缺失关键直接丢弃（设计方案 3.1：缺失关键字段的日志直接丢弃）。
    out = CleanEvent{};
    out.oper_id = logpolicy::json_string_field(json, "oper_id");
    // 客户端 operation-logs 信封使用 operator_id；必须优先取它，
    // 否则 oper_id 落到 actor（进程名）上，跨操作员聚合会退化成"每个进程一个人"。
    if (out.oper_id.empty()) out.oper_id = logpolicy::json_string_field(json, "operator_id");
    if (out.oper_id.empty()) out.oper_id = logpolicy::json_string_field(json, "operator");
    if (out.oper_id.empty()) out.oper_id = logpolicy::json_string_field(json, "actor");
    if (out.oper_id.empty()) return false;

    out.ts_ms = static_cast<u64>(logpolicy::json_size_field(json, "event_timestamp", 0));
    if (out.ts_ms == 0) out.ts_ms = static_cast<u64>(logpolicy::json_size_field(json, "client_ts", 0));
    if (out.ts_ms == 0) out.ts_ms = static_cast<u64>(logpolicy::json_size_field(json, "server_ts", 0));
    // 微秒时间戳优先取显式字段，缺失时由毫秒换算（M6-3 timespan 口径统一为微秒）
    out.ts_us = static_cast<u64>(logpolicy::json_size_field(json, "event_timestamp_us", 0));
    if (out.ts_us == 0) out.ts_us = static_cast<u64>(logpolicy::json_size_field(json, "logged_time_us", 0));
    if (out.ts_us == 0) out.ts_us = static_cast<u64>(logpolicy::json_size_field(json, "ts_micros", 0));
    if (out.ts_ms == 0 && out.ts_us > 0) out.ts_ms = out.ts_us / 1000;
    if (out.ts_ms == 0) return false;
    if (out.ts_us == 0) out.ts_us = out.ts_ms * 1000;

    out.server_id = logpolicy::json_string_field(json, "server_id");
    if (out.server_id.empty()) out.server_id = logpolicy::json_string_field(json, "host_id");
    if (out.server_id.empty()) return false;

    out.op_type = logpolicy::json_string_field(json, "op_type");
    if (out.op_type.empty()) {
        auto ot = logpolicy::json_string_field(json, "operation_type");
        auto et = logpolicy::json_string_field(json, "event_type");
        out.op_type = ot.empty() ? et : (et.empty() ? ot : ot + "/" + et);
    }
    if (out.op_type.empty()) return false;

    out.res_key = logpolicy::json_string_field(json, "res_key");
    if (out.res_key.empty()) out.res_key = logpolicy::json_string_field(json, "target");
    if (out.res_key.empty()) return false;

    // 归一化动作（<verb>.<object>）：客户端 ActionNormalizer 产出，规则据此精确匹配。
    // 优先级：顶层 action_norm → ozsf.action_norm（精确归一化）→ ocsf.activity_name（HTTP method 单字兜底）。
    // 注意：ocsf.activity_name 是 "create"/"delete" 这种单字，它不是空，
    // 必须让 ozsf.action_norm 优先，否则精确归一化会被单字挡住，规则永远匹配不上。
    out.action_norm = logpolicy::json_string_field(json, "action_norm");
    if (out.action_norm.empty()) out.action_norm = logpolicy::json_string_field(json, "ozsf.action_norm");
    if (out.action_norm.empty()) out.action_norm = logpolicy::json_string_field(json, "ocsf.activity_name");

    out.op_param = logpolicy::json_string_field(json, "op_param");
    if (out.op_param.empty()) out.op_param = logpolicy::json_string_field(json, "message");
    // 进程命令行补充：进程采集器只把命令行放在 attrs["process.command_line"]，
    // 而服务端原先不读该字段，导致 mountvol / vssadmin 这类动作在日志里只剩进程名，
    // 规则永远匹配不到。这里补进 op_param，让真实命令行进入检测视野。
    {
        const std::string cmdline = logpolicy::json_string_field(json, "process.command_line");
        if (!cmdline.empty() && out.op_param.find(cmdline) == std::string::npos) {
            out.op_param += " cmd=" + cmdline;
        }
    }
    out.work_order_id = logpolicy::json_string_field(json, "work_order_id");
    if (out.work_order_id.empty()) out.work_order_id = logpolicy::json_string_field(json, "ticket_id");

    // 只处理执行成功的操作：return_code 存在且非 0 → 丢弃；
    // outcome 明确为失败/拒绝 → 丢弃（现有审计日志 outcome=unknown 视为成功入库）。
    if (json_has_field(json, "return_code")) {
        auto rc = logpolicy::json_size_field(json, "return_code", 0);
        if (rc != 0) return false;
    }
    auto outcome = to_lower_copy(logpolicy::json_string_field(json, "outcome"));
    if (outcome == "failed" || outcome == "failure" || outcome == "error" ||
        outcome == "denied" || outcome == "blocked") {
        return false;
    }

    out.raw = json.size() > kMaxRawEvidence ? json.substr(0, kMaxRawEvidence) : json;
    return true;
}

bool verify_work_order(const std::vector<WorkOrder>& registry, const WorkOrder& wo,
                       const std::vector<std::string>& operators, u64 now_epoch) {
    // 外部工单核验四要素：真实存在 + 状态有效 + 人员匹配 + 有效期覆盖
    if (wo.work_order_id.empty()) return false;
    bool status_ok = (wo.status == "执行中" || wo.status == "已完成" ||
                      wo.status == "in_progress" || wo.status == "done" || wo.status == "closed");
    if (!status_ok) return false;
    if (wo.valid_from_epoch && now_epoch < wo.valid_from_epoch) return false;
    if (wo.valid_until_epoch && now_epoch > wo.valid_until_epoch) return false;
    for (const auto& op : operators) {
        bool found = false;
        for (const auto& allow : wo.allowed_operators) {
            if (allow == "*" || allow == op) { found = true; break; }
        }
        if (!found) return false;
    }
    (void)registry;
    return true;
}

bool in_whitelist(const std::vector<WhitelistGroup>& groups, const AggSet& set, u64 now_epoch) {
    if (set.operator_ids.empty()) return false;
    for (const auto& g : groups) {
        if (g.valid_until_epoch && now_epoch > g.valid_until_epoch) continue;
        bool all_in = true;
        for (const auto& op : set.operator_ids) {
            if (std::find(g.operators.begin(), g.operators.end(), op) == g.operators.end()) {
                all_in = false;
                break;
            }
        }
        if (all_in) return true;
    }
    return false;
}

DetectionResult detect(const AggSet& set,
                       const EngineConfig& cfg,
                       const std::vector<Rule>& rules,
                       const ProfileSnapshot& profile,
                       const std::vector<WorkOrder>& workorders,
                       u64 now_epoch,
                       af::ml::OnnxModel* onnx_model,
                       af::graph::BehaviorGraph* baseline_graph) {
    DetectionResult res;

    // ---- 白名单预检：预登记合法协同组直接放行（仅保留低级别线索记录） ----
    if (in_whitelist(cfg.whitelist_groups, set, now_epoch)) {
        res.whitelisted = true;
        res.score_notes.push_back("命中操作员白名单协同组，判定为合法协同（仅保留线索记录）");
        res.total_score = 0;
        res.level = "LOW";
        return res;
    }

    // ---- 工单外部核验（不采信日志自带字段，仅登记于工单桩的才有效） ----
    for (const auto& wo_id : set.work_order_ids) {
        bool found = false;
        for (const auto& wo : workorders) {
            if (wo.work_order_id != wo_id) continue;
            found = true;
            if (verify_work_order(workorders, wo, set.operator_ids, now_epoch)) {
                res.ticket_valid = true;
                res.score_notes.push_back("关联有效工单 " + wo_id + "（外部核验通过，减 " +
                                          std::to_string(cfg.work_order_deduct) + " 分）");
            }
            break;
        }
        if (!found) {
            res.forged_ticket = true;
            res.score_notes.push_back("工单 " + wo_id + " 外部核验不通过（疑似伪造，加 " +
                                      std::to_string(cfg.forged_ticket_bonus) + " 分）");
        }
        if (res.ticket_valid) break;
    }
    if (set.work_order_ids.empty()) {
        res.score_notes.push_back("无关联工单");
    }

    // ---- 规则引擎：确定性规则覆盖已知合谋模式 ----
    if (!rules.empty()) {
        Rule const* first_hit = nullptr;
        int extra = 0;
        for (const auto& r : rules) {
            if (!r.enabled) continue;
            // 按操作员/对象分组的 Sigma correlation 规则由关联引擎单独评估（M6-3），
            // 避免与资产组聚合集合的检测重复计分。
            if (r.group_by != "asset_group") continue;
            if (r.asset_group != "*" && r.asset_group != set.asset_group) continue;
            if (set.distinct_op_count() < r.min_operator_cnt) continue;
            if (!is_subsequence(r.sequence, set.events)) continue;
            res.hit_rules.push_back(r.rule_id + " " + r.name);
            if (!first_hit) {
                first_hit = &r;
                res.rule_factor += r.base_score;   // 首条规则基础分直接计入（50~85）
            } else {
                extra += r.base_score;             // 多规则命中：累加部分受 rule_max_factor 限制
            }
        }
        if (first_hit) {
            res.rule_factor += std::min(extra, cfg.rule_max_factor);
            // 涉事操作员数量：超过 2 人后 +5 分/人（仅与规则命中叠加，封顶 20）
            if (set.distinct_op_count() > 2) {
                res.rule_factor += std::min((set.distinct_op_count() - 2) * 5, 20);
            }
            // ---- 时间跨度衰减：链拉得越长，单条证据的关联性越弱 ----
            // 注意这里不设「超过 X 分钟就不算」的硬门槛——那正是固定窗口的毛病，
            // 攻击者拖长时间就能绕过。改为只扣分不否决：跨 12 小时的链依然是
            // MID/HIGH，只是分数比 10 分钟内完成的同类链条低一些。
            if (!set.events.empty() && set.events.back().ts_ms > set.events.front().ts_ms) {
                u64 span_ms = set.events.back().ts_ms - set.events.front().ts_ms;
                if (cfg.span_decay_start_ms > 0 && span_ms > cfg.span_decay_start_ms &&
                    cfg.span_decay_per_hour > 0) {
                    u64 over_hours = (span_ms - cfg.span_decay_start_ms) / 3600000ull;
                    int minus = static_cast<int>(over_hours) * cfg.span_decay_per_hour;
                    minus = std::min(minus, cfg.span_decay_max);
                    if (minus > 0) {
                        res.rule_factor = std::max(res.rule_factor - minus, 0);
                        res.score_notes.push_back(
                            "证据链跨度 " + std::to_string(span_ms / 60000ull) +
                            " 分钟（跨窗口/跨时段），按长跨度衰减 -" + std::to_string(minus) +
                            " 分（不否决命中）");
                    }
                }
            }
        }
    }

    // ---- 行为画像异常引擎：仅提供线索，因子上限 profile_max_factor ----
    if (cfg.profile_enabled) {
        // 陌生协作：集合内操作员两两之间历史协作次数均极少（<2）
        bool any_pair = false;
        for (std::size_t i = 0; i < set.operator_ids.size() && !any_pair; ++i) {
            for (std::size_t k = i + 1; k < set.operator_ids.size(); ++k) {
                auto it = profile.pair_counts.find(pair_key(set.operator_ids[i], set.operator_ids[k]));
                if (it != profile.pair_counts.end() && it->second >= 2) { any_pair = true; break; }
            }
        }
        if (!any_pair) {
            res.profile_factor += 12;
            res.profile_notes.push_back("聚合内操作员历史无协同记录（陌生协作 +12）");
        }
        // 跨域操作：操作员几乎从不接触该资产组
        int cross_domain = 0;
        for (const auto& op : set.operator_ids) {
            auto it = profile.operator_assets.find(op);
            if (it == profile.operator_assets.end()) { ++cross_domain; continue; }
            auto git = it->second.find(set.asset_group);
            if (git == it->second.end() || git->second < 2) ++cross_domain;
        }
        if (cross_domain > 0) {
            int add = std::min(cross_domain * 6, 13);
            res.profile_factor += add;
            res.profile_notes.push_back(std::to_string(cross_domain) +
                                        " 名操作员操作非日常资产组（跨域操作 +" + std::to_string(add) + "）");
        }
        // 伪造工单是强风险信号（6.5：不仅不减分，反而小幅加分）
        if (res.forged_ticket) {
            res.profile_factor += cfg.forged_ticket_bonus;
        }
        res.profile_factor = std::min(res.profile_factor, cfg.profile_max_factor);
    }

    // ---- ML 异常检测引擎（M3 措施3，ONNX 推理，因子上限 ml_max_factor）----
    //   设计约束：ML 仅提供线索因子，不直接触发 HIGH 风险（后续硬约束会钳制）
    if (cfg.ml_enabled) {
        if (onnx_model && onnx_model->is_loaded()) {
            // 特征工程：从聚合事件提取 20 维行为特征
            af::ml::FeatureExtractor extractor;
            auto feats = extractor.extract(set.events, profile, set.asset_group);
            auto feat_vec = feats.to_vector();

            // ONNX 推理
            auto scores = onnx_model->infer(feat_vec);
            if (!scores.empty()) {
                float if_score = scores[0];
                if (if_score > cfg.ml_high_threshold) {
                    int add = static_cast<int>(if_score * cfg.ml_max_factor);
                    res.ml_factor += std::min(add, cfg.ml_max_factor);
                    res.ml_notes.push_back("孤立森林异常分数=" +
                                           std::to_string(if_score) +
                                           "（阈值 " + std::to_string(cfg.ml_high_threshold) + "）");
                } else {
                    res.ml_notes.push_back("ML 异常分数 " +
                                           std::to_string(if_score) +
                                           " 未超阈值，不计入因子");
                }
            } else {
                res.ml_notes.push_back("ML 推理返回空结果（模型输出异常），因子降级为 0");
            }
        } else {
            // 优雅降级：ML 已开启但模型未加载/未集成
            res.ml_notes.push_back("ML 已开启但 ONNX 模型未加载（优雅降级：ml_factor=0）");
        }
        res.ml_factor = std::min(res.ml_factor, cfg.ml_max_factor);
    }

    // ---- 操作员合谋图谱（M7：节点从主机升级为操作员）----
    //   边：同对象共现 + 角色互补；稠密度作为 graph_factor 输入；
    //   异常分量复用 M4 图算法；仅提供线索因子，不直接触发 HIGH 风险。
    if (cfg.graph_enabled) {
        std::vector<af::graph::OperatorEvent> oevents;
        oevents.reserve(set.events.size());
        for (const auto& ev : set.events) {
            af::graph::OperatorEvent oe;
            oe.oper_id = ev.oper_id;
            oe.ts_us = ev.ts_us ? ev.ts_us : ev.ts_ms * 1000;
            oe.object_key = ev.res_key;
            oe.action = ev.op_type;
            oe.target_system = ev.server_id;
            oevents.push_back(std::move(oe));
        }
        af::graph::OperatorGraphConfig gcfg;
        gcfg.window_us = cfg.graph_window_us;
        gcfg.density_threshold = cfg.graph_density_threshold;
        gcfg.max_factor = cfg.graph_max_factor;
        gcfg.complement_pairs = cfg.complement_pairs;

        auto analysis = af::graph::analyze_operator_graph(oevents, gcfg, baseline_graph);
        res.graph_factor = std::min(analysis.graph_factor, cfg.graph_max_factor);
        for (const auto& n : analysis.notes) res.graph_notes.push_back(n);
    }

    // ---- 风险评分：total = 规则+画像+ML+图 - 有效工单扣减，收敛 0~100 ----
    int total = res.rule_factor + res.profile_factor + res.ml_factor + res.graph_factor -
                (res.ticket_valid ? cfg.work_order_deduct : 0);
    res.total_score = std::max(0, std::min(total, 100));

    // ---- 硬约束：仅画像/ML/图异常、规则零命中时，禁止触发高风险（防误报） ----
    if (res.rule_factor == 0 && res.total_score >= cfg.score_high) {
        res.total_score = cfg.score_high - 1;
        res.score_notes.push_back("规则零命中，画像/ML/图线索不触发高风险（评分钳制）");
    }

    if (res.total_score >= cfg.score_high) res.level = "HIGH";
    else if (res.total_score >= cfg.score_mid) res.level = "MID";
    else if (res.total_score > 0) res.level = "LOW";
    else res.level = "NONE";
    return res;
}

// ---------------- Engine 单例 ----------------

Engine& Engine::instance() {
    static Engine inst;
    return inst;
}

Engine::~Engine() = default;  // unique_ptr<OnnxModel> 在此析构（完整类型在此可见）

void Engine::start(const std::string& data_dir) {
    std::lock_guard<std::mutex> lk(mutex_);
    data_dir_ = data_dir.empty() ? "data" : data_dir;
    // 重置内存缓冲与降噪状态：避免切换数据目录/重入时残留上一轮事件
    short_sets_.clear();
    long_sets_.clear();
    corr_events_.clear();
    chain_events_.clear();
    last_alert_epoch_.clear();
    last_corr_alert_ms_.clear();
    last_chain_alert_ms_.clear();
    eager_last_count_.clear();
    (void)fs::create_directories(collusion_dir(data_dir_));
    (void)fs::create_directories(policy_dir(data_dir_));

    // 首次运行生成默认配置 / 规则 / 工单桩，后续热更新
    auto cfg_text = read_file_text(config_path(data_dir_));
    if (cfg_text.empty()) {
        write_file_text(config_path(data_dir_), default_config_json());
        cfg_text = default_config_json();
    }
    cfg_ = config_from_json(cfg_text);

    auto rules_text = read_file_text(rules_path(data_dir_));
    if (rules_text.empty()) {
        write_file_text(rules_path(data_dir_), default_rules_json());
        rules_text = default_rules_json();
    }
    rules_ = rules_from_json(rules_text);

    auto wo_text = read_file_text(workorders_path(data_dir_));
    if (wo_text.empty()) {
        write_file_text(workorders_path(data_dir_), default_workorders_json());
        wo_text = default_workorders_json();
    }
    workorders_ = workorders_from_json(wo_text);

    load_profile_locked();

    // ---- M3: 初始化 ONNX 模型（条件编译，优雅降级）----
    if (cfg_.ml_enabled && !cfg_.ml_model_path.empty()) {
        onnx_if_ = std::make_unique<af::ml::OnnxModel>();
        if (onnx_if_->load(cfg_.ml_model_path)) {
            AF_LOG_INFO("collusion: ML 引擎已启用，模型加载成功: " << cfg_.ml_model_path);
        } else {
            AF_LOG_WARN("collusion: ML 已启用但模型加载失败: " << onnx_if_->last_error()
                        << " —— ML 因子将降级为 0");
        }
    }

    started_ = true;
    AF_LOG_INFO("collusion: 模块已启动 short_window=" << (cfg_.short_window_ms / 60000)
                << "min long_window=" << (cfg_.long_window_ms / 3600000)
                << "h rules=" << rules_.size()
                << " asset_groups=" << cfg_.asset_groups.size()
                << (cfg_.enabled ? "" : "（当前已禁用）")
                << (cfg_.ml_enabled ? " ml=on" : "")
                << (cfg_.graph_enabled ? " graph=on" : ""));
}

void Engine::stop() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!started_) return;
    save_profile_locked();
    profile_dirty_ = false;
    started_ = false;
    AF_LOG_INFO("collusion: 模块已停止，画像已落盘");
}

void Engine::load_profile_locked() {
    profile_ = ProfileSnapshot{};
    auto text = read_file_text(profile_path(data_dir_));
    if (text.empty()) return;
    for (const auto& rec : logpolicy::json_object_array_field(text, "pairs")) {
        auto k = logpolicy::json_string_field(rec, "key");
        if (!k.empty()) profile_.pair_counts[k] = static_cast<u64>(logpolicy::json_size_field(rec, "count", 0));
    }
    for (const auto& rec : logpolicy::json_object_array_field(text, "operator_assets")) {
        auto op = logpolicy::json_string_field(rec, "operator");
        if (op.empty()) continue;
        for (const auto& g : logpolicy::json_object_array_field(rec, "assets")) {
            auto name = logpolicy::json_string_field(g, "group");
            if (!name.empty()) {
                profile_.operator_assets[op][name] =
                    static_cast<u64>(logpolicy::json_size_field(g, "count", 0));
            }
        }
    }
}

void Engine::save_profile_locked() {
    std::ostringstream o;
    o << "{\n  \"updated_at\": \"" << iso_time_epoch(now_epoch()) << "\",\n";
    o << "  \"note\": \"操作员协作画像：滚动累计，供陌生协作/跨域操作判定\",\n";
    o << "  \"pairs\": [\n";
    bool first = true;
    for (const auto& kv : profile_.pair_counts) {
        if (!first) o << ",\n";
        first = false;
        o << "    { \"key\": \"" << json_escape(kv.first) << "\", \"count\": " << kv.second << " }";
    }
    o << "\n  ],\n  \"operator_assets\": [\n";
    first = true;
    for (const auto& okv : profile_.operator_assets) {
        if (!first) o << ",\n";
        first = false;
        o << "    { \"operator\": \"" << json_escape(okv.first) << "\", \"assets\": [";
        bool gfirst = true;
        for (const auto& gkv : okv.second) {
            if (!gfirst) o << ", ";
            gfirst = false;
            o << "{ \"group\": \"" << json_escape(gkv.first) << "\", \"count\": " << gkv.second << " }";
        }
        o << "] }";
    }
    o << "\n  ]\n}\n";
    write_file_text(profile_path(data_dir_), o.str());
}

void Engine::maybe_reload_locked(u64 now_ms) {
    // 热更新节流：每 2 秒最多检查一次配置/规则文件变化
    if (now_ms < cfg_mtime_check_ms_ + 2000) return;
    cfg_mtime_check_ms_ = now_ms;
    auto cfg_text = read_file_text(config_path(data_dir_));
    if (!cfg_text.empty()) {
        auto cand = config_from_json(cfg_text);
        if (config_to_json(cand) != config_to_json(cfg_)) {
            bool emergency_was = cfg_.emergency_mode;
            u64 until_was = cfg_.emergency_until_epoch;
            cfg_ = cand;
            // 应急状态不由配置文件覆盖写丢失（保持运行时状态优先）
            cfg_.emergency_mode = cand.emergency_mode || emergency_was;
            cfg_.emergency_until_epoch = std::max(cand.emergency_until_epoch, until_was);
            AF_LOG_INFO("collusion: 配置热更新已生效");
        }
    }
    auto rules_text = read_file_text(rules_path(data_dir_));
    if (!rules_text.empty()) {
        auto cand = rules_from_json(rules_text);
        if (rules_to_json(cand) != rules_to_json(rules_)) {
            rules_ = cand;
            AF_LOG_INFO("collusion: 规则热加载已生效 rules=" << rules_.size());
        }
    }
    auto wo_text = read_file_text(workorders_path(data_dir_));
    if (!wo_text.empty()) {
        auto cand = workorders_from_json(wo_text);
        if (workorders_to_json(cand) != workorders_to_json(workorders_)) {
            workorders_ = cand;
        }
    }
}

void Engine::append_audit_locked(const std::string& action, const std::string& detail) {
    std::ostringstream line;
    line << "{"
         << "\"timestamp\":\"" << iso_time_epoch(now_epoch()) << "\","
         << "\"action\":\"" << json_escape(action) << "\","
         << "\"detail\":\"" << json_escape(detail) << "\""
         << "}";
    auto path = audit_path(data_dir_);
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (out) out << line.str() << "\n";
}

void Engine::ingest_json(const std::string& event_json) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!started_ || !cfg_.enabled) return;
    u64 now = now_ms();
    maybe_reload_locked(now);

    CleanEvent e;
    if (!clean_event_json(event_json, e)) return;
    auto ag = match_asset_group(cfg_.asset_groups, e.res_key);
    // 未纳入任何资产组的资源不参与资产组合谋聚合；
    // 但仍进入 M6-3 关联规则缓冲（group_by=operator/object 不依赖资产组）。
    if (!ag.empty()) {
        auto add = [&](std::map<std::string, AggSet>& m, const char* kind) {
            u64 win = (std::string(kind) == "short") ? cfg_.short_window_ms : cfg_.long_window_ms;
            u64 ws = e.ts_ms - (e.ts_ms % win);
            std::string key = ag + "|" + std::to_string(ws) + "|" + std::to_string(ws + win) + "|" + kind;
            auto& s = m[key];
            if (s.operator_ids.empty()) {
                s.aggregate_key = key;
                s.asset_group = ag;
                s.window_kind = kind;
                s.window_start_ms = ws;
                s.window_end_ms = ws + win;
            }
            if (std::find(s.operator_ids.begin(), s.operator_ids.end(), e.oper_id) == s.operator_ids.end())
                s.operator_ids.push_back(e.oper_id);
            if (!e.work_order_id.empty() &&
                std::find(s.work_order_ids.begin(), s.work_order_ids.end(), e.work_order_id) == s.work_order_ids.end())
                s.work_order_ids.push_back(e.work_order_id);
            // 按发生时间插入（不是 push_back）：跨机器上报的到达顺序不可靠，
            // 详见 append_event_ordered 的说明。
            append_event_ordered(s.events, e);
        };
        add(short_sets_, "short");
        add(long_sets_, "long");
        // 实验模式：不等窗口结束，事件一进集合就评估一次（只看本事件所属窗口）
        if (cfg_.chain_mode) {
            // 链式滑动匹配：不按固定窗口切分，跨窗口/跨时段的慢速合谋也能拼成链
            chain_eval_locked(e);
        } else if (cfg_.eager_eval) {
            for (auto& kv : short_sets_) {
                if (kv.second.asset_group == ag &&
                    std::find(kv.second.operator_ids.begin(), kv.second.operator_ids.end(), e.oper_id)
                        != kv.second.operator_ids.end()) {
                    eager_evaluate_locked(kv.second);
                }
            }
        }
    }
    evaluate_correlation_locked(e);

    flush_due_locked(now);
}

int Engine::ingest_native_json(const std::string& body) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!started_ || !cfg_.enabled) return 0;
    u64 now = now_ms();
    maybe_reload_locked(now);

    int accepted = 0;
    auto objects = logpolicy::json_object_array_field(body, "events");
    if (objects.empty()) {
        // 单对象或数组直接按事件清洗（要求 oper_id 可解析）
        CleanEvent probe;
        if (clean_event_json(body, probe)) objects.push_back(body);
    }
    for (const auto& obj : objects) {
        CleanEvent e;
        if (!clean_event_json(obj, e)) continue;
        auto ag = match_asset_group(cfg_.asset_groups, e.res_key);
        if (!ag.empty()) {
            auto add = [&](std::map<std::string, AggSet>& m, const char* kind) {
                u64 win = (std::string(kind) == "short") ? cfg_.short_window_ms : cfg_.long_window_ms;
                u64 ws = e.ts_ms - (e.ts_ms % win);
                std::string key = ag + "|" + std::to_string(ws) + "|" + std::to_string(ws + win) + "|" + kind;
                auto& s = m[key];
                if (s.operator_ids.empty()) {
                    s.aggregate_key = key;
                    s.asset_group = ag;
                    s.window_kind = kind;
                    s.window_start_ms = ws;
                    s.window_end_ms = ws + win;
                }
                if (std::find(s.operator_ids.begin(), s.operator_ids.end(), e.oper_id) == s.operator_ids.end())
                    s.operator_ids.push_back(e.oper_id);
                if (!e.work_order_id.empty() &&
                    std::find(s.work_order_ids.begin(), s.work_order_ids.end(), e.work_order_id) == s.work_order_ids.end())
                    s.work_order_ids.push_back(e.work_order_id);
                // 按发生时间插入（不是 push_back）：跨机器上报的到达顺序不可靠，
                // 详见 append_event_ordered 的说明。
                append_event_ordered(s.events, e);
            };
            add(short_sets_, "short");
            add(long_sets_, "long");
            if (cfg_.chain_mode) {
                chain_eval_locked(e);
            } else if (cfg_.eager_eval) {
                for (auto& kv : short_sets_) {
                    if (kv.second.asset_group == ag &&
                        std::find(kv.second.operator_ids.begin(), kv.second.operator_ids.end(), e.oper_id)
                            != kv.second.operator_ids.end()) {
                        eager_evaluate_locked(kv.second);
                    }
                }
            }
        }
        evaluate_correlation_locked(e);
        ++accepted;
    }
    flush_due_locked(now);
    return accepted;
}

// 实验模式：窗口尚未结束时对当前集合做一次增量评估。
// 同一 key 只在事件数增加时评估，避免重复计算与重复告警。
void Engine::eager_evaluate_locked(const AggSet& set) {
    if (!cfg_.eager_eval) return;
    if (set.distinct_op_count() < 2) return;
    auto it = eager_last_count_.find(set.aggregate_key);
    if (it != eager_last_count_.end() && it->second == set.events.size()) return;
    eager_last_count_[set.aggregate_key] = set.events.size();
    evaluate_locked(set, /*update_profile=*/false, /*eager=*/true);
}

// ---------------- 链式滑动匹配（低频慢速合谋） ----------------
//
// 固定窗口的根本问题不在"窗口太短"，而在"按自然时间切片"：
// 三步操作只要分别落在 :14 和 :16、或者上午和下午，就会被切进两个互不相干的
// 集合，各自都凑不齐序列 → 永远不报。窗口调多大都只是把攻击成本从 5 分钟
// 抬高到 4 小时，攻击者拖到第二天照样绕过。
//
// 这里的做法是彻底换掉"切片"这个前提：
//   1) 维护一个按发生时间排序的事件缓冲，不与任何窗口边界挂钩；
//   2) 每来一条新事件，就以它为右端点向前回溯 chain_span 取候选集；
//   3) 在候选集里为每条规则求「最短跨度匹配窗口」（minimal_match_window），
//      只用这条最小证据链去做判定与落库；
//   4) 跨度长不否决命中，只按 span_decay_* 温和扣分——长跨度是"可疑但关联弱"，
//      不是"不算"。
// 于是"早上一步、晚上一步"与"十秒内三步"走的是同一套判定，只是分数不同。

void Engine::prune_chain_locked() {
    // 容量兜底：链跨度可以配成不限，但内存不能真无限
    const std::size_t hard_cap = std::max<std::size_t>(cfg_.chain_max_events * 8, 512);
    while (chain_events_.size() > hard_cap) chain_events_.pop_front();

    if (!chain_events_.empty() && cfg_.chain_span_ms > 0) {
        const u64 newest = chain_events_.back().ts_ms;
        if (newest > cfg_.chain_span_ms) {
            const u64 cutoff = newest - cfg_.chain_span_ms;
            while (!chain_events_.empty() && chain_events_.front().ts_ms < cutoff)
                chain_events_.pop_front();
        }
    }

    // 降噪表容量保护：清理已经出了降噪窗口的指纹
    if (last_chain_alert_ms_.size() > 4096) {
        const u64 now_ms_v = now_ms();
        const u64 dedup_ms = cfg_.chain_dedup_seconds * 1000ull;
        for (auto it = last_chain_alert_ms_.begin(); it != last_chain_alert_ms_.end();) {
            if (now_ms_v >= it->second + dedup_ms) it = last_chain_alert_ms_.erase(it);
            else ++it;
        }
    }
}

void Engine::chain_eval_locked(const CleanEvent& e) {
    if (!cfg_.chain_mode || e.ts_ms == 0) return;

    // 去重：重试/批次重放会把同一事件再送一遍，重复计入会让"操作员数"和
    // 证据链长度虚高。只比对最近 2 秒内的同源事件，开销可忽略。
    for (auto it = chain_events_.rbegin(); it != chain_events_.rend(); ++it) {
        if (it->ts_ms + 2000 < e.ts_ms) break;
        if (it->ts_ms == e.ts_ms && it->oper_id == e.oper_id && it->res_key == e.res_key &&
            it->action_norm == e.action_norm)
            return;
    }
    // 按发生时间插入（多台上报的到达顺序不可靠）
    auto pos = chain_events_.end();
    while (pos != chain_events_.begin() && (pos - 1)->ts_ms > e.ts_ms) --pos;
    chain_events_.insert(pos, e);

    prune_chain_locked();

    const std::string ag = match_asset_group(cfg_.asset_groups, e.res_key);
    if (ag.empty()) return;

    // 候选集：同资产组、[e.ts - chain_span, e.ts]
    const u64 lo = (cfg_.chain_span_ms > 0 && e.ts_ms > cfg_.chain_span_ms)
                       ? e.ts_ms - cfg_.chain_span_ms : 0;
    std::vector<CleanEvent> cand;
    cand.reserve(std::min<std::size_t>(chain_events_.size(), cfg_.chain_max_events));
    for (const auto& ev : chain_events_) {
        if (ev.ts_ms < lo || ev.ts_ms > e.ts_ms) continue;
        if (match_asset_group(cfg_.asset_groups, ev.res_key) != ag) continue;
        cand.push_back(ev);
    }
    if (cand.size() > cfg_.chain_max_events) {
        cand.erase(cand.begin(),
                   cand.begin() + static_cast<std::ptrdiff_t>(cand.size() - cfg_.chain_max_events));
    }
    if (cand.size() < 2) return;

    // 在候选集里为每条规则求最短跨度窗口，取最紧的一条作为本次证据链
    const Rule* best_rule = nullptr;
    std::size_t best_b = 0, best_e = 0;
    u64 best_span = 0;
    for (const auto& r : rules_) {
        if (!r.enabled || r.group_by != "asset_group") continue;
        if (r.asset_group != "*" && r.asset_group != ag) continue;
        std::size_t b = 0, en = 0;
        if (!minimal_match_window(r, cand, b, en)) continue;
        const u64 span = cand[en].ts_ms - cand[b].ts_ms;
        if (!best_rule || span < best_span) {
            best_rule = &r;
            best_b = b;
            best_e = en;
            best_span = span;
        }
    }
    if (!best_rule) return;   // 没有任何规则能凑齐：不评估（画像/图谱仍由固定窗口维护）

    AggSet set;
    set.asset_group = ag;
    set.window_kind = "chain";
    set.events.assign(cand.begin() + static_cast<std::ptrdiff_t>(best_b),
                      cand.begin() + static_cast<std::ptrdiff_t>(best_e) + 1);
    set.window_start_ms = set.events.front().ts_ms;
    set.window_end_ms = set.events.back().ts_ms;
    // 操作员/工单只统计真正参与这条链的事件，避免把同时段无关人员算进去
    for (const auto& ev : set.events) {
        if (std::find(set.operator_ids.begin(), set.operator_ids.end(), ev.oper_id) == set.operator_ids.end())
            set.operator_ids.push_back(ev.oper_id);
        if (!ev.work_order_id.empty() &&
            std::find(set.work_order_ids.begin(), set.work_order_ids.end(), ev.work_order_id)
                == set.work_order_ids.end())
            set.work_order_ids.push_back(ev.work_order_id);
    }
    if (set.distinct_op_count() < 2) return;

    // 链指纹：首事件（操作员 + 毫秒时间戳）固定时，同一条链的 key 保持不变，
    // 后续事件延长链也只会生成"同一批人 + 同一入口"的新指纹，便于降噪。
    std::string ops_key;
    for (const auto& op : set.operator_ids) { ops_key += op; ops_key += ","; }
    set.aggregate_key = "chain|" + best_rule->rule_id + "|" + ag + "|" + ops_key +
                        "|" + std::to_string(set.window_start_ms);

    evaluate_locked(set, /*update_profile=*/false, /*eager=*/true);
}

void Engine::flush_due_locked(u64 now) {
    auto flush_map = [this](std::map<std::string, AggSet>& m, u64 now) {
        for (auto it = m.begin(); it != m.end();) {
            if (it->second.window_end_ms + cfg_.flush_grace_ms <= now) {
                if (cfg_.chain_mode) {
                    // 链式模式下规则告警统一由 chain_eval_locked 负责（它是固定窗口
                    // 的超集，且不会被窗口边界切断）。固定窗口在这里只保留画像维护，
                    // 否则同一次合谋会被"固定窗口"和"滑动链"各报一次。
                    update_profile_locked(it->second);
                } else {
                    evaluate_locked(it->second, true, false);
                }
                it = m.erase(it);
            } else {
                ++it;
            }
        }
    };
    flush_map(short_sets_, now);
    flush_map(long_sets_, now);
    if (profile_dirty_ && now >= profile_save_ms_ + 60000) {
        save_profile_locked();      // 画像周期性落盘（至少每分钟一次）
        profile_dirty_ = false;
        profile_save_ms_ = now;
    }
}

void Engine::prune_correlation_locked() {
    constexpr std::size_t kMaxCorrEvents = 4096;
    if (corr_events_.size() > kMaxCorrEvents) {
        corr_events_.erase(corr_events_.begin(),
                          corr_events_.begin() + static_cast<std::ptrdiff_t>(
                              corr_events_.size() - kMaxCorrEvents));
    }
    // 以所有启用关联规则的最大 timespan 作为缓冲保留上界
    u64 max_span = 0;
    for (const auto& r : rules_) {
        if (r.enabled && r.group_by != "asset_group" && r.timespan_us > max_span)
            max_span = r.timespan_us;
    }
    // 降噪表容量保护：超过上限时清理已过降噪窗口的条目，避免分组键无限累积
    if (last_corr_alert_ms_.size() > 4096) {
        u64 now_ms_v = now_ms();
        for (auto it = last_corr_alert_ms_.begin(); it != last_corr_alert_ms_.end();) {
            if (now_ms_v >= it->second + cfg_.alert_dedup_seconds * 1000) it = last_corr_alert_ms_.erase(it);
            else ++it;
        }
    }
    if (max_span == 0 || corr_events_.empty()) return;   // 0 = 不限，仅受容量上限约束
    u64 newest = 0;
    for (const auto& e : corr_events_) {
        u64 ts = e.ts_us ? e.ts_us : e.ts_ms * 1000;
        if (ts > newest) newest = ts;
    }
    while (!corr_events_.empty()) {
        const auto& f = corr_events_.front();
        u64 ts = f.ts_us ? f.ts_us : f.ts_ms * 1000;
        if (newest <= ts + max_span) break;
        corr_events_.pop_front();
    }
}

void Engine::evaluate_correlation_locked(const CleanEvent& e) {
    // 同上：关联规则的 timespan 与 prune 的"最旧/最新"判断都假定队列按时间升序，
    // 跨机器上报必须按发生时间插入，否则会误删还没过期的事件。
    auto pos = corr_events_.end();
    while (pos != corr_events_.begin() && (pos - 1)->ts_ms > e.ts_ms) --pos;
    corr_events_.insert(pos, e);
    prune_correlation_locked();

    std::vector<const Rule*> active;
    for (const auto& r : rules_) {
        if (r.enabled && r.group_by != "asset_group") active.push_back(&r);
    }
    if (active.empty()) return;

    std::vector<CleanEvent> events(corr_events_.begin(), corr_events_.end());
    u64 now_ep = now_epoch();
    u64 now_ms_v = now_ms();
    bool emergency_active = cfg_.emergency_mode &&
        (cfg_.emergency_until_epoch == 0 || now_ep <= cfg_.emergency_until_epoch);

    for (const Rule* rule : active) {
        CorrelationMatch m;
        if (!match_correlation_rule(*rule, events, cfg_.asset_groups, m)) continue;

        // 告警降噪：同一规则 + 同一分组在降噪窗口内只落一条风险事件
        std::string dedup_key = "corr|" + rule->rule_id + "|" + m.group_by + "|" + m.group_key;
        auto last_it = last_corr_alert_ms_.find(dedup_key);
        if (last_it != last_corr_alert_ms_.end() &&
            now_ms_v < last_it->second + cfg_.alert_dedup_seconds * 1000) {
            continue;
        }
        last_corr_alert_ms_[dedup_key] = now_ms_v;

        // 规则命中直接驱动危害定级（基础分按阈值映射等级）
        int score = rule->base_score;
        std::string level = score >= cfg_.score_high ? "HIGH"
                          : (score >= cfg_.score_mid ? "MID" : "LOW");
        std::vector<std::string> notes;
        notes.push_back("Sigma 关联规则命中：group_by=" + m.group_by + " group=" + m.group_key);
        notes.push_back("timespan_us=" + std::to_string(rule->timespan_us) +
                        "（实际跨度 " + std::to_string(m.window_end_us - m.window_start_us) + "us）");
        notes.push_back("有序序列步数=" + std::to_string(rule->sequence.size()) +
                        "，涉及操作员数=" + std::to_string(m.operator_ids.size()));
        if (emergency_active && level != "LOW") {
            level = (level == "HIGH") ? "MID" : "LOW";
            notes.push_back("应急运维模式生效：等级自动降一级");
        }

        std::string event_id = "ce-" + crypto::random_hex(8);
        std::string alert_id = "alert-" + crypto::random_hex(8);
        std::string created_iso = iso_time_epoch(now_ep);
        std::string asset_group = match_asset_group(cfg_.asset_groups, m.events.front().res_key);
        std::vector<std::string> matched_rules = { rule->rule_id + " " + rule->name };
        std::vector<std::string> work_order_ids;
        for (const auto& ev : m.events) {
            if (ev.work_order_id.empty()) continue;
            if (std::find(work_order_ids.begin(), work_order_ids.end(), ev.work_order_id) ==
                work_order_ids.end()) {
                work_order_ids.push_back(ev.work_order_id);
            }
        }

        // 与资产组聚合风险事件保持同一存储结构，复用事件查询/处置/报表接口
        std::ostringstream ev;
        ev << "{"
           << "\"event_id\": \"" << event_id << "\","
           << "\"alert_id\": \"" << alert_id << "\","
           << "\"created_at\": \"" << created_iso << "\","
           << "\"created_epoch\": " << now_ep << ","
           << "\"window_kind\": \"correlation\","
           << "\"asset_group\": \"" << json_escape(asset_group) << "\","
           << "\"aggregate_key\": \"" << json_escape(dedup_key) << "\","
           << "\"group_by\": \"" << json_escape(m.group_by) << "\","
           << "\"group_key\": \"" << json_escape(m.group_key) << "\","
           << "\"window_start\": \"" << iso_time_ms(m.window_start_us / 1000) << "\","
           << "\"window_end\": \"" << iso_time_ms(m.window_end_us / 1000) << "\","
           << "\"window_span_us\": " << (m.window_end_us - m.window_start_us) << ","
           << "\"risk_level\": \"" << level << "\","
           << "\"risk_score\": " << score << ","
           << "\"rule_factor\": " << score << ","
           << "\"profile_factor\": 0,"
           << "\"ml_factor\": 0,"
           << "\"graph_factor\": 0,"
           << "\"matched_rules\": " << json_array_of_strings(matched_rules) << ","
           << "\"operators\": " << json_array_of_strings(m.operator_ids) << ","
           << "\"operator_count\": " << m.operator_ids.size() << ","
           << "\"work_order_ids\": " << json_array_of_strings(work_order_ids) << ","
           << "\"profile_notes\": [],"
           << "\"ml_notes\": [],"
           << "\"graph_notes\": [],"
           << "\"score_notes\": " << json_array_of_strings(notes) << ","
           << "\"dispose\": { \"status\": \"待复核\", \"disposer\": \"\", \"note\": \"\", \"time\": \"\" },"
           << "\"evidence_timeline\": [";
        for (std::size_t i = 0; i < m.events.size(); ++i) {
            const auto& ce = m.events[i];
            ev << "{ \"ts\": \"" << iso_time_ms(ce.ts_us / 1000) << "\", \"ts_ms\": " << ce.ts_ms
               << ", \"ts_us\": " << ce.ts_us
               << ", \"oper_id\": \"" << json_escape(ce.oper_id)
               << "\", \"server_id\": \"" << json_escape(ce.server_id)
               << "\", \"op_type\": \"" << json_escape(ce.op_type)
               << "\", \"res_key\": \"" << json_escape(ce.res_key)
               << "\", \"op_param\": \"" << json_escape(ce.op_param) << "\" }";
            if (i + 1 < m.events.size()) ev << ",";
        }
        ev << "]}";
        persist_risk_locked(ev.str(), level);

        // 平台告警（HIGH/MID 推送；LOW 仅留线索）
        if (level == "HIGH" || level == "MID") {
            std::string host = m.events.empty() ? "collusion" : m.events.front().server_id;
            std::string severity = level == "HIGH" ? "critical" : "warning";
            std::ostringstream msg;
            msg << "关联规则" << (level == "HIGH" ? "高风险" : "中风险") << "事件 "
                << level << "(" << score << "分) 规则=" << rule->rule_id << " "
                << rule->name << " 分组=" << m.group_by << ":" << m.group_key
                << " 操作员数=" << m.operator_ids.size();
            std::ostringstream evidence;
            evidence << "{\"event_id\":\"" << event_id << "\",\"group_by\":\""
                     << json_escape(m.group_by) << "\",\"group_key\":\""
                     << json_escape(m.group_key) << "\",\"operators\":"
                     << json_array_of_strings(m.operator_ids) << ",\"matched_rules\":"
                     << json_array_of_strings(matched_rules) << ",\"window\":\""
                     << iso_time_ms(m.window_start_us / 1000) << "~"
                     << iso_time_ms(m.window_end_us / 1000) << "\"}";
            std::ostringstream aline;
            aline << "{"
                  << "\"alert_id\":\"" << alert_id << "\","
                  << "\"timestamp\":\"" << created_iso << "\","
                  << "\"host_id\":\"" << json_escape(host) << "\","
                  << "\"source\":\"collusion\","
                  << "\"severity\":\"" << severity << "\","
                  << "\"rule_id\":\"" << json_escape(rule->rule_id + " " + rule->name) << "\","
                  << "\"message\":\"" << json_escape(msg.str()) << "\","
                  << "\"evidence\":\"" << json_escape(evidence.str()) << "\","
                  << "\"status\":\"open\""
                  << "}";
            auto adir = alert_day_dir(data_dir_, now_epoch());   // 按天分片，纳入归档体系
            (void)fs::create_directories(adir);
            std::ofstream aout(fs::join(adir, host + ".jsonl"), std::ios::binary | std::ios::app);
            if (aout) aout << aline.str() << "\n";
            AF_LOG_WARN("collusion: " << msg.str() << " event_id=" << event_id);
        } else {
            AF_LOG_INFO("collusion: 关联规则低风险线索 event_id=" << event_id
                        << " 规则=" << rule->rule_id);
        }
    }
}

void Engine::persist_risk_locked(const std::string& event_line, const std::string& level) {
    // 存储分层：中高风险 180 天、低风险 90 天（按 created_epoch 秒过滤），行数上限保护
    (void)fs::create_directories(collusion_dir(data_dir_));   // ofstream 不会自动建目录
    auto lines = read_jsonl(events_path(data_dir_));
    u64 now_ep = now_epoch();
    u64 keep_sec = (level == "LOW") ? 90ull * 86400 : 180ull * 86400;
    u64 cutoff_epoch = now_ep >= keep_sec ? now_ep - keep_sec : 0;
    std::vector<std::string> kept;
    kept.reserve(lines.size() + 1);
    for (const auto& l : lines) {
        u64 ce = static_cast<u64>(logpolicy::json_size_field(l, "created_epoch", 0));
        if (ce < cutoff_epoch) continue;   // 超过保存周期的历史事件清除
        kept.push_back(l);
    }
    kept.push_back(event_line);
    if (kept.size() > kMaxStoredEvents) {
        kept.erase(kept.begin(), kept.begin() + static_cast<std::ptrdiff_t>(kept.size() - kMaxStoredEvents));
    }
    std::ofstream out(events_path(data_dir_), std::ios::binary | std::ios::trunc);
    if (out) {
        for (const auto& l : kept) out << l << "\n";
    }
}

void Engine::update_profile_locked(const AggSet& set) {
    if (!cfg_.profile_enabled) return;
    for (std::size_t i = 0; i < set.operator_ids.size(); ++i) {
        for (std::size_t k = i + 1; k < set.operator_ids.size(); ++k) {
            profile_.pair_counts[pair_key(set.operator_ids[i], set.operator_ids[k])] += 1;
        }
        profile_.operator_assets[set.operator_ids[i]][set.asset_group] += 1;
    }
    profile_dirty_ = true;
}

void Engine::evaluate_locked(const AggSet& set, bool update_profile, bool eager) {
    // 过滤规则：集合内不同操作员 < 2 直接丢弃（单人操作交由原有单条审计处理）
    if (set.distinct_op_count() < 2) return;

    u64 now_ep = now_epoch();
    auto res = detect(set, cfg_, rules_, profile_, workorders_, now_ep, onnx_if_.get(), graph_baseline_.get());

    // 画像以本次集合为历史：先检测后更新（保证“陌生/跨域”基于此前基线判定）
    // eager 增量评估不更新画像，否则同一批事件会被重复计入协作次数。
    if (update_profile) update_profile_locked(set);

    if (res.level == "NONE") return;   // 0 分无风险：直接丢弃不存储
    // eager 增量评估期间，中间态（LOW）不落库，避免窗口未结束时刷屏；
    // 真正的 HIGH/MID 仍然正常存储与告警。
    if (eager && res.level == "LOW") return;

    // 长窗口为弱关联线索：最高只记为中风险（不触发高危）
    if (set.window_kind == "long" && res.level == "HIGH") {
        res.level = "MID";
        res.score_notes.push_back("长窗口弱关联线索：等级由 HIGH 降为 MID");
    }
    // 应急运维模式：等级自动降一级（开关操作留审计日志）
    bool emergency_active = cfg_.emergency_mode &&
        (cfg_.emergency_until_epoch == 0 || now_ep <= cfg_.emergency_until_epoch);
    if (emergency_active && res.level != "LOW") {
        res.level = (res.level == "HIGH") ? "MID" : "LOW";
        res.score_notes.push_back("应急运维模式生效：等级自动降一级");
    }

    // 告警降噪：相同聚合 key 在降噪窗口内只告警一次
    // 链式集合的 key 会随"证据链增长"重建，用独立的 chain_dedup_seconds 控制，
    // 避免同一条链每来一条新事件都被重复落库，同时不会把 1 小时内的重跑场景
    // 当成"同一条链"而抑制掉（旧实现固定取 max(alert_dedup, 3600)）。
    u64 dedup_secs = cfg_.alert_dedup_seconds;
    if (set.window_kind == "chain") dedup_secs = cfg_.chain_dedup_seconds;
    u64 last = 0;
    auto it = last_alert_epoch_.find(set.aggregate_key);
    if (it != last_alert_epoch_.end()) last = it->second;
    u64 now_ms_v = now_ms();
    if (res.level != "LOW" && last && now_ms_v < last + dedup_secs * 1000) {
        res.score_notes.push_back("同一聚合 key 告警降噪窗口内，抑制重复告警");
        return;
    }
    if (res.level != "LOW") last_alert_epoch_[set.aggregate_key] = now_ms_v;

    // ---- 构造完整风险事件（含证据链）并存储 ----
    std::string event_id = "ce-" + crypto::random_hex(8);
    std::string alert_id = "alert-" + crypto::random_hex(8);
    std::string created_iso = iso_time_epoch(now_ep);

    // 注意：events.jsonl 为 JSONL 存储，事件对象必须是紧凑单行 JSON，
    // 多行格式会被 read_jsonl 按行拆成碎片导致统计与检索错乱。
    std::ostringstream ev;
    ev << "{"
       << "\"event_id\": \"" << event_id << "\","
       << "\"alert_id\": \"" << alert_id << "\","
       << "\"created_at\": \"" << created_iso << "\","
       << "\"created_epoch\": " << now_ep << ","
       << "\"window_kind\": \"" << set.window_kind << "\","
       << "\"asset_group\": \"" << json_escape(set.asset_group) << "\","
       << "\"aggregate_key\": \"" << json_escape(set.aggregate_key) << "\","
       << "\"window_start\": \"" << iso_time_ms(set.window_start_ms) << "\","
       << "\"window_end\": \"" << iso_time_ms(set.window_end_ms) << "\","
       << "\"risk_level\": \"" << res.level << "\","
       << "\"risk_score\": " << res.total_score << ","
       << "\"rule_factor\": " << res.rule_factor << ","
       << "\"profile_factor\": " << res.profile_factor << ","
       << "\"ml_factor\": " << res.ml_factor << ","
       << "\"graph_factor\": " << res.graph_factor << ","
       << "\"matched_rules\": " << json_array_of_strings(res.hit_rules) << ","
       << "\"operators\": " << json_array_of_strings(set.operator_ids) << ","
       << "\"operator_count\": " << set.operator_ids.size() << ","
       << "\"work_order_ids\": " << json_array_of_strings(set.work_order_ids) << ","
       << "\"profile_notes\": " << json_array_of_strings(res.profile_notes) << ","
       << "\"ml_notes\": " << json_array_of_strings(res.ml_notes) << ","
       << "\"graph_notes\": " << json_array_of_strings(res.graph_notes) << ","
       << "\"score_notes\": " << json_array_of_strings(res.score_notes) << ","
       << "\"dispose\": { \"status\": \"待复核\", \"disposer\": \"\", \"note\": \"\", \"time\": \"\" },";

    // 证据时间线：按时间升序的完整操作明细
    auto sorted = set.events;
    std::sort(sorted.begin(), sorted.end(), [](const CleanEvent& a, const CleanEvent& b) {
        return a.ts_ms < b.ts_ms;
    });
    ev << "\"evidence_timeline\": [";
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        const auto& e = sorted[i];
        ev << "{ \"ts\": \"" << iso_time_ms(e.ts_ms) << "\", \"ts_ms\": " << e.ts_ms
           << ", \"oper_id\": \"" << json_escape(e.oper_id)
           << "\", \"server_id\": \"" << json_escape(e.server_id)
           << "\", \"op_type\": \"" << json_escape(e.op_type)
           << "\", \"res_key\": \"" << json_escape(e.res_key)
           << "\", \"op_param\": \"" << json_escape(e.op_param) << "\" }";
        if (i + 1 < sorted.size()) ev << ",";
    }
    ev << "]}";

    persist_risk_locked(ev.str(), res.level);

    // 平台告警（按天分片写入 alerts/<YYYY-MM-DD>/<host>.jsonl，与 manager 侧一致，
    // 可在“日志与告警”面板查看，并纳入归档线程的搬移/压缩/清理）：
    // HIGH/MID 推送；LOW 仅留存线索，不推送。
    if (res.level == "HIGH" || res.level == "MID") {
        std::string host = sorted.empty() ? "collusion" : sorted.front().server_id;
        std::string severity = res.level == "HIGH" ? "critical" : "warning";
        std::ostringstream msg;
        msg << "跨操作员合谋" << (res.level == "HIGH" ? "高风险" : "中风险")
            << "事件 " << res.level << "(" << res.total_score << "分) 资产组="
            << set.asset_group << " 操作员数=" << set.operator_ids.size();
        if (!res.hit_rules.empty()) msg << " 规则=" << res.hit_rules.front();
        std::ostringstream evidence;
        evidence << "{\"event_id\":\"" << event_id << "\",\"asset_group\":\""
                 << json_escape(set.asset_group) << "\",\"operators\":"
                 << json_array_of_strings(set.operator_ids) << ",\"matched_rules\":"
                 << json_array_of_strings(res.hit_rules) << ",\"window\":\""
                 << iso_time_ms(set.window_start_ms) << "~" << iso_time_ms(set.window_end_ms)
                 << "\"}";
        std::ostringstream aline;
        aline << "{"
              << "\"alert_id\":\"" << alert_id << "\","
              << "\"timestamp\":\"" << created_iso << "\","
              << "\"host_id\":\"" << json_escape(host) << "\","
              << "\"source\":\"collusion\","
              << "\"severity\":\"" << severity << "\","
              << "\"rule_id\":\"" << json_escape(res.hit_rules.empty() ? "profile_anomaly" : res.hit_rules.front()) << "\","
              << "\"message\":\"" << json_escape(msg.str()) << "\","
              << "\"evidence\":\"" << json_escape(evidence.str()) << "\","
              << "\"status\":\"open\""
              << "}";
        auto adir = alert_day_dir(data_dir_, now_epoch());   // 按天分片，纳入归档体系
        (void)fs::create_directories(adir);
        std::ofstream aout(fs::join(adir, host + ".jsonl"), std::ios::binary | std::ios::app);
        if (aout) aout << aline.str() << "\n";
        AF_LOG_WARN("collusion: " << msg.str() << " event_id=" << event_id);
    } else {
        AF_LOG_INFO("collusion: 低风险线索 event_id=" << event_id << " score=" << res.total_score
                    << " asset_group=" << set.asset_group);
    }
}

// ---------------- 查询 / 处置 API ----------------

std::string Engine::overview_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (started_) {
        u64 now = now_ms();
        maybe_reload_locked(now);
        flush_due_locked(now);   // 查询时顺带冲刷到期窗口，保证展示及时
    }
    auto lines = read_jsonl(events_path(data_dir_));
    u64 high = 0, mid = 0, low = 0, pending_review = 0;
    for (const auto& l : lines) {
        auto lv = logpolicy::json_string_field(l, "risk_level");
        if (lv == "HIGH") ++high;
        else if (lv == "MID") ++mid;
        else if (lv == "LOW") ++low;
        auto st = logpolicy::json_string_field(json_object_text(l, "dispose"), "status");
        if (st.empty()) st = "待复核";
        if (st == "待复核") ++pending_review;
    }
    bool emergency_active = cfg_.emergency_mode &&
        (cfg_.emergency_until_epoch == 0 || now_epoch() <= cfg_.emergency_until_epoch);
    std::ostringstream o;
    o << "{\n"
      << "  \"enabled\": " << (cfg_.enabled ? "true" : "false") << ",\n"
      << "  \"started\": " << (started_ ? "true" : "false") << ",\n"
      << "  \"short_window_minutes\": " << (cfg_.short_window_ms / 60000) << ",\n"
      << "  \"long_window_hours\": " << (cfg_.long_window_ms / 3600000) << ",\n"
      << "  \"score_high\": " << cfg_.score_high << ",\n"
      << "  \"score_mid\": " << cfg_.score_mid << ",\n"
      << "  \"emergency_mode\": " << (emergency_active ? "true" : "false") << ",\n"
      << "  \"emergency_until\": \"" << iso_time_epoch(cfg_.emergency_until_epoch) << "\",\n"
      << "  \"rules_count\": " << rules_.size() << ",\n"
      << "  \"asset_groups_count\": " << cfg_.asset_groups.size() << ",\n"
      << "  \"profile_operators\": " << profile_.operator_assets.size() << ",\n"
      << "  \"profile_pairs\": " << profile_.pair_counts.size() << ",\n"
      << "  \"active_windows\": { \"short\": " << short_sets_.size()
      << ", \"long\": " << long_sets_.size()
      << ", \"chain_buffer\": " << chain_events_.size() << " },\n"
      << "  \"chain_mode\": " << (cfg_.chain_mode ? "true" : "false") << ",\n"
      << "  \"chain_span_minutes\": " << (cfg_.chain_span_ms / 60000) << ",\n"
      << "  \"event_counts\": { \"HIGH\": " << high << ", \"MID\": " << mid
      << ", \"LOW\": " << low << " },\n"
      << "  \"pending_review\": " << pending_review << "\n"
      << "}";
    return o.str();
}

std::string Engine::events_json(const std::string& level, const std::string& status, std::size_t limit) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto lines = read_jsonl(events_path(data_dir_));
    std::vector<std::string> matched;
    for (auto it = lines.rbegin(); it != lines.rend(); ++it) {   // 新事件在前
        const auto& l = *it;
        if (!level.empty() && logpolicy::json_string_field(l, "risk_level") != level) continue;
        if (!status.empty()) {
            auto st = logpolicy::json_string_field(json_object_text(l, "dispose"), "status");
            if (st.empty()) st = "待复核";
            if (st != status) continue;
        }
        matched.push_back(l);
        if (limit && matched.size() >= limit) break;
    }
    std::ostringstream o;
    o << "{\n  \"count\": " << matched.size() << ",\n  \"events\": [\n";
    for (std::size_t i = 0; i < matched.size(); ++i) {
        o << "  " << matched[i];
        if (i + 1 < matched.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}";
    return o.str();
}

std::string Engine::event_detail_json(const std::string& event_id) {
    std::lock_guard<std::mutex> lk(mutex_);
    for (const auto& l : read_jsonl(events_path(data_dir_))) {
        if (logpolicy::json_string_field(l, "event_id") == event_id) return l;
    }
    return "{}";
}

std::string Engine::export_event_json(const std::string& event_id) {
    // 证据链导出：完整风险事件 JSON（含时间线、规则命中、处置记录）
    return event_detail_json(event_id);
}

bool Engine::dispose_event(const std::string& event_id, const std::string& status,
                           const std::string& disposer, const std::string& note, std::string& err) {
    static const char* kAllowed[] = { "待复核", "确认合谋攻击", "合法运维（误报）", "待进一步调查" };
    bool ok = false;
    for (auto s : kAllowed) if (status == s) { ok = true; break; }
    if (!ok) {
        err = "处置状态必须是：待复核 / 确认合谋攻击 / 合法运维（误报） / 待进一步调查";
        return false;
    }
    if (event_id.empty()) {
        err = "事件 ID 不能为空";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    auto lines = read_jsonl(events_path(data_dir_));
    bool found = false;
    std::ostringstream dispose_obj;
    dispose_obj << "{ \"status\": \"" << json_escape(status)
                << "\", \"disposer\": \"" << json_escape(disposer)
                << "\", \"note\": \"" << json_escape(note)
                << "\", \"time\": \"" << iso_time_epoch(now_epoch()) << "\" }";
    for (auto& l : lines) {
        if (logpolicy::json_string_field(l, "event_id") != event_id) continue;
        found = true;
        json_replace_object_field(l, "dispose", dispose_obj.str());
        break;
    }
    if (!found) {
        err = "风险事件不存在：" + event_id;
        return false;
    }
    {
        std::ofstream out(events_path(data_dir_), std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "处置结果写盘失败";
            return false;
        }
        for (const auto& l : lines) out << l << "\n";
    }
    append_audit_locked("dispose", "event=" + event_id + " status=" + status +
                        " disposer=" + disposer + " note=" + note);
    AF_LOG_INFO("collusion: 风险事件处置 event=" << event_id << " status=" << status
                << " disposer=" << disposer);
    return true;
}

std::string Engine::config_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    auto text = read_file_text(config_path(data_dir_));
    if (text.empty()) return config_to_json(cfg_);
    return text;
}

bool Engine::save_config_json(const std::string& body, std::string& err) {
    if (body.find('{') == std::string::npos) {
        err = "配置必须是 JSON 对象";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    auto cand = config_from_json(body);   // 解析失败字段自动取默认，越界值自动钳制
    if (cand.asset_groups.empty()) {
        err = "asset_groups 不能为空（至少保留一个资产组用于聚合）";
        return false;
    }
    cfg_ = cand;
    if (!write_file_text(config_path(data_dir_), config_to_json(cfg_))) {
        err = "配置写盘失败";
        return false;
    }
    append_audit_locked("config_update", "合谋检测配置已更新（热生效）");
    AF_LOG_INFO("collusion: 配置已热更新");
    return true;
}

std::string Engine::rules_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    auto text = read_file_text(rules_path(data_dir_));
    if (text.empty()) return rules_to_json(rules_);
    return text;
}

bool Engine::save_rules_json(const std::string& body, std::string& err) {
    if (body.find("\"rules\"") == std::string::npos) {
        err = "规则配置必须包含 rules 数组";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    auto cand = rules_from_json(body);
    if (cand.empty()) {
        err = "rules 数组为空或格式不正确（至少保留一条有效规则）";
        return false;
    }
    rules_ = cand;
    if (!write_file_text(rules_path(data_dir_), rules_to_json(rules_))) {
        err = "规则写盘失败";
        return false;
    }
    append_audit_locked("rules_update", "检测规则已更新（热加载）");
    AF_LOG_INFO("collusion: 规则已热加载 rules=" << rules_.size());
    return true;
}

std::string Engine::workorders_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    auto text = read_file_text(workorders_path(data_dir_));
    if (text.empty()) return workorders_to_json(workorders_);
    return text;
}

bool Engine::save_workorders_json(const std::string& body, std::string& err) {
    if (body.find("\"workorders\"") == std::string::npos) {
        err = "工单配置必须包含 workorders 数组";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    workorders_ = workorders_from_json(body);
    if (!write_file_text(workorders_path(data_dir_), workorders_to_json(workorders_))) {
        err = "工单写盘失败";
        return false;
    }
    append_audit_locked("workorders_update", "工单桩登记已更新（模拟外部工单系统核验数据）");
    return true;
}

std::string Engine::set_emergency(bool enabled, u64 duration_minutes, const std::string& actor) {
    std::lock_guard<std::mutex> lk(mutex_);
    cfg_.emergency_mode = enabled;
    cfg_.emergency_until_epoch = 0;
    if (enabled && duration_minutes > 0) {
        cfg_.emergency_until_epoch = now_epoch() + duration_minutes * 60;
    }
    // 持久化到配置文件（保留其余字段），重启后应急状态不丢失语义
    auto text = read_file_text(config_path(data_dir_));
    if (!text.empty()) {
        auto c = config_from_json(text);
        c.emergency_mode = cfg_.emergency_mode;
        c.emergency_until_epoch = cfg_.emergency_until_epoch;
        (void)write_file_text(config_path(data_dir_), config_to_json(c));
    }
    std::ostringstream detail;
    detail << (enabled ? "开启" : "关闭") << "应急运维模式 actor=" << actor;
    if (enabled && cfg_.emergency_until_epoch) {
        detail << " 截止=" << iso_time_epoch(cfg_.emergency_until_epoch);
    }
    append_audit_locked("emergency_mode", detail.str());
    AF_LOG_WARN("collusion: " << detail.str());

    bool active = cfg_.emergency_mode &&
        (cfg_.emergency_until_epoch == 0 || now_epoch() <= cfg_.emergency_until_epoch);
    std::ostringstream o;
    o << "{\n  \"emergency_mode\": " << (active ? "true" : "false") << ",\n"
      << "  \"until\": \"" << iso_time_epoch(cfg_.emergency_until_epoch) << "\",\n"
      << "  \"note\": \"开启后新产生的风险事件等级自动降一级，操作已留审计日志\"\n}";
    return o.str();
}

std::string Engine::report_json(int days) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (days <= 0) days = 7;
    u64 now_ep = now_epoch();
    u64 from = now_ep >= static_cast<u64>(days) * 86400 ? now_ep - static_cast<u64>(days) * 86400 : 0;
    auto lines = read_jsonl(events_path(data_dir_));

    std::map<std::string, int> by_level, by_rule, by_dispose, by_day;
    int total = 0, misreports = 0, confirmed = 0;
    long long score_sum = 0;
    for (const auto& l : lines) {
        u64 ce = static_cast<u64>(logpolicy::json_size_field(l, "created_epoch", 0));
        if (ce < from) continue;
        ++total;
        score_sum += static_cast<long long>(logpolicy::json_size_field(l, "risk_score", 0));
        auto lv = logpolicy::json_string_field(l, "risk_level");
        if (!lv.empty()) ++by_level[lv];
        for (const auto& r : logpolicy::json_string_array_field(l, "matched_rules")) {
            ++by_rule[r.substr(0, 5)];   // 规则编号（R-001）
        }
        auto st = logpolicy::json_string_field(json_object_text(l, "dispose"), "status");
        if (st.empty()) st = "待复核";
        ++by_dispose[st];
        if (st == "合法运维（误报）") ++misreports;
        if (st == "确认合谋攻击") ++confirmed;
        // 按日分布（UTC 日期）
        auto iso = iso_time_epoch(ce);
        if (iso.size() >= 10) ++by_day[iso.substr(0, 10)];
    }
    std::ostringstream o;
    o << "{\n  \"days\": " << days << ",\n  \"total_events\": " << total << ",\n"
      << "  \"avg_score\": " << (total ? score_sum / total : 0) << ",\n"
      << "  \"confirmed_attacks\": " << confirmed << ",\n"
      << "  \"misreports\": " << misreports << ",\n"
      << "  \"by_level\": {";
    bool first = true;
    for (const auto& kv : by_level) {
        if (!first) o << ",";
        first = false;
        o << " \"" << kv.first << "\": " << kv.second;
    }
    o << " },\n  \"by_rule\": {";
    first = true;
    for (const auto& kv : by_rule) {
        if (!first) o << ",";
        first = false;
        o << " \"" << json_escape(kv.first) << "\": " << kv.second;
    }
    o << " },\n  \"by_dispose_status\": {";
    first = true;
    for (const auto& kv : by_dispose) {
        if (!first) o << ",";
        first = false;
        o << " \"" << json_escape(kv.first) << "\": " << kv.second;
    }
    o << " },\n  \"by_day\": {";
    first = true;
    for (const auto& kv : by_day) {
        if (!first) o << ",";
        first = false;
        o << " \"" << kv.first << "\": " << kv.second;
    }
    o << " }\n}";
    return o.str();
}

namespace {

std::string md_cell(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 4);
    for (char c : text) {
        if (c == '|') out += "\\|";
        else if (c == '\n' || c == '\r') out.push_back(' ');
        else out.push_back(c);
    }
    return out;
}

int level_rank(const std::string& level) {
    if (level == "HIGH") return 3;
    if (level == "MID") return 2;
    if (level == "LOW") return 1;
    return 0;
}

std::string join_text(const std::vector<std::string>& values, const char* sep) {
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) out += sep;
        out += values[i];
    }
    return out;
}

struct ReportEvent {
    std::string line;
    std::string event_id;
    std::string rule;
    std::string level;
    int         score { 0 };
    int         rule_factor { 0 };
    int         profile_factor { 0 };
    int         ml_factor { 0 };
    int         graph_factor { 0 };
};

}  // namespace

std::string build_incident_report_markdown(const std::vector<std::string>& lines,
                                           int days, u64 now_epoch) {
    const u64 keep_sec = days > 0 ? static_cast<u64>(days) * 86400ull : 0;
    const u64 cutoff = (keep_sec > 0 && now_epoch > keep_sec) ? now_epoch - keep_sec : 0;

    std::vector<ReportEvent> events;
    int count_high = 0, count_mid = 0, count_low = 0, count_other = 0;
    for (const auto& line : lines) {
        if (line.find('{') == std::string::npos) continue;
        const u64 created = static_cast<u64>(logpolicy::json_size_field(line, "created_epoch", 0));
        if (cutoff > 0 && created > 0 && created < cutoff) continue;

        ReportEvent ev;
        ev.line = line;
        ev.event_id = logpolicy::json_string_field(line, "event_id");
        ev.level = logpolicy::json_string_field(line, "risk_level");
        ev.score = static_cast<int>(logpolicy::json_size_field(line, "risk_score", 0));
        ev.rule_factor = static_cast<int>(logpolicy::json_size_field(line, "rule_factor", 0));
        ev.profile_factor = static_cast<int>(logpolicy::json_size_field(line, "profile_factor", 0));
        ev.ml_factor = static_cast<int>(logpolicy::json_size_field(line, "ml_factor", 0));
        ev.graph_factor = static_cast<int>(logpolicy::json_size_field(line, "graph_factor", 0));
        auto rules = logpolicy::json_string_array_field(line, "matched_rules");
        ev.rule = rules.empty() ? "未命中规则" : rules.front();
        if (ev.level == "HIGH") ++count_high;
        else if (ev.level == "MID") ++count_mid;
        else if (ev.level == "LOW") ++count_low;
        else ++count_other;
        events.push_back(std::move(ev));
    }

    // 规则分组：按规则编号聚合，组内按评分降序
    std::map<std::string, std::vector<const ReportEvent*>> by_rule;
    for (const auto& ev : events) by_rule[ev.rule].push_back(&ev);
    for (auto& kv : by_rule) {
        std::stable_sort(kv.second.begin(), kv.second.end(),
                         [](const ReportEvent* a, const ReportEvent* b) {
                             if (a->score != b->score) return a->score > b->score;
                             return a->event_id < b->event_id;
                         });
    }

    std::ostringstream o;
    o << "# 合谋危害定级报告\n\n";
    o << "- 生成时间：" << iso_time_epoch(now_epoch) << "\n";
    if (days > 0) {
        o << "- 统计区间：最近 " << days << " 天";
        if (cutoff > 0) o << "（自 " << iso_time_epoch(cutoff) << " 起）";
        o << "\n";
    } else {
        o << "- 统计区间：全量\n";
    }
    o << "- 风险事件总数：" << events.size()
      << "（HIGH=" << count_high << " / MID=" << count_mid
      << " / LOW=" << count_low << " / 其他=" << count_other << "）\n";
    o << "- 涉及规则数：" << by_rule.size() << "\n\n";

    if (events.empty()) {
        o << "> 统计区间内暂无可定级的合谋风险事件。\n";
        return o.str();
    }

    o << "## 规则汇总\n\n";
    o << "| 规则 | 命中次数 | 最高等级 | 最高评分 |\n";
    o << "|------|----------|----------|----------|\n";
    for (const auto& kv : by_rule) {
        std::string top_level;
        int top_score = 0;
        int top_rank = 0;
        for (const auto* ev : kv.second) {
            const int rank = level_rank(ev->level);
            if (rank > top_rank || (rank == top_rank && ev->score > top_score)) {
                top_rank = rank;
                top_level = ev->level;
                top_score = ev->score;
            }
        }
        o << "| " << md_cell(kv.first) << " | " << kv.second.size() << " | "
          << (top_level.empty() ? "-" : md_cell(top_level)) << " | " << top_score << " |\n";
    }
    o << "\n";

    constexpr std::size_t kMaxEventsPerRule = 20;
    for (const auto& kv : by_rule) {
        o << "## 规则 " << md_cell(kv.first) << "\n\n";
        o << "- 命中次数：" << kv.second.size() << "\n\n";
        std::size_t shown = 0;
        for (const auto* ev : kv.second) {
            if (shown >= kMaxEventsPerRule) break;
            ++shown;
            const auto& line = ev->line;
            const auto operators = logpolicy::json_string_array_field(line, "operators");
            const auto score_notes = logpolicy::json_string_array_field(line, "score_notes");
            const auto graph_notes = logpolicy::json_string_array_field(line, "graph_notes");
            const auto matched_rules = logpolicy::json_string_array_field(line, "matched_rules");
            const std::string asset_group = logpolicy::json_string_field(line, "asset_group");
            const std::string group_by = logpolicy::json_string_field(line, "group_by");
            const std::string group_key = logpolicy::json_string_field(line, "group_key");
            const std::string window_start = logpolicy::json_string_field(line, "window_start");
            const std::string window_end = logpolicy::json_string_field(line, "window_end");
            const u64 span_us = static_cast<u64>(logpolicy::json_size_field(line, "window_span_us", 0));

            o << "### 事件 " << md_cell(ev->event_id) << "（"
              << (ev->level.empty() ? "未分级" : md_cell(ev->level)) << " / "
              << ev->score << " 分）\n\n";
            o << "- 证据规则：" << md_cell(join_text(matched_rules, "；")) << "\n";
            o << "- 涉及操作员：" << (operators.empty() ? "-" : md_cell(join_text(operators, ", ")))
              << "（" << operators.size() << " 人）\n";
            o << "- 资产组：" << (asset_group.empty() ? "-" : md_cell(asset_group));
            if (!group_by.empty()) {
                o << "；分组维度：" << md_cell(group_by) << "，分组键：" << md_cell(group_key);
            }
            o << "\n";
            if (!window_start.empty() || !window_end.empty()) {
                o << "- 时间窗：" << md_cell(window_start) << " ~ " << md_cell(window_end);
                if (span_us > 0) o << "（跨度 " << span_us << " us）";
                o << "\n";
            }
            o << "- 评分构成：规则 " << ev->rule_factor << " / 画像 " << ev->profile_factor
              << " / ML " << ev->ml_factor << " / 图 " << ev->graph_factor << "\n";
            if (!score_notes.empty()) {
                o << "- 评分说明：" << md_cell(join_text(score_notes, "；")) << "\n";
            }
            if (!graph_notes.empty()) {
                o << "- 图谱指标：" << md_cell(join_text(graph_notes, "；")) << "\n";
            }
            const auto timeline = logpolicy::json_object_array_field(line, "evidence_timeline");
            if (!timeline.empty()) {
                o << "\n| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |\n";
                o << "|------|--------|------|------|------|------|\n";
                for (const auto& item : timeline) {
                    o << "| " << md_cell(logpolicy::json_string_field(item, "ts"))
                      << " | " << md_cell(logpolicy::json_string_field(item, "oper_id"))
                      << " | " << md_cell(logpolicy::json_string_field(item, "server_id"))
                      << " | " << md_cell(logpolicy::json_string_field(item, "op_type"))
                      << " | " << md_cell(logpolicy::json_string_field(item, "res_key"))
                      << " | " << md_cell(logpolicy::json_string_field(item, "op_param"))
                      << " |\n";
                }
            }
            o << "\n";
        }
        if (kv.second.size() > kMaxEventsPerRule) {
            o << "> 该规则仅展示评分最高的 " << kMaxEventsPerRule << " 条，共 "
              << kv.second.size() << " 条。\n\n";
        }
    }
    return o.str();
}

std::string Engine::incident_report_markdown(int days) {
    std::lock_guard<std::mutex> lk(mutex_);
    return build_incident_report_markdown(read_jsonl(events_path(data_dir_)), days, now_epoch());
}

}  // namespace af::collusion
