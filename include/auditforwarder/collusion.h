#pragma once
// AuditForwarder - 跨操作员合谋协同检测模块（并行无侵入扩展层）。
//
// 设计依据《跨操作员合谋协同行为检测子系统-系统设计方案》：
//   - 与原有单条审计并行运行，从已入库的操作日志流消费事件，不改造采集链路；
//   - 按「资产组 + 时间窗口」聚合（不按操作员分组），过滤操作员数 < 2 的集合；
//   - 双路检测：确定性规则引擎（R-001~R-005 预置，可配置热加载）
//               + 行为画像异常引擎（陌生协作 / 跨域操作，仅提供线索）；
//   - 风险评分 0~100：总分 = min(规则因子,40) + min(画像因子,25) - 有效工单扣减(40)；
//     硬约束：规则零命中时总分强制 < 80（不产生高风险），画像因子上限 25；
//   - 不自动阻断：仅输出分级告警与完整证据链，人工处置闭环；
//   - 所有配置 / 应急开关 / 处置操作均留审计日志。

#include "auditforwarder/operator_graph.h"   // M7：操作员合谋图谱
#include "auditforwarder/types.h"

#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// 前向声明（PIMPL，完整定义在 onnx_inference.h，实现在 .cpp 中引用）
namespace af::ml { class OnnxModel; }

namespace af::collusion {

// ---------------- 配置结构（与 policies/collusion_config.json 对应，支持热更新） ----------------

struct AssetGroup {
    std::string name;                    // 资产组名，如 backup-group
    std::vector<std::string> patterns;   // 资源匹配通配符，如 *backup*
};

struct WhitelistGroup {
    std::string name;                        // 白名单协同组名称
    std::vector<std::string> operators;      // 预登记的合法协同操作员
    u64 valid_until_epoch { 0 };             // 有效期（0 = 长期有效）
};

struct EngineConfig {
    bool    enabled            { true };
    u64     short_window_ms    { 15 * 60 * 1000 };   // 短窗口：5~30 分钟可配
    u64     long_window_ms     { 4 * 60 * 60 * 1000 }; // 长窗口（慢合谋线索）
    u64     flush_grace_ms     { 10 * 1000 };        // 窗口结束后容忍乱序事件的宽限期
    int     rule_max_factor    { 40 };               // 规则引擎风险因子上限
    int     profile_max_factor { 25 };               // 画像引擎风险因子上限
    int     work_order_deduct  { 40 };               // 有效工单扣减分
    int     forged_ticket_bonus{ 10 };               // 伪造工单加分
    int     score_high         { 80 };               // 高风险阈值
    int     score_mid          { 40 };               // 中风险阈值
    u64     alert_dedup_seconds{ 300 };              // 同一聚合 key 告警降噪窗口
    // 链式集合的指纹降噪窗口：原实现固定取 max(alert_dedup_seconds, 3600)，
    // 结果是同一场景在 1 小时内重跑会被当成"同一条链"静默抑制，实验/复核时
    // 看不到新告警。改为独立可配（默认与 alert_dedup_seconds 一致）。
    u64     chain_dedup_seconds{ 300 };
    // ---- 链式滑动匹配（低频慢速合谋）----
    // 固定窗口（tumbling window）以 :00/:15/:30/:45 对齐切分，攻击者只要把三步
    // 跨过窗口边界（甚至隔几小时、隔天）就完全落进不同集合，固定窗口永远拼不出链。
    // chain_mode=true 时改为「以最新事件为右端点、向前回溯 chain_span」的滑动聚合：
    //   - 不按自然时间切片，相邻两步间隔再大也只受 chain_span 总跨度约束；
    //   - 跨度越长证据关联越弱，由 span_decay_* 做温和降分，而不是直接漏检。
    bool    chain_mode        { true };
    u64     chain_span_ms     { 7ull * 24 * 3600 * 1000 };  // 链最大总跨度（0 = 不限，仅受容量约束）
    std::size_t chain_max_events{ 200 };             // 单次链评估取用的最近事件上限
    u64     span_decay_start_ms{ 60ull * 60 * 1000 };  // 跨度超过 1 小时后开始降分
    int     span_decay_per_hour{ 1 };                // 每超 1 小时扣 1 分
    int     span_decay_max    { 15 };                // 降分封顶（只削弱、不抹除）
    // 实验/演示模式：每接入一条事件就对所属窗口做一次增量评估，
    // 不必等 15 分钟窗口结束才出结果（答辩现场不可能等窗口）。
    // 只影响"何时评估"，不影响判定规则本身；LOW 结果不落库，避免刷屏。
    bool    eager_eval         { false };
    bool    emergency_mode     { false };            // 应急运维模式（等级自动降一级）
    u64     emergency_until_epoch { 0 };             // 应急模式截止时间（0 = 手动关闭前一直生效）
    bool    profile_enabled    { true };
    // ---- ML 异常检测配置（M3 措施3，ONNX 推理）----
    bool    ml_enabled         { false };  // ML 开关（默认关闭，模型就绪后开启）
    float   ml_high_threshold { 0.7f };   // 异常分数高于此值时计入 ml_factor
    int     ml_max_factor     { 30 };      // ML 因子上限（线索性质，不直接触发 HIGH）
    std::string ml_model_path;              // ONNX 模型路径（models/isolation_forest.onnx）
    // ---- 图算法配置（M4 措施4，轻量级图算法替代 GNN）----
    bool    graph_enabled     { false };  // 图分析开关（默认关闭，基线就绪后开启）
    float   graph_threshold   { 0.3f };   // 图异常分量阈值（任一超阈值即计入 graph_factor）
    int     graph_max_factor  { 25 };      // 图因子上限（线索性质，不直接触发 HIGH）
    // ---- 操作员合谋图谱配置（M7）----
    u64     graph_window_us   { 15ull * 60ull * 1000000ull };  // 同对象共现/互补判定时间窗（微秒）
    float   graph_density_threshold { 0.3f };                  // 时间窗稠密度阈值
    std::vector<af::graph::ComplementPair> complement_pairs;   // 危险互补动作组合
    std::vector<AssetGroup>    asset_groups;
    std::vector<WhitelistGroup> whitelist_groups;
};

// ---------------- 规则结构（与 policies/collusion_rules.json 对应，支持热加载） ----------------

struct RuleStep {
    std::vector<std::string> any_of;   // 任一关键词命中（大小写不敏感子串）即视为完成该步骤
};

struct Rule {
    std::string rule_id;               // 如 R-001
    std::string name;                  // 如 备份销毁合谋
    bool   enabled { true };
    std::string asset_group;           // 限定资产组，"*" 表示任意资产组
    int    min_operator_cnt { 2 };     // 最少不同操作员数
    int    base_score { 80 };          // 命中基础分
    std::vector<RuleStep> sequence;    // 操作子序列（按时间有序，非必须连续）
    // ---- Sigma correlation 风格扩展（M6-3）----
    // group_by = asset_group（默认，沿用资产组+时间窗口聚合集合）
    //          / operator（同一操作员的跨事件序列）
    //          / object（同一被操作对象的跨操作员序列）
    std::string group_by { "asset_group" };
    u64 timespan_us { 0 };             // 有序序列最大时间跨度（微秒，0 = 不限）
};

// ---------------- 工单结构（外部工单系统 API 的本地桩） ----------------

struct WorkOrder {
    std::string work_order_id;
    std::string status;                       // 待执行 / 执行中 / 已完成 / 已关闭
    std::vector<std::string> allowed_operators;
    u64 valid_from_epoch  { 0 };              // 0 = 不限
    u64 valid_until_epoch { 0 };              // 0 = 不限
};

// ---------------- 清洗后的标准事件 ----------------

struct CleanEvent {
    std::string oper_id;        // 操作员唯一 ID
    u64         ts_ms { 0 };    // 操作发生时间戳（UTC 毫秒）
    std::string server_id;      // 目标服务器唯一标识（即 host_id）
    std::string op_type;        // 操作类型（如 file/delete 或 delete_backup）
    std::string action_norm;    // 归一化动作（<verb>.<object>，如 delete.backup），规则精确匹配用
    std::string res_key;        // 被操作资源唯一标识（聚合核心 key）
    std::string op_param;       // 操作参数（还原证据链用）
    std::string work_order_id;  // 运维工单编号，可为空
    std::string raw;            // 原始 JSON 单行（证据链留存，超长截断）
    u64         ts_us { 0 };    // 微秒时间戳（M6-3 关联规则的 timespan 判定口径）
};

// ---------------- 聚合事件集合（资产组 + 时间窗口） ----------------

struct AggSet {
    std::string aggregate_key;
    std::string asset_group;
    std::string window_kind;          // short / long
    u64 window_start_ms { 0 };
    u64 window_end_ms   { 0 };
    std::vector<std::string> operator_ids;   // 去重后的操作员
    std::vector<std::string> work_order_ids; // 关联工单（未核验）
    std::vector<CleanEvent>  events;         // 按时间升序
    int distinct_op_count() const { return static_cast<int>(operator_ids.size()); }
};

// ---------------- 行为画像快照（协作关系 + 资产域分布） ----------------

struct ProfileSnapshot {
    // 协作关系图："opA|opB"（字典序）-> 历史同窗口协作次数
    std::map<std::string, u64> pair_counts;
    // 操作员资产域分布：operator -> 资产组 -> 历史操作次数
    std::map<std::string, std::map<std::string, u64>> operator_assets;
};

// ---------------- 检测结果 ----------------

struct DetectionResult {
    int  rule_factor    { 0 };
    int  profile_factor { 0 };
    int  ml_factor      { 0 };                // ML 异常检测因子（M3 措施3）
    int  graph_factor   { 0 };               // 图算法异常因子（M4 措施4）
    int  total_score    { 0 };
    std::vector<std::string> hit_rules;       // 命中的规则编号
    std::vector<std::string> profile_notes;   // 画像异常描述（线索）
    std::vector<std::string> ml_notes;        // ML 推理说明（异常分数/降级提示）
    std::vector<std::string> graph_notes;     // 图算法异常说明（社区/三角形/相似度线索）
    std::vector<std::string> score_notes;     // 其他评分说明（工单/白名单/应急）
    bool ticket_valid   { false };
    bool whitelisted    { false };
    bool forged_ticket  { false };            // 引用了工单但外部核验不通过
    std::string level;                        // HIGH / MID / LOW / NONE
};

// ---------------- 关联规则命中结果（M6-3 Sigma correlation） ----------------

struct CorrelationMatch {
    std::string rule_id;
    std::string name;
    std::string group_by;                     // operator / object / asset_group
    std::string group_key;                    // 命中分组键（操作员 ID / 对象 / 资产组名）
    u64 window_start_us { 0 };                // 序列首事件时间（微秒）
    u64 window_end_us { 0 };                  // 序列末事件时间（微秒）
    std::vector<std::string> operator_ids;    // 序列涉及的操作员（去重）
    std::vector<CleanEvent> events;           // 按时间升序的命中事件（证据链）
};

// ---------------- 纯逻辑函数（独立于 IO，便于单元测试） ----------------

// 通配符匹配：支持 * 与 ?，大小写不敏感
bool wildcard_match(const std::string& pattern, const std::string& text);

// 关键词列表是否任一命中文本（大小写不敏感子串）
bool any_keyword_hit(const std::vector<std::string>& keywords, const std::string& text);

// 规则操作子序列匹配：sequence 各步骤依次匹配 events（时间有序、允许跳过无关事件）
bool is_subsequence(const std::vector<RuleStep>& sequence, const std::vector<CleanEvent>& events);

// 关联规则分组键：按 rule.group_by 计算事件所属分组；无法分组时返回空串
std::string correlation_group_key(const std::string& group_by, const CleanEvent& e,
                                  const std::vector<AssetGroup>& groups);

// Sigma correlation 匹配：按 group_by 分组、timespan_us 时间窗、sequence 有序序列匹配。
//   events 需为事件集合（内部按微秒时间戳升序稳定排序）；
//   命中后填充 out（含分组键、时间窗与证据事件），并校验 min_operator_cnt。
bool match_correlation_rule(const Rule& rule, const std::vector<CleanEvent>& events,
                            const std::vector<AssetGroup>& groups, CorrelationMatch& out);

// res_key 归属资产组；未命中任何组返回空串
std::string match_asset_group(const std::vector<AssetGroup>& groups, const std::string& res_key);

// 事件 JSON 清洗：兼容设计文档原生字段与现有审计日志字段；不符合要求返回 false
bool clean_event_json(const std::string& json, CleanEvent& out);

// 工单外部核验（本地桩实现）：存在 + 状态有效 + 操作员均在允许名单 + 有效期内
bool verify_work_order(const std::vector<WorkOrder>& registry, const WorkOrder& wo,
                       const std::vector<std::string>& operators, u64 now_epoch);

// 聚合事件集合是否命中操作员白名单（集合内操作员全部包含于某有效白名单组）
bool in_whitelist(const std::vector<WhitelistGroup>& groups, const AggSet& set, u64 now_epoch);

// 双路检测 + 风险评分（核心算法，见设计方案第 5/6 章与伪代码 10.4/10.5）
//   onnx_model: 可选 ONNX 模型指针（M3 措施3）；非空且已加载时执行 ML 推理
//   baseline_graph: 可选历史基线图指针（M4 措施4）；非空时执行图算法对比分析
DetectionResult detect(const AggSet& set,
                       const EngineConfig& cfg,
                       const std::vector<Rule>& rules,
                       const ProfileSnapshot& profile,
                       const std::vector<WorkOrder>& workorders,
                       u64 now_epoch,
                       af::ml::OnnxModel* onnx_model = nullptr,
                       af::graph::BehaviorGraph* baseline_graph = nullptr);

// 危害定级报告（M8）：把风险事件 JSONL 汇总为 Markdown 证据链报告。
//   lines     : 风险事件行（collusion_events.jsonl）
//   days      : 统计最近天数（<=0 表示全量）
//   now_epoch : 当前 Unix 秒
std::string build_incident_report_markdown(const std::vector<std::string>& lines,
                                           int days, u64 now_epoch);

// ---------------- 风险事件（存储/处置闭环模型） ----------------

struct DisposeInfo {
    std::string status;    // 待复核 / 确认合谋攻击 / 合法运维（误报）/ 待进一步调查
    std::string disposer;
    std::string note;
    std::string time_iso;
};

// ---------------- 引擎单例：聚合缓冲、画像持久化、风险事件存储与查询 ----------------

class Engine {
public:
    static Engine& instance();

    // 启动：加载画像 / 配置 / 规则（data_dir 即服务端数据目录）
    void start(const std::string& data_dir);
    // 停止：落盘画像
    void stop();

    // 从操作日志流接入一条 JSON 日志（兼容现有 /agent/operation-logs 字段）
    void ingest_json(const std::string& event_json);

    // 接入设计文档原生格式事件（/collusion/ingest，支持单对象或 {"events":[...]}）
    // 返回清洗成功的事件数
    int ingest_native_json(const std::string& body);

    // ---- 查询 / 处置 API（返回 JSON 文本） ----
    std::string overview_json();
    std::string events_json(const std::string& level, const std::string& status, std::size_t limit);
    // 危害定级报告（M8）：Markdown 证据链聚合，days<=0 表示全量
    std::string incident_report_markdown(int days);
    std::string event_detail_json(const std::string& event_id);
    std::string export_event_json(const std::string& event_id);   // 证据链导出
    bool dispose_event(const std::string& event_id, const std::string& status,
                       const std::string& disposer, const std::string& note, std::string& err);

    std::string config_json();                                    // 当前配置（含默认值兜底）
    bool save_config_json(const std::string& body, std::string& err);
    std::string rules_json();
    bool save_rules_json(const std::string& body, std::string& err);
    std::string workorders_json();
    bool save_workorders_json(const std::string& body, std::string& err);

    // 应急运维开关：enabled=true 时 duration_minutes>0 设置自动到期，返回审计 JSON
    std::string set_emergency(bool enabled, u64 duration_minutes, const std::string& actor);

    // 统计报表（最近 days 天：等级分布 / 规则命中 / 处置与误报统计）
    std::string report_json(int days);

private:
    Engine() = default;
    ~Engine();  // 需在 .cpp 定义（unique_ptr<OnnxModel> 完整类型在 .cpp 可见）

    void maybe_reload_locked(u64 now_ms);         // 配置/规则热更新（带节流）
    void flush_due_locked(u64 now_ms);            // 冲刷到期窗口 → 检测 → 告警/存储
    void evaluate_locked(const AggSet& set, bool update_profile = true, bool eager = false);
    void eager_evaluate_locked(const AggSet& set);   // 实验模式：窗口未结束也评估
    void chain_eval_locked(const CleanEvent& e);      // 链式滑动匹配：以 e 为右端点回溯聚合
    void prune_chain_locked();                        // 裁剪链事件缓冲（跨度 + 容量）
    // ---- M6-3 Sigma correlation 关联规则 ----
    void evaluate_correlation_locked(const CleanEvent& e);      // 滚动缓冲内匹配跨事件序列
    void prune_correlation_locked();                            // 按最大 timespan 与容量裁剪
    void persist_risk_locked(const std::string& event_line, const std::string& level);
    void update_profile_locked(const AggSet& set);
    void save_profile_locked();
    void load_profile_locked();
    void append_audit_locked(const std::string& action, const std::string& detail);

    std::mutex mutex_;
    std::string data_dir_;
    bool started_ { false };

    EngineConfig cfg_;
    std::vector<Rule> rules_;
    std::vector<WorkOrder> workorders_;
    u64 cfg_mtime_check_ms_ { 0 };                // 上次热更新检查时间

    ProfileSnapshot profile_;
    bool profile_dirty_ { false };
    u64  profile_save_ms_ { 0 };                  // 上次画像落盘时间（节流用）

    std::map<std::string, AggSet> short_sets_;    // aggregate_key -> 集合
    std::map<std::string, AggSet> long_sets_;
    std::deque<CleanEvent>    chain_events_;      // 链式滑动匹配的事件缓冲（按 ts 升序）
    std::map<std::string, u64> last_chain_alert_ms_;  // 链指纹降噪：指纹 -> 上次告警毫秒
    std::map<std::string, u64> last_alert_epoch_; // 告警降噪：aggregate_key -> 上次告警时间
    std::map<std::string, std::size_t> eager_last_count_;  // eager 模式：key -> 已评估事件数
    // ---- M6-3：Sigma correlation 滚动事件缓冲与告警降噪 ----
    std::deque<CleanEvent> corr_events_;          // 按接入顺序的最近事件（匹配时按微秒排序）
    std::map<std::string, u64> last_corr_alert_ms_; // 降噪：rule_id|group -> 上次告警毫秒

    // ---- ML 异常检测（M3 措施3，ONNX 推理）----
    std::unique_ptr<af::ml::OnnxModel> onnx_if_;   // ONNX 模型实例（条件编译优雅降级）
    // ---- 图算法基线（M4 措施4，历史行为图谱基线）----
    std::unique_ptr<af::graph::BehaviorGraph> graph_baseline_;   // 历史基线图（空 = 无基线）
};

}  // namespace af::collusion
