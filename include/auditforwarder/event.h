#pragma once
// AuditForwarder - 审计事件模型和处理管道。

#include "auditforwarder/types.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace af {

// ---- 事件类别（顶层分类）----
enum class EventCategory : u8 {
    System      = 0,  // 启动/关闭，内核事件
    Process     = 1,  // 执行、fork、退出
    File        = 2,  // 创建/读/写/删除/重命名/修改权限
    Network     = 3,  // 连接、监听、发送、接收
    Registry    = 4,  // Windows 注册表
    Command     = 5,  // Shell 命令行
    Gui         = 6,  // GUI 交互（窗口焦点、剪贴板）
    Auth        = 7,  // 登录、注销、sudo、UAC
    Privilege   = 8,  // 权限变更
    Driver      = 9,  // 内核驱动加载/卸载
    Syscall     = 10, // 低级系统调用追踪
    Config      = 11, // 代理配置变更
    Update      = 12, // 代理升级
    Other       = 255,
};

const char* to_string(EventCategory c) noexcept;
EventCategory category_from_string(const std::string& s) noexcept;

// ---- 执行的动作（动词）----
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
    KeyEvent      = 30,  // 键盘事件（隐私过滤）
    MouseEvent    = 31,
    WindowFocus   = 32,
    Clipboard     = 33,
    Screenshot    = 34,
    Set           = 40,  // 注册表 / 配置设置
    Get           = 41,  // 注册表 / 配置获取
    Load          = 50,  // 驱动 / 模块加载
    Unload        = 51,
    Alert         = 100, // 检测告警
    Block         = 101, // 策略阻止
    Quarantine    = 102,
    Kill          = 103,
    Annotate      = 200,
    SystemStart   = 210,
    SystemStop    = 211,
};

const char* to_string(EventAction a) noexcept;
EventAction action_from_string(const std::string& s) noexcept;

// ---- 结果 ----
enum class EventOutcome : u8 {
    Unknown = 0,
    Success = 1,
    Failure = 2,
    Denied  = 3,
};

const char* to_string(EventOutcome o) noexcept;

// ---- 操作者（谁执行了操作）----
struct Actor {
    u32         pid     { 0 };
    u32         tid     { 0 };
    std::string name;
    std::string path;
    std::string user;
    std::string sid;     // Windows SID / Linux uid:gid
    std::string session; // 会话 ID
    std::string remote;  // 远程操作者的地址
};

// ---- 目标（受影响的对象）----
struct Target {
    std::string kind;     // 文件、注册表键、套接字、进程...
    std::string path;     // 文件路径或键
    std::string address;  // 网络地址
    u16         port      { 0 };
    std::string protocol; // tcp/udp/icmp...
};

// ---- 单个审计事件 ----
struct AuditEvent {
    u64                 id            { 0 }; // 全局分配
    u64                 seq           { 0 }; // 单调序列号
    SysTime             timestamp     {};   // 墙钟时间
    u64                 ts_micros     { 0 };
    EventCategory       category      { EventCategory::Other };
    EventAction         action        { EventAction::Unknown };
    EventOutcome        outcome       { EventOutcome::Unknown };
    Severity            severity      { Severity::Info };
    std::string         host;
    std::string         agent_id;
    std::string         rule_id;      // 检测规则 ID
    Actor               actor;
    Target              target;
    std::string         command;      // 执行的命令行
    std::string         message;      // 人类可读描述
    std::map<std::string, std::string> attrs;  // 附加属性
    ByteBuffer          raw_payload;  // 可选原始证据（加密）
    std::string         hash;         // 规范化后计算
    std::string         prev_hash;    // 链链接
    std::string         signature;    // 签名载荷
    std::string         batch_id;     // 事件所属批次
    u32                 schema_ver    { 1 };

    std::string to_json() const;
    static AuditEvent from_json(const std::string& s);
    void compute_hash();
};

// ---- 事件接收接口 ----
class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void on_event(const AuditEvent& ev) = 0;
    virtual void flush() {}
    virtual void shutdown() {}
};

using EventSinkPtr = std::shared_ptr<EventSink>;

// ---- 批量事件容器 ----
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
