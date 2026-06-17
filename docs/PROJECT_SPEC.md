# AuditForwarder 企业级跨平台安全审计代理系统

## 一、项目概述

### 1.1 项目定位

AuditForwarder 是一款企业级跨平台安全审计代理系统，以操作系统内核级/系统级驻留程序的形式运行，实现对终端操作员全量操作的实时监控、日志采集、可信存证、异常检测与自动处置功能。

### 1.2 核心价值

| 维度 | 价值描述 |
|-----|---------|
| 合规性 | 满足等保2.0、SOX、PCI-DSS等合规要求，提供完整的操作审计轨迹 |
| 安全性 | 实时检测违规操作，支持自动响应，构建纵深防御体系 |
| 可靠性 | 端侧可信存证，确保日志完整性与不可篡改性 |
| 跨平台 | 统一架构支持 Linux 和 Windows 两大主流操作系统 |
| 低侵入 | 低资源占用设计，不影响业务系统正常运行 |

### 1.3 适用场景

- 企业内部终端安全审计
- 金融机构操作合规监控
- 涉密系统操作追踪
- 云环境多租户审计
- 工控系统安全监控

---

## 二、功能特性

### 2.1 端侧代理驻留与运行

| 功能 | 说明 |
|-----|------|
| 自启动 | Linux systemd 服务 / Windows 服务，系统启动时自动加载 |
| 进程隐藏 | 专用服务账户运行，Windows 注册为受保护服务，Linux 使用私有命名空间 |
| 防篡改 | 二进制完整性校验，安装目录权限锁定 |
| 自恢复 | Watchdog 机制，进程异常时自动重启 |
| 无感知升级 | 支持远程升级，新二进制需 Ed25519 签名验证 |

### 2.2 全量操作行为采集

| 采集类型 | Linux | Windows | 说明 |
|---------|-------|---------|------|
| 文件系统 | inotify | ReadDirectoryChangesW | 文件创建、修改、删除、重命名 |
| 进程活动 | /proc | WMI/ETW | 进程创建、退出、命令行参数 |
| 网络连接 | /proc/net | GetTcpTable2 | TCP/UDP 连接状态 |
| 命令行 | auditd/bash | ETW | 命令执行记录 |
| 注册表 | - | RegNotifyChangeKeyValue | 注册表键值变更 |
| 系统调用 | auditd | ETW | 系统调用追踪 |
| 用户认证 | PAM/audit | ETW/Logon | 登录登出事件 |

### 2.3 日志范式化与本地预处理

| 处理阶段 | 功能 |
|---------|------|
| 标准化 | 统一日志格式与字段定义 |
| 数据清洗 | 去除无效数据，补全缺失字段 |
| 过滤 | 基于正则表达式的事件过滤 |
| PII脱敏 | 自动识别并掩码敏感信息（密码、密钥、Token等） |
| 去重 | 基于时间窗口的重复事件合并 |
| 聚合 | 周期性统计聚合，降低数据量 |

### 2.4 可信存证与完整性保障

| 技术机制 | 说明 |
|---------|------|
| SHA-256哈希链 | 每个事件包含前一事件哈希，形成链式关联 |
| Merkle树 | 每批次事件构建 Merkle 树，生成单一根哈希 |
| 数字签名 | Ed25519 签名（或 HMAC-SHA-256 备选） |
| 本地持久化 | 签名批次存储至本地磁盘 |

### 2.5 定时/实时上传与远程同步

| 传输特性 | 说明 |
|---------|------|
| 实时模式 | 事件生成后立即传输 |
| 批量模式 | 按时间或数量阈值批量上传 |
| 断点续传 | 支持失败重试，指数退避策略 |
| 数据压缩 | zlib 压缩，降低带宽占用 |
| payload加密 | AES-256-GCM 端到端加密 |
| 多服务器故障转移 | 配置多个 ingest 端点，自动故障切换 |
| 双向TLS | 支持 mTLS 认证 |

### 2.6 违规操作实时检测与自动处置

| 检测类型 | 说明 |
|---------|------|
| 规则引擎 | YAML/JSON 规则配置，支持类别、动作、字段匹配、正则表达式 |
| 频率阈值 | 滑动窗口内频率检测 |
| 行为基线 | 基于历史行为的异常检测 |

| 响应动作 | 效果 |
|---------|------|
| alert | 生成告警事件，记录日志并转发 |
| block | 标记事件为拒绝，从管道中丢弃 |
| kill | 终止触发进程 |
| quarantine | 将涉及文件移动至隔离区域 |

### 2.7 远程监控与管理

| API端点 | 方法 | 说明 |
|---------|------|------|
| /health | GET | 健康状态与统计信息 |
| /config | GET | 获取当前配置 |
| /config/reload | POST | 重新加载配置文件 |
| /batches | GET | 获取最近签名批次 |
| /upgrade | POST | 触发远程升级 |

---

## 三、技术架构

### 3.1 整体架构

End-point Agent 接收来自操作员的各类事件（file, process, network, command, registry, syscall, auth 等），经过 Collectors 采集、Processors 处理、Detector 检测、Chain（Merkle + sign）签名后，本地存储并通过 HTTPS Uploader（compress + encrypt + resume）上传至 Central Audit Platform（SIEM/UEBA 平台）。同时提供 Manager API、Self-Protect、Watchdog 和 Healthcheck 功能。

### 3.2 模块架构

| 模块 | 职责 | 文件位置 |
|-----|------|---------|
| Core | 代理编排、生命周期管理 | src/core/agent.cpp |
| Collectors | 操作系统事件采集 | src/collector/ |
| Processors | 事件预处理管道 | src/processor/ |
| Detector | 规则引擎与行为基线检测 | src/detector/ |
| Chain | 哈希链与 Merkle 签名 | src/crypto/chain.cpp |
| Crypto | 密码学原语 | src/crypto/crypto.cpp |
| Transport | HTTPS 上传 | src/transport/ |
| Manager | 远程管理 API | src/manager/ |
| Self-Protect | 完整性校验与看门狗 | src/core/self_protect.cpp |
| Common | 通用工具（日志、配置、线程池等） | src/common/ |

---

## 四、部署与使用

### 4.1 环境要求

| 平台 | 版本要求 |
|-----|---------|
| Linux | Kernel >= 3.10，支持 systemd |
| Windows | Windows 10 / Server 2016+ |
| 编译器 | C++17 (GCC >= 8, MSVC >= 2019) |

### 4.2 依赖组件

| 依赖 | 版本 | 用途 |
|-----|------|------|
| OpenSSL | >= 1.1 | 加密、哈希、TLS |
| zlib | - | 数据压缩 |
| pthreads | - | 多线程支持 |
| libaudit | (Linux) | 内核审计采集 |
| yaml-cpp | (可选) | YAML 配置解析 |
| GTest | (可选) | 单元测试 |

### 4.3 构建与安装

#### Linux 构建

安装依赖：
sudo apt install -y build-essential cmake pkg-config libssl-dev zlib1g-dev libaudit-dev

构建：
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

安装：
sudo ./scripts/install_linux.sh --start

检查状态：
sudo systemctl status auditforwarder
sudo journalctl -u auditforwarder -f

#### Windows 构建

安装 vcpkg 依赖：
vcpkg install openssl zlib

构建：
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release -j

安装为服务：
powershell -ExecutionPolicy Bypass -File scripts/install_windows.ps1 -Start

### 4.4 运行模式

#### 前台调试模式

./auditforwarderd --no-manager --no-selfprotect -d ./data -L debug

#### 服务模式

Linux：
sudo systemctl start auditforwarder

Windows：
Start-Service AuditForwarder

---

## 五、配置管理

### 5.1 配置文件结构

主配置文件：Linux 为 /etc/auditforwarder/agent.yaml，Windows 为 C:\ProgramData\AuditForwarder\agent.yaml

agent:
  id: "agent-001"
  name: "Production-Server-01"

data_dir: "/var/lib/auditforwarder"

collectors:
  enabled:
    - file
    - process
    - network
    - command
    - registry
  exclude_paths:
    - "/tmp/*"
    - "/var/log/*"

processor:
  pii_mask: true
  dedup_window_sec: 300
  sample_ratio: 1.0

chain:
  batch_size: 1000
  signing_key_path: "/etc/auditforwarder/keys/agent.pem"

transport:
  servers:
    - "https://audit.example.com/ingest"
    - "https://audit-failover.example.com/ingest"
  compress: true
  encrypt_payload: true

detector:
  rules_path: "/etc/auditforwarder/rules.yaml"
  baseline_window_hours: 24

self_protect:
  enabled: true
  check_interval_sec: 300
  known_good_hash: "abc123..."

manager:
  listen: "127.0.0.1:8443"
  auth_token: "your-secret-token"

### 5.2 规则配置

规则文件：/etc/auditforwarder/rules.yaml

- id: R-CMD-001
  name: "潜在反向shell"
  severity: critical
  categories: ["command"]
  cmd_match:
    - "bash\\s+-i.*>&?\\s*/dev/tcp/"
    - "nc\\s+-e\\s+/bin/bash"
  responses: ["alert", "kill"]

- id: R-FILE-001
  name: "敏感文件访问"
  severity: high
  categories: ["file"]
  path_match:
    - "/etc/passwd"
    - "/etc/shadow"
  responses: ["alert"]

### 5.3 配置重载

curl -X POST http://127.0.0.1:8443/config/reload -H "Authorization: Bearer your-secret-token"

---

## 六、安全模型

### 6.1 抗篡改机制

| 机制 | 说明 |
|-----|------|
| 二进制完整性校验 | 启动时及定期计算二进制 SHA-256，与配置中的期望值比对 |
| 安装目录锁定 | Linux: chmod 0555，Windows: ACL 限制非管理员写入 |
| Watchdog 重启 | 校验失败触发 critical 事件，系统服务自动重启 |
| 签名验证升级 | 新二进制需 Ed25519 签名验证 |

### 6.2 进程隐藏

- Linux：使用私有 /proc 命名空间
- Windows：注册为受保护服务

### 6.3 纵深防御

即使某个采集器被绕过，链模块仍会签名接收到的所有事件，链中的间隙在平台端可见。

---

## 七、资源占用

| 资源 | 典型使用 |
|-----|---------|
| CPU | 4核 x86_64 稳态 < 2% |
| 内存 | 30-60 MiB |
| 磁盘 | 受 data_dir 配额限制，旧批次自动轮转 |
| 网络 | 压缩+加密后，1k 事件/分钟约 4 KiB/s |

---

## 八、故障排除

### 8.1 常见问题

| 症状 | 原因 | 解决方案 |
|-----|------|---------|
| audit_open: permission denied | libaudit 需要 root 权限 | 授予 CAP_AUDIT_READ 或以 root 运行 |
| Cannot bind manager: address in use | 端口被占用 | 修改 manager.listen 配置 |
| HTTP 401 from manager | Bearer token 错误/缺失 | 设置正确的 manager.auth_token |
| chain.flush: no events | 采集器未运行 | 检查日志中的采集器启动错误 |
| 高 CPU 占用 | 采样率为 1.0 + 高事件量 | 设置 keep_ratio=0.5 或添加正则过滤器 |
| ETW 采集失败（Windows） | 缺少管理员权限 | 以管理员身份运行或授予相应权限 |

### 8.2 日志位置

| 平台 | 日志位置 |
|-----|---------|
| Linux | journalctl -u auditforwarder |
| Windows | 事件查看器 -> 应用程序日志 -> AuditForwarder |

---

## 九、扩展开发

### 9.1 添加新采集器

1. 继承 af::Collector 基类
2. 实现 poll() 方法
3. 在 platform_linux.h 或 platform_windows.h 的 create_*_collectors 中注册

### 9.2 添加新处理器

1. 继承 af::Processor 基类
2. 实现 process() 方法
3. 在 Agent::init() 中注册

### 9.3 添加新规则

直接编辑 rules.yaml 配置文件，无需修改代码。

---

## 十、许可证

Apache 2.0 许可证（详见 LICENSE 文件）。

---

## 附录：术语表

| 术语 | 说明 |
|-----|------|
| PII | 个人身份信息（Personally Identifiable Information） |
| Merkle Tree | 默克尔树，一种哈希树结构，用于验证数据完整性 |
| Ed25519 | 一种椭圆曲线数字签名算法 |
| AEAD | 认证加密（Authenticated Encryption with Associated Data） |
| mTLS | 双向 TLS 认证（mutual TLS） |
| SIEM | 安全信息与事件管理（Security Information and Event Management） |
| UEBA | 用户实体行为分析（User and Entity Behavior Analytics） |
