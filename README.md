﻿﻿﻿# AuditForwarder

企业级跨平台安全审计代理系统。

## 主要特性

- 跨平台支持：Linux 和 Windows
- 实时操作监控与日志采集
- SHA-256 哈希链 + Merkle 树可信存证
- 规则引擎异常检测
- HTTPS 传输（压缩 + 加密）
- 自我保护机制（完整性校验、看门狗）
- 远程管理 API

## 快速开始

### Linux

```bash
sudo apt install -y build-essential cmake pkg-config libssl-dev zlib1g-dev libaudit-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo ./scripts/install_linux.sh --start
```

### Windows

```powershell
vcpkg install openssl zlib
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release -j
powershell -ExecutionPolicy Bypass -File scripts\install_windows.ps1 -Start
```

## 许可证

Apache 2.0
