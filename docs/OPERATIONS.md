# AuditForwarder 运维指南

## 1. 服务生命周期

### Linux

```bash
sudo systemctl {start|stop|restart|status} auditforwarder
sudo journalctl -u auditforwarder -f
sudo journalctl -u auditforwarder --since "1 hour ago"
```

### Windows

```powershell
Get-Service AuditForwarder
Restart-Service AuditForwarder
Get-EventLog -LogName Application -Source AuditForwarder -Newest 50
```

## 2. 更新配置

编辑 `/etc/auditforwarder/agent.yaml` 后：

```bash
# 重新加载而不重启（推荐）
curl -X POST http://127.0.0.1:8443/config/reload \
     -H "Authorization: Bearer $TOKEN"

# 或重启
sudo systemctl restart auditforwarder
```

## 3. 轮换签名密钥

1. 生成新密钥对：
   ```bash
   openssl genpkey -algorithm ed25519 -out /etc/auditforwarder/keys/agent.pem.new
   openssl pkey -in /etc/auditforwarder/keys/agent.pem.new -pubout \
        -out /etc/auditforwarder/keys/agent.pub.new
   ```
2. 更新 `agent.yaml` 中的 `chain.signing_key_path`。
3. 重新加载（或重启）代理。
4. 删除旧密钥文件。

> 代理保留前一批次的签名，因此如果保留旧公钥，历史验证仍然可能。

## 4. 重放/验证旧批次

`chain` 模块在 `$data_dir/batches/` 下每个文件持久化一个签名批次。批次文件是包含事件、Merkle根和签名的JSON文档。

从单独的主机验证批次（无代理运行）很简单：读取JSON，从 `events[].hash` 重新计算Merkle根，并用代理的公钥验证签名。

## 5. 升级代理

```bash
# 1. 放置新二进制文件
sudo cp auditforwarderd /usr/local/bin/auditforwarderd.new
sudo chmod 0755 /usr/local/bin/auditforwarderd.new

# 2. 更新 agent.yaml 中的 SHA-256
NEW_HASH=$(sha256sum /usr/local/bin/auditforwarderd.new | cut -d' ' -f1)
sudo sed -i "s/known_good_hash:.*/known_good_hash: \"$NEW_HASH\"/" /etc/auditforwarder/agent.yaml

# 3. 替换并重启
sudo mv /usr/local/bin/auditforwarderd.new /usr/local/bin/auditforwarderd
sudo systemctl restart auditforwarder
```

对于零停机滚动升级，通过manager API触发升级（POST /upgrade 并带上新二进制文件的URL）。代理下载、哈希验证并自动重启。

## 6. 常见问题

| 症状 | 原因 | 解决方案 |
|---|---|---|
| `audit_open: permission denied` | libaudit 需要root权限 | 授予 `CAP_AUDIT_READ` 或以root运行 |
| `Cannot bind manager: address in use` | 端口已被占用 | 修改 `manager.listen` |
| `HTTP 401` from manager | Bearer token错误/缺失 | 设置 `manager.auth_token` |
| `chain.flush: no events` | 采集器未运行 | 检查journal中的采集器启动错误 |
| 高CPU占用 | 采样器 `keep_ratio=1.0` + 高事件量 | 设置 `keep_ratio=0.5` 或添加 `RegexFilter` |

## 7. 健康检查

manager暴露 `/health` 用于存活/就绪检查：

```bash
$ curl -s http://127.0.0.1:8443/health
{
  "running": true,
  "events_collected": 124532,
  "events_uploaded": 124510,
  "events_failed": 22,
  "events_dropped": 0,
  "alerts": 4,
  "bytes_uploaded": 11893422,
  "uptime_seconds": 6321
}
```

简单的就绪检查可以验证 `running=true` 且 `events_failed` 没有增长。
