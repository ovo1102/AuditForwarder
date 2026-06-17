# AuditForwarder

> Enterprise-grade cross-platform security audit agent. Captures every
> operator action on Linux and Windows endpoints, normalises the data,
> builds a tamper-evident chain of custody, and forwards the result to a
> centralised platform with optional automatic response.

```
                   +-----------------------+
                   |   Operators (users)   |
                   +-----------+-----------+
                               |
   file, process, network,     |     command, registry, syscall,
   command, syscall ...        |     auth, driver load ...
                               v
+----------------------------------+----------------------------------+
|                       End-point Agent                              |
|                                                                      |
|  Collectors -> Processors -> Detector -> Chain (Merkle + sign) ->    |
|  Local storage -> HTTPS Uploader (compress + encrypt + resume)       |
|                                                                      |
|  Manager API    Self-Protect    Watchdog    Healthcheck             |
+----------------------------------+----------------------------------+
                               |
                               v
                +-----------------------------+
                |  Central Audit Platform     |
                |  (your existing SIEM/UEBA)  |
                +-----------------------------+
```

## Highlights

| Capability | Implementation |
|---|---|
| **End-point residency** | Linux systemd service / Windows service; integrity check, install-dir lockdown, watchdog |
| **Full-spectrum capture** | Inotify (Linux) / `ReadDirectoryChangesW` (Windows), `/proc`/`audit`/ETW, `GetTcpTable2`, WMI, registry notifications, command line, GUI (configurable) |
| **Normalization & pre-processing** | Field-level schema, regex filter, PII masker, deduper, sampler, aggregator, enricher |
| **Trusted chain of custody** | SHA-256 hash chain, Merkle tree per batch, Ed25519 (or HMAC-SHA-256) signature, on-disk JSON envelopes |
| **Transport** | HTTPS with mutual TLS, zlib compression, AES-256-GCM payload encryption, resume index with exponential backoff, multi-server failover |
| **Detection & auto-response** | Rule engine (YAML/JSON), frequency thresholds, behaviour baseline, response actions: alert / block / kill / quarantine |
| **Remote management** | Local HTTP API (token or mTLS), endpoints: `/health`, `/config`, `/config/reload`, `/batches`, `/upgrade` |
| **Cross-platform** | Single C++17 source tree, Linux (kernel ≥3.10) + Windows 10/Server 2016+ |

## Repository layout

```
AuditForwarder/
├── CMakeLists.txt            # Build entry point
├── README.md
├── include/auditforwarder/   # Public headers
│   ├── build_config.h        # Platform macros
│   ├── types.h               # Result, severity, etc.
│   ├── logger.h              # Async logger
│   ├── config.h              # YAML/JSON configuration
│   ├── fs.h                  # Filesystem utilities
│   ├── process.h             # Process utilities
│   ├── thread_pool.h         # Worker pool
│   ├── event.h               # Audit event model
│   ├── crypto.h              # Hash, AEAD, sign, Merkle
│   ├── chain.h               # Hash chain + signed batches
│   ├── processor.h           # Filter / enrich / aggregate
│   ├── transport.h           # HTTPS uploader
│   ├── detector.h            # Rule engine + behaviour baseline
│   ├── manager.h             # Admin HTTP interface
│   ├── self_protect.h        # Integrity check + watchdog
│   ├── collector_base.h      # Path filter + FS watch interface
│   ├── agent.h               # Agent orchestrator
│   ├── platform_linux.h      # Linux entry
│   └── platform_windows.h    # Windows entry
├── src/                      # Implementation
│   ├── main.cpp
│   ├── common/               # Logger, config, FS, process, threadpool, event
│   ├── core/                 # Agent, self-protect, platform daemon
│   ├── crypto/               # Primitives + chain
│   ├── processor/            # Pipeline processors
│   ├── transport/            # HTTPS uploader
│   ├── detector/             # Rule engine
│   ├── manager/              # Admin HTTP server
│   └── collector/
│       ├── linux/            # inotify, /proc, /proc/net, libaudit
│       └── windows/          # RDCW, ETW, registry, process snapshot
├── config/
│   ├── agent.yaml            # Default configuration
│   └── rules.yaml            # Default detection rules
├── scripts/
│   ├── install_linux.sh      # systemd installer
│   └── install_windows.ps1   # Windows service installer
├── tests/unit/               # Smoke tests (no external deps)
└── docs/                     # Architecture & operations
```

## Quick start

### Linux (Debian/Ubuntu/RHEL)

```bash
# 1. install build dependencies
sudo apt install -y build-essential cmake pkg-config libssl-dev zlib1g-dev libaudit-dev

# 2. build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# 3. install (creates /etc/auditforwarder, /var/lib/auditforwarder, ...)
sudo ./scripts/install_linux.sh --start

# 4. check status
sudo systemctl status auditforwarder
sudo journalctl -u auditforwarder -f
curl -s http://127.0.0.1:8443/health
```

### Windows (PowerShell, Administrator)

```powershell
# 1. install vcpkg deps: openssl, zlib, gtest
vcpkg install openssl zlib

# 2. build
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
      -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release -j

# 3. install as a service
powershell -ExecutionPolicy Bypass -File scripts\install_windows.ps1 -Start
```

## Configuration

Edit `/etc/auditforwarder/agent.yaml` (or `C:\ProgramData\AuditForwarder\agent.yaml`).
Reload without a restart:

```bash
curl -X POST http://127.0.0.1:8443/config/reload -H "Authorization: Bearer $TOKEN"
```

Key sections:

- `agent.id`              - globally unique agent identifier
- `chain.batch_size`      - events per signed Merkle batch
- `transport.servers[]`   - list of ingest endpoints (failover order)
- `transport.compress`    - enable zlib compression
- `transport.encrypt_payload` - enable AES-256-GCM payload encryption
- `detector.rules_path`   - path to your rules file
- `self_protect.known_good_hash` - expected SHA-256 of the binary
- `manager.auth_token`    - bearer token for the admin API

## Detection rules

`/etc/auditforwarder/rules.yaml` is a YAML (or JSON) list of rule objects.
Each rule selects events on `category`, `action`, exact field matches, and
regular expressions on actor/path/command. A rule can also be a frequency
threshold within a sliding window.

Response actions supported per rule:

| Action | Effect |
|---|---|
| `alert` | Emit an alert event, log, forward |
| `block` | Mark the event as denied and drop from pipeline |
| `kill`   | `TerminateProcess` (Win) / `kill -9` (Linux) on the actor PID |
| `quarantine` | Move the file to a sealed vault (next observation) |

Example:

```yaml
- id: R-CMD-001
  name: Possible reverse shell
  severity: critical
  categories: [command]
  cmd_match: ["bash\\s+-i.*>&?\\s*/dev/tcp/"]
  responses: [alert, kill]
```

## Verifying a chain of custody

```cpp
af::chain::Chain ch(cfg);
ch.start();
ch.set_signer(kp);                       // Ed25519 key pair
// ... events flow in ...
auto b = ch.flush();                     // returns a signed EventBatch
bool ok = af::chain::Chain::verify_batch_with_key(b, kp);
```

A single SHA-256 root per batch and a per-event prev_hash link form the
Merkle + linear chain. A single-byte change in any event invalidates the
batch root, and the per-event hash link invalidates everything downstream
of the tampered event.

## Remote management

| Verb | Path | Description |
|---|---|---|
| `GET`  | `/health`        | Liveness + stats |
| `GET`  | `/config`        | Dump current configuration |
| `POST` | `/config/reload` | Reload configuration from disk |
| `GET`  | `/batches`       | Recent signed batches |
| `POST` | `/upgrade`       | Trigger remote upgrade (URL in body) |

The admin interface binds to `127.0.0.1:8443` by default and requires the
`manager.auth_token` bearer token when bound to a non-loopback address.
Place it behind an mTLS front-end for production.

## Resource budget

| Resource | Typical use |
|---|---|
| CPU  | < 2% steady-state on 4-core x86_64 |
| RAM  | 30-60 MiB |
| Disk | bounded by `data_dir` quota; old batches rotated |
| Net  | compress + encrypt; average 4 KiB/s for 1k events/min |

## Security model

- **Anti-tamper:** The agent binary is hashed at start-up and on a schedule;
  a mismatch raises a `critical` audit event and triggers the watchdog
  (restart from a known-good copy if signed). The install directory is
  locked down (`chmod 0555` / Windows DACL).
- **Process hiding:** Runs under a dedicated service account; on Windows
  registers as a protected service, on Linux uses a private `/proc` mount
  namespace when available.
- **Self-upgrade:** New binaries must be signed by an operator-provided
  Ed25519 public key in the local trust store. The upgrade payload is
  hash-verified before being swapped.
- **Defense in depth:** Even if a collector is bypassed, the chain module
  still signs every event it receives; gaps in the chain are visible to
  the platform.

## Build options

| CMake option | Default | Description |
|---|---|---|
| `BUILD_TESTING`     | ON  | Build the unit tests |
| `CMAKE_BUILD_TYPE`  | Release | Standard CMake switch |

Dependencies (required):

- C++17 compiler
- OpenSSL ≥ 1.1
- zlib
- pthreads

Optional (auto-detected):

- `yaml-cpp`  - improves config loading performance
- `nlohmann_json` - faster event serialization
- `spdlog` - drop-in faster logger
- `GTest` - enables `BUILD_TESTING`
- `libaudit` (Linux) - enables kernel-audit collector

## License

Apache 2.0 (see `LICENSE`).
