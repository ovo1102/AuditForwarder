# AuditForwarder - Wire Protocol

This document describes the wire format used by the HTTPS transport.

## 1. Envelope

A batch upload is a single HTTPS POST. The body is the **wire envelope**;
the headers carry authentication, batch identifier, and agent identifier.

### 1.1 Request

```
POST /api/v1/ingest HTTP/1.1
Host: audit.example.com
Content-Type: application/octet-stream
Content-Length: <len>
X-AuditForwarder-Batch: <batch_id>
X-AuditForwarder-Agent: <agent_id>
Authorization: Bearer <token>            (optional, when mTLS is not used)
Connection: close
```

`<body>` is the wire envelope defined below.

### 1.2 Wire envelope

```
+--------+--------+--------+--------+--------+--------+
|  'A'   |  'E'   |  '1'   | iv_len |   iv  (12B)   |
+--------+--------+--------+--------+--------+--------+
|       cipher_len (u32 LE)              | cipher...
+---------------------------------------+--------------+
```

- `'AE1'` - envelope magic (ASCII).
- `iv_len` - 1 byte, currently always `12`.
- `iv` - random 12 bytes for AES-256-GCM.
- `cipher_len` - little-endian u32, length of `cipher`.
- `cipher` - GCM ciphertext concatenated with the 16-byte tag.

The plaintext of `cipher` is the **zlib-compressed canonical JSON** of the
batch document (§2). The AEAD AAD is the 16-character batch id.

If `transport.encrypt_payload=false`, the envelope is the raw
zlib-compressed JSON (no `AE1` header, no IV).

## 2. Batch document (canonical JSON)

```json
{
  "id":          "9f1b2c3d4e5f6071",
  "merkle_root": "a3f5...c2",
  "signature":   "ed25519-sig-hex",
  "count":       256,
  "created_at":  1700000000000000,
  "events": [ { ... }, { ... } ]
}
```

`created_at` is microseconds since the Unix epoch.

### 2.1 Event

```json
{
  "id": 0, "seq": 1234, "ts_micros": 1700000000000123, "schema_ver": 1,
  "category": "process", "action": "spawn", "outcome": "success", "severity": "info",
  "host": "host-1", "agent_id": "host-1-1234", "rule_id": "R-CMD-001",
  "actor": { "pid": 4321, "tid": 4321, "name": "bash", "path": "/bin/bash",
             "user": "root", "sid": "0:0", "session": "1", "remote": "" },
  "target": { "kind": "process", "path": "", "address": "", "port": 0, "protocol": "" },
  "command": "bash -i",
  "message": "process spawn pid=4321",
  "hash":      "abc...123",
  "prev_hash": "def...456",
  "signature": "...",
  "batch_id":  "9f1b2c3d4e5f6071",
  "attrs":     { "k": "v" }
}
```

## 3. Response

The server returns HTTP 2xx on success. The response body is a JSON
document:

```json
{ "status": "ok", "checkpoint": "9f1b2c3d4e5f6071", "server_ts": 1700000001 }
```

`checkpoint` is echoed back to the client. The client uses it to evict
the resume entry.

On a non-2xx response the body may include an error description:

```json
{ "error": "batch rejected", "reason": "unknown agent_id" }
```

## 4. Resume protocol

The client keeps a JSON file at `${data_dir}/transport.index` with the
list of in-flight batch ids:

```json
{ "resumed": ["9f1b2c3d4e5f6071", "..."] }
```

On start-up the client reads this file and re-queues the listed batches
**at the head of the queue** before resuming normal operation. The
file is rewritten after every successful upload and after every failed
attempt.

## 5. Versioning

The envelope magic is `'AE1'`. Future versions (e.g. AE2) will be
introduced in a backwards-compatible way; the first three bytes are
always ASCII and start with the same prefix.
