# Feature: Audit Logging (Tamper-Evident, HMAC Chain)

## Summary

Add a pluggable audit logging subsystem that records every authenticated request and response through one or more audit devices, with tamper-evident hash chaining across entries and HMAC-based integrity verification.

## Motivation

BastionVault currently has no operational audit trail. Operators cannot answer basic questions:

- Who accessed a secret and when?
- What changed during an incident window?
- Was a policy modified, and by whom?
- Can we prove the audit log itself has not been tampered with?

Compliance frameworks (SOC 2, PCI-DSS, HIPAA, FedRAMP) require auditable access logs for secrets management systems. Without audit logging, BastionVault cannot be deployed in regulated environments.

## Current State

The codebase has **stubs and infrastructure** but no working audit implementation:

**What exists:**
- Handler trait defines a `log()` phase that runs after every request (`src/handler.rs:40`).
- System module registers API endpoints for `GET /sys/audit`, `POST /sys/audit/{path}`, `DELETE /sys/audit/{path}` -- but all handlers return empty responses (`src/modules/system/mod.rs:573-595`).
- The `audit/` mount path is protected from user remounting (`src/mount.rs:38`).
- Auth struct carries `metadata` and `display_name` fields explicitly documented as "for audit logging" (`src/logical/auth.rs:43-44`).
- HMAC infrastructure exists: `derive_hmac_key()` on barriers, `hmac_sha256_hex()` utility, `MountEntryHMACLevel` config with None/Compat/High levels.
- Request struct has `id`, `operation`, `path`, `client_token`, `connection` -- sufficient context for audit entries.

**What is missing:**
- No audit entry data structure.
- No audit device trait or implementations (file, syslog, HTTP webhook, etc.).
- No audit broker to fan-out entries to multiple devices.
- No hash chaining across audit entries for tamper detection.
- No sensitive data detection or redaction in logged entries.
- No audit log storage, rotation, or retention.
- No CLI commands for audit management.
- No tests.

## Design

### Audit Entry Structure

Each auditable operation produces an `AuditEntry`:

```json
{
  "time": "2026-04-14T15:30:00.123456Z",
  "type": "request",
  "auth": {
    "client_token": "hmac:abc123...",
    "accessor": "hmac:def456...",
    "display_name": "token-operator",
    "policies": ["default", "admin"],
    "metadata": { "role": "deploy" },
    "remote_address": "10.0.0.5"
  },
  "request": {
    "id": "req-uuid-here",
    "operation": "read",
    "path": "secret/data/myapp/db",
    "data": null,
    "remote_address": "10.0.0.5",
    "wrap_ttl": 0
  },
  "response": {
    "data": null,
    "redirect": "",
    "warnings": []
  },
  "error": "",
  "prev_hash": "sha256:aabbccdd..."
}
```

Two entry types are recorded per operation:
1. **Request entry** (`"type": "request"`) -- logged before the operation executes.
2. **Response entry** (`"type": "response"`) -- logged after the operation completes, including the outcome.

### Sensitive Data Handling

Audit entries must not contain raw secrets. The following fields are HMAC-hashed before logging:

- `client_token` -- replaced with `hmac:<hash>` so entries can be correlated without exposing the token.
- `accessor` -- same treatment.
- Request `data` values for write operations on secret paths -- replaced with `hmac:<hash>` per value, or omitted entirely if the audit device is configured with `hmac_accessor = false`.
- Response `data` -- HMAC-hashed or omitted depending on device configuration.

The HMAC key is derived from the barrier's `derive_hmac_key()`, which is already available in the core state after unseal.

### Tamper-Evident Hash Chain

Each audit entry includes a `prev_hash` field containing the SHA-256 hash of the previous entry's serialized JSON. This creates a hash chain:

```
Entry 1: prev_hash = "sha256:0000...0000" (genesis)
Entry 2: prev_hash = sha256(serialize(Entry 1))
Entry 3: prev_hash = sha256(serialize(Entry 2))
```

Verification: given a contiguous sequence of audit entries, any tampering (insertion, deletion, modification) breaks the chain and is detectable by recomputing hashes forward.

The hash chain is maintained per audit device. Each device tracks its own `last_hash`.

### Audit Device Trait

```rust
pub trait AuditDevice: Send + Sync {
    /// Device type identifier (e.g., "file", "syslog").
    fn device_type(&self) -> &str;

    /// Log a single audit entry. Must be durable before returning Ok.
    async fn log_entry(&self, entry: &AuditEntry) -> Result<(), RvError>;

    /// Flush any buffered entries.
    async fn flush(&self) -> Result<(), RvError>;

    /// Reload configuration (e.g., reopen file handles after rotation).
    async fn reload(&self) -> Result<(), RvError>;
}
```

### Audit Broker

The `AuditBroker` manages multiple audit devices and fans out entries:

- Holds a `Vec<Arc<dyn AuditDevice>>`.
- On each auditable operation, serializes the entry once and sends it to all devices.
- **Fail policy**: if any enabled audit device fails to log, the entire request is rejected. This ensures audit coverage is never silently lost. (Matches Vault behavior.)
- The broker is stored on `Core` and called from the handler's `log()` phase.

### Audit Devices (Phase 1)

#### File Audit Device

Writes JSON-lines to a local file.

Config:
```json
{
  "type": "file",
  "options": {
    "file_path": "/var/log/bvault/audit.log",
    "hmac_accessor": true,
    "log_raw": false,
    "mode": "0600"
  }
}
```

- Each entry is a single JSON line (no pretty-printing) for grep/stream compatibility.
- File is opened in append mode. Writes are flushed after each entry.
- `log_raw: true` disables HMAC hashing of sensitive fields (use only in controlled debug environments).

### Audit Devices (Future Phases)

- **Syslog**: forward entries to a syslog daemon.
- **Socket**: write to a Unix or TCP socket.
- **HTTP webhook**: POST entries to an external endpoint.

### API Endpoints

These endpoints already exist as stubs in the system module and need implementation:

| Endpoint | Method | Description |
|---|---|---|
| `/v1/sys/audit` | GET | List all enabled audit devices with their config. |
| `/v1/sys/audit/{path}` | POST | Enable an audit device at the given path. |
| `/v1/sys/audit/{path}` | DELETE | Disable an audit device. |

Enable request body:
```json
{
  "type": "file",
  "description": "Primary audit log",
  "options": {
    "file_path": "/var/log/bvault/audit.log"
  }
}
```

### CLI Commands

| Command | Description |
|---|---|
| `bvault audit enable file -path=main-audit -options=file_path=/var/log/bvault/audit.log` | Enable a file audit device. |
| `bvault audit disable main-audit` | Disable an audit device. |
| `bvault audit list` | List enabled audit devices. |

### Integration with Request Pipeline

The audit broker hooks into the existing handler pipeline:

1. **Pre-request**: after authentication, before dispatching to backend -- log request entry.
2. **Post-request**: after backend returns response -- log response entry.
3. **On error**: log response entry with error field populated.

If any audit device fails during pre-request logging, the request is rejected with a 500 error. This prevents unaudited operations.

### Persistence

Audit device configuration is stored in the barrier at `core/audit` (similar to `core/mounts`). On unseal, the audit broker loads and re-enables all configured devices.

## Implementation Scope

### New Files

| File | Purpose |
|---|---|
| `src/audit/mod.rs` | AuditEntry, AuditBroker, AuditDevice trait |
| `src/audit/entry.rs` | AuditEntry struct, serialization, HMAC hashing logic |
| `src/audit/broker.rs` | AuditBroker: fan-out, fail policy, hash chain |
| `src/audit/file_device.rs` | File-based audit device implementation |
| `src/audit/hash_chain.rs` | Hash chain computation and verification |
| `features/audit-logging.md` | This document |

### Modified Files

| File | Change |
|---|---|
| `src/lib.rs` | Add `pub mod audit` |
| `src/core.rs` | Add `audit_broker: Option<AuditBroker>` to Core, hook into request pipeline |
| `src/modules/system/mod.rs` | Implement `handle_audit_table`, `handle_audit_enable`, `handle_audit_disable` |
| `src/handler.rs` | Call audit broker from `log()` phase |
| `src/cli/command/` | Add audit enable/disable/list CLI commands |

## Testing Requirements

### Unit Tests
- AuditEntry serialization round-trip.
- HMAC hashing of sensitive fields (token, data values).
- Hash chain computation and verification.
- Hash chain tampering detection (insert, delete, modify).

### Integration Tests
- Enable file audit device, perform operations, verify log file contains entries.
- Verify request and response entries are paired.
- Verify audit device failure blocks the request.
- Verify audit config persists across seal/unseal.

### Cucumber BDD Scenarios
- Enable an audit device and verify it logs operations.
- Perform a secret write and verify the audit entry contains the path and operation.
- Verify sensitive data is HMAC-hashed in audit entries.
- Disable an audit device and verify operations still succeed.
- Verify hash chain integrity across a sequence of entries.

## Security Considerations

- The hash chain provides tamper detection, not tamper prevention. An attacker with storage access can rewrite the entire chain. For stronger guarantees, forward the chain head to an external witness (out of scope for Phase 1).
- `log_raw: true` must be treated as a dangerous option. It exposes secret values in plaintext in the audit log. Default is false.
- Audit log files must be protected by filesystem permissions. The file device creates files with mode 0600 by default.
- The fail-closed policy (reject requests if audit fails) prioritizes auditability over availability. Operators who need the opposite can disable all audit devices.
- The HMAC key used for hashing audit fields is derived from the barrier key. If the barrier is compromised, audit HMACs can be recomputed. This is acceptable because barrier compromise implies full system compromise.
