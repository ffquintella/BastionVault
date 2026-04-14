# Feature: Batch Operations

## Summary

Add a batch API endpoint that accepts multiple vault operations in a single HTTP request, executes them sequentially, and returns all results in a single response. This reduces round-trip overhead for clients that need to read or write many secrets at once.

## Motivation

Common operational patterns require many vault operations in quick succession:

- **Application startup**: a service reads 10-20 secrets (database credentials, API keys, TLS certs) during initialization. Today this requires 10-20 sequential HTTP requests.
- **Secret rotation**: rotating credentials across multiple paths requires separate write calls for each.
- **Configuration deployment**: CI/CD pipelines writing a set of secrets for a new deployment.
- **Audit/compliance scans**: reading all secrets under a prefix to verify they meet policy.

Each HTTP request incurs TLS handshake overhead (if not using keep-alive), authentication, policy evaluation, and storage access. Batching amortizes the authentication and connection costs across multiple operations.

## Current State

- The HTTP API handles exactly one operation per request (`src/http/logical.rs`).
- The `Request` struct represents a single operation with one path, one operation type, and one body.
- The storage `Backend` trait has no batch/transaction methods -- each `get()`/`put()`/`delete()` is independent.
- The `Client` API (`src/api/logical.rs`) exposes only single-operation methods: `read()`, `write()`, `list()`, `delete()`.
- No batch or bulk endpoints exist anywhere in the HTTP layer.
- Hiqlite supports transactions (`client.txn()`) but they are not exposed through BastionVault.

## Design

### Batch API Endpoint

```
POST /v1/sys/batch
```

Request body:

```json
{
  "operations": [
    {
      "operation": "read",
      "path": "secret/data/myapp/db"
    },
    {
      "operation": "read",
      "path": "secret/data/myapp/api-key"
    },
    {
      "operation": "write",
      "path": "secret/data/myapp/cache-ttl",
      "data": { "data": { "ttl": "300" } }
    },
    {
      "operation": "delete",
      "path": "secret/data/myapp/deprecated-key"
    }
  ]
}
```

Response body:

```json
{
  "results": [
    {
      "status": 200,
      "path": "secret/data/myapp/db",
      "data": {
        "data": { "username": "admin", "password": "s3cret" },
        "metadata": { "version": 3 }
      }
    },
    {
      "status": 200,
      "path": "secret/data/myapp/api-key",
      "data": {
        "data": { "key": "abc123" }
      }
    },
    {
      "status": 204,
      "path": "secret/data/myapp/cache-ttl",
      "data": {
        "version": 1
      }
    },
    {
      "status": 204,
      "path": "secret/data/myapp/deprecated-key",
      "data": null
    }
  ]
}
```

### Semantics

**Sequential execution**: operations execute in order. Each operation sees the effects of previous operations in the batch. This is simpler to reason about than parallel execution and avoids concurrency hazards.

**Independent results**: each operation produces its own status code and result. A failure in one operation does not abort the batch. The caller inspects each result individually.

**Authentication**: the batch request is authenticated once using the token in the `X-BastionVault-Token` header. All operations in the batch execute under that token's identity and policies.

**Authorization**: each operation is individually authorized against the token's policies. An operation that the token is not authorized for returns a 403 in its result slot, but other operations proceed.

**Audit**: each operation in the batch produces its own audit entry. The audit entries include a `batch_id` field linking them to the same batch request.

### Limits

| Limit | Default | Config Key |
|---|---|---|
| Max operations per batch | 128 | `batch_max_operations` |
| Max request body size | 32 MB | `batch_max_body_size` |

Requests exceeding these limits are rejected with 400 before any operations execute.

### Supported Operations

| Operation | Description |
|---|---|
| `read` | Read a secret or config. Equivalent to `GET /v1/{path}`. |
| `write` | Write a secret or config. Equivalent to `POST /v1/{path}`. Requires `data` field. |
| `delete` | Delete a secret. Equivalent to `DELETE /v1/{path}`. |
| `list` | List keys at a prefix. Equivalent to `LIST /v1/{path}`. |

### Operation Structure

```json
{
  "operation": "read | write | delete | list",
  "path": "mount/path/to/secret",
  "data": { ... }
}
```

- `operation` (required): one of `read`, `write`, `delete`, `list`.
- `path` (required): full path including mount prefix (e.g., `secret/data/myapp`).
- `data` (optional): request body for write operations. Ignored for read/delete/list.

### Result Structure

```json
{
  "status": 200,
  "path": "secret/data/myapp",
  "data": { ... },
  "errors": ["..."],
  "warnings": ["..."]
}
```

- `status`: HTTP status code that would have been returned for an individual request.
- `path`: echoed from the operation.
- `data`: response data (same shape as an individual API response).
- `errors`: error messages if the operation failed.
- `warnings`: warning messages.

### CLI Support

```bash
# Batch read from a file
bvault batch -input=operations.json

# Batch read from stdin (pipe-friendly)
cat operations.json | bvault batch -input=-

# Inline batch (convenience for scripts)
bvault batch \
  -op="read:secret/data/db" \
  -op="read:secret/data/api-key" \
  -op="delete:secret/data/old-key"
```

The CLI parses the JSON response and prints each result with its status.

### Client SDK

Add a `batch()` method to the `Client` API (`src/api/logical.rs`):

```rust
pub fn batch(&self, operations: &[BatchOperation]) -> Result<Vec<BatchResult>, RvError>
```

This sends a single HTTP POST to `/v1/sys/batch` and deserializes the response.

## Implementation Scope

### New Files

| File | Purpose |
|---|---|
| `src/http/batch.rs` | Batch HTTP handler: parse request, iterate operations, collect results |
| `src/api/batch.rs` | Client-side batch method |
| `src/cli/command/batch.rs` | Batch CLI command |

### Modified Files

| File | Change |
|---|---|
| `src/http/mod.rs` | Register `/v1/sys/batch` route |
| `src/api/mod.rs` | Add batch module |
| `src/cli/mod.rs` | Register batch command |
| `src/cli/config.rs` | Add `batch_max_operations` and `batch_max_body_size` config keys |

### Not In Scope

- **Transactional batches** (all-or-nothing atomicity). Too complex for Phase 1 and not supported by Vault. Each operation is independent.
- **Parallel execution** within a batch. Sequential is simpler, safer, and matches Vault behavior.
- **Streaming responses**. The entire batch result is returned at once. For very large batches, the client should split into multiple batch requests.
- **Batch-specific rate limiting**. A batch of 100 operations counts as 1 API request for rate limiting purposes. Per-operation rate limiting can be added later.

## Testing Requirements

### Unit Tests
- Batch request parsing: valid operations, missing fields, exceeding limits.
- Result collection: mixed success/failure results.
- Authorization: unauthorized operation returns 403 in result, doesn't abort batch.

### Integration Tests
- Batch read of multiple secrets: all return correct data.
- Batch write followed by batch read in the same request: reads see the writes.
- Batch with one unauthorized operation: authorized operations succeed, unauthorized returns 403.
- Batch exceeding max operations limit: rejected with 400.
- Batch with invalid path: individual result returns 404, others succeed.
- Audit log contains individual entries for each operation in the batch.

### Cucumber BDD Scenarios
- Read multiple secrets in a single batch request.
- Write and read in the same batch, verify read sees the write.
- Include an unauthorized operation in a batch, verify it fails independently.
- Exceed the batch size limit, verify the entire request is rejected.

## Security Considerations

- **Authentication is shared**: all operations in a batch use the same token. There is no per-operation token. This is intentional -- a batch is a convenience wrapper, not a multi-tenant operation.
- **Authorization is per-operation**: a token with read-only access cannot sneak a write into a batch. Each operation is individually checked.
- **Audit coverage**: every operation in a batch is individually audited. The `batch_id` field enables correlation. No operations are hidden from audit.
- **Denial of service**: a batch of 128 write operations is more expensive than a single write. The `batch_max_operations` limit bounds the cost. Operators can lower it if needed.
- **Error information leakage**: a 403 result for one operation confirms the path exists (or at least that the token lacks access). This is the same information leakage as individual requests -- no new risk.
- **Request body size**: the `batch_max_body_size` limit (default 32 MB) prevents memory exhaustion from oversized batch requests.
