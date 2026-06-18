//! Offline integrity + structural validation for backup documents.
//!
//! Validates a `.bvx` (password-encrypted) or plaintext `bvx.v1` JSON file
//! without a running vault, barrier, or network — so an operator can run it
//! straight against the files in the scheduled-export destination (e.g.
//! `/backups`). The checks, in order:
//!
//!   1. **Format** — is this a `BVX` envelope or a bare `bvx.v1` document?
//!   2. **Integrity / authenticity** (`.bvx` only) — does the XChaCha20-
//!      Poly1305 AEAD tag verify under the supplied password? A pass proves
//!      the ciphertext and envelope parameters were not altered.
//!   3. **Structure** — does the inner payload parse as an `ExchangeDocument`
//!      and carry the expected `bvx.v1` schema tag?
//!   4. **File-blob content** — for every embedded file, re-hash the bytes and
//!      compare against the `sha256` / `size_bytes` recorded in its metadata.
//!   5. **Non-emptiness** — a document with zero items is reported as a
//!      failure: a "successful" backup that captured nothing is the exact
//!      regression that produced 577-byte exports.

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::errors::RvError;
use crate::exchange::envelope::ENVELOPE_MAGIC;
use crate::exchange::{decrypt_bvx, schema::ExchangeDocument, Envelope};

/// Per-item counts for a verified document.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ItemCounts {
    pub kv: u64,
    pub resources: u64,
    pub files: u64,
    pub asset_groups: u64,
    pub resource_groups: u64,
}

impl ItemCounts {
    pub fn total(&self) -> u64 {
        self.kv + self.resources + self.files + self.asset_groups + self.resource_groups
    }
}

/// A file blob whose embedded bytes did not match its recorded metadata.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileIssue {
    pub id: String,
    pub name: Option<String>,
    pub problem: String,
}

/// Structured result of verifying a backup file.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    /// `"bvx"` (encrypted envelope) or `"json"` (plaintext document).
    pub format: String,
    /// `.bvx` only: the AEAD tag verified under the supplied password, i.e.
    /// the ciphertext + KDF/AEAD parameters are intact and authentic.
    pub decrypted: bool,
    /// The inner payload parsed and carried the `bvx.v1` schema tag.
    pub schema_ok: bool,
    pub schema_tag: String,
    pub exported_at: String,
    /// `"full"` or `"selective"`.
    pub scope_kind: String,
    /// Envelope `created_at` (`.bvx` only).
    pub created_at: Option<String>,
    pub comment: Option<String>,
    pub counts: ItemCounts,
    pub total_items: u64,
    /// Number of embedded file blobs whose hash + size were checked.
    pub files_checked: u64,
    /// File blobs that failed their integrity check.
    pub file_issues: Vec<FileIssue>,
    /// Warnings carried inside the document plus any raised by the verifier
    /// (e.g. the empty-backup guard).
    pub warnings: Vec<String>,
    /// Overall verdict: integrity + structure + file hashes + non-emptiness.
    pub ok: bool,
}

/// Verify a backup file's bytes. `password` is required for `.bvx` files and
/// ignored for plaintext JSON.
///
/// Returns a populated [`VerifyReport`] for any file that is structurally a
/// backup; `report.ok` is the overall verdict. Returns `Err` only when the
/// input cannot be classified or decrypted at all (wrong password, tampered
/// ciphertext, not a backup file).
pub fn verify_backup_bytes(bytes: &[u8], password: Option<&str>) -> Result<VerifyReport, RvError> {
    // Classify: a `.bvx` is a JSON envelope whose `magic` is `BVX`. Anything
    // else we attempt to read as a bare `bvx.v1` document.
    let is_envelope = serde_json::from_slice::<Envelope>(bytes)
        .map(|e| e.magic == ENVELOPE_MAGIC)
        .unwrap_or(false);

    let (format, decrypted, inner) = if is_envelope {
        let pw = password.ok_or_else(|| {
            log::warn!("verify: .bvx file requires a password");
            RvError::ErrRequestInvalid
        })?;
        // AEAD failure here = wrong password or tampered file; fail closed.
        let plaintext = decrypt_bvx(bytes, pw)?;
        ("bvx".to_string(), true, plaintext)
    } else {
        ("json".to_string(), false, bytes.to_vec())
    };

    // Envelope-level metadata (best-effort; the envelope already parsed above
    // when `is_envelope`).
    let (created_at, comment) = if is_envelope {
        serde_json::from_slice::<Envelope>(bytes)
            .map(|e| (Some(e.created_at), e.comment))
            .unwrap_or((None, None))
    } else {
        (None, None)
    };

    let document: ExchangeDocument =
        serde_json::from_slice(&inner).map_err(|_| RvError::ErrRequestInvalid)?;

    let schema_ok = document.validate_schema_tag().is_ok();

    let counts = ItemCounts {
        kv: document.items.kv.len() as u64,
        resources: document.items.resources.len() as u64,
        files: document.items.files.len() as u64,
        asset_groups: document.items.asset_groups.len() as u64,
        resource_groups: document.items.resource_groups.len() as u64,
    };
    let total_items = counts.total();

    // File-blob content integrity: re-hash the bytes and compare against the
    // metadata recorded at export time.
    let mut file_issues = Vec::new();
    for f in &document.items.files {
        let name = f
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let raw = match base64::engine::general_purpose::STANDARD.decode(f.content_b64.as_bytes()) {
            Ok(b) => b,
            Err(_) => {
                file_issues.push(FileIssue {
                    id: f.id.clone(),
                    name,
                    problem: "content_b64 is not valid base64".to_string(),
                });
                continue;
            }
        };
        if let Some(expected) = f.metadata.get("sha256").and_then(|v| v.as_str()) {
            let actual = sha256_hex(&raw);
            if !actual.eq_ignore_ascii_case(expected) {
                file_issues.push(FileIssue {
                    id: f.id.clone(),
                    name: name.clone(),
                    problem: format!("sha256 mismatch: metadata={expected} actual={actual}"),
                });
                continue;
            }
        }
        if let Some(expected) = f.metadata.get("size_bytes").and_then(|v| v.as_u64()) {
            if expected != raw.len() as u64 {
                file_issues.push(FileIssue {
                    id: f.id.clone(),
                    name,
                    problem: format!(
                        "size mismatch: metadata={expected} actual={}",
                        raw.len()
                    ),
                });
            }
        }
    }

    let mut warnings = document.warnings.clone();
    if total_items == 0 {
        warnings.push(
            "document contains zero items — the backup captured no data".to_string(),
        );
    }

    let ok = schema_ok && file_issues.is_empty() && total_items > 0;

    Ok(VerifyReport {
        format,
        decrypted,
        schema_ok,
        schema_tag: document.schema,
        exported_at: document.exported_at,
        scope_kind: match document.scope.kind {
            crate::exchange::ScopeKind::Full => "full".to_string(),
            crate::exchange::ScopeKind::Selective => "selective".to_string(),
        },
        created_at,
        comment,
        counts,
        total_items,
        files_checked: document.items.files.len() as u64,
        file_issues,
        warnings,
        ok,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::schema::{ExchangeItems, ExporterInfo, FileItem, KvItem, ScopeSpec};
    use crate::exchange::{encrypt_bvx, ScopeKind};
    use serde_json::json;

    fn doc_with(items: ExchangeItems) -> ExchangeDocument {
        ExchangeDocument::new(
            ExporterInfo::default(),
            ScopeSpec { kind: ScopeKind::Full, include: vec![] },
            items,
        )
    }

    fn file_item(bytes: &[u8]) -> FileItem {
        FileItem {
            id: "f1".to_string(),
            metadata: json!({
                "name": "doc.bin",
                "sha256": sha256_hex(bytes),
                "size_bytes": bytes.len(),
            }),
            content_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    #[test]
    fn verifies_healthy_bvx_with_file_hash() {
        let bytes = vec![1u8, 2, 3, 4, 5];
        let doc = doc_with(ExchangeItems {
            kv: vec![KvItem { mount: "secret/".into(), path: "data/a".into(), value: json!({"x":1}) }],
            files: vec![file_item(&bytes)],
            ..Default::default()
        });
        let inner = serde_json::to_vec(&doc).unwrap();
        let env = encrypt_bvx(&inner, "correct-horse-battery", "", Some("nightly".into())).unwrap();

        let report = verify_backup_bytes(&env, Some("correct-horse-battery")).unwrap();
        assert!(report.ok);
        assert!(report.decrypted);
        assert_eq!(report.format, "bvx");
        assert_eq!(report.counts.kv, 1);
        assert_eq!(report.counts.files, 1);
        assert_eq!(report.files_checked, 1);
        assert!(report.file_issues.is_empty());
        assert_eq!(report.comment.as_deref(), Some("nightly"));
    }

    #[test]
    fn empty_document_is_not_ok() {
        let doc = doc_with(ExchangeItems::default());
        let inner = serde_json::to_vec(&doc).unwrap();
        let env = encrypt_bvx(&inner, "correct-horse-battery", "", None).unwrap();

        let report = verify_backup_bytes(&env, Some("correct-horse-battery")).unwrap();
        assert!(!report.ok, "empty backup must fail verification");
        assert_eq!(report.total_items, 0);
        assert!(report.warnings.iter().any(|w| w.contains("zero items")));
    }

    #[test]
    fn wrong_password_fails_closed() {
        let doc = doc_with(ExchangeItems {
            kv: vec![KvItem { mount: "secret/".into(), path: "a".into(), value: json!({}) }],
            ..Default::default()
        });
        let inner = serde_json::to_vec(&doc).unwrap();
        let env = encrypt_bvx(&inner, "correct-horse-battery", "", None).unwrap();
        assert!(verify_backup_bytes(&env, Some("the-wrong-password")).is_err());
    }

    #[test]
    fn detects_corrupted_file_blob() {
        let bytes = vec![9u8; 32];
        let mut f = file_item(&bytes);
        // Corrupt the content while leaving the metadata hash intact.
        f.content_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 32]);
        let doc = doc_with(ExchangeItems { files: vec![f], ..Default::default() });
        let inner = serde_json::to_vec(&doc).unwrap();

        // Plaintext JSON path (no password needed).
        let report = verify_backup_bytes(&inner, None).unwrap();
        assert_eq!(report.format, "json");
        assert!(!report.ok);
        assert_eq!(report.file_issues.len(), 1);
        assert!(report.file_issues[0].problem.contains("sha256 mismatch"));
    }

    #[test]
    fn plaintext_json_round_trips() {
        let doc = doc_with(ExchangeItems {
            kv: vec![KvItem { mount: "secret/".into(), path: "a".into(), value: json!({"k":"v"}) }],
            ..Default::default()
        });
        let inner = serde_json::to_vec(&doc).unwrap();
        let report = verify_backup_bytes(&inner, None).unwrap();
        assert!(report.ok);
        assert_eq!(report.format, "json");
        assert!(!report.decrypted);
        assert_eq!(report.counts.kv, 1);
    }
}
