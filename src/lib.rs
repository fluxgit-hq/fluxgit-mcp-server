use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const SERVER_NAME: &str = "fluxgit-mcp-sidecar";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The latest stateless MCP protocol revision implemented by the sidecar.
pub const LATEST_PROTOCOL_VERSION: &str = "2026-07-28";
/// The handshake-era revision retained for older MCP hosts.
pub const LEGACY_PROTOCOL_VERSION: &str = "2024-11-05";
/// Backward-compatible alias used by integrations that imported this constant.
pub const PROTOCOL_VERSION: &str = LEGACY_PROTOCOL_VERSION;
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] =
    [LATEST_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION];

const MCP_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MCP_MAX_LEGACY_HEADER_BYTES: usize = 8 * 1024;
const MCP_MAX_REQUEST_ID_BYTES: usize = 1_024;
/// A bridge payload is embedded twice in modern MCP tool results: once as
/// structuredContent and once as JSON text. Keep inbound bridge JSON well
/// below the wire ceiling; [`serialize_response`] remains the final fail-safe
/// for escaping/pretty-print overhead and every non-bridge response.
const MCP_MAX_BRIDGE_RESPONSE_BYTES: usize = MCP_MAX_FRAME_BYTES / 3;
const MCP_LIST_CACHE_TTL_MS: u64 = 30_000;
const MCP_ALLOWED_ROOTS_ENV: &str = "FLUXGIT_MCP_ALLOWED_ROOTS";
const MCP_INSTRUCTIONS: &str = "Use repo.brief first for repository context. Read tools never mutate Git state. operation.preview.* only creates an in-app FluxGit proposal: keep the returned previewId, let FluxGit show its card and notifications, and use operation.status until the user-approved guarded pipeline reports a terminal result.";
const MCP_MAX_PATCH_CHARS: usize = 4 * 1024 * 1024;
const MCP_MAX_MESSAGE_CHARS: usize = 64 * 1024;
const MCP_MAX_REASON_CHARS: usize = 4096;
const MCP_MAX_REF_CHARS: usize = 4096;
const MCP_MAX_PATH_CHARS: usize = 32 * 1024;
const MCP_MAX_PATH_ITEMS: usize = 10_000;

const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);
const GIT_STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
/// Commands whose callers present their output as complete must fit below this
/// ceiling. Returning an error is safer than silently presenting a prefix as a
/// complete repository snapshot.
const GIT_COMPLETE_STDOUT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// `diff.text` and conflict blob reads advertise explicit truncation metadata,
/// but still need a finite amount of work to calculate their exact totals.
const GIT_BOUNDED_SCAN_MAX_BYTES: usize = 64 * 1024 * 1024;
const GIT_STDERR_CAPTURE_BYTES: usize = 64 * 1024;
const GIT_STDERR_MAX_BYTES: usize = 1024 * 1024;

/// Audit records contain metadata and fingerprints, never patch bodies or Git
/// output. A generous explicit line ceiling protects both appenders and the
/// streaming verifier from malformed or attacker-controlled JSONL files.
pub const AUDIT_MAX_LINE_BYTES: usize = 256 * 1024;
/// The active JSONL and each immutable rotated segment are independently
/// bounded. A legacy-only active file may exceed this by at most one line
/// while the first chained entry anchors that legacy prefix.
pub const AUDIT_MAX_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
/// Retain at most four immutable segments plus the active JSONL. Normal
/// operation therefore uses at most roughly 20 MiB (plus tiny lock/checkpoint
/// metadata) and never grows without bound.
pub const AUDIT_MAX_ROTATED_SEGMENTS: usize = 4;
const AUDIT_MAX_SIGNING_KEY_BYTES: u64 = 64 * 1024;
const AUDIT_MAX_CHECKPOINT_BYTES: u64 = 16 * 1024;
const AUDIT_MAX_DIRECTORY_ENTRIES: usize = 4_096;
const AUDIT_MAX_CHECKPOINT_FILES: usize = 16;
const AUDIT_CHAIN_VERSION: u64 = 1;
const AUDIT_SCHEMA_VERSION: u64 = 1;
const AUDIT_SIGNATURE_VERSION: u64 = 3;
const AUDIT_GENESIS_HASH: &str = "genesis";
const AUDIT_SUMMARY_MAX_CHARS: usize = 512;

#[derive(Debug, Clone)]
pub struct McpSidecar {
    gateway_state: GatewayState,
    audit_ledger: Option<AuditLedger>,
    /// The connected agent's own name, taken from `clientInfo.name` in the MCP
    /// `initialize` request.
    ///
    /// Every dispatch used to send a hardcoded "external-mcp-sidecar", so the
    /// per-agent policy in PLAYBOOK §14.10 could never match a real agent — a
    /// rule for `agent-claude` was dead text — and all connected agents shared
    /// one MAX_PENDING_PER_AGENT budget, letting a chatty agent starve another.
    /// It is a self-declared name, not an authenticated identity: it makes
    /// policy and quotas addressable, and is not a security boundary.
    client_id: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

/// Per-install Ed25519 audit signer. Loaded once at startup from
/// `FLUXGIT_MCP_AUDIT_SIGN_KEY` (PEM PKCS8, matching the license-server convention).
/// Signing is opt-in when the env var is unset. An explicitly configured key
/// is fail-closed: unsafe, unreadable, oversized, or invalid material is an
/// audit startup error and can never silently downgrade to unsigned entries.
#[derive(Clone)]
pub struct AuditSigner {
    signing_key: SigningKey,
    /// Short hex prefix of the public key (first 8 bytes -> 16 hex chars).
    /// Allows multiple keys to co-exist in the same JSONL if rotated.
    key_id: String,
}

impl fmt::Debug for AuditSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditSigner")
            .field("key_id", &self.key_id)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl AuditSigner {
    /// Load a signer from a PEM-encoded PKCS8 Ed25519 private key file.
    pub fn from_pem_file(path: &Path) -> Result<Self, AuditSignerError> {
        let pem = read_secure_signing_key(path).map_err(AuditSignerError::Io)?;
        Self::from_pem_str(&pem)
    }

    /// Load a signer from an in-memory PEM PKCS8 string. Exposed for tests
    /// (so a keypair can be generated and consumed without touching disk).
    pub fn from_pem_str(pem: &str) -> Result<Self, AuditSignerError> {
        if pem.len() as u64 > AUDIT_MAX_SIGNING_KEY_BYTES {
            return Err(AuditSignerError::Parse(format!(
                "key exceeds the {AUDIT_MAX_SIGNING_KEY_BYTES}-byte safety limit"
            )));
        }
        let signing_key =
            SigningKey::from_pkcs8_pem(pem).map_err(|e| AuditSignerError::Parse(e.to_string()))?;
        Ok(Self::from_signing_key(signing_key))
    }

    /// Build a signer directly from a [`SigningKey`]. Used by tests and by
    /// callers that already have the key material in memory.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let public = signing_key.verifying_key();
        let key_id = short_key_id(&public);
        Self {
            signing_key,
            key_id,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Build a signer from raw 32-byte Ed25519 secret material. Public so the
    /// gateway's decision-audit tests can construct a deterministic signer
    /// without touching disk or PEM.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(secret))
    }

    /// Sign the canonical-JSON form of `event` (event MUST NOT yet contain
    /// a `signature` field). Returns the base64url-no-pad signature. Public
    /// so the gateway can sign its human-decision audit events with the exact
    /// same canonical form the sidecar uses (PLAYBOOK §6.1).
    pub fn sign_event(&self, event: &Value) -> String {
        let canonical = canonical_json_bytes(event);
        let sig: Signature = self.signing_key.sign(&canonical);
        BASE64_URL_NO_PAD.encode(sig.to_bytes())
    }
}

/// Reasons an audit signer might fail to load. They are fatal to an explicitly
/// configured audit surface; callers must not substitute an unsigned signer.
#[derive(Debug)]
pub enum AuditSignerError {
    Io(io::Error),
    Parse(String),
}

impl fmt::Display for AuditSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cannot read audit signing key file: {err}"),
            Self::Parse(msg) => write!(
                f,
                "audit signing key is not a valid PEM PKCS8 Ed25519 key: {msg}"
            ),
        }
    }
}

impl std::error::Error for AuditSignerError {}

/// Reasons audit signature verification can fail.
#[derive(Debug)]
pub enum AuditVerificationError {
    /// The event is not a JSON object (top-level must be `{...}`).
    NotAnObject,
    /// The `signature` field is missing — caller should treat the entry as
    /// unsigned, not as tampered.
    MissingSignature,
    /// The `signature` field exists but is not a base64url string.
    MalformedSignature(String),
    /// The decoded signature was the wrong length for Ed25519.
    InvalidSignatureLength(usize),
}

impl fmt::Display for AuditVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "audit event must be a JSON object"),
            Self::MissingSignature => write!(f, "audit event has no signature field"),
            Self::MalformedSignature(msg) => {
                write!(f, "signature field is not valid base64url: {msg}")
            }
            Self::InvalidSignatureLength(n) => {
                write!(f, "signature has wrong length: {n} (expected 64)")
            }
        }
    }
}

impl std::error::Error for AuditVerificationError {}

/// First 8 bytes of the public key, hex-encoded. 16 characters is short
/// enough to read at a glance and long enough that accidental collisions
/// across coexisting installs are vanishingly unlikely.
fn short_key_id(public: &VerifyingKey) -> String {
    let bytes = public.to_bytes();
    let mut id = String::with_capacity(16);
    for b in &bytes[..8] {
        use std::fmt::Write;
        let _ = write!(id, "{:02x}", b);
    }
    id
}

/// Recursively rewrite a [`Value`] into a form whose serialization is
/// canonical: JSON object keys are sorted lexicographically (by their UTF-8
/// byte order, which matches `BTreeMap`). Arrays preserve order. Primitives
/// are returned as-is.
fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered: std::collections::BTreeMap<String, Value> =
                std::collections::BTreeMap::new();
            for (k, v) in map {
                ordered.insert(k.clone(), canonicalize_value(v));
            }
            let mut out = Map::new();
            for (k, v) in ordered {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

/// Serialize an event to the canonical byte form used for signing/verifying.
///
/// Canonicalization rule (documented in `product/mcp/PLAYBOOK.md` §6):
///   - JSON object keys are sorted lexicographically by their UTF-8 byte order
///     (this is what `serde_json::Map` backed by a `BTreeMap` yields, and what
///     `BTreeMap<String, Value>` produces directly).
///   - No insignificant whitespace, no newlines (compact form).
///   - Arrays preserve their order.
///   - Numbers and strings use serde_json's default representation.
///
/// The `signature` field MUST be stripped before this function is called.
fn canonical_json_bytes(event: &Value) -> Vec<u8> {
    let canonical = canonicalize_value(event);
    // `serde_json::to_vec` produces compact (no-whitespace) output, and a
    // BTreeMap-backed Object iterates in sorted order, so this is canonical.
    serde_json::to_vec(&canonical).unwrap_or_default()
}

/// Verify the signature of a single audit event against `public_key`.
///
/// `event` is the parsed JSON object as it appears in the JSONL log
/// (with `signature` and `signatureKeyId` still present).
///
/// Returns:
///   - `Ok(true)`  — signature is present and valid.
///   - `Ok(false)` — signature is present but does not verify.
///   - `Err(AuditVerificationError::MissingSignature)` — the event has no
///     `signature` field. Callers writing audit-proof tools should treat
///     this as "unsigned entry" rather than "tampered", to stay compatible
///     with deployments that haven't enabled signing yet.
///   - Other `Err(_)` variants — the entry is malformed.
pub fn verify_audit_event_signature(
    event: &Value,
    public_key: &VerifyingKey,
) -> Result<bool, AuditVerificationError> {
    let obj = event
        .as_object()
        .ok_or(AuditVerificationError::NotAnObject)?;
    let signature_b64 = obj
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(AuditVerificationError::MissingSignature)?;
    let sig_bytes = BASE64_URL_NO_PAD
        .decode(signature_b64)
        .map_err(|e| AuditVerificationError::MalformedSignature(e.to_string()))?;
    if sig_bytes.len() != Signature::BYTE_SIZE {
        return Err(AuditVerificationError::InvalidSignatureLength(
            sig_bytes.len(),
        ));
    }
    let mut sig_array = [0u8; Signature::BYTE_SIZE];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);

    // Signature v2 binds the key id so it cannot be relabelled during key
    // rotation. Legacy entries omitted that metadata from the signed bytes;
    // keep their verification path for backward compatibility.
    let mut unsigned = obj.clone();
    unsigned.remove("signature");
    if unsigned
        .get("signatureVersion")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        < 2
    {
        unsigned.remove("signatureKeyId");
    }
    let canonical = canonical_json_bytes(&Value::Object(unsigned));

    Ok(public_key.verify(&canonical, &signature).is_ok())
}

/// Parse a PEM-encoded Ed25519 public key (SubjectPublicKeyInfo, the format
/// emitted by Python `cryptography` and matching license-server convention).
pub fn parse_public_key_pem(pem: &str) -> Result<VerifyingKey, AuditSignerError> {
    VerifyingKey::from_public_key_pem(pem).map_err(|e| AuditSignerError::Parse(e.to_string()))
}

/// A single, shared, bounded audit ledger implementation used by both the
/// MCP stdio sidecar and the gateway's human-decision endpoints.
///
/// Every append takes a stable sibling lock, validates the directory and file
/// again after locking/opening, repairs only an unmistakable partial active
/// tail, validates the retained chain, rotates under the same lock, writes one
/// complete JSONL record, and synchronizes it before releasing the lock.
#[derive(Clone)]
pub struct AuditLedger {
    path: PathBuf,
    signer: Option<AuditSigner>,
    max_segment_bytes: u64,
    max_rotated_segments: usize,
}

impl fmt::Debug for AuditLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLedger")
            .field("path", &self.path)
            .field(
                "signer",
                &self.signer.as_ref().map(|signer| signer.key_id()),
            )
            .field("max_segment_bytes", &self.max_segment_bytes)
            .field("max_rotated_segments", &self.max_rotated_segments)
            .finish()
    }
}

#[derive(Debug)]
pub enum AuditLedgerError {
    Io(io::Error),
    Configuration(String),
    Serialization(String),
    Integrity {
        segment: usize,
        line: usize,
        reason: String,
    },
}

impl AuditLedgerError {
    fn integrity(segment: usize, line: usize, reason: impl Into<String>) -> Self {
        Self::Integrity {
            segment,
            line,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for AuditLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "audit I/O error: {error}"),
            Self::Configuration(message) => write!(f, "invalid audit configuration: {message}"),
            Self::Serialization(message) => write!(f, "cannot serialize audit metadata: {message}"),
            Self::Integrity {
                segment,
                line,
                reason,
            } => write!(
                f,
                "audit integrity failure in segment {segment}, line {line}: {reason}"
            ),
        }
    }
}

impl std::error::Error for AuditLedgerError {}

impl From<io::Error> for AuditLedgerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl AuditLedger {
    /// Resolve the common environment contract. Auditing is enabled by
    /// default at `<run_dir>/audit/mcp.jsonl`; `FLUXGIT_MCP_AUDIT_LOG`
    /// overrides it and `FLUXGIT_MCP_AUDIT_DISABLED` disables appends.
    ///
    /// The signing key is deliberately loaded first: explicitly configuring
    /// an invalid key is an error even when another variable disables audit,
    /// avoiding a latent silent downgrade on the next restart.
    pub fn from_env() -> Result<Option<Self>, AuditLedgerError> {
        let signer = load_audit_signer_from_env()?;
        let Some(path) = mcp_audit_log_path_checked()? else {
            return Ok(None);
        };
        Self::new(path, signer).map(Some)
    }

    pub fn new(path: PathBuf, signer: Option<AuditSigner>) -> Result<Self, AuditLedgerError> {
        Self::with_limits(
            path,
            signer,
            AUDIT_MAX_SEGMENT_BYTES,
            AUDIT_MAX_ROTATED_SEGMENTS,
        )
    }

    /// Construct a ledger with explicit retention limits. Public primarily so
    /// the gateway can share the implementation and adversarial tests can
    /// exercise rotation without writing multi-megabyte fixtures.
    pub fn with_limits(
        path: PathBuf,
        signer: Option<AuditSigner>,
        max_segment_bytes: u64,
        max_rotated_segments: usize,
    ) -> Result<Self, AuditLedgerError> {
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            return Err(AuditLedgerError::Configuration(
                "audit log path must name a file".into(),
            ));
        }
        if max_segment_bytes < 512 {
            return Err(AuditLedgerError::Configuration(
                "audit segment limit must be at least 512 bytes".into(),
            ));
        }
        if max_rotated_segments == 0 || max_rotated_segments > 64 {
            return Err(AuditLedgerError::Configuration(
                "audit rotated-segment limit must be between 1 and 64".into(),
            ));
        }
        Ok(Self {
            path,
            signer,
            max_segment_bytes,
            max_rotated_segments,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: Value) -> Result<(), AuditLedgerError> {
        prepare_audit_parent(&self.path)?;
        let lock_path = audit_lock_path(&self.path)?;
        let lock_file = open_secure_audit_file(&lock_path, true, true)?;
        lock_file.lock_exclusive()?;

        // The lock file and destination are attacker-reachable filesystem
        // names. Re-check them only after ownership of the stable lock is held.
        validate_audit_parent(&self.path)?;
        validate_opened_path(&lock_path, &lock_file)?;
        recover_active_tail(&self.path)?;

        let mut scan = scan_audit_ledger(
            &self.path,
            None,
            false,
            self.max_segment_bytes,
            self.max_rotated_segments,
        )?;
        let rotated_count = scan
            .files
            .iter()
            .filter(|segment| segment.path != self.path)
            .count();
        if rotated_count > self.max_rotated_segments {
            prune_rotated_segments(
                &self.path,
                self.signer.as_ref(),
                self.max_segment_bytes,
                self.max_rotated_segments,
            )?;
            scan = scan_audit_ledger(
                &self.path,
                None,
                false,
                self.max_segment_bytes,
                self.max_rotated_segments,
            )?;
        }
        let mut segment_id = scan
            .active
            .as_ref()
            .and_then(|active| active.segment_id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let mut chained = build_chained_event(event, &scan, &segment_id, self.signer.as_ref())?;
        let mut line = serialize_audit_line(&chained)?;

        let mut active_len = fs::symlink_metadata(&self.path)
            .map(|metadata| metadata.len())
            .or_else(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    Ok(0)
                } else {
                    Err(error)
                }
            })?;
        let active_has_chain = scan
            .active
            .as_ref()
            .is_some_and(|active| active.last_sequence.is_some());
        if active_len > 0
            && active_has_chain
            && active_len.saturating_add(line.len() as u64) > self.max_segment_bytes
        {
            rotate_active_segment(&self.path, &scan)?;
            prune_rotated_segments(
                &self.path,
                self.signer.as_ref(),
                self.max_segment_bytes,
                self.max_rotated_segments,
            )?;
            scan = scan_audit_ledger(
                &self.path,
                None,
                false,
                self.max_segment_bytes,
                self.max_rotated_segments,
            )?;
            segment_id = Uuid::new_v4().to_string();
            chained = build_chained_event(chained, &scan, &segment_id, self.signer.as_ref())?;
            line = serialize_audit_line(&chained)?;
            active_len = 0;
        }

        // A pre-chain legacy file must first receive a chained boundary entry
        // that commits to its complete prefix. It may cross the normal segment
        // limit by at most this one bounded line; the next append rotates it.
        let hard_limit = self
            .max_segment_bytes
            .saturating_add(AUDIT_MAX_LINE_BYTES as u64);
        if active_len.saturating_add(line.len() as u64) > hard_limit {
            return Err(AuditLedgerError::Configuration(format!(
                "active audit segment would exceed its {hard_limit}-byte hard limit"
            )));
        }

        let mut file = open_secure_audit_file(&self.path, true, true)?;
        validate_audit_parent(&self.path)?;
        validate_opened_path(&self.path, &file)?;
        file.seek(SeekFrom::End(0))?;
        file.write_all(&line)?;
        file.sync_data()?;
        Ok(())
    }
}

fn serialize_audit_line(event: &Value) -> Result<Vec<u8>, AuditLedgerError> {
    let mut line = serde_json::to_vec(event)
        .map_err(|error| AuditLedgerError::Serialization(error.to_string()))?;
    line.push(b'\n');
    if line.len() > AUDIT_MAX_LINE_BYTES {
        return Err(AuditLedgerError::Configuration(format!(
            "audit event is {} bytes; maximum JSONL line is {AUDIT_MAX_LINE_BYTES} bytes",
            line.len()
        )));
    }
    Ok(line)
}

fn sibling_audit_path(path: &Path, suffix: &str) -> Result<PathBuf, AuditLedgerError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| AuditLedgerError::Configuration("audit log path must name a file".into()))?;
    let mut sibling = file_name.to_os_string();
    sibling.push(suffix);
    Ok(path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(sibling))
}

fn audit_lock_path(path: &Path) -> Result<PathBuf, AuditLedgerError> {
    sibling_audit_path(path, ".lock")
}

fn prepare_audit_parent(path: &Path) -> Result<(), AuditLedgerError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let was_missing = match fs::symlink_metadata(parent) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error.into()),
    };
    fs::create_dir_all(parent)?;
    secure_audit_directory(parent, was_missing)?;
    validate_audit_parent(path)
}

fn validate_audit_parent(path: &Path) -> Result<(), AuditLedgerError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    secure_audit_directory(parent, false)?;
    Ok(())
}

fn open_secure_audit_file(
    path: &Path,
    create: bool,
    writable: bool,
) -> Result<File, AuditLedgerError> {
    reject_unsafe_audit_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(writable).create(create);
    configure_secure_audit_open(&mut options);
    let file = options.open(path)?;
    secure_audit_file(path, &file)?;
    validate_opened_path(path, &file)?;
    Ok(file)
}

/// Repair only the final unterminated record of the active file. A valid JSON
/// value merely receives its missing newline; an invalid suffix is truncated
/// only when at least one complete earlier line exists. Corruption of a
/// one-record file is ambiguous and therefore fails closed.
fn recover_active_tail(path: &Path) -> Result<(), AuditLedgerError> {
    let mut file = match open_secure_audit_file(path, false, true) {
        Ok(file) => file,
        Err(AuditLedgerError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(())
        }
        Err(error) => return Err(error),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }

    let mut cursor = len;
    let mut previous_newline = None;
    let mut chunk = [0u8; 8 * 1024];
    while cursor > 0 {
        let read_len = usize::try_from(cursor.min(chunk.len() as u64)).unwrap_or(chunk.len());
        cursor -= read_len as u64;
        file.seek(SeekFrom::Start(cursor))?;
        file.read_exact(&mut chunk[..read_len])?;
        if let Some(index) = chunk[..read_len].iter().rposition(|byte| *byte == b'\n') {
            previous_newline = Some(cursor + index as u64);
            break;
        }
    }
    let tail_start = previous_newline.map_or(0, |position| position + 1);
    let tail_len = len.saturating_sub(tail_start);
    if tail_len == 0 || tail_len > AUDIT_MAX_LINE_BYTES as u64 {
        return Err(AuditLedgerError::integrity(
            usize::MAX,
            0,
            "unterminated active tail exceeds the line bound",
        ));
    }
    let mut tail = vec![0u8; tail_len as usize];
    file.seek(SeekFrom::Start(tail_start))?;
    file.read_exact(&mut tail)?;
    let valid_object = serde_json::from_slice::<Value>(&tail)
        .ok()
        .is_some_and(|value| value.is_object());
    if valid_object {
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"\n")?;
    } else if tail_start > 0 {
        file.set_len(tail_start)?;
    } else {
        return Err(AuditLedgerError::integrity(
            usize::MAX,
            1,
            "single-record active file has an invalid partial tail",
        ));
    }
    file.sync_data()?;
    Ok(())
}

#[derive(Clone, Debug)]
struct RotatedSegmentName {
    path: PathBuf,
    first_sequence: u64,
    last_sequence: u64,
    segment_id: String,
}

#[derive(Clone, Debug)]
enum LedgerFileKind {
    Rotated(RotatedSegmentName),
    Active,
}

#[derive(Clone, Debug)]
struct LedgerFile {
    path: PathBuf,
    kind: LedgerFileKind,
}

#[derive(Clone, Debug, Default)]
struct ScannedSegment {
    path: PathBuf,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    last_hash: Option<String>,
    segment_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct LedgerScan {
    files: Vec<ScannedSegment>,
    active: Option<ScannedSegment>,
    last_sequence: u64,
    last_hash: Option<String>,
    legacy_anchor: Option<[u8; 32]>,
    entries: u64,
    chained: u64,
    legacy: u64,
    signed: u64,
    unsigned: u64,
    first_sequence: Option<u64>,
    checkpoint_used: bool,
}

#[derive(Clone, Debug)]
struct RetentionCheckpoint {
    next_sequence: u64,
    previous_hash: String,
}

/// Bounded summary returned by the streaming ledger verifier. It contains
/// counters and sequence metadata only, never event bodies, repository names,
/// tool arguments, paths, or signatures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditLedgerVerification {
    pub entries: u64,
    pub chained: u64,
    pub legacy: u64,
    pub signed: u64,
    pub unsigned: u64,
    pub segments: usize,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub retention_checkpoint_used: bool,
}

/// Stream and verify the active audit JSONL plus all retained rotation
/// segments. Legacy per-entry records remain accepted and their signatures
/// are checked, but they are reported separately and are never described as
/// chained. New records must have a contiguous sequence and matching
/// previous/entry hashes, so modification, intermediate deletion, duplicate
/// insertion, and reordering fail verification.
pub fn verify_audit_ledger(
    path: &Path,
    public_key: &VerifyingKey,
    require_signed: bool,
) -> Result<AuditLedgerVerification, AuditLedgerError> {
    let scan = scan_audit_ledger(
        path,
        Some(public_key),
        require_signed,
        AUDIT_MAX_SEGMENT_BYTES,
        AUDIT_MAX_ROTATED_SEGMENTS,
    )?;
    Ok(AuditLedgerVerification {
        entries: scan.entries,
        chained: scan.chained,
        legacy: scan.legacy,
        signed: scan.signed,
        unsigned: scan.unsigned,
        segments: scan.files.len(),
        first_sequence: scan.first_sequence,
        last_sequence: (scan.last_sequence > 0).then_some(scan.last_sequence),
        retention_checkpoint_used: scan.checkpoint_used,
    })
}

/// Domain-separated SHA-256 fingerprint suitable for `repo_scope`. This is
/// intentionally one-way and never returns any part of the repository path.
pub fn audit_repo_scope_fingerprint(repo_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"fluxgit-mcp-repo-scope-v1\0");
    hasher.update(repo_path.as_bytes());
    format!("sha256:{}", lowercase_hex(&hasher.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", lowercase_hex(&Sha256::digest(bytes)))
}

fn is_sha256_label(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn legacy_anchor_next(previous: Option<[u8; 32]>, event: &Value) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"fluxgit-mcp-legacy-prefix-v1\0");
    hasher.update(previous.unwrap_or([0u8; 32]));
    hasher.update(canonical_json_bytes(event));
    hasher.finalize().into()
}

fn legacy_anchor_label(anchor: &[u8; 32]) -> String {
    format!("legacy-sha256:{}", lowercase_hex(anchor))
}

fn bounded_audit_text(value: &str, max_chars: usize) -> String {
    let mut output = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(max_chars.saturating_add(1))
        .collect::<String>();
    if output.chars().count() > max_chars {
        output = output.chars().take(max_chars.saturating_sub(1)).collect();
        output.push('.');
    }
    output
}

fn build_chained_event(
    event: Value,
    scan: &LedgerScan,
    segment_id: &str,
    signer: Option<&AuditSigner>,
) -> Result<Value, AuditLedgerError> {
    let mut object = event.as_object().cloned().ok_or_else(|| {
        AuditLedgerError::Configuration("audit events must be JSON objects".into())
    })?;
    for reserved in [
        "id",
        "auditSchemaVersion",
        "auditChainVersion",
        "sequence",
        "segmentId",
        "previousHash",
        "entryHash",
        "signature",
        "signatureKeyId",
        "signatureVersion",
    ] {
        object.remove(reserved);
    }
    if !object.get("timestamp").is_some_and(Value::is_number) {
        object.insert("timestamp".into(), json!(now_ms()));
    }
    if let Some(summary) = object.get("summary").and_then(Value::as_str) {
        object.insert(
            "summary".into(),
            Value::String(bounded_audit_text(summary, AUDIT_SUMMARY_MAX_CHARS)),
        );
    }
    object.insert("id".into(), Value::String(Uuid::new_v4().to_string()));
    object.insert("auditSchemaVersion".into(), json!(AUDIT_SCHEMA_VERSION));
    object.insert("auditChainVersion".into(), json!(AUDIT_CHAIN_VERSION));
    object.insert(
        "sequence".into(),
        json!(scan.last_sequence.saturating_add(1)),
    );
    object.insert("segmentId".into(), Value::String(segment_id.to_string()));
    let previous_hash = scan
        .last_hash
        .clone()
        .or_else(|| scan.legacy_anchor.as_ref().map(legacy_anchor_label))
        .unwrap_or_else(|| AUDIT_GENESIS_HASH.to_string());
    object.insert("previousHash".into(), Value::String(previous_hash));
    if let Some(signer) = signer {
        object.insert(
            "signatureKeyId".into(),
            Value::String(signer.key_id().to_string()),
        );
        object.insert("signatureVersion".into(), json!(AUDIT_SIGNATURE_VERSION));
    }
    let mut value = Value::Object(object);
    let entry_hash = calculate_entry_hash(&value)?;
    value["entryHash"] = Value::String(entry_hash);
    if let Some(signer) = signer {
        value["signature"] = Value::String(signer.sign_event(&value));
    }
    Ok(value)
}

fn calculate_entry_hash(event: &Value) -> Result<String, AuditLedgerError> {
    let mut object = event.as_object().cloned().ok_or_else(|| {
        AuditLedgerError::Configuration("chained audit entry is not an object".into())
    })?;
    object.remove("entryHash");
    object.remove("signature");
    Ok(sha256_label(&canonical_json_bytes(&Value::Object(object))))
}

fn ledger_name_prefix(path: &Path) -> Result<String, AuditLedgerError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| {
            AuditLedgerError::Configuration(
                "audit log filename must be valid Unicode for bounded rotation".into(),
            )
        })
}

fn collect_ledger_files(path: &Path) -> Result<Vec<LedgerFile>, AuditLedgerError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = ledger_name_prefix(path)?;
    let rotated_prefix = format!("{base}.segment-");
    let mut rotated = Vec::new();
    let mut directory_entries = 0usize;
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        directory_entries = directory_entries.saturating_add(1);
        if directory_entries > AUDIT_MAX_DIRECTORY_ENTRIES {
            return Err(AuditLedgerError::Configuration(format!(
                "audit directory exceeds the {AUDIT_MAX_DIRECTORY_ENTRIES}-entry scan bound"
            )));
        }
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&rotated_prefix) else {
            continue;
        };
        let mut pieces = rest.splitn(3, '-');
        let first_raw = pieces.next().unwrap_or_default();
        let last_raw = pieces.next().unwrap_or_default();
        let segment_id = pieces.next().unwrap_or_default();
        if first_raw.len() != 20 || last_raw.len() != 20 || Uuid::parse_str(segment_id).is_err() {
            return Err(AuditLedgerError::Configuration(
                "malformed audit rotation filename".into(),
            ));
        }
        let first_sequence = first_raw.parse::<u64>().map_err(|_| {
            AuditLedgerError::Configuration("malformed audit rotation sequence".into())
        })?;
        let last_sequence = last_raw.parse::<u64>().map_err(|_| {
            AuditLedgerError::Configuration("malformed audit rotation sequence".into())
        })?;
        if first_sequence == 0 || last_sequence < first_sequence {
            return Err(AuditLedgerError::Configuration(
                "invalid audit rotation sequence range".into(),
            ));
        }
        rotated.push(RotatedSegmentName {
            path: entry.path(),
            first_sequence,
            last_sequence,
            segment_id: segment_id.to_string(),
        });
    }
    rotated.sort_by_key(|segment| segment.first_sequence);
    for pair in rotated.windows(2) {
        if pair[0].last_sequence >= pair[1].first_sequence {
            return Err(AuditLedgerError::Configuration(
                "overlapping or duplicate audit rotation ranges".into(),
            ));
        }
    }
    let mut files = rotated
        .into_iter()
        .map(|segment| LedgerFile {
            path: segment.path.clone(),
            kind: LedgerFileKind::Rotated(segment),
        })
        .collect::<Vec<_>>();
    match fs::symlink_metadata(path) {
        Ok(_) => files.push(LedgerFile {
            path: path.to_path_buf(),
            kind: LedgerFileKind::Active,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(files)
}

fn collect_checkpoint_paths(path: &Path) -> Result<Vec<PathBuf>, AuditLedgerError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = format!("{}.checkpoint-", ledger_name_prefix(path)?);
    let mut checkpoints = Vec::new();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(checkpoints),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let matches = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(&prefix));
        if matches {
            checkpoints.push(entry.path());
            if checkpoints.len() > AUDIT_MAX_CHECKPOINT_FILES {
                return Err(AuditLedgerError::Configuration(format!(
                    "too many audit retention checkpoints (maximum {AUDIT_MAX_CHECKPOINT_FILES})"
                )));
            }
        }
    }
    Ok(checkpoints)
}

fn read_retention_checkpoints(
    path: &Path,
    public_key: Option<&VerifyingKey>,
    require_signed: bool,
) -> Result<Vec<RetentionCheckpoint>, AuditLedgerError> {
    let mut checkpoints = Vec::new();
    for (index, checkpoint_path) in collect_checkpoint_paths(path)?.into_iter().enumerate() {
        let file = open_secure_audit_file(&checkpoint_path, false, false)?;
        let size = file.metadata()?.len();
        if size == 0 || size > AUDIT_MAX_CHECKPOINT_BYTES {
            return Err(AuditLedgerError::integrity(
                index,
                1,
                "retention checkpoint exceeds its byte bound",
            ));
        }
        let mut bytes = Vec::with_capacity(size as usize);
        file.take(AUDIT_MAX_CHECKPOINT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            AuditLedgerError::integrity(index, 1, "retention checkpoint is malformed JSON")
        })?;
        let object = value.as_object().ok_or_else(|| {
            AuditLedgerError::integrity(index, 1, "retention checkpoint is not an object")
        })?;
        if object.get("auditCheckpointVersion").and_then(Value::as_u64) != Some(1) {
            return Err(AuditLedgerError::integrity(
                index,
                1,
                "unsupported retention checkpoint version",
            ));
        }
        let next_sequence = object
            .get("nextSequence")
            .and_then(Value::as_u64)
            .filter(|sequence| *sequence > 1)
            .ok_or_else(|| {
                AuditLedgerError::integrity(
                    index,
                    1,
                    "retention checkpoint has an invalid next sequence",
                )
            })?;
        let previous_hash = object
            .get("previousHash")
            .and_then(Value::as_str)
            .filter(|hash| is_sha256_label(hash))
            .ok_or_else(|| {
                AuditLedgerError::integrity(
                    index,
                    1,
                    "retention checkpoint has an invalid previous hash",
                )
            })?
            .to_string();
        verify_optional_signature(&value, public_key, require_signed, index, 1)?;
        checkpoints.push(RetentionCheckpoint {
            next_sequence,
            previous_hash,
        });
    }
    Ok(checkpoints)
}

enum BoundedAuditLine {
    Eof,
    Data { terminated: bool },
    TooLong,
}

fn read_bounded_ledger_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> io::Result<BoundedAuditLine> {
    line.clear();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() && !too_long {
                Ok(BoundedAuditLine::Eof)
            } else if too_long {
                Ok(BoundedAuditLine::TooLong)
            } else {
                Ok(BoundedAuditLine::Data { terminated: false })
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        if !too_long {
            if line.len().saturating_add(consumed) > AUDIT_MAX_LINE_BYTES {
                line.clear();
                too_long = true;
            } else {
                line.extend_from_slice(&available[..consumed]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(if too_long {
                BoundedAuditLine::TooLong
            } else {
                BoundedAuditLine::Data { terminated: true }
            });
        }
    }
}

fn verify_optional_signature(
    event: &Value,
    public_key: Option<&VerifyingKey>,
    require_signed: bool,
    segment: usize,
    line: usize,
) -> Result<bool, AuditLedgerError> {
    let Some(signature) = event.get("signature") else {
        if require_signed {
            return Err(AuditLedgerError::integrity(
                segment,
                line,
                "required signature is missing",
            ));
        }
        return Ok(false);
    };
    let encoded = signature
        .as_str()
        .ok_or_else(|| AuditLedgerError::integrity(segment, line, "signature is not a string"))?;
    let decoded = BASE64_URL_NO_PAD.decode(encoded).map_err(|_| {
        AuditLedgerError::integrity(segment, line, "signature is not valid base64url")
    })?;
    if decoded.len() != Signature::BYTE_SIZE {
        return Err(AuditLedgerError::integrity(
            segment,
            line,
            "signature has the wrong length",
        ));
    }
    if let Some(public_key) = public_key {
        match verify_audit_event_signature(event, public_key) {
            Ok(true) => {}
            Ok(false) => {
                return Err(AuditLedgerError::integrity(
                    segment,
                    line,
                    "signature verification failed",
                ))
            }
            Err(_) => {
                return Err(AuditLedgerError::integrity(
                    segment,
                    line,
                    "signature metadata is malformed",
                ))
            }
        }
    }
    Ok(true)
}

fn scan_audit_ledger(
    path: &Path,
    public_key: Option<&VerifyingKey>,
    require_signed: bool,
    max_segment_bytes: u64,
    max_rotated_segments: usize,
) -> Result<LedgerScan, AuditLedgerError> {
    validate_audit_parent(path)?;
    let files = collect_ledger_files(path)?;
    let rotated_count = files
        .iter()
        .filter(|file| matches!(file.kind, LedgerFileKind::Rotated(_)))
        .count();
    // One extra segment can exist after an otherwise atomic active-file rename
    // if the process crashed before retention pruning. It remains bounded and
    // the next successful append prunes it under the same lock.
    if rotated_count > max_rotated_segments.saturating_add(1) {
        return Err(AuditLedgerError::Configuration(format!(
            "audit ledger has {rotated_count} rotated segments; maximum retained is {max_rotated_segments}"
        )));
    }
    let checkpoints = read_retention_checkpoints(path, public_key, require_signed)?;
    let hard_segment_limit = max_segment_bytes.saturating_add(AUDIT_MAX_LINE_BYTES as u64);
    let mut scan = LedgerScan::default();
    let mut expected_sequence: Option<u64> = None;
    let mut expected_previous: Option<String> = None;
    let mut chain_started = false;
    let mut prior_segment_id: Option<String> = None;

    for (segment_index, descriptor) in files.iter().enumerate() {
        let metadata = fs::symlink_metadata(&descriptor.path)?;
        if metadata.len() > hard_segment_limit {
            return Err(AuditLedgerError::integrity(
                segment_index,
                0,
                "segment exceeds its byte bound",
            ));
        }
        let file = open_secure_audit_file(&descriptor.path, false, false)?;
        validate_opened_path(&descriptor.path, &file)?;
        let mut reader = BufReader::new(file);
        let mut line = Vec::with_capacity(4096);
        let mut line_number = 0usize;
        let mut segment = ScannedSegment {
            path: descriptor.path.clone(),
            ..ScannedSegment::default()
        };

        loop {
            match read_bounded_ledger_line(&mut reader, &mut line)? {
                BoundedAuditLine::Eof => break,
                BoundedAuditLine::TooLong => {
                    return Err(AuditLedgerError::integrity(
                        segment_index,
                        line_number.saturating_add(1),
                        "JSONL record exceeds the line bound",
                    ))
                }
                BoundedAuditLine::Data { terminated } => {
                    line_number = line_number.saturating_add(1);
                    if !terminated {
                        return Err(AuditLedgerError::integrity(
                            segment_index,
                            line_number,
                            "segment ends with an unterminated record",
                        ));
                    }
                }
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                return Err(AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "blank JSONL records are not allowed",
                ));
            }
            let event: Value = serde_json::from_slice(&line).map_err(|_| {
                AuditLedgerError::integrity(segment_index, line_number, "record is malformed JSON")
            })?;
            let object = event.as_object().ok_or_else(|| {
                AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "record is not a JSON object",
                )
            })?;
            let is_chained = object.contains_key("auditChainVersion");
            let signed = verify_optional_signature(
                &event,
                public_key,
                require_signed,
                segment_index,
                line_number,
            )?;
            scan.entries = scan.entries.saturating_add(1);
            if signed {
                scan.signed = scan.signed.saturating_add(1);
            } else {
                scan.unsigned = scan.unsigned.saturating_add(1);
            }

            if !is_chained {
                if chain_started || expected_sequence.is_some() {
                    return Err(AuditLedgerError::integrity(
                        segment_index,
                        line_number,
                        "legacy record appears after the chained ledger began",
                    ));
                }
                if matches!(descriptor.kind, LedgerFileKind::Rotated(_)) {
                    // Rotated legacy prefixes are only supported when the same
                    // segment also contains the chained boundary that anchors
                    // them; the post-read filename check enforces that.
                }
                scan.legacy_anchor = Some(legacy_anchor_next(scan.legacy_anchor, &event));
                scan.legacy = scan.legacy.saturating_add(1);
                continue;
            }

            if object.get("auditChainVersion").and_then(Value::as_u64) != Some(AUDIT_CHAIN_VERSION)
                || object.get("auditSchemaVersion").and_then(Value::as_u64)
                    != Some(AUDIT_SCHEMA_VERSION)
            {
                return Err(AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "unsupported audit chain/schema version",
                ));
            }
            let sequence = object
                .get("sequence")
                .and_then(Value::as_u64)
                .filter(|sequence| *sequence > 0)
                .ok_or_else(|| {
                    AuditLedgerError::integrity(
                        segment_index,
                        line_number,
                        "missing or invalid sequence",
                    )
                })?;
            let previous_hash = object
                .get("previousHash")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AuditLedgerError::integrity(segment_index, line_number, "missing previous hash")
                })?;
            let entry_hash = object
                .get("entryHash")
                .and_then(Value::as_str)
                .filter(|hash| is_sha256_label(hash))
                .ok_or_else(|| {
                    AuditLedgerError::integrity(
                        segment_index,
                        line_number,
                        "missing or invalid entry hash",
                    )
                })?;
            let segment_id = object
                .get("segmentId")
                .and_then(Value::as_str)
                .filter(|id| {
                    Uuid::parse_str(id)
                        .ok()
                        .is_some_and(|parsed| parsed.to_string() == *id)
                })
                .ok_or_else(|| {
                    AuditLedgerError::integrity(
                        segment_index,
                        line_number,
                        "missing or invalid segment UUID",
                    )
                })?;
            let event_id = object
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| {
                    Uuid::parse_str(id).ok().is_some_and(|parsed| {
                        parsed.to_string() == *id && parsed.get_version_num() == 4
                    })
                })
                .ok_or_else(|| {
                    AuditLedgerError::integrity(
                        segment_index,
                        line_number,
                        "missing or invalid v4 event UUID",
                    )
                })?;
            let _ = event_id;
            if !object.get("timestamp").is_some_and(Value::is_number) {
                return Err(AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "missing numeric timestamp",
                ));
            }

            if !chain_started {
                let (initial_sequence, initial_previous, used_checkpoint) =
                    if let Some(anchor) = scan.legacy_anchor.as_ref() {
                        (1, legacy_anchor_label(anchor), false)
                    } else if sequence == 1 {
                        (1, AUDIT_GENESIS_HASH.to_string(), false)
                    } else {
                        let matching = checkpoints
                            .iter()
                            .filter(|checkpoint| {
                                checkpoint.next_sequence == sequence
                                    && checkpoint.previous_hash == previous_hash
                            })
                            .count();
                        if matching != 1 {
                            return Err(AuditLedgerError::integrity(
                                segment_index,
                                line_number,
                                "retained prefix lacks one matching retention checkpoint",
                            ));
                        }
                        (sequence, previous_hash.to_string(), true)
                    };
                expected_sequence = Some(initial_sequence);
                expected_previous = Some(initial_previous);
                scan.checkpoint_used = used_checkpoint;
                chain_started = true;
            }
            if expected_sequence != Some(sequence) {
                return Err(AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "sequence is duplicated, missing, or out of order",
                ));
            }
            if expected_previous.as_deref() != Some(previous_hash) {
                return Err(AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "previous hash does not match the preceding entry",
                ));
            }
            let calculated_hash = calculate_entry_hash(&event)?;
            if calculated_hash != entry_hash {
                return Err(AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "entry hash does not match canonical event bytes",
                ));
            }
            if let Some(file_segment_id) = segment.segment_id.as_deref() {
                if file_segment_id != segment_id {
                    return Err(AuditLedgerError::integrity(
                        segment_index,
                        line_number,
                        "one file contains multiple segment UUIDs",
                    ));
                }
            } else {
                if prior_segment_id.as_deref() == Some(segment_id) {
                    return Err(AuditLedgerError::integrity(
                        segment_index,
                        line_number,
                        "segment UUID was reused across rotation files",
                    ));
                }
                segment.segment_id = Some(segment_id.to_string());
            }
            segment.first_sequence.get_or_insert(sequence);
            segment.last_sequence = Some(sequence);
            segment.last_hash = Some(entry_hash.to_string());
            scan.first_sequence.get_or_insert(sequence);
            scan.last_sequence = sequence;
            scan.last_hash = Some(entry_hash.to_string());
            scan.chained = scan.chained.saturating_add(1);
            expected_sequence = sequence.checked_add(1);
            if expected_sequence.is_none() {
                return Err(AuditLedgerError::integrity(
                    segment_index,
                    line_number,
                    "audit sequence exhausted u64",
                ));
            }
            expected_previous = Some(entry_hash.to_string());
        }

        match &descriptor.kind {
            LedgerFileKind::Rotated(claimed) => {
                if segment.first_sequence != Some(claimed.first_sequence)
                    || segment.last_sequence != Some(claimed.last_sequence)
                    || segment.segment_id.as_deref() != Some(claimed.segment_id.as_str())
                {
                    return Err(AuditLedgerError::integrity(
                        segment_index,
                        0,
                        "rotation filename does not match segment contents",
                    ));
                }
            }
            LedgerFileKind::Active => scan.active = Some(segment.clone()),
        }
        if let Some(segment_id) = segment.segment_id.clone() {
            prior_segment_id = Some(segment_id);
        }
        scan.files.push(segment);
    }

    // A checkpoint is meaningful only when it exactly anchors the first
    // retained chain entry. Unused future checkpoints may remain after a crash
    // between atomic checkpoint creation and old-segment deletion, but no more
    // than one may match any actual retained start (enforced above).
    Ok(scan)
}

fn rotate_active_segment(path: &Path, scan: &LedgerScan) -> Result<(), AuditLedgerError> {
    let active = scan.active.as_ref().ok_or_else(|| {
        AuditLedgerError::Configuration("active audit segment disappeared before rotation".into())
    })?;
    let first = active.first_sequence.ok_or_else(|| {
        AuditLedgerError::Configuration(
            "legacy-only audit segment cannot rotate before a chained boundary".into(),
        )
    })?;
    let last = active.last_sequence.ok_or_else(|| {
        AuditLedgerError::Configuration("active audit segment has no final sequence".into())
    })?;
    let segment_id = active.segment_id.as_deref().ok_or_else(|| {
        AuditLedgerError::Configuration("active audit segment has no segment UUID".into())
    })?;
    let file = open_secure_audit_file(path, false, true)?;
    file.sync_all()?;
    validate_opened_path(path, &file)?;
    drop(file);

    let suffix = format!(".segment-{first:020}-{last:020}-{segment_id}");
    let rotated = sibling_audit_path(path, &suffix)?;
    match fs::symlink_metadata(&rotated) {
        Ok(_) => {
            return Err(AuditLedgerError::Configuration(
                "audit rotation destination already exists".into(),
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    validate_audit_parent(path)?;
    fs::rename(path, &rotated)?;
    sync_audit_parent(path)?;
    Ok(())
}

fn write_retention_checkpoint(
    path: &Path,
    next_sequence: u64,
    previous_hash: &str,
    signer: Option<&AuditSigner>,
) -> Result<PathBuf, AuditLedgerError> {
    let mut checkpoint = json!({
        "auditCheckpointVersion": 1,
        "nextSequence": next_sequence,
        "previousHash": previous_hash,
        "prunedThroughSequence": next_sequence.saturating_sub(1),
        "createdAt": now_ms(),
    });
    if let Some(signer) = signer {
        checkpoint["signatureKeyId"] = Value::String(signer.key_id().to_string());
        checkpoint["signatureVersion"] = json!(AUDIT_SIGNATURE_VERSION);
        checkpoint["signature"] = Value::String(signer.sign_event(&checkpoint));
    }
    let bytes = serde_json::to_vec(&checkpoint)
        .map_err(|error| AuditLedgerError::Serialization(error.to_string()))?;
    if bytes.len() as u64 > AUDIT_MAX_CHECKPOINT_BYTES {
        return Err(AuditLedgerError::Configuration(
            "retention checkpoint exceeds its byte bound".into(),
        ));
    }
    let suffix = format!(".checkpoint-{next_sequence:020}-{}.json", Uuid::new_v4());
    let checkpoint_path = sibling_audit_path(path, &suffix)?;
    reject_unsafe_audit_path(&checkpoint_path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    configure_secure_audit_open(&mut options);
    let mut file = options.open(&checkpoint_path)?;
    secure_audit_file(&checkpoint_path, &file)?;
    validate_opened_path(&checkpoint_path, &file)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_audit_parent(path)?;
    Ok(checkpoint_path)
}

fn prune_rotated_segments(
    path: &Path,
    signer: Option<&AuditSigner>,
    max_segment_bytes: u64,
    max_rotated_segments: usize,
) -> Result<(), AuditLedgerError> {
    let scan = scan_audit_ledger(path, None, false, max_segment_bytes, max_rotated_segments)?;
    let rotated = scan
        .files
        .iter()
        .filter(|segment| segment.path != path)
        .collect::<Vec<_>>();
    if rotated.len() <= max_rotated_segments {
        return Ok(());
    }
    let prune_count = rotated.len() - max_rotated_segments;
    let last_pruned = rotated[prune_count - 1];
    let first_retained = rotated[prune_count];
    let pruned_sequence = last_pruned.last_sequence.ok_or_else(|| {
        AuditLedgerError::Configuration("pruned segment lacks a final sequence".into())
    })?;
    let previous_hash = last_pruned.last_hash.as_deref().ok_or_else(|| {
        AuditLedgerError::Configuration("pruned segment lacks a final hash".into())
    })?;
    let next_sequence = first_retained.first_sequence.ok_or_else(|| {
        AuditLedgerError::Configuration("retained segment lacks a first sequence".into())
    })?;
    if pruned_sequence.checked_add(1) != Some(next_sequence) {
        return Err(AuditLedgerError::Configuration(
            "retention boundary is not sequence-contiguous".into(),
        ));
    }

    // Checkpoint creation is immutable and synchronized before deletion. A
    // crash can therefore leave an extra older segment, never an unexplained
    // missing prefix.
    let new_checkpoint = write_retention_checkpoint(path, next_sequence, previous_hash, signer)?;
    for segment in rotated.into_iter().take(prune_count) {
        reject_unsafe_audit_path(&segment.path)?;
        fs::remove_file(&segment.path)?;
    }
    sync_audit_parent(path)?;
    for old_checkpoint in collect_checkpoint_paths(path)? {
        if old_checkpoint != new_checkpoint {
            reject_unsafe_audit_path(&old_checkpoint)?;
            fs::remove_file(old_checkpoint)?;
        }
    }
    sync_audit_parent(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_audit_parent(path: &Path) -> Result<(), AuditLedgerError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_audit_parent(_path: &Path) -> Result<(), AuditLedgerError> {
    // Windows rename durability is provided by the synchronized files; Rust
    // 1.75 has no portable way to open a directory handle for FlushFileBuffers.
    Ok(())
}

#[derive(Debug, Clone)]
enum GatewayState {
    NotConfigured,
    Configured,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct ToolSpec {
    name: &'static str,
    title: String,
    description: &'static str,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
    #[serde(rename = "outputSchema")]
    output_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<ToolAnnotations>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct ToolAnnotations {
    #[serde(rename = "readOnlyHint")]
    read_only_hint: bool,
    /// MCP destructive-operation hint. Only set (true) on the proposal tools
    /// whose approved execution can destroy uncommitted or committed work
    /// (`operation.preview.reset`, `operation.preview.discard`). Omitted
    /// entirely for every other tool so the advertised JSON stays compact.
    #[serde(rename = "destructiveHint", skip_serializing_if = "Option::is_none")]
    destructive_hint: Option<bool>,
    #[serde(rename = "idempotentHint")]
    idempotent_hint: bool,
    #[serde(rename = "openWorldHint")]
    open_world_hint: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct ToolCallContent {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct ToolCallResult {
    content: Vec<ToolCallContent>,
    #[serde(rename = "structuredContent")]
    structured_content: Value,
    #[serde(rename = "isError")]
    is_error: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
    capabilities: Value,
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
    instructions: &'static str,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct ServerInfo {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolEra {
    Legacy,
    Modern,
}

#[derive(Debug, Clone)]
struct ProtocolContext {
    era: ProtocolEra,
    agent_id: String,
}

impl ProtocolContext {
    fn is_modern(&self) -> bool {
        self.era == ProtocolEra::Modern
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolKind {
    SafetyTimeline,
    SafetyEventDetails,
    FleetRadar,
    RepoBrief,
    RepoScope,
    RepoStatus,
    RepoRefs,
    RepoBranchStack,
    RepoConflictPreflight,
    ConflictRead,
    RepoReflog,
    RepoHistory,
    CommitDetails,
    WorktreeChanges,
    WorktreeList,
    SubmoduleStatus,
    DiffText,
    DiffSemantic,
    DiffSemanticFallbacks,
    FluxLatestRestorePoint,
    FluxRestorePoints,
    FluxRestorePointDetails,
    /// Read-only status check for a previously proposed operation
    /// (PLAYBOOK §10.6). Talks to the gateway handshake bridge, not to
    /// local git; requires only `previewId`.
    OperationStatus,
    // Write-with-UI-handshake operations (PLAYBOOK §10, Phase 3).
    // These are NOT read-only — they request a preview the user must approve
    // inside FluxGit. The sidecar never performs the write itself. When the
    // FluxGit desktop app is running and FLUXGIT_MCP_HANDSHAKE_ADDR is set,
    // calls dispatch through the HTTP handshake bridge (preview -> approval ->
    // result); otherwise they return `write_handshake_pending` (code 10003).
    OperationPreviewMerge,
    OperationPreviewRebase,
    OperationPreviewDiscard,
    OperationPreviewReset,
    OperationPreviewPatch,
    OperationPreviewPlan,
    OperationPreviewWorktree,
    OperationPreviewCommit,
    OperationPreviewPush,
    OperationPreviewBranch,
    /// Write-adjacent: withdraws one of THIS agent's still-pending proposals
    /// by `previewId`. Never touches the repository and can only cancel
    /// proposals created by the same agent, so it needs no policy gating.
    OperationCancel,
}

impl ToolKind {
    fn as_str(self) -> &'static str {
        match self {
            ToolKind::SafetyTimeline => "safety.timeline",
            ToolKind::SafetyEventDetails => "safety.eventDetails",
            ToolKind::FleetRadar => "fleet.radar",
            ToolKind::RepoBrief => "repo.brief",
            ToolKind::RepoScope => "repo.scope",
            ToolKind::RepoStatus => "repo.status",
            ToolKind::RepoRefs => "repo.refs",
            ToolKind::RepoBranchStack => "repo.branchStack",
            ToolKind::RepoConflictPreflight => "repo.conflictPreflight",
            ToolKind::ConflictRead => "conflict.read",
            ToolKind::RepoReflog => "repo.reflog",
            ToolKind::RepoHistory => "repo.history",
            ToolKind::CommitDetails => "commit.details",
            ToolKind::WorktreeChanges => "worktree.changes",
            ToolKind::WorktreeList => "worktree.list",
            ToolKind::SubmoduleStatus => "submodule.status",
            ToolKind::DiffText => "diff.text",
            ToolKind::DiffSemantic => "diff.semantic",
            ToolKind::DiffSemanticFallbacks => "diff.semanticFallbacks",
            ToolKind::FluxLatestRestorePoint => "flux.latestRestorePoint",
            ToolKind::FluxRestorePoints => "flux.restorePoints",
            ToolKind::FluxRestorePointDetails => "flux.restorePointDetails",
            ToolKind::OperationStatus => "operation.status",
            ToolKind::OperationCancel => "operation.cancel",
            ToolKind::OperationPreviewMerge => "operation.preview.merge",
            ToolKind::OperationPreviewRebase => "operation.preview.rebase",
            ToolKind::OperationPreviewDiscard => "operation.preview.discard",
            ToolKind::OperationPreviewReset => "operation.preview.reset",
            ToolKind::OperationPreviewPatch => "operation.preview.patch",
            ToolKind::OperationPreviewPlan => "operation.preview.plan",
            ToolKind::OperationPreviewWorktree => "operation.preview.worktree",
            ToolKind::OperationPreviewCommit => "operation.preview.commit",
            ToolKind::OperationPreviewPush => "operation.preview.push",
            ToolKind::OperationPreviewBranch => "operation.preview.branch",
        }
    }
}

/// Tools that propose a write through the FluxGit UI handshake (PLAYBOOK §10).
/// They are not read-only and they never execute locally. With the FluxGit
/// desktop app running (FLUXGIT_MCP_HANDSHAKE_ADDR set), each call dispatches
/// to the app: FluxGit opens a preview and the sidecar returns its stable id
/// immediately (or a synchronous terminal result). The agent follows pending
/// work with `operation.status`. Without the app these tools return
/// `write_handshake_pending` (code 10003) with agent guidance.
const WRITE_HANDSHAKE_TOOL_KINDS: &[ToolKind] = &[
    ToolKind::OperationPreviewMerge,
    ToolKind::OperationPreviewRebase,
    ToolKind::OperationPreviewDiscard,
    ToolKind::OperationPreviewReset,
    ToolKind::OperationPreviewPatch,
    ToolKind::OperationPreviewPlan,
    ToolKind::OperationPreviewWorktree,
    ToolKind::OperationPreviewCommit,
    ToolKind::OperationPreviewPush,
    ToolKind::OperationPreviewBranch,
    // operation.cancel is write-adjacent (it mutates handshake state, never
    // the repository). It is short-circuited in handle_tools_call before the
    // generic preview dispatch runs.
    ToolKind::OperationCancel,
];

fn is_write_handshake(kind: ToolKind) -> bool {
    WRITE_HANDSHAKE_TOOL_KINDS.contains(&kind)
}

const READ_ONLY_TOOL_KINDS: &[ToolKind] = &[
    // repo.brief is intentionally first: it is the recommended first call of an
    // agent session and hosts that scan tools in order should see it up front.
    ToolKind::RepoBrief,
    ToolKind::RepoScope,
    ToolKind::SafetyTimeline,
    ToolKind::SafetyEventDetails,
    ToolKind::FleetRadar,
    ToolKind::RepoStatus,
    ToolKind::RepoRefs,
    ToolKind::RepoBranchStack,
    ToolKind::RepoConflictPreflight,
    ToolKind::ConflictRead,
    ToolKind::RepoReflog,
    ToolKind::RepoHistory,
    ToolKind::CommitDetails,
    ToolKind::WorktreeChanges,
    ToolKind::WorktreeList,
    ToolKind::SubmoduleStatus,
    ToolKind::DiffText,
    ToolKind::DiffSemantic,
    ToolKind::DiffSemanticFallbacks,
    ToolKind::FluxLatestRestorePoint,
    ToolKind::FluxRestorePoints,
    ToolKind::FluxRestorePointDetails,
    // operation.status is read-only: it inspects the lifecycle of an existing
    // proposal through the gateway handshake bridge and mutates nothing.
    ToolKind::OperationStatus,
];

/// Tools that strictly require a configured FluxGit gateway to produce meaningful payloads.
/// This is the boundary that drives the "free shell vs FluxGit-powered" business model
/// described in `product/mcp/PLAYBOOK.md` §2.
///
/// Three tiers exist:
/// - Free-shell (🟢): served from local `git`, do not appear here. Examples:
///   `repo.status`, `repo.refs`, `repo.history`, `commit.details`, `diff.text`, etc.
/// - Hybrid (🟢/🔵): work locally with limited signals, FluxGit enriches when wired.
///   `fleet.radar`, `diff.semantic`, `diff.semanticFallbacks`, `repo.conflictPreflight`.
///   Not in this list — they degrade gracefully via documented fallback semantics.
/// - Strict FluxGit-required (🔵): conceptually meaningless without FluxGit.
///   Listed here. Return `gateway_not_configured` when the gateway is not set,
///   even if a `repoPath` is supplied, because synthesizing a fake answer from
///   local refs would mislead the agent and undermine the safety guarantees the
///   FluxGit-app provides (restore points, audit-grade safety timeline).
fn is_fluxgit_required(kind: ToolKind) -> bool {
    matches!(
        kind,
        ToolKind::SafetyTimeline
            | ToolKind::SafetyEventDetails
            | ToolKind::FluxLatestRestorePoint
            | ToolKind::FluxRestorePoints
            | ToolKind::FluxRestorePointDetails,
    )
}

impl McpSidecar {
    pub fn from_env() -> Result<Self, AuditLedgerError> {
        let gateway_state = if resolve_handshake_addr().is_some() {
            GatewayState::Configured
        } else {
            GatewayState::NotConfigured
        };

        Ok(Self {
            gateway_state,
            audit_ledger: AuditLedger::from_env()?,
            client_id: Default::default(),
        })
    }

    pub fn new_for_tests(gateway_configured: bool) -> Self {
        Self {
            gateway_state: if gateway_configured {
                GatewayState::Configured
            } else {
                GatewayState::NotConfigured
            },
            audit_ledger: None,
            client_id: Default::default(),
        }
    }

    pub fn new_for_tests_with_audit(gateway_configured: bool, audit_log: PathBuf) -> Self {
        Self {
            gateway_state: if gateway_configured {
                GatewayState::Configured
            } else {
                GatewayState::NotConfigured
            },
            audit_ledger: Some(
                AuditLedger::new(audit_log, None).expect("valid test audit ledger configuration"),
            ),
            client_id: Default::default(),
        }
    }

    /// Test-only constructor for audit + signing. Lets unit tests inject an
    /// in-memory keypair so we don't have to touch disk or shell out PEM.
    pub fn new_for_tests_with_signed_audit(
        gateway_configured: bool,
        audit_log: PathBuf,
        signer: AuditSigner,
    ) -> Self {
        Self {
            gateway_state: if gateway_configured {
                GatewayState::Configured
            } else {
                GatewayState::NotConfigured
            },
            audit_ledger: Some(
                AuditLedger::new(audit_log, Some(signer))
                    .expect("valid signed test audit ledger configuration"),
            ),
            client_id: Default::default(),
        }
    }

    pub fn run_stdio(&self) -> io::Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut input = io::BufReader::new(stdin.lock());
        let mut output = stdout.lock();

        while let Some(frame) = read_frame(&mut input)? {
            let response = self.handle_frame(&frame);
            if let Some(response) = response {
                // MCP stdio is newline-delimited JSON-RPC. We still accept the
                // pre-standard Content-Length input used by older FluxGit
                // builds, but every response is emitted on the standard wire.
                write_frame(&mut output, &response)?;
            }
        }

        output.flush()?;
        Ok(())
    }

    /// The agent id sent to the gateway on every dispatch.
    ///
    /// Falls back to the old constant when a client did not identify itself, so
    /// an existing `external-mcp-sidecar` policy rule keeps working rather than
    /// silently ceasing to match.
    fn agent_id(&self) -> String {
        self.client_id
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .unwrap_or_else(|| "external-mcp-sidecar".to_string())
    }

    pub fn handle_frame(&self, frame: &[u8]) -> Option<Vec<u8>> {
        let parsed: Result<Value, _> = serde_json::from_slice(frame);
        let value = match parsed {
            Ok(value) => value,
            Err(err) => {
                return Some(serialize_response(&JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: "Parse error".into(),
                        data: Some(json!({ "details": err.to_string() })),
                    }),
                }));
            }
        };

        self.handle_value(value)
            .map(|response| serialize_response(&response))
    }

    fn handle_value(&self, value: Value) -> Option<JsonRpcResponse> {
        if value.is_array() {
            return Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: "Batch requests are not supported".into(),
                    data: None,
                }),
            });
        }

        let request_id = value.get("id").cloned();
        let has_request_id = value
            .as_object()
            .is_some_and(|object| object.contains_key("id"));

        let request: JsonRpcRequest = match serde_json::from_value(value) {
            Ok(request) => request,
            Err(err) => {
                return Some(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32600,
                        message: "Invalid request".into(),
                        data: Some(json!({ "details": err.to_string() })),
                    }),
                });
            }
        };

        if request.jsonrpc != "2.0" {
            return Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id.unwrap_or(Value::Null),
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: "Invalid request".into(),
                    data: Some(json!({ "details": "jsonrpc must be \"2.0\"" })),
                }),
            });
        }

        if has_request_id && !request_id.as_ref().is_some_and(valid_request_id) {
            return Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: "Invalid request".into(),
                    data: Some(json!({
                        "details": format!(
                            "id must be an integer or a string no longer than {MCP_MAX_REQUEST_ID_BYTES} bytes"
                        )
                    })),
                }),
            });
        }

        // JSON-RPC notifications never receive a response. MCP request methods
        // require an id, and intentionally are not executed when sent as a
        // notification so a host cannot create a write proposal it cannot track.
        if !has_request_id {
            return None;
        }

        let id = request.id.unwrap_or(Value::Null);
        let response = match request.method.as_str() {
            "initialize" => {
                if let Some(name) = client_id_from_info(request.params.get("clientInfo")) {
                    if let Ok(mut slot) = self.client_id.lock() {
                        *slot = Some(name);
                    }
                }
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!(InitializeResult::new())),
                    error: None,
                }
            }
            method => {
                let context = match self.protocol_context(&request.params, method) {
                    Ok(context) => context,
                    Err(error) => {
                        return Some(JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: None,
                            error: Some(error),
                        });
                    }
                };

                match method {
                    "server/discover" => JsonRpcResponse {
                        jsonrpc: "2.0",
                        id,
                        result: Some(discover_result()),
                        error: None,
                    },
                    "ping" => JsonRpcResponse {
                        jsonrpc: "2.0",
                        id,
                        result: Some(protocol_result(json!({}), &context, false)),
                        error: None,
                    },
                    "tools/list" => {
                        if let Err(error) = validate_tools_list_cursor(&request.params) {
                            JsonRpcResponse {
                                jsonrpc: "2.0",
                                id,
                                result: None,
                                error: Some(error),
                            }
                        } else {
                            let result = json!({ "tools": all_advertised_tools() });
                            JsonRpcResponse {
                                jsonrpc: "2.0",
                                id,
                                result: Some(protocol_result(result, &context, true)),
                                error: None,
                            }
                        }
                    }
                    "tools/call" => {
                        let audit_context =
                            McpAuditContext::from_params(&request.params, &context.agent_id);
                        match self.handle_tools_call(request.params, &context.agent_id) {
                            Ok(result) => {
                                self.record_tool_audit(&audit_context, &result);
                                JsonRpcResponse {
                                    jsonrpc: "2.0",
                                    id,
                                    result: Some(protocol_result(json!(result), &context, false)),
                                    error: None,
                                }
                            }
                            Err(error) => {
                                self.record_tool_error_audit(&audit_context, &error);
                                JsonRpcResponse {
                                    jsonrpc: "2.0",
                                    id,
                                    result: None,
                                    error: Some(error),
                                }
                            }
                        }
                    }
                    _ => JsonRpcResponse {
                        jsonrpc: "2.0",
                        id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32601,
                            message: "Method not found".into(),
                            data: Some(json!({ "method": request.method })),
                        }),
                    },
                }
            }
        };

        Some(response)
    }

    fn protocol_context(
        &self,
        params: &Value,
        method: &str,
    ) -> Result<ProtocolContext, JsonRpcError> {
        let meta = params.get("_meta").and_then(Value::as_object);
        let version = meta.and_then(|meta| meta.get("io.modelcontextprotocol/protocolVersion"));

        let Some(version) = version else {
            if method == "server/discover" {
                return Err(invalid_params_error(
                    "server/discover requires _meta.io.modelcontextprotocol/protocolVersion",
                ));
            }
            return Ok(ProtocolContext {
                era: ProtocolEra::Legacy,
                agent_id: self.agent_id(),
            });
        };

        let requested = version.as_str().ok_or_else(|| {
            invalid_params_error("_meta.io.modelcontextprotocol/protocolVersion must be a string")
        })?;
        if requested != LATEST_PROTOCOL_VERSION {
            return Err(unsupported_protocol_version_error(requested));
        }

        let capabilities =
            meta.and_then(|meta| meta.get("io.modelcontextprotocol/clientCapabilities"));
        if !capabilities.is_some_and(Value::is_object) {
            return Err(invalid_params_error(
                "modern requests require _meta.io.modelcontextprotocol/clientCapabilities as an object",
            ));
        }

        let client_info = meta.and_then(|meta| meta.get("io.modelcontextprotocol/clientInfo"));
        if let Some(client_info) = client_info {
            let valid = client_info.as_object().is_some_and(|client_info| {
                ["name", "version"].iter().all(|field| {
                    client_info
                        .get(*field)
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty())
                })
            });
            if !valid {
                return Err(invalid_params_error(
                    "_meta.io.modelcontextprotocol/clientInfo must contain non-empty name and version strings",
                ));
            }
        }
        Ok(ProtocolContext {
            era: ProtocolEra::Modern,
            // clientInfo is self-reported attribution, never authentication.
            agent_id: client_id_from_info(client_info)
                .unwrap_or_else(|| "external-mcp-sidecar".to_string()),
        })
    }

    fn handle_tools_call(
        &self,
        params: Value,
        agent_id: &str,
    ) -> Result<ToolCallResult, JsonRpcError> {
        let object = params.as_object().ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "Invalid params".into(),
            data: Some(json!({ "details": "tools/call expects an object" })),
        })?;

        let tool_name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Invalid params".into(),
                data: Some(json!({ "details": "missing tool name" })),
            })?;

        let kind = ToolKind::from_name(tool_name).ok_or_else(|| JsonRpcError {
            code: -32602,
            message: format!("Unknown tool '{tool_name}'"),
            data: Some(json!({
                "tool": tool_name,
                "reason": "This server exposes read-only inspection tools plus operation.preview.* write proposals that require human approval inside FluxGit. The requested name matches neither surface.",
                "readOnlyTools": read_only_tool_names(),
                "writeProposalTools": write_handshake_tool_names(),
            })),
        })?;

        let raw_arguments = object.get("arguments").unwrap_or(&Value::Null);
        // Schema validation and allowed-root enforcement deliberately produce
        // the single argument object used by every dispatcher below.  In
        // particular, an allowed symlink/junction alias is replaced with its
        // canonical target before the alias can be retargeted to escape the
        // configured roots (or before a raw spelling can reappear in a gateway
        // proposal, semantic request, fleet scan, or local Git invocation).
        let validated_arguments = validate_and_canonicalize_tool_arguments(kind, raw_arguments)?;
        let arguments = &validated_arguments;

        // operation.status / operation.cancel talk directly to the gateway
        // handshake bridge (they take only a previewId, no repoPath), so they
        // are short-circuited before every other dispatch path — including the
        // generic write-handshake block below, which would otherwise try to
        // POST a preview for operation.cancel.
        if kind == ToolKind::OperationStatus {
            return operation_status_tool_call(arguments);
        }
        if kind == ToolKind::OperationCancel {
            return operation_cancel_tool_call(agent_id, arguments);
        }

        // Write-with-UI-handshake tools (PLAYBOOK §10, §14.2, §14.7):
        // All ten `operation.preview.*` tools dispatch through the gateway HTTP
        // bridge when the handshake address is configured. Resolution order per
        // playbook §14.2:
        //   1. FLUXGIT_MCP_HANDSHAKE_ADDR (canonical for the handshake server)
        //   2. FLUXGIT_GATEWAY_ADDR (fallback for backward compatibility)
        // When the env is unset or the dispatch POST fails we
        // fall through to the standard `write_handshake_pending_error` (code 10003)
        // so the agent gets the existing, well-known error contract.
        if is_write_handshake(kind) {
            if let Some(addr) = resolve_handshake_addr() {
                let dispatched = match kind {
                    ToolKind::OperationPreviewMerge => {
                        dispatch_operation_preview_merge(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewRebase => {
                        dispatch_operation_preview_rebase(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewDiscard => {
                        dispatch_operation_preview_discard(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewReset => {
                        dispatch_operation_preview_reset(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewPatch => {
                        dispatch_operation_preview_patch(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewPlan => {
                        dispatch_operation_preview_plan(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewWorktree => {
                        dispatch_operation_preview_worktree(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewCommit => {
                        dispatch_operation_preview_commit(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewPush => {
                        dispatch_operation_preview_push(&addr, agent_id, arguments)
                    }
                    ToolKind::OperationPreviewBranch => {
                        dispatch_operation_preview_branch(&addr, agent_id, arguments)
                    }
                    _ => None,
                };
                if let Some(result) = dispatched {
                    return Ok(result);
                }
            }
            // Fall through to the standard write_handshake_pending error when the
            // gateway is unset or unreachable.
        }
        if is_write_handshake(kind) {
            let error = write_handshake_pending_error(kind.as_str());
            return Ok(text_tool_result(
                json!({
                        "error": error,
                        "tool": kind.as_str(),
                        "readOnly": false,
                        "tier": "fluxgit-write-handshake",
                }),
                true,
            ));
        }

        // Enforce the free-shell vs FluxGit-powered boundary (PLAYBOOK §2).
        // Tools that require FluxGit must error out when the gateway is not configured,
        // even if a repoPath was supplied: synthesizing them from local git alone would
        // produce misleading "FluxGit-powered" results and undermine the business model.
        if is_fluxgit_required(kind) && matches!(self.gateway_state, GatewayState::NotConfigured) {
            let error = gateway_not_configured_error(kind.as_str());
            return Ok(text_tool_result(
                json!({
                        "error": error,
                        "tool": kind.as_str(),
                        "readOnly": true,
                        "tier": "fluxgit",
                }),
                true,
            ));
        }

        if kind == ToolKind::FleetRadar {
            return Ok(render_fleet_radar_tool_result(arguments));
        }

        // Hybrid semantic tier (PLAYBOOK §4): when the FluxGit gateway is
        // reachable — the same handshake-address resolution the write tools
        // use (FLUXGIT_MCP_HANDSHAKE_ADDR, then FLUXGIT_GATEWAY_ADDR) — and
        // the repository is registered in FluxGit, diff.semantic and
        // diff.semanticFallbacks are served from the real diff-engine through
        // the gateway's read-only bridge. ANY failure along the way (env
        // unset, gateway unreachable, repo not registered, HTTP or parse
        // error) falls through to the exact same honest local fallback as
        // before: supported:false plus textDiffArguments, never a synthetic
        // "semantic" answer.
        if matches!(
            kind,
            ToolKind::DiffSemantic | ToolKind::DiffSemanticFallbacks
        ) {
            if let (Some(addr), Some(repo_path)) = (
                resolve_handshake_addr(),
                repo_path_from_arguments(arguments),
            ) {
                if let Some(payload) =
                    semantic_gateway_tool_payload(kind, &addr, &repo_path, arguments)
                {
                    return Ok(text_tool_result(
                        json!({
                            "tool": kind.as_str(),
                            "readOnly": true,
                            "source": "fluxgit-gateway",
                            "repoPath": repo_path,
                            "data": payload,
                        }),
                        false,
                    ));
                }
            }
        }

        if let Some(repo_path) = repo_path_from_arguments(arguments) {
            return Ok(render_local_tool_result(kind, arguments, &repo_path));
        }

        let error = match self.gateway_state {
            GatewayState::NotConfigured => gateway_not_configured_error(kind.as_str()),
            GatewayState::Configured => gateway_unavailable_error(kind.as_str()),
        };

        Ok(text_tool_result(
            json!({
                    "error": error,
                    "tool": kind.as_str(),
                    "readOnly": true,
            }),
            true,
        ))
    }

    fn record_tool_audit(&self, context: &McpAuditContext, result: &ToolCallResult) {
        let labels = context.audit_labels();
        let result_label = if result.is_error { "error" } else { "success" };
        let noun = match labels.event_type {
            "write_proposal" => "write-proposal",
            "proposal_cancel" => "proposal-cancel",
            _ => "read-only",
        };
        let summary = if result.is_error {
            format!(
                "MCP {noun} tool {} returned a structured error.",
                context.tool
            )
        } else {
            format!("MCP {noun} tool {} completed.", context.tool)
        };
        self.append_audit_event(json!({
            "timestamp": now_ms(),
            "tool": context.tool,
            "repo_scope": context.repo_scope,
            "args_fingerprint": context.args_fingerprint,
            "risk": labels.risk,
            "approval": labels.approval,
            "result": result_label,
            "event_type": labels.event_type,
            "session_id": context.agent_id,
            "duration_ms": context.duration_ms(),
            "summary": summary,
            "readOnly": labels.read_only,
            "sidecarReadOnly": true,
        }));
    }

    fn record_tool_error_audit(&self, context: &McpAuditContext, error: &JsonRpcError) {
        let labels = context.audit_labels();
        self.append_audit_event(json!({
            "timestamp": now_ms(),
            "tool": context.tool,
            "repo_scope": context.repo_scope,
            "args_fingerprint": context.args_fingerprint,
            "risk": labels.risk,
            "approval": "denied",
            "result": "blocked",
            "event_type": "write_block",
            "session_id": context.agent_id,
            "duration_ms": context.duration_ms(),
            "summary": format!("MCP tool {} was blocked: {}", context.tool, error.message),
            "readOnly": labels.read_only,
            "sidecarReadOnly": true,
        }));
    }

    fn append_audit_event(&self, event: Value) {
        let Some(ledger) = &self.audit_ledger else {
            return;
        };
        if let Err(error) = ledger.append(event) {
            eprintln!(
                "fluxgit-mcp-sidecar: cannot append audit log {}: {error}",
                ledger.path().display()
            );
        }
    }
}

fn reject_unsafe_audit_path(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata_is_reparse_point(&metadata) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "audit log must not be a symlink or reparse point",
                ));
            }
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "audit log path must be a regular file",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn secure_audit_directory(path: &Path, newly_created: bool) -> io::Result<()> {
    validate_no_reparse_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit parent must be a directory",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if newly_created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let mode = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("audit directory permissions {mode:03o} are not private (expected 700)"),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = newly_created;
    Ok(())
}

fn validate_no_reparse_ancestors(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata_is_reparse_point(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "audit directory component {} is a symlink or reparse point",
                    ancestor.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(any(unix, windows)))]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn configure_secure_audit_open(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse point itself rather than following it if the path is
        // swapped between the metadata check and CreateFileW.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

fn secure_audit_file(_path: &Path, file: &File) -> io::Result<()> {
    validate_regular_unlinked_file(file, "audit log")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn validate_regular_unlinked_file(file: &File, label: &str) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("opened {label} is not a regular non-reparse file"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} must not be hard-linked"),
            ));
        }
    }
    #[cfg(windows)]
    {
        let (_, _, links) = windows_file_identity(file)?;
        if links != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} must not be hard-linked"),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_opened_path(path: &Path, file: &File) -> Result<(), AuditLedgerError> {
    use std::os::unix::fs::MetadataExt;
    reject_unsafe_audit_path(path)?;
    let named = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    if named.dev() != opened.dev() || named.ino() != opened.ino() {
        return Err(AuditLedgerError::Configuration(
            "audit path changed during secure open".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> io::Result<(u32, u64, u32)> {
    use std::mem::zeroed;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let success =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64;
    Ok((
        information.dwVolumeSerialNumber,
        index,
        information.nNumberOfLinks,
    ))
}

#[cfg(windows)]
fn validate_opened_path(path: &Path, file: &File) -> Result<(), AuditLedgerError> {
    reject_unsafe_audit_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_audit_open(&mut options);
    let named = options.open(path)?;
    validate_regular_unlinked_file(&named, "audit path")?;
    if windows_file_identity(file)? != windows_file_identity(&named)? {
        return Err(AuditLedgerError::Configuration(
            "audit path changed during secure open".into(),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_opened_path(path: &Path, _file: &File) -> Result<(), AuditLedgerError> {
    reject_unsafe_audit_path(path)?;
    Ok(())
}

fn read_secure_signing_key(path: &Path) -> io::Result<String> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signing key path is empty",
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    validate_no_reparse_ancestors(parent)?;
    reject_unsafe_audit_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_secure_audit_open(&mut options);
    let file = options.open(path)?;
    validate_regular_unlinked_file(&file, "audit signing key")?;
    validate_opened_path(path, &file)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
    let metadata = file.metadata()?;
    if metadata.len() == 0 || metadata.len() > AUDIT_MAX_SIGNING_KEY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("audit signing key must contain 1 to {AUDIT_MAX_SIGNING_KEY_BYTES} bytes"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("audit signing key permissions {mode:03o} are not private"),
            ));
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(AUDIT_MAX_SIGNING_KEY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn valid_request_id(id: &Value) -> bool {
    id.as_str()
        .is_some_and(|value| value.len() <= MCP_MAX_REQUEST_ID_BYTES)
        || id
            .as_number()
            .is_some_and(|number| number.is_i64() || number.is_u64())
}

/// tools/list is intentionally a single complete page. Silently accepting a
/// continuation token would make a host believe it had resumed pagination
/// while returning the first page again, which can duplicate tools or loop.
fn validate_tools_list_cursor(params: &Value) -> Result<(), JsonRpcError> {
    match params.get("cursor") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(cursor)) if cursor.is_empty() => Ok(()),
        Some(Value::String(_)) => Err(invalid_params_error(
            "tools/list is a single complete page and does not accept a non-empty cursor",
        )),
        Some(_) => Err(invalid_params_error(
            "tools/list cursor must be a string when provided",
        )),
    }
}

/// Convert self-reported MCP client metadata into a bounded policy/audit label.
/// This is attribution only: neither the sidecar nor gateway treats it as an
/// authenticated principal.
fn client_id_from_info(info: Option<&Value>) -> Option<String> {
    let raw = info?.as_object()?.get("name")?.as_str()?.trim();
    if raw.is_empty() {
        return None;
    }

    let mut sanitized = String::with_capacity(raw.len().min(128));
    let mut previous_dash = false;
    for character in raw.chars() {
        let mapped = if character.is_ascii_alphanumeric() || "._:-".contains(character) {
            character
        } else {
            '-'
        };
        if mapped == '-' && previous_dash {
            continue;
        }
        if sanitized.len() + mapped.len_utf8() > 128 {
            break;
        }
        sanitized.push(mapped);
        previous_dash = mapped == '-';
    }
    let sanitized = sanitized.trim_matches('-').to_string();
    (!sanitized.is_empty()).then_some(sanitized)
}

fn unsupported_protocol_version_error(requested: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32022,
        message: "Unsupported protocol version".into(),
        data: Some(json!({
            "supported": SUPPORTED_PROTOCOL_VERSIONS,
            "requested": requested,
        })),
    }
}

fn server_info_json() -> Value {
    json!({
        "name": SERVER_NAME,
        "version": SERVER_VERSION,
        "description": "Safe Git intelligence and human-approved FluxGit operations for coding agents.",
        "websiteUrl": "https://fluxgit.com/features/mcp-agent-git/",
    })
}

fn server_capabilities_json() -> Value {
    json!({
        "tools": {
            "listChanged": false,
        }
    })
}

fn discover_result() -> Value {
    json!({
        "resultType": "complete",
        "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
        "capabilities": server_capabilities_json(),
        "instructions": MCP_INSTRUCTIONS,
        "ttlMs": MCP_LIST_CACHE_TTL_MS,
        "cacheScope": "public",
        "_meta": {
            "io.modelcontextprotocol/serverInfo": server_info_json(),
        }
    })
}

/// Add revision-specific wire members without leaking modern-only members into
/// the 2024 handshake contract.
fn protocol_result(mut result: Value, context: &ProtocolContext, cacheable: bool) -> Value {
    let Some(object) = result.as_object_mut() else {
        return result;
    };

    if !context.is_modern() {
        object.remove("structuredContent");
        if let Some(tools) = object.get_mut("tools").and_then(Value::as_array_mut) {
            for tool in tools {
                if let Some(tool) = tool.as_object_mut() {
                    tool.remove("title");
                    tool.remove("outputSchema");
                    tool.remove("annotations");
                }
            }
        }
        return result;
    }

    object.insert("resultType".into(), Value::String("complete".into()));
    if cacheable {
        object.insert("ttlMs".into(), json!(MCP_LIST_CACHE_TTL_MS));
        object.insert("cacheScope".into(), Value::String("public".into()));
    }
    object.insert(
        "_meta".into(),
        json!({
            "io.modelcontextprotocol/serverInfo": server_info_json(),
        }),
    );
    result
}

struct McpAuditContext {
    tool: String,
    repo_scope: String,
    args_fingerprint: Option<String>,
    kind: Option<ToolKind>,
    agent_id: String,
    started_at: Instant,
}

/// Honest audit labels per tool class. Write-proposal tools must never be
/// mislabeled as read-only / no-risk / no-approval: the whole point of the
/// audit chain is that agent intent for a write is distinguishable from a
/// read at a glance.
struct AuditLabels {
    event_type: &'static str,
    read_only: bool,
    approval: &'static str,
    risk: &'static str,
}

impl McpAuditContext {
    fn duration_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn audit_labels(&self) -> AuditLabels {
        match self.kind {
            Some(ToolKind::OperationCancel) => AuditLabels {
                event_type: "proposal_cancel",
                read_only: false,
                approval: "not_required",
                risk: "none",
            },
            Some(kind) if is_write_handshake(kind) => AuditLabels {
                event_type: "write_proposal",
                read_only: false,
                approval: "ui_handshake",
                risk: operation_risk(kind),
            },
            Some(_) => AuditLabels {
                event_type: "tool_call",
                read_only: true,
                approval: "not_required",
                risk: "none",
            },
            // Unknown tool name: blocked before dispatch.
            None => AuditLabels {
                event_type: "write_block",
                read_only: false,
                approval: "denied",
                risk: "none",
            },
        }
    }

    fn from_params(params: &Value, agent_id: &str) -> Self {
        let tool = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let arguments = params.get("arguments").unwrap_or(&Value::Null);
        let repo_scope = arguments
            .get("repoId")
            .and_then(Value::as_str)
            .or_else(|| arguments.get("repo_id").and_then(Value::as_str))
            .map(str::to_string)
            .or_else(|| {
                arguments
                    .get("repoPath")
                    .and_then(Value::as_str)
                    .map(|path| {
                        let fingerprint = arguments_fingerprint(&Value::String(path.to_string()))
                            .unwrap_or_else(|| "sha256:unavailable".into());
                        format!("repoPath:{fingerprint}")
                    })
            })
            .or_else(|| {
                arguments
                    .get("repoPaths")
                    .and_then(Value::as_array)
                    .map(|paths| format!("fleet:{}", paths.len()))
            })
            .or_else(|| {
                arguments
                    .get("repositories")
                    .and_then(Value::as_array)
                    .map(|repos| format!("fleet:{}", repos.len()))
            })
            .unwrap_or_else(|| "unknown".into());
        Self {
            args_fingerprint: arguments_fingerprint(arguments),
            kind: ToolKind::from_name(&tool),
            tool,
            repo_scope,
            agent_id: agent_id.to_string(),
            started_at: Instant::now(),
        }
    }
}

/// Risk label of an approved write proposal, per operation type. Drives the
/// audit `risk` field so operators can filter high-risk agent intent.
fn operation_risk(kind: ToolKind) -> &'static str {
    match kind {
        // Reset and discard can destroy work (hard reset / working-tree loss).
        ToolKind::OperationPreviewReset | ToolKind::OperationPreviewDiscard => "high",
        // History rewrites, working-tree mutations and remote-ref mutations
        // (push), but always behind a restore point and preview. Push with
        // forceWithLease can rewrite the remote branch — the approval card
        // renders it as HIGH risk at runtime; the static per-tool label stays
        // medium because a plain push is a routine remote update.
        ToolKind::OperationPreviewMerge
        | ToolKind::OperationPreviewRebase
        | ToolKind::OperationPreviewPatch
        | ToolKind::OperationPreviewPlan
        | ToolKind::OperationPreviewPush => "medium",
        // Worktree/branch creation and committing staged work are
        // non-destructive (they only add state, never rewrite or delete);
        // cancel touches no repo state.
        ToolKind::OperationPreviewWorktree
        | ToolKind::OperationPreviewCommit
        | ToolKind::OperationPreviewBranch => "low",
        _ => "none",
    }
}

/// SHA-256 fingerprint of the serialized tool arguments. The audit log never
/// stores arguments verbatim; this hash lets identical calls be correlated
/// without leaking paths or ref names. Labeled `sha256:` so verifiers know
/// the algorithm (the pre-hardening `fnv1a64:` label is retired — FNV-1a is
/// not collision-resistant and must not anchor an audit trail).
/// Gateway-scoped idempotency for one explicit logical operation.
///
/// Agents that need retry deduplication supply the optional `idempotencyKey`;
/// the tool scope prevents the same client key from aliasing two operation
/// types. Calls without a key are intentionally distinct, even when their
/// arguments match: repository state can change between two otherwise
/// identical commit/push intentions while terminal gateway records remain in
/// the one-hour retention window.
fn idempotency_key_for(tool: &str, arguments: &Value) -> Option<String> {
    let object = arguments.as_object()?;
    match object.get("idempotencyKey").and_then(Value::as_str) {
        Some(key) => Some(format!("{tool}:client:{key}")),
        None => Some(format!("{tool}:call:{}", uuid::Uuid::new_v4())),
    }
}

fn arguments_fingerprint(arguments: &Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    if arguments.is_null() {
        return None;
    }
    // Object insertion order is not semantic JSON. Canonicalization keeps the
    // privacy-preserving audit correlation stable across serializers.
    let serialized = canonical_json_bytes(arguments);
    let digest = Sha256::digest(&serialized);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    Some(out)
}

fn render_local_tool_result(kind: ToolKind, arguments: &Value, repo_path: &Path) -> ToolCallResult {
    match local_tool_payload(kind, arguments, repo_path) {
        Ok(payload) => text_tool_result(payload, false),
        Err(error) => text_tool_result(
            json!({
                "error": error,
                "tool": kind.as_str(),
                "readOnly": true,
                "source": "local-git",
            }),
            true,
        ),
    }
}

fn render_fleet_radar_tool_result(arguments: &Value) -> ToolCallResult {
    match fleet_radar_payload(arguments) {
        Ok(payload) => text_tool_result(
            json!({
                "tool": ToolKind::FleetRadar.as_str(),
                "readOnly": true,
                "source": "local-git",
                "data": payload,
            }),
            false,
        ),
        Err(error) => text_tool_result(
            json!({
                "error": error,
                "tool": ToolKind::FleetRadar.as_str(),
                "readOnly": true,
                "source": "local-git",
            }),
            true,
        ),
    }
}

fn text_tool_result(payload: Value, is_error: bool) -> ToolCallResult {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|serialize_err| {
        format!(
            "{{\"error\":{{\"code\":\"internal_serialization_error\",\"message\":\"{}\"}}}}",
            serialize_err
        )
    });
    ToolCallResult {
        content: vec![ToolCallContent { kind: "text", text }],
        structured_content: payload,
        is_error,
    }
}

#[derive(Debug, Clone)]
struct FleetRepoInput {
    path: PathBuf,
    repo_id: Option<String>,
    label: Option<String>,
}

fn local_tool_payload(
    kind: ToolKind,
    arguments: &Value,
    repo_path: &Path,
) -> Result<Value, JsonRpcError> {
    ensure_git_repo(repo_path)?;

    let payload = match kind {
        ToolKind::SafetyTimeline => safety_timeline_payload(repo_path, arguments)?,
        ToolKind::SafetyEventDetails => safety_event_details_payload(repo_path, arguments)?,
        ToolKind::FleetRadar => fleet_radar_payload(arguments)?,
        ToolKind::RepoBrief => repo_brief_payload(repo_path, arguments)?,
        ToolKind::RepoScope => repo_scope_payload(repo_path, arguments)?,
        ToolKind::RepoStatus => repo_status_payload(repo_path)?,
        ToolKind::RepoRefs => repo_refs_payload(repo_path)?,
        ToolKind::RepoBranchStack => repo_branch_stack_payload(repo_path, arguments)?,
        ToolKind::RepoConflictPreflight => repo_conflict_preflight_payload(repo_path, arguments)?,
        ToolKind::ConflictRead => conflict_read_payload(repo_path, arguments)?,
        ToolKind::RepoReflog => repo_reflog_payload(repo_path, arguments)?,
        ToolKind::RepoHistory => repo_history_payload(repo_path, arguments)?,
        ToolKind::CommitDetails => commit_details_payload(repo_path, arguments)?,
        ToolKind::WorktreeChanges => worktree_changes_payload(repo_path)?,
        ToolKind::WorktreeList => worktree_list_payload(repo_path)?,
        ToolKind::SubmoduleStatus => submodule_status_payload(repo_path)?,
        ToolKind::DiffText => diff_text_payload(repo_path, arguments)?,
        ToolKind::DiffSemantic => semantic_fallback_payload(repo_path, arguments),
        ToolKind::DiffSemanticFallbacks => semantic_fallbacks_payload(repo_path, arguments),
        ToolKind::FluxLatestRestorePoint => flux_latest_restore_point_payload(repo_path, arguments),
        ToolKind::FluxRestorePoints => flux_restore_points_payload(repo_path, arguments),
        ToolKind::FluxRestorePointDetails => {
            flux_restore_point_details_payload(repo_path, arguments)
        }
        ToolKind::OperationPreviewMerge
        | ToolKind::OperationPreviewRebase
        | ToolKind::OperationPreviewDiscard
        | ToolKind::OperationPreviewReset
        | ToolKind::OperationPreviewPatch
        | ToolKind::OperationPreviewPlan
        | ToolKind::OperationPreviewWorktree
        | ToolKind::OperationPreviewCommit
        | ToolKind::OperationPreviewPush
        | ToolKind::OperationPreviewBranch
        | ToolKind::OperationStatus
        | ToolKind::OperationCancel => {
            // Handshake-bridge tools are short-circuited in handle_tools_call
            // before reaching here. If execution gets here, something rerouted
            // incorrectly.
            unreachable!(
                "operation.* handshake tools must be short-circuited by handle_tools_call before local dispatch"
            );
        }
    };

    Ok(json!({
        "tool": kind.as_str(),
        "readOnly": true,
        "source": "local-git",
        "repoPath": repo_path,
        "data": payload,
    }))
}

fn repo_path_from_arguments(arguments: &Value) -> Option<PathBuf> {
    // Every local/semantic single-repository schema requires `repoPath`.
    // Treating a tool-specific `path` (for example a diff scope or worktree
    // destination) as a repository fallback could bypass the canonicalized
    // allowed-root field if a future schema changed, so no aliases are
    // accepted here.
    arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .map(PathBuf::from)
}

fn safety_timeline_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 200) as usize;
    let reflog_limit = arguments
        .get("reflogLimit")
        .and_then(Value::as_u64)
        .unwrap_or(12)
        .clamp(1, 100);
    let include_reflog = arguments
        .get("includeReflog")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let include_restore_points = arguments
        .get("includeRestorePoints")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let repo_label = repo_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repository");
    let mut events = Vec::new();

    if include_restore_points {
        for restore_point in read_flux_restore_points(repo_path, arguments) {
            let metadata = restore_point.get("metadata").unwrap_or(&Value::Null);
            let operation = restore_point
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("history operation");
            let created_at = metadata
                .get("createdAt")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let restore_event_id = format!(
                "restore:{}:{}",
                restore_point
                    .get("repoId")
                    .and_then(Value::as_str)
                    .unwrap_or("repo"),
                created_at
            );

            events.push(json!({
                "id": restore_event_id,
                "repoLabel": repo_label,
                "source": "restore_point",
                "kind": "restore_created",
                "severity": "warning",
                "title": format!("Flux restore point for {operation}"),
                "summary": "FluxGit recorded before/after state for a risky history operation. Undo/redo remains app-approved and is not exposed through MCP.",
                "occurredAtUnix": created_at,
                "headBefore": restore_point.get("before").cloned().unwrap_or(Value::Null),
                "headAfter": restore_point.get("after").cloned().unwrap_or(Value::Null),
                "restorePoint": restore_point,
                "actions": ["openRestorePoint", "compareBeforeAfter", "copyRedactedSummary"],
                "approvalRequired": true,
                "networkFetchPerformed": false,
            }));
        }
    }

    if include_reflog {
        let reflog_args = json!({
            "refName": arguments
                .get("refName")
                .or_else(|| arguments.get("ref"))
                .and_then(Value::as_str)
                .unwrap_or("HEAD"),
            "limit": reflog_limit,
        });
        let reflog = repo_reflog_payload(repo_path, &reflog_args)?;
        if let Some(entries) = reflog.get("entries").and_then(Value::as_array) {
            for entry in entries {
                let selector = entry
                    .get("selector")
                    .and_then(Value::as_str)
                    .unwrap_or("HEAD@{?}");
                let message = entry
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Reflog movement");
                let timestamp = entry
                    .get("timestamp")
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                events.push(json!({
                    "id": format!("reflog:{selector}"),
                    "repoLabel": repo_label,
                    "source": "reflog",
                    "kind": "ref_move",
                    "severity": safety_severity_for_reflog_message(message),
                    "title": format!("Reflog movement {selector}"),
                    "summary": message,
                    "occurredAtUnix": timestamp,
                    "headBefore": entry.get("oldCommit").cloned().unwrap_or(Value::Null),
                    "headAfter": entry.get("newCommit").cloned().unwrap_or(Value::Null),
                    "reflogSelector": selector,
                    "canCompare": entry.get("canCompare").cloned().unwrap_or(Value::Bool(false)),
                    "actions": ["openReflogEntry", "compareBeforeAfter", "createRescueBranch", "copyRedactedSummary"],
                    "approvalRequired": true,
                    "networkFetchPerformed": false,
                }));
            }
        }
    }

    events.sort_by(|a, b| {
        b.get("occurredAtUnix")
            .and_then(Value::as_i64)
            .unwrap_or_default()
            .cmp(
                &a.get("occurredAtUnix")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
            )
    });
    events.truncate(limit);
    let event_count = events.len();

    Ok(json!({
        "events": events,
        "eventCount": event_count,
        "readOnly": true,
        "approvalRequired": true,
        "approvalMessage": "Safety Timeline is read-only over MCP. Recovery actions must open FluxGit approval flows.",
        "networkFetchPerformed": false,
    }))
}

fn safety_event_details_payload(
    repo_path: &Path,
    arguments: &Value,
) -> Result<Value, JsonRpcError> {
    let timeline = safety_timeline_payload(repo_path, arguments)?;
    let event_id = arguments.get("eventId").and_then(Value::as_str);
    let event = timeline
        .get("events")
        .and_then(Value::as_array)
        .and_then(|events| {
            if let Some(event_id) = event_id {
                events
                    .iter()
                    .find(|event| event.get("id").and_then(Value::as_str) == Some(event_id))
                    .cloned()
            } else {
                events.first().cloned()
            }
        });
    let event_found = event.is_some();

    Ok(json!({
        "event": event,
        "eventFound": event_found,
        "readOnly": true,
        "approvalRequired": true,
        "approvalMessage": "Safety event details are explanatory only. Execute recovery through FluxGit UI approval flows.",
    }))
}

fn safety_severity_for_reflog_message(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("reset")
        || lower.contains("rebase")
        || lower.contains("merge")
        || lower.contains("cherry-pick")
        || lower.contains("revert")
    {
        "warning"
    } else {
        "info"
    }
}

fn fleet_radar_payload(arguments: &Value) -> Result<Value, JsonRpcError> {
    let started = now_ms();
    let max_repos = arguments
        .get("maxRepos")
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .clamp(1, 500) as usize;
    let inputs = fleet_repo_inputs_from_arguments(arguments)?;
    let requested_count = inputs.len();
    let entries = inputs
        .into_iter()
        .take(max_repos)
        .map(fleet_radar_entry)
        .collect::<Vec<_>>();
    let failed_count = entries
        .iter()
        .filter(|entry| {
            entry
                .get("error")
                .and_then(Value::as_str)
                .is_some_and(|error| !error.trim().is_empty())
        })
        .count();
    let dirty_count = entries
        .iter()
        .filter(|entry| entry.get("dirty").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let conflict_count = entries
        .iter()
        .filter(|entry| {
            entry
                .get("conflictActive")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    let attention_stack = fleet_attention_stack(&entries);
    let scanned_count = entries.len();

    Ok(json!({
        "entries": entries,
        "attentionStack": attention_stack,
        "requestedCount": requested_count,
        "scannedCount": scanned_count,
        "failedCount": failed_count,
        "dirtyCount": dirty_count,
        "conflictCount": conflict_count,
        "truncatedCount": requested_count.saturating_sub(max_repos),
        "elapsedMs": now_ms().saturating_sub(started),
        "network": {
            "fetchPerformed": false,
            "remoteStateSource": "cached local refs only",
        },
        "guidance": "Fleet Radar is read-only and does not fetch. It prioritizes local changes, conflicts, ahead/behind from cached upstream refs, and unknown repos so agents can tell the user which repositories need attention without touching disk state.",
    }))
}

fn fleet_repo_inputs_from_arguments(
    arguments: &Value,
) -> Result<Vec<FleetRepoInput>, JsonRpcError> {
    let object = arguments
        .as_object()
        .ok_or_else(|| invalid_params_error("fleet.radar expects an arguments object"))?;
    let mut inputs = Vec::new();

    if let Some(repo_path) = object.get("repoPath").and_then(Value::as_str) {
        inputs.push(FleetRepoInput {
            path: PathBuf::from(repo_path),
            repo_id: object
                .get("repoId")
                .and_then(Value::as_str)
                .map(str::to_string),
            label: object
                .get("label")
                .or_else(|| object.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }

    for key in ["repoPaths", "repositories"] {
        let Some(values) = object.get(key).and_then(Value::as_array) else {
            continue;
        };
        for value in values {
            match value {
                Value::String(path) => inputs.push(FleetRepoInput {
                    path: PathBuf::from(path),
                    repo_id: None,
                    label: None,
                }),
                Value::Object(repo) => {
                    let path = repo
                        .get("repoPath")
                        .or_else(|| repo.get("repositoryPath"))
                        .or_else(|| repo.get("root"))
                        .or_else(|| repo.get("path"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            invalid_params_error("fleet repository entry missing repoPath")
                        })?;
                    inputs.push(FleetRepoInput {
                        path: PathBuf::from(path),
                        repo_id: repo
                            .get("repoId")
                            .or_else(|| repo.get("id"))
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        label: repo
                            .get("label")
                            .or_else(|| repo.get("name"))
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    });
                }
                _ => {
                    return Err(invalid_params_error(
                        "fleet repoPaths entries must be strings or objects",
                    ))
                }
            }
        }
    }

    if inputs.is_empty() {
        return Err(invalid_params_error(
            "fleet.radar requires repoPaths, repositories, or repoPath",
        ));
    }

    Ok(inputs)
}

fn fleet_radar_entry(input: FleetRepoInput) -> Value {
    let started = now_ms();
    let repo_path = input.path;
    let label = input.label.unwrap_or_else(|| {
        repo_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("repository")
            .to_string()
    });
    let repo_id = input.repo_id;
    let repo_path_display = repo_path.to_string_lossy().to_string();

    if let Err(error) = ensure_git_repo(&repo_path) {
        return json!({
            "repoId": repo_id,
            "label": label,
            "repoPath": repo_path_display,
            "status": "unknown",
            "priority": 10,
            "summary": "Repository could not be inspected.",
            "dirty": false,
            "changedFiles": 0,
            "ahead": 0,
            "behind": 0,
            "hasUpstream": false,
            "upstream": null,
            "branch": null,
            "head": null,
            "shortHead": null,
            "conflictActive": false,
            "conflictOperation": null,
            "potentialConflictActive": false,
            "potentialConflictCount": 0,
            "potentialConflictTarget": null,
            "potentialConflictPaths": [],
            "lastCommitTimestamp": null,
            "elapsedMs": now_ms().saturating_sub(started),
            "error": error.message,
            "suggestedActions": ["Open the repository in FluxGit to inspect the failure", "Check that the path is a local Git worktree"],
        });
    }

    let status_payload = repo_status_payload(&repo_path).unwrap_or_else(|_| {
        json!({
            "branch": null,
            "ahead": 0,
            "behind": 0,
            "clean": true,
            "changedFiles": 0,
            "entries": [],
        })
    });
    let upstream = run_git(
        &repo_path,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    )
    .ok()
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty());
    let (ahead, behind) = cached_ahead_behind(&repo_path).unwrap_or_else(|| {
        (
            status_payload["ahead"].as_i64().unwrap_or_default(),
            status_payload["behind"].as_i64().unwrap_or_default(),
        )
    });
    let dirty = !status_payload["clean"].as_bool().unwrap_or(true);
    let changed_files = status_payload["changedFiles"].as_u64().unwrap_or_default();
    let conflict_operation = active_conflict_operation(&repo_path);
    let conflict_active = conflict_operation.is_some();
    let potential_conflict_paths =
        predict_upstream_conflict_paths(&repo_path, upstream.as_deref(), ahead, behind);
    let potential_conflict_active = !potential_conflict_paths.is_empty();
    let potential_conflict_count = potential_conflict_paths.len();
    let head = run_git(&repo_path, &["rev-parse", "HEAD"])
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let short_head = run_git(&repo_path, &["rev-parse", "--short", "HEAD"])
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let last_commit_timestamp = run_git(&repo_path, &["log", "-1", "--format=%ct"])
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let branch = status_payload["branch"]
        .as_str()
        .map(str::to_string)
        .filter(|value| !value.is_empty());
    let (status, priority, summary, suggested_actions) = fleet_attention_classification(
        dirty,
        changed_files,
        ahead,
        behind,
        conflict_active,
        potential_conflict_active,
        potential_conflict_count,
        upstream.as_deref(),
        upstream.is_some(),
    );

    json!({
        "repoId": repo_id,
        "label": label,
        "repoPath": repo_path_display,
        "status": status,
        "priority": priority,
        "summary": summary,
        "dirty": dirty,
        "changedFiles": changed_files,
        "ahead": ahead,
        "behind": behind,
        "hasUpstream": upstream.is_some(),
        "upstream": upstream,
        "branch": branch,
        "head": head,
        "shortHead": short_head,
        "conflictActive": conflict_active,
        "conflictOperation": conflict_operation,
        "potentialConflictActive": potential_conflict_active,
        "potentialConflictCount": potential_conflict_count,
        "potentialConflictTarget": if potential_conflict_active { upstream.clone() } else { None },
        "potentialConflictPaths": potential_conflict_paths,
        "lastCommitTimestamp": last_commit_timestamp,
        "elapsedMs": now_ms().saturating_sub(started),
        "error": "",
        "suggestedActions": suggested_actions,
    })
}

fn cached_ahead_behind(repo_path: &Path) -> Option<(i64, i64)> {
    let output = run_git(
        repo_path,
        &["rev-list", "--left-right", "--count", "HEAD...@{u}"],
    )
    .ok()?;
    let mut parts = output.split_whitespace();
    let ahead = parts.next()?.parse::<i64>().ok()?;
    let behind = parts.next()?.parse::<i64>().ok()?;
    Some((ahead, behind))
}

fn predict_upstream_conflict_paths(
    repo_path: &Path,
    upstream: Option<&str>,
    ahead: i64,
    behind: i64,
) -> Vec<String> {
    let Some(upstream) = upstream else {
        return Vec::new();
    };
    if ahead <= 0 || behind <= 0 {
        return Vec::new();
    }

    let Ok(current_oid) = run_git(repo_path, &["rev-parse", "HEAD"]) else {
        return Vec::new();
    };
    let Ok(target_oid) = run_git(repo_path, &["rev-parse", upstream]) else {
        return Vec::new();
    };
    let current_oid = current_oid.trim().to_string();
    let target_oid = target_oid.trim().to_string();
    let Ok(merge_base) = run_git(repo_path, &["merge-base", &current_oid, &target_oid]) else {
        return Vec::new();
    };
    let Ok(merge_tree) = run_git(
        repo_path,
        &["merge-tree", merge_base.trim(), &current_oid, &target_oid],
    ) else {
        return Vec::new();
    };
    conflict_paths_from_merge_tree(&merge_tree)
}

fn active_conflict_operation(repo_path: &Path) -> Option<&'static str> {
    for (marker, label) in [
        ("MERGE_HEAD", "merge"),
        ("REBASE_HEAD", "rebase"),
        ("CHERRY_PICK_HEAD", "cherry-pick"),
        ("REVERT_HEAD", "revert"),
    ] {
        if git_path_exists(repo_path, marker) {
            return Some(label);
        }
    }
    None
}

fn git_path_exists(repo_path: &Path, marker: &str) -> bool {
    let Ok(path) = run_git(repo_path, &["rev-parse", "--git-path", marker]) else {
        return false;
    };
    let path = PathBuf::from(path.trim());
    let resolved = if path.is_absolute() {
        path
    } else {
        repo_path.join(path)
    };
    resolved.exists()
}

// These independent signals deliberately mirror the typed Fleet Radar output;
// grouping them would obscure the classifier's pinned decision table.
#[allow(clippy::too_many_arguments)]
fn fleet_attention_classification(
    dirty: bool,
    changed_files: u64,
    ahead: i64,
    behind: i64,
    conflict_active: bool,
    potential_conflict_active: bool,
    potential_conflict_count: usize,
    potential_conflict_target: Option<&str>,
    has_upstream: bool,
) -> (&'static str, u8, String, Vec<&'static str>) {
    if conflict_active {
        return (
            "conflict",
            100,
            "Repository is paused on a conflict operation.".into(),
            vec![
                "Open FluxGit conflict panel",
                "Resolve every conflicted file",
                "Continue or abort from the app",
            ],
        );
    }
    if potential_conflict_active {
        return (
            "potential_conflict",
            95,
            format!(
                "Read-only preflight predicts {potential_conflict_count} conflicting file{} before merging {}.",
                if potential_conflict_count == 1 { "" } else { "s" },
                potential_conflict_target.unwrap_or("upstream"),
            ),
            vec![
                "Open the repository in FluxGit",
                "Review predicted paths before merge/rebase",
                "Use a guarded merge dialog or Trinity if Git pauses",
            ],
        );
    }
    if ahead > 0 && behind > 0 {
        return (
            "divergent",
            90,
            format!(
                "Local and upstream diverged: {ahead} local commits and {behind} upstream commits."
            ),
            vec![
                "Open sync guide",
                "Review local and remote commits",
                "Choose merge, rebase or push strategy in FluxGit",
            ],
        );
    }
    if dirty {
        return (
            "local_changes",
            80,
            format!("{changed_files} local file changes need review."),
            vec![
                "Open repository",
                "Review staged and unstaged changes",
                "Commit, stash or discard explicitly",
            ],
        );
    }
    if behind > 0 {
        return (
            "behind",
            70,
            format!("Repository is {behind} commits behind cached upstream."),
            vec![
                "Open repository",
                "Review incoming commits",
                "Pull or rebase from FluxGit",
            ],
        );
    }
    if ahead > 0 {
        return (
            "ahead",
            60,
            format!("Repository has {ahead} local commits not pushed."),
            vec![
                "Open repository",
                "Review outgoing commits",
                "Push or create pull request",
            ],
        );
    }
    if !has_upstream {
        return (
            "no_upstream",
            40,
            "Current branch has no upstream configured.".into(),
            vec!["Open branch settings", "Set upstream or publish branch"],
        );
    }
    (
        "clean",
        0,
        "Repository is clean against cached local refs.".into(),
        vec!["No action needed"],
    )
}

fn fleet_attention_stack(entries: &[Value]) -> Vec<Value> {
    let mut items = entries
        .iter()
        .filter(|entry| entry["status"].as_str() != Some("clean"))
        .map(|entry| {
            json!({
                "repoId": entry.get("repoId").cloned().unwrap_or(Value::Null),
                "label": entry.get("label").cloned().unwrap_or(Value::Null),
                "repoPath": entry.get("repoPath").cloned().unwrap_or(Value::Null),
                "status": entry.get("status").cloned().unwrap_or(Value::Null),
                "priority": entry.get("priority").cloned().unwrap_or(Value::Null),
                "summary": entry.get("summary").cloned().unwrap_or(Value::Null),
                "suggestedActions": entry.get("suggestedActions").cloned().unwrap_or(Value::Null),
            })
        })
        .collect::<Vec<_>>();

    items.sort_by(|left, right| {
        let left_priority = left["priority"].as_u64().unwrap_or_default();
        let right_priority = right["priority"].as_u64().unwrap_or_default();
        right_priority.cmp(&left_priority)
    });
    items
}

fn ensure_git_repo(repo_path: &Path) -> Result<(), JsonRpcError> {
    run_git(repo_path, &["rev-parse", "--show-toplevel"]).map(|_| ())
}

/// `repo.scope` — monorepo scoping (AGENT_FIRST_ROADMAP P0). One read-only
/// call answers "what is going on under this subtree": working-tree changes,
/// recent commits, churn and CODEOWNERS owners. Output is capped and flags
/// truncation explicitly (no silent caps).
fn repo_scope_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let scope = arguments
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if scope.is_empty() {
        return Err(JsonRpcError {
            code: -32602,
            message: "path is required".into(),
            data: Some(json!({
                "hint": "Pass a repository-relative subtree, e.g. {\"path\": \"packages/api\"}."
            })),
        });
    }
    let normalized_scope = scope.trim_matches('/');
    if Path::new(normalized_scope).is_absolute()
        || normalized_scope.split('/').any(|part| part == "..")
    {
        return Err(JsonRpcError {
            code: -32602,
            message: "path must be repository-relative without '..'".into(),
            data: Some(json!({ "path": scope })),
        });
    }

    let commit_limit = arguments
        .get("recentCommits")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 20);
    let churn_days = arguments
        .get("churnDays")
        .and_then(Value::as_u64)
        .unwrap_or(90)
        .clamp(1, 365);

    // Working-tree changes restricted to the scope; entries capped at 20.
    let status_output = run_git(
        repo_path,
        &["status", "--porcelain=v1", "--", normalized_scope],
    )?;
    let mut entries: Vec<Value> = Vec::new();
    let mut changed = 0u64;
    for line in status_output.lines().filter(|line| line.len() > 3) {
        changed += 1;
        if entries.len() < 20 {
            entries.push(json!({
                "status": line[..2].trim(),
                "path": line[3..].trim(),
            }));
        }
    }

    let recent_commits: Vec<Value> = run_git_optional(
        repo_path,
        &[
            "log",
            "--pretty=format:%h%x1f%s",
            &format!("-n{commit_limit}"),
            "--",
            normalized_scope,
        ],
    )
    .map(|output| {
        output
            .lines()
            .filter_map(|line| {
                let (sha, subject) = line.split_once('\u{1f}')?;
                Some(json!({ "sha": sha, "subject": subject }))
            })
            .collect()
    })
    .unwrap_or_default();

    let churn = run_git_optional(
        repo_path,
        &[
            "log",
            &format!("--since={churn_days}.days"),
            "--pretty=format:%an",
            "--",
            normalized_scope,
        ],
    )
    .map(|output| {
        let authors: Vec<&str> = output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        let distinct: std::collections::HashSet<&str> = authors.iter().copied().collect();
        json!({
            "days": churn_days,
            "commits": authors.len(),
            "authors": distinct.len(),
        })
    })
    .unwrap_or_else(|| json!({ "days": churn_days, "commits": 0, "authors": 0 }));

    let owners = codeowners_for_scope(repo_path, normalized_scope);

    let mut hints: Vec<String> = Vec::new();
    if changed > 0 {
        hints.push(format!(
            "{changed} path(s) under {normalized_scope} have uncommitted changes; inspect them before proposing operations."
        ));
    }
    if let Some(owners_value) = owners.as_ref() {
        if let Some(list) = owners_value.get("owners").and_then(Value::as_array) {
            if !list.is_empty() {
                let names: Vec<String> = list
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
                hints.push(format!(
                    "Changes under {normalized_scope} are owned by {} per CODEOWNERS; mention them in proposals.",
                    names.join(", "),
                ));
            }
        }
    }
    hints.truncate(3);

    Ok(json!({
        "scope": normalized_scope,
        "workingTree": {
            "changed": changed,
            "entries": entries,
            "truncated": changed as usize > 20,
        },
        "recentCommits": recent_commits,
        "churn": churn,
        "owners": owners,
        "hints": hints,
    }))
}

/// Resolve owners for a scope from CODEOWNERS using simplified, documented
/// semantics: the LAST matching pattern wins (like git's CODEOWNERS), with
/// prefix/glob-lite matching (`*` only at the end of a path segment chain).
/// Returns None when no CODEOWNERS file exists; the field is then null so the
/// agent knows ownership is simply not declared (honest absence, not empty).
fn codeowners_for_scope(repo_path: &Path, scope: &str) -> Option<Value> {
    let candidates = [
        repo_path.join(".github/CODEOWNERS"),
        repo_path.join("CODEOWNERS"),
        repo_path.join("docs/CODEOWNERS"),
    ];
    let (file, content) = candidates.iter().find_map(|candidate| {
        std::fs::read_to_string(candidate)
            .ok()
            .map(|content| (candidate.clone(), content))
    })?;

    let mut matched_pattern: Option<String> = None;
    let mut matched_owners: Vec<String> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pattern) = parts.next() else {
            continue;
        };
        let owners: Vec<String> = parts.map(str::to_string).collect();
        if owners.is_empty() {
            continue;
        }
        let normalized = pattern
            .trim_matches('/')
            .trim_end_matches("/**")
            .trim_end_matches("/*");
        // A pattern matches when it covers the scope or an ancestor of it.
        // A pattern DEEPER than the scope (e.g. `api/handlers` vs scope `api`)
        // must not claim ownership of the whole scope.
        let matches = normalized == "*"
            || scope == normalized
            || scope.starts_with(&format!("{normalized}/"));
        if matches {
            matched_pattern = Some(pattern.to_string());
            matched_owners = owners;
        }
    }

    Some(json!({
        "source": file.strip_prefix(repo_path).unwrap_or(&file).to_string_lossy(),
        "matchedPattern": matched_pattern,
        "owners": matched_owners,
        "matching": "simplified-prefix (last match wins)",
    }))
}

/// `repo.brief` — one-call situational awareness (AGENT_FIRST_ROADMAP P0).
/// Aggregates what an agent would otherwise spend 6-10 git calls on. The payload
/// is deliberately compact: counts and one-liners, not full listings; non-clean
/// submodules are capped with an explicit truncation flag (no silent caps).
fn repo_brief_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let commit_limit = arguments
        .get("recentCommits")
        .and_then(Value::as_u64)
        .unwrap_or(10)
        .clamp(1, 20);

    // Branch / upstream / ahead-behind / working tree summary from one status call.
    let status_output = run_git(repo_path, &["status", "--porcelain=v1", "-b"])?;
    let mut branch: Option<String> = None;
    let mut upstream: Option<String> = None;
    let mut ahead = 0u64;
    let mut behind = 0u64;
    let mut detached = false;
    let (mut staged, mut unstaged, mut untracked, mut conflicted) = (0u64, 0u64, 0u64, 0u64);
    for line in status_output.lines() {
        if let Some(header) = line.strip_prefix("## ") {
            if header.starts_with("HEAD (no branch)") {
                detached = true;
                continue;
            }
            // Fresh repository without commits: `## No commits yet on <branch>`.
            if let Some(name) = header.strip_prefix("No commits yet on ") {
                branch = Some(name.trim().to_string());
                continue;
            }
            let (name_part, counts_part) = match header.split_once(" [") {
                Some((name, counts)) => (name, Some(counts.trim_end_matches(']'))),
                None => (header, None),
            };
            match name_part.split_once("...") {
                Some((local, remote)) => {
                    branch = Some(local.to_string());
                    upstream = Some(remote.to_string());
                }
                None => branch = Some(name_part.to_string()),
            }
            if let Some(counts) = counts_part {
                for part in counts.split(", ") {
                    if let Some(n) = part.strip_prefix("ahead ") {
                        ahead = n.parse().unwrap_or(0);
                    } else if let Some(n) = part.strip_prefix("behind ") {
                        behind = n.parse().unwrap_or(0);
                    }
                }
            }
            continue;
        }
        let mut chars = line.chars();
        let x = chars.next().unwrap_or(' ');
        let y = chars.next().unwrap_or(' ');
        if x == '?' && y == '?' {
            untracked += 1;
            continue;
        }
        if x == 'U' || y == 'U' || (x == 'A' && y == 'A') || (x == 'D' && y == 'D') {
            conflicted += 1;
            continue;
        }
        if x != ' ' {
            staged += 1;
        }
        if y != ' ' {
            unstaged += 1;
        }
    }
    let clean = staged == 0 && unstaged == 0 && untracked == 0 && conflicted == 0;

    let head_sha = run_git_optional(repo_path, &["rev-parse", "--short", "HEAD"])
        .map(|out| out.trim().to_string())
        .filter(|sha| !sha.is_empty());

    // In-progress operation, resolved via the actual git dir so linked worktrees work.
    let operation_in_progress = run_git_optional(repo_path, &["rev-parse", "--git-dir"])
        .map(|out| out.trim().to_string())
        .and_then(|git_dir| {
            let git_dir = if Path::new(&git_dir).is_absolute() {
                PathBuf::from(git_dir)
            } else {
                repo_path.join(git_dir)
            };
            if git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists() {
                Some("rebase")
            } else if git_dir.join("MERGE_HEAD").exists() {
                Some("merge")
            } else if git_dir.join("CHERRY_PICK_HEAD").exists() {
                Some("cherry-pick")
            } else if git_dir.join("REVERT_HEAD").exists() {
                Some("revert")
            } else if git_dir.join("BISECT_LOG").exists() {
                Some("bisect")
            } else {
                None
            }
        });

    let stashes = run_git_optional(repo_path, &["stash", "list", "--format=%H"])
        .map(|out| out.lines().filter(|line| !line.trim().is_empty()).count())
        .unwrap_or(0);

    // Aggregated recursive submodule drift. Only non-clean entries are listed,
    // capped at 10 with an explicit truncation flag.
    let submodules = submodule_status_entries(repo_path)
        .ok()
        .map(|entries| {
            let mut total = 0u64;
            let mut clean_count = 0u64;
            let mut uninitialized = 0u64;
            let mut drifted = 0u64;
            let mut conflicts = 0u64;
            let mut attention = Vec::new();
            for entry in entries {
                total += 1;
                let state = entry["state"]
                    .as_str()
                    .and_then(|state| state.chars().next())
                    .unwrap_or(' ');
                match state {
                    '-' => uninitialized += 1,
                    '+' => drifted += 1,
                    'U' => conflicts += 1,
                    _ => clean_count += 1,
                }
                if state != ' ' && attention.len() < 10 {
                    attention.push(entry);
                }
            }
            let needs_attention = (uninitialized + drifted + conflicts) as usize;
            json!({
                "total": total,
                "clean": clean_count,
                "drifted": drifted,
                "uninitialized": uninitialized,
                "conflicts": conflicts,
                "attention": attention,
                "attentionTruncated": needs_attention > attention.len(),
            })
        })
        .unwrap_or_else(|| {
            json!({
                "total": 0,
                "clean": 0,
                "drifted": 0,
                "uninitialized": 0,
                "conflicts": 0,
                "attention": [],
                "attentionTruncated": false,
            })
        });
    let submodules_needing_attention =
        submodules["total"].as_u64().unwrap_or(0) - submodules["clean"].as_u64().unwrap_or(0);

    let recent_commits: Vec<Value> = run_git_optional(
        repo_path,
        &[
            "log",
            "--pretty=format:%h%x1f%s",
            &format!("-n{commit_limit}"),
        ],
    )
    .map(|output| {
        output
            .lines()
            .filter_map(|line| {
                let (sha, subject) = line.split_once('\u{1f}')?;
                Some(json!({ "sha": sha, "subject": subject }))
            })
            .collect()
    })
    .unwrap_or_default();

    // Conventions: share of recent subjects following a `type(scope): subject`
    // shape (standard conventional-commits types or a repo-specific lowercase
    // prefix), plus the default branch when origin/HEAD is known.
    let conventional_commit_ratio =
        run_git_optional(repo_path, &["log", "--pretty=format:%s", "-n50"]).and_then(|output| {
            let subjects: Vec<&str> = output
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();
            if subjects.is_empty() {
                return None;
            }
            let matches = subjects
                .iter()
                .filter(|subject| subject_is_conventional(subject))
                .count();
            Some((matches as f64 / subjects.len() as f64 * 100.0).round() / 100.0)
        });
    let default_branch = run_git_optional(
        repo_path,
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
    )
    .map(|out| out.trim().trim_start_matches("origin/").to_string())
    .filter(|name| !name.is_empty());

    // Self-guiding hints, ordered by priority, max 3. The agent should follow
    // the first hint before proposing anything.
    let mut hints: Vec<String> = Vec::new();
    if conflicted > 0 {
        hints.push(format!(
            "Working tree has {conflicted} conflicted path(s); resolve them before proposing operations."
        ));
    }
    if let Some(operation) = operation_in_progress {
        hints.push(format!(
            "A {operation} is in progress; finish or abort it before proposing new operations."
        ));
    }
    if detached {
        hints.push(
            "HEAD is detached; create a branch before proposing history changes.".to_string(),
        );
    }
    if behind > 0 && conflicted == 0 {
        hints.push(format!(
            "Branch is {behind} commit(s) behind its upstream; run repo.conflictPreflight before recommending a merge or rebase."
        ));
    }
    if submodules_needing_attention > 0 {
        hints.push(format!(
            "{submodules_needing_attention} submodule(s) need attention; call submodule.status for details."
        ));
    }
    hints.truncate(3);

    Ok(json!({
        "head": {
            "branch": branch,
            "detached": detached,
            "sha": head_sha,
            "upstream": upstream,
            "ahead": ahead,
            "behind": behind,
        },
        "operationInProgress": operation_in_progress,
        "workingTree": {
            "clean": clean,
            "staged": staged,
            "unstaged": unstaged,
            "untracked": untracked,
            "conflicted": conflicted,
        },
        "stashes": stashes,
        "submodules": submodules,
        "recentCommits": recent_commits,
        "conventions": {
            "conventionalCommitRatio": conventional_commit_ratio,
            "defaultBranch": default_branch,
        },
        "hints": hints,
    }))
}

/// Loose conventional-commit shape: a short lowercase type token, optional
/// `(scope)`, optional `!`, then `:`. Detects repo-specific prefixes too.
fn subject_is_conventional(subject: &str) -> bool {
    let Some((prefix, rest)) = subject.split_once(':') else {
        return false;
    };
    if rest.trim().is_empty() {
        return false;
    }
    let prefix = prefix.trim_end_matches('!');
    let kind = match prefix.split_once('(') {
        Some((kind, scope)) if scope.ends_with(')') => kind,
        Some(_) => return false,
        None => prefix,
    };
    !kind.is_empty() && kind.len() <= 12 && kind.chars().all(|c| c.is_ascii_lowercase())
}

fn repo_status_payload(repo_path: &Path) -> Result<Value, JsonRpcError> {
    let output = run_git(repo_path, &["status", "--porcelain=v1", "-b"])?;
    let mut branch = None;
    let mut ahead = 0_i64;
    let mut behind = 0_i64;
    let mut entries = Vec::new();

    for line in output.lines() {
        if let Some(header) = line.strip_prefix("## ") {
            let parsed = parse_status_header(header);
            branch = parsed.0;
            ahead = parsed.1;
            behind = parsed.2;
        } else if !line.is_empty() {
            entries.push(status_entry_json(line));
        }
    }

    Ok(json!({
        "branch": branch,
        "ahead": ahead,
        "behind": behind,
        "clean": entries.is_empty(),
        "changedFiles": entries.len(),
        "entries": entries,
    }))
}

fn repo_refs_payload(repo_path: &Path) -> Result<Value, JsonRpcError> {
    Ok(json!({
        "head": run_git(repo_path, &["rev-parse", "--abbrev-ref", "HEAD"])?.trim(),
        "branches": lines_json(run_git(repo_path, &["branch", "-a", "--format=%(refname:short)"])?),
        "tags": lines_json(run_git(repo_path, &["tag", "--list"])?),
        // Return remote *names*, never configured URLs. `git remote -v`
        // echoes HTTPS userinfo, sensitive query parameters, and fragments;
        // those credentials would otherwise be duplicated into both MCP text
        // and structuredContent. Agents can resolve refs without endpoints.
        "remotes": lines_json(run_git(repo_path, &["remote"])?),
        "stashes": lines_json(run_git(repo_path, &["stash", "list"])?),
    }))
}

fn repo_branch_stack_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let max_related = arguments
        .get("maxRelated")
        .and_then(Value::as_u64)
        .unwrap_or(8)
        .clamp(1, 50) as usize;
    let default_base_candidates = ["main", "master", "develop", "dev", "trunk"];
    let base_candidates: Vec<String> = arguments
        .get("baseCandidates")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .filter(|items: &Vec<String>| !items.is_empty())
        .unwrap_or_else(|| {
            default_base_candidates
                .iter()
                .map(|item| item.to_string())
                .collect()
        });
    let current_ref = run_git_optional(repo_path, &["symbolic-ref", "-q", "HEAD"]);
    let current_branch = run_git_optional(repo_path, &["rev-parse", "--abbrev-ref", "HEAD"])
        .unwrap_or_else(|| "HEAD".into());
    let current_commit = run_git(repo_path, &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    let upstream_ref = run_git_optional(
        repo_path,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    );
    let upstream_commit = upstream_ref
        .as_deref()
        .and_then(|upstream| run_git_optional(repo_path, &["rev-parse", upstream]));
    let (ahead, behind) = upstream_ref
        .as_deref()
        .and_then(|upstream| ahead_behind(repo_path, "HEAD", upstream))
        .unwrap_or((0, 0));
    let base_ref =
        resolve_branch_stack_base_ref(repo_path, &base_candidates, current_ref.as_deref());
    let base_commit = base_ref
        .as_deref()
        .and_then(|base| run_git_optional(repo_path, &["rev-parse", base]));
    let base_distance = base_ref.as_deref().map(|base| {
        let ahead_from_base = run_git_optional(
            repo_path,
            &["rev-list", "--count", &format!("{base}..HEAD")],
        )
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
        let behind_base = run_git_optional(
            repo_path,
            &["rev-list", "--count", &format!("HEAD..{base}")],
        )
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
        json!({
            "aheadFromBase": ahead_from_base,
            "behindBase": behind_base,
        })
    });
    let related = discover_related_branch_stack_refs(
        repo_path,
        current_ref.as_deref(),
        base_ref.as_deref(),
        max_related,
    );
    let risk = if ahead > 0 && behind > 0 {
        "high"
    } else if upstream_ref.is_none() || behind > 0 || !related.is_empty() {
        "medium"
    } else {
        "low"
    };
    let upstream_label = upstream_ref
        .as_deref()
        .map(clean_mcp_ref_label)
        .unwrap_or_else(|| "no upstream".into());
    let current_label = current_ref
        .as_deref()
        .map(clean_mcp_ref_label)
        .unwrap_or(current_branch);
    let summary = if ahead > 0 && behind > 0 {
        format!("{current_label} diverged from {upstream_label}")
    } else if ahead > 0 {
        format!(
            "{current_label} has {ahead} local commit{} over {upstream_label}",
            if ahead == 1 { "" } else { "s" }
        )
    } else if behind > 0 {
        format!(
            "{current_label} is {behind} commit{} behind {upstream_label}",
            if behind == 1 { "" } else { "s" }
        )
    } else {
        format!("{current_label} has no detected upstream drift")
    };

    Ok(json!({
        "current": {
            "ref": current_ref,
            "label": current_label,
            "commit": current_commit,
            "ahead": ahead,
            "behind": behind,
        },
        "upstream": upstream_ref.as_ref().map(|upstream| json!({
            "ref": upstream,
            "label": clean_mcp_ref_label(upstream),
            "commit": upstream_commit,
        })),
        "base": base_ref.as_ref().map(|base| json!({
            "ref": base,
            "label": clean_mcp_ref_label(base),
            "commit": base_commit,
            "distance": base_distance,
        })),
        "related": related,
        "risk": risk,
        "summary": summary,
        "guidance": "Branch Stack is read-only over MCP. Agents may explain relationships and propose a guarded rebase/compare plan, but FluxGit UI owns checkpoints, writes and approvals.",
        "suggestedActions": [
            "compareWithBase",
            "showAllBranchContext",
            "openSafetyTimeline",
            "prepareGuardedRebasePlan"
        ],
        "model": "real-git-refs-no-virtual-branches",
        "networkFetchPerformed": false,
        "readOnly": true,
    }))
}

fn repo_conflict_preflight_payload(
    repo_path: &Path,
    arguments: &Value,
) -> Result<Value, JsonRpcError> {
    let current_ref = arguments
        .get("currentRef")
        .or_else(|| arguments.get("current"))
        .or_else(|| arguments.get("sourceRef"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("HEAD");
    let target_ref = arguments
        .get("targetRef")
        .or_else(|| arguments.get("target"))
        .or_else(|| arguments.get("mergeTarget"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_params_error("repo.conflictPreflight requires targetRef"))?;
    // Both are interpolated into a rev spec below and handed to git as argv.
    let current_ref = checked_rev(current_ref, "currentRef")?;
    let target_ref = checked_rev(target_ref, "targetRef")?;

    let current_spec = format!("{current_ref}^{{commit}}");
    let target_spec = format!("{target_ref}^{{commit}}");
    let current_oid = run_git(repo_path, &["rev-parse", "--verify", &current_spec])?
        .trim()
        .to_string();
    let target_oid = run_git(repo_path, &["rev-parse", "--verify", &target_spec])?
        .trim()
        .to_string();
    let merge_base_oid = run_git_optional(repo_path, &["merge-base", &current_oid, &target_oid]);

    let target_is_ancestor = run_git_status(
        repo_path,
        &["merge-base", "--is-ancestor", &target_oid, &current_oid],
    );
    let current_is_ancestor = run_git_status(
        repo_path,
        &["merge-base", "--is-ancestor", &current_oid, &target_oid],
    );

    let (status, conflicting_paths, guidance) = if merge_base_oid.is_none() {
        (
            "unrelated-histories",
            Vec::<String>::new(),
            "These refs do not share a merge base. FluxGit should require an explicit unrelated-history approval before any merge.",
        )
    } else if target_is_ancestor {
        (
            "already-up-to-date",
            Vec::<String>::new(),
            "The target is already reachable from the current ref.",
        )
    } else if current_is_ancestor {
        (
            "fast-forward",
            Vec::<String>::new(),
            "The current ref can fast-forward to the target if the user approves that operation in FluxGit.",
        )
    } else {
        let merge_base = merge_base_oid.as_deref().unwrap_or_default();
        let merge_tree = run_git(
            repo_path,
            &["merge-tree", merge_base, &current_oid, &target_oid],
        )?;
        let paths = conflict_paths_from_merge_tree(&merge_tree);
        if paths.is_empty() {
            (
                "clean-merge",
                paths,
                "The read-only merge-tree preflight did not detect conflicting files.",
            )
        } else {
            (
                "conflicts",
                paths,
                "Predicted conflicts are informational. Open FluxGit Trinity or a guarded merge dialog before mutating the repository.",
            )
        }
    };

    let conflict_count = conflicting_paths.len();

    Ok(json!({
        "currentRef": current_ref,
        "targetRef": target_ref,
        "currentOid": current_oid,
        "targetOid": target_oid,
        "mergeBaseOid": merge_base_oid,
        "status": status,
        "conflictingPaths": conflicting_paths,
        "conflictCount": conflict_count,
        "readOnly": true,
        "networkFetchPerformed": false,
        "workingTreeMutated": false,
        "approvalRequiredForMerge": true,
        "guidance": guidance,
    }))
}

/// `conflict.read` — read an ACTIVE merge/rebase/cherry-pick conflict as
/// structured data so agents do not waste tokens hand-parsing `<<<<<<<` marker
/// soup. Free-shell tier: served entirely from local `git`, no gateway. Output
/// follows the repo.brief budget discipline: per-side content is byte-capped
/// with explicit `truncated` flags, binary blobs are flagged instead of dumped,
/// and the file list cap is reported honestly via `fileListTruncated`.
fn conflict_read_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let max_files = arguments
        .get("maxFiles")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .clamp(1, 200) as usize;
    let max_bytes_per_side = arguments
        .get("maxBytesPerSide")
        .and_then(Value::as_u64)
        .unwrap_or(16_384)
        .clamp(1, 1_048_576) as usize;

    // Resolve the actual git dir so linked worktrees work (same approach as repo.brief).
    let git_dir = run_git(repo_path, &["rev-parse", "--git-dir"])?;
    let git_dir = git_dir.trim();
    let git_dir = if Path::new(git_dir).is_absolute() {
        PathBuf::from(git_dir)
    } else {
        repo_path.join(git_dir)
    };

    // Detect the in-progress operation and which pseudo-ref names "theirs".
    let detected = if git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists()
    {
        Some(("rebase", "REBASE_HEAD"))
    } else if git_dir.join("MERGE_HEAD").exists() {
        Some(("merge", "MERGE_HEAD"))
    } else if git_dir.join("CHERRY_PICK_HEAD").exists() {
        Some(("cherry-pick", "CHERRY_PICK_HEAD"))
    } else if git_dir.join("REVERT_HEAD").exists() {
        Some(("revert", "REVERT_HEAD"))
    } else {
        None
    };

    // Unmerged index entries: "<mode> <sha> <stage>\t<path>\0" per ls-files -u -z.
    let unmerged_output = run_git(repo_path, &["ls-files", "-u", "-z"])?;
    let mut order: Vec<String> = Vec::new();
    let mut stages_by_path: std::collections::HashMap<String, [Option<String>; 3]> =
        std::collections::HashMap::new();
    for entry in unmerged_output
        .split('\0')
        .filter(|entry| !entry.is_empty())
    {
        let Some((meta, path)) = entry.split_once('\t') else {
            continue;
        };
        let mut parts = meta.split_whitespace();
        let _mode = parts.next();
        let sha = parts.next();
        let stage = parts.next().and_then(|raw| raw.parse::<usize>().ok());
        let (Some(sha), Some(stage @ 1..=3)) = (sha, stage) else {
            continue;
        };
        let slots = stages_by_path.entry(path.to_string()).or_insert_with(|| {
            order.push(path.to_string());
            [None, None, None]
        });
        slots[stage - 1] = Some(sha.to_string());
    }

    let Some((operation, theirs_ref)) = detected else {
        if order.is_empty() {
            return Ok(json!({
                "inConflict": false,
                "hint": "No merge, rebase or cherry-pick is in progress and the index has no unmerged entries. To PREDICT whether a future merge would conflict, use repo.conflictPreflight instead.",
            }));
        }
        // Honest edge case: unmerged index entries without a recognizable
        // operation (e.g. a failed stash apply). Report what is derivable.
        return Ok(conflict_read_result(
            repo_path,
            "unknown",
            None,
            &order,
            &stages_by_path,
            max_files,
            max_bytes_per_side,
        ));
    };

    Ok(conflict_read_result(
        repo_path,
        operation,
        Some(theirs_ref),
        &order,
        &stages_by_path,
        max_files,
        max_bytes_per_side,
    ))
}

fn conflict_read_result(
    repo_path: &Path,
    operation: &str,
    theirs_ref: Option<&str>,
    order: &[String],
    stages_by_path: &std::collections::HashMap<String, [Option<String>; 3]>,
    max_files: usize,
    max_bytes_per_side: usize,
) -> Value {
    let ours_commit = conflict_commit_summary(repo_path, "HEAD");
    let theirs_commit = theirs_ref
        .map(|reference| conflict_commit_summary(repo_path, reference))
        .unwrap_or(Value::Null);

    let mut files = Vec::with_capacity(order.len().min(max_files));
    for path in order.iter().take(max_files) {
        let slots = &stages_by_path[path];
        let (base, ours, theirs) = (
            slots[0].as_deref(),
            slots[1].as_deref(),
            slots[2].as_deref(),
        );
        files.push(json!({
            "path": path,
            "kind": conflict_stage_kind(base.is_some(), ours.is_some(), theirs.is_some()),
            "sides": {
                "base": conflict_side_value(repo_path, base, max_bytes_per_side),
                "ours": conflict_side_value(repo_path, ours, max_bytes_per_side),
                "theirs": conflict_side_value(repo_path, theirs, max_bytes_per_side),
            },
            "regions": conflict_marker_regions_for_file(&repo_path.join(path)),
        }));
    }

    let mut guidance = String::from(
        "Read-only snapshot of the active conflict. Propose resolutions as a unified diff via operation.preview.patch (the user approves in FluxGit) — never write conflicted files directly.",
    );
    if operation == "rebase" {
        guidance.push_str(
            " During a rebase, 'ours' is the branch being rebased ONTO (HEAD) and 'theirs' is the commit being replayed.",
        );
    }
    if order.is_empty() {
        guidance.push_str(
            " The operation is still in progress but the index has no unmerged entries: every conflict appears staged as resolved.",
        );
    }

    json!({
        "inConflict": true,
        "operation": operation,
        "ours": ours_commit,
        "theirs": theirs_commit,
        "conflictedFileCount": order.len(),
        "files": files,
        "fileListTruncated": order.len() > max_files,
        "maxBytesPerSide": max_bytes_per_side,
        "guidance": guidance,
    })
}

/// sha + subject for one producing commit, or null when the rev is not
/// derivable (unborn HEAD, missing pseudo-ref) — honest absence, not a guess.
fn conflict_commit_summary(repo_path: &Path, rev: &str) -> Value {
    let Some(line) = run_git_optional(repo_path, &["log", "-1", "--format=%H%x1f%s", rev]) else {
        return Value::Null;
    };
    match line.split_once('\u{1f}') {
        Some((sha, subject)) => json!({ "sha": sha, "subject": subject.trim() }),
        None => json!({ "sha": line, "subject": "" }),
    }
}

/// Classify which index stages exist (1=base, 2=ours, 3=theirs) the way
/// `git status` words it, so the agent immediately knows the conflict shape.
fn conflict_stage_kind(base: bool, ours: bool, theirs: bool) -> &'static str {
    match (base, ours, theirs) {
        (true, true, true) => "both-modified",
        (true, true, false) => "deleted-by-them",
        (true, false, true) => "deleted-by-us",
        (false, true, true) => "both-added",
        (false, true, false) => "added-by-us",
        (false, false, true) => "added-by-them",
        (true, false, false) => "both-deleted",
        (false, false, false) => "unknown",
    }
}

/// One side of a conflicted file, read via `git cat-file blob`, capped at
/// `max_bytes` with an explicit truncation flag and the full byte size.
/// Binary blobs (NUL byte in the first 8000 bytes, git's own heuristic) are
/// flagged instead of dumped into the agent's context.
fn conflict_side_value(repo_path: &Path, sha: Option<&str>, max_bytes: usize) -> Value {
    let Some(sha) = sha else {
        return Value::Null;
    };
    let capture_bytes = max_bytes.max(8_000);
    let Ok(output) = run_git_bounded(repo_path, &["cat-file", "blob", sha], capture_bytes) else {
        return json!({ "sha": sha, "error": "blob unreadable" });
    };
    let size = output.total_bytes;
    if output.prefix[..output.prefix.len().min(8_000)].contains(&0) {
        return json!({ "sha": sha, "binary": true, "size": size });
    }
    let truncated = size > max_bytes as u64;
    json!({
        "sha": sha,
        "size": size,
        "truncated": truncated,
        "content": String::from_utf8_lossy(&output.prefix[..output.prefix.len().min(max_bytes)]),
    })
}

/// Parse `<<<<<<<` / `=======` / `>>>>>>>` regions from the checked-out file so
/// the agent can map hunks to line ranges. Returns an empty array when the file
/// is missing, binary, or carries no markers (e.g. rm/rm conflicts).
fn conflict_marker_regions_for_file(file_path: &Path) -> Vec<Value> {
    const MAX_MARKER_SCAN_BYTES: u64 = 8 * 1024 * 1024;
    let Ok(metadata) = fs::symlink_metadata(file_path) else {
        return Vec::new();
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Vec::new();
    }
    let Ok(file) = File::open(file_path) else {
        return Vec::new();
    };
    let mut bytes =
        Vec::with_capacity(metadata.len().min(MAX_MARKER_SCAN_BYTES).min(65_536) as usize);
    if file
        .take(MAX_MARKER_SCAN_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Vec::new();
    }
    if bytes[..bytes.len().min(8000)].contains(&0) {
        return Vec::new();
    }
    let content = String::from_utf8_lossy(&bytes);
    let mut regions = Vec::new();
    let mut start_line: Option<usize> = None;
    let mut sep_line: Option<usize> = None;
    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        if line == "<<<<<<<" || line.starts_with("<<<<<<< ") {
            start_line = Some(line_number);
            sep_line = None;
        } else if line == "=======" && start_line.is_some() && sep_line.is_none() {
            sep_line = Some(line_number);
        } else if line == ">>>>>>>" || line.starts_with(">>>>>>> ") {
            if let (Some(start), Some(sep)) = (start_line, sep_line) {
                regions.push(json!({
                    "startLine": start,
                    "sepLine": sep,
                    "endLine": line_number,
                }));
            }
            start_line = None;
            sep_line = None;
        }
    }
    regions
}

fn repo_reflog_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let ref_name = arguments
        .get("refName")
        .or_else(|| arguments.get("ref"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("HEAD");
    let ref_name = checked_rev(ref_name, "refName")?;
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(12)
        .clamp(1, 100);
    let max_arg = format!("-n{limit}");
    let output = run_git(
        repo_path,
        &[
            "reflog",
            "show",
            ref_name,
            "--date=unix",
            "--pretty=format:%H%x1f%h%x1f%gd%x1f%gs%x1f%gn%x1f%ge%x1f%gt",
            &max_arg,
        ],
    )?;
    let parsed: Vec<Value> = output.lines().filter_map(parse_reflog_line).collect();
    let mut entries = Vec::with_capacity(parsed.len());

    for (index, entry) in parsed.iter().enumerate() {
        let new_commit = entry["newCommit"].as_str().unwrap_or_default();
        let old_commit = parsed
            .get(index + 1)
            .and_then(|next| next["newCommit"].as_str())
            .unwrap_or_default();
        entries.push(json!({
            "index": index,
            "refName": ref_name,
            "selector": entry["selector"],
            "oldCommit": old_commit,
            "newCommit": new_commit,
            "shortNewCommit": entry["shortNewCommit"],
            "message": entry["message"],
            "authorName": entry["authorName"],
            "authorEmail": entry["authorEmail"],
            "timestamp": entry["timestamp"],
            "canCompare": !old_commit.is_empty() && old_commit != new_commit,
        }));
    }

    Ok(json!({
        "refName": ref_name,
        "entries": entries,
        "entryCount": entries.len(),
        "readOnly": true,
        "recoveryGuidance": "Use reflog as a local movement timeline. Agents may compare or explain entries, but recovery actions such as reset, branch creation, undo or redo must be performed through FluxGit UI approval flows.",
    }))
}

fn repo_history_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 200);
    let skip = arguments
        .get("cursor")
        .and_then(Value::as_str)
        .and_then(|cursor| cursor.parse::<u64>().ok())
        .unwrap_or(0);
    let max_arg = format!("-n{limit}");
    let skip_arg = format!("--skip={skip}");
    let output = run_git(
        repo_path,
        &[
            "log",
            "--pretty=format:%H%x1f%h%x1f%an%x1f%ae%x1f%at%x1f%s",
            &max_arg,
            &skip_arg,
        ],
    )?;
    let commits: Vec<Value> = output.lines().filter_map(parse_history_line).collect();
    let next_cursor = if commits.len() == limit as usize {
        Some((skip + commits.len() as u64).to_string())
    } else {
        None
    };

    Ok(json!({
        "commits": commits,
        "nextCursor": next_cursor,
    }))
}

fn commit_details_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let commit = arguments
        .get("commit")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params_error("missing commit"))?;
    let commit = checked_rev(commit, "commit")?;
    let details = run_git(
        repo_path,
        &[
            "show",
            "-s",
            "--pretty=format:%H%x1f%h%x1f%an%x1f%ae%x1f%at%x1f%P%x1f%B",
            commit,
        ],
    )?;
    let files = run_git(
        repo_path,
        &["diff-tree", "--no-commit-id", "--name-status", "-r", commit],
    )?;

    Ok(json!({
        "commit": parse_commit_details(&details),
        "files": files.lines().map(parse_name_status).collect::<Vec<_>>(),
    }))
}

fn worktree_changes_payload(repo_path: &Path) -> Result<Value, JsonRpcError> {
    let output = run_git(repo_path, &["status", "--porcelain=v1"])?;
    let mut staged = Vec::new();
    let mut unstaged = Vec::new();
    let mut untracked = Vec::new();

    for line in output.lines() {
        if line.starts_with("??") {
            untracked.push(status_entry_json(line));
            continue;
        }
        let bytes = line.as_bytes();
        if bytes.first().is_some_and(|status| *status != b' ') {
            staged.push(status_entry_json(line));
        }
        if bytes.get(1).is_some_and(|status| *status != b' ') {
            unstaged.push(status_entry_json(line));
        }
    }

    Ok(json!({
        "staged": staged,
        "unstaged": unstaged,
        "untracked": untracked,
    }))
}

/// `worktree.list` — enumerate the repository's worktrees (AGENT_FIRST_ROADMAP
/// P2: agent worktree fleets, read-only first step). Parses
/// `git worktree list --porcelain`; the first entry is the main worktree.
fn worktree_list_payload(repo_path: &Path) -> Result<Value, JsonRpcError> {
    let output = run_git(repo_path, &["worktree", "list", "--porcelain"])?;
    let mut worktrees: Vec<Value> = Vec::new();
    let mut current: Option<Map<String, Value>> = None;

    let flush = |entry: Option<Map<String, Value>>, out: &mut Vec<Value>| {
        if let Some(map) = entry {
            if !map.is_empty() {
                out.push(Value::Object(map));
            }
        }
    };

    for line in output.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            flush(current.take(), &mut worktrees);
            continue;
        }
        if let Some(path) = line.strip_prefix("worktree ") {
            flush(current.take(), &mut worktrees);
            let mut map = Map::new();
            map.insert("path".into(), json!(path));
            map.insert("isMain".into(), json!(worktrees.is_empty()));
            map.insert("detached".into(), json!(false));
            map.insert("locked".into(), json!(false));
            map.insert("prunable".into(), json!(false));
            current = Some(map);
            continue;
        }
        let Some(map) = current.as_mut() else {
            continue;
        };
        if let Some(sha) = line.strip_prefix("HEAD ") {
            map.insert("headSha".into(), json!(sha.get(..12).unwrap_or(sha)));
        } else if let Some(branch) = line.strip_prefix("branch ") {
            map.insert(
                "branch".into(),
                json!(branch.trim_start_matches("refs/heads/")),
            );
        } else if line == "detached" {
            map.insert("detached".into(), json!(true));
        } else if line == "bare" {
            map.insert("bare".into(), json!(true));
        } else if line == "locked" || line.starts_with("locked ") {
            map.insert("locked".into(), json!(true));
            if let Some(reason) = line.strip_prefix("locked ") {
                map.insert("lockedReason".into(), json!(reason));
            }
        } else if line == "prunable" || line.starts_with("prunable ") {
            map.insert("prunable".into(), json!(true));
        }
    }
    flush(current.take(), &mut worktrees);

    Ok(json!({
        "total": worktrees.len(),
        "worktrees": worktrees,
    }))
}

fn submodule_status_payload(repo_path: &Path) -> Result<Value, JsonRpcError> {
    Ok(json!({
        "submodules": submodule_status_entries(repo_path)?,
    }))
}

const SUBMODULE_STATUS_MAX_ENTRIES: usize = 1_000;
const SUBMODULE_STATUS_MAX_DEPTH: usize = 16;

#[derive(Clone)]
struct IndexedGitlink {
    commit: String,
    conflicted: bool,
}

/// Read submodule pins through Git's built-in index plumbing instead of the
/// `git submodule` shell script. This avoids executing inherited shell/helper
/// machinery and lets the sidecar enforce recursion and entry ceilings.
fn submodule_status_entries(repo_path: &Path) -> Result<Vec<Value>, JsonRpcError> {
    let canonical_root = repo_path
        .canonicalize()
        .map_err(|error| local_git_error(&["ls-files", "--stage"], error.to_string()))?;
    let mut entries = Vec::new();
    let mut visited = std::collections::HashSet::new();
    collect_submodule_status_entries(
        &canonical_root,
        &canonical_root,
        "",
        0,
        &mut visited,
        &mut entries,
    )?;
    Ok(entries)
}

fn collect_submodule_status_entries(
    root: &Path,
    repo_path: &Path,
    prefix: &str,
    depth: usize,
    visited: &mut std::collections::HashSet<PathBuf>,
    entries: &mut Vec<Value>,
) -> Result<(), JsonRpcError> {
    if depth > SUBMODULE_STATUS_MAX_DEPTH {
        return Err(local_git_error(
            &["ls-files", "--stage"],
            format!(
                "submodule nesting exceeds the {SUBMODULE_STATUS_MAX_DEPTH}-level safety limit"
            ),
        ));
    }
    let canonical_repo = repo_path
        .canonicalize()
        .map_err(|error| local_git_error(&["ls-files", "--stage"], error.to_string()))?;
    if !canonical_repo.starts_with(root) || !visited.insert(canonical_repo.clone()) {
        return Ok(());
    }

    let output = run_git(&canonical_repo, &["ls-files", "--stage", "-z"])?;
    let mut gitlinks = std::collections::BTreeMap::<String, IndexedGitlink>::new();
    for record in output.split('\0').filter(|record| !record.is_empty()) {
        let Some((metadata, path)) = record.split_once('\t') else {
            continue;
        };
        let mut fields = metadata.split_whitespace();
        let mode = fields.next().unwrap_or_default();
        let commit = fields.next().unwrap_or_default();
        let stage = fields.next().unwrap_or_default();
        if mode != "160000" || commit.is_empty() || path.is_empty() {
            continue;
        }
        let candidate = gitlinks
            .entry(path.to_string())
            .or_insert_with(|| IndexedGitlink {
                commit: commit.to_string(),
                conflicted: stage != "0",
            });
        candidate.conflicted |= stage != "0";
        if stage == "2" || candidate.commit.is_empty() {
            candidate.commit = commit.to_string();
        }
    }

    for (path, gitlink) in gitlinks {
        if entries.len() >= SUBMODULE_STATUS_MAX_ENTRIES {
            return Err(local_git_error(
                &["ls-files", "--stage"],
                format!(
                    "submodule count exceeds the {SUBMODULE_STATUS_MAX_ENTRIES}-entry safety limit"
                ),
            ));
        }
        let display_path = if prefix.is_empty() {
            path.clone()
        } else {
            format!("{prefix}/{path}")
        };
        let candidate_path = canonical_repo.join(&path);
        let canonical_candidate = candidate_path
            .canonicalize()
            .ok()
            .filter(|candidate| candidate.starts_with(root));
        let current_commit = canonical_candidate
            .as_deref()
            .and_then(|candidate| run_git_optional(candidate, &["rev-parse", "HEAD"]));
        let state = if gitlink.conflicted {
            "U"
        } else if current_commit.is_none() {
            "-"
        } else if current_commit.as_deref() != Some(gitlink.commit.as_str()) {
            "+"
        } else {
            " "
        };
        entries.push(json!({
            "state": state,
            "commit": gitlink.commit,
            "path": display_path,
            "description": "",
        }));

        if current_commit.is_some() {
            let Some(candidate) = canonical_candidate else {
                continue;
            };
            collect_submodule_status_entries(
                root,
                &candidate,
                &display_path,
                depth + 1,
                visited,
                entries,
            )?;
        }
    }
    Ok(())
}

/// Default byte cap for `diff.text` output (64 KiB). A repo-wide diff can be
/// hundreds of megabytes; dumping it uncapped floods the agent's context and
/// can wedge the MCP host. Truncation mirrors conflict.read's pattern:
/// explicit `truncated: true` plus the full `totalBytes`, never a silent cut.
const DIFF_TEXT_DEFAULT_MAX_BYTES: u64 = 65_536;
/// Hard ceiling for the `maxBytes` input (1 MiB).
const DIFF_TEXT_MAX_MAX_BYTES: u64 = 1_048_576;

fn diff_text_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let base = arguments.get("base").and_then(Value::as_str);
    let head = arguments.get("head").and_then(Value::as_str);
    let path_filter = diff_path_filter(arguments, repo_path);
    let max_bytes = arguments
        .get("maxBytes")
        .and_then(Value::as_u64)
        .unwrap_or(DIFF_TEXT_DEFAULT_MAX_BYTES)
        .clamp(1, DIFF_TEXT_MAX_MAX_BYTES) as usize;
    let max_lines = arguments
        .get("maxLines")
        .and_then(Value::as_u64)
        .map(|value| value.max(1) as usize);

    // Never execute repository-configured external diff/textconv commands from
    // a read-only MCP inspection.
    let mut args = vec!["diff", "--no-ext-diff", "--no-textconv"];
    if let Some(base) = checked_rev_opt(base, "base")? {
        args.push(base);
    }
    if let Some(head) = checked_rev_opt(head, "head")? {
        args.push(head);
    }
    if let Some(path) = path_filter.as_deref() {
        args.push("--");
        args.push(path);
    }

    let streamed = run_git_bounded(repo_path, &args, max_bytes.saturating_add(4))?;
    let prefix = String::from_utf8_lossy(&streamed.prefix);
    let (diff, prefix_truncated) = truncate_diff_text(&prefix, max_bytes, max_lines);
    let truncated = prefix_truncated || streamed.total_bytes > streamed.prefix.len() as u64;

    Ok(json!({
        "format": "text",
        "base": base,
        "head": head,
        "path": path_filter,
        "diff": diff,
        "truncated": truncated,
        "totalBytes": streamed.total_bytes,
        "totalLines": streamed.total_lines,
        "maxBytes": max_bytes,
    }))
}

/// Apply the optional line cap, then the byte cap, cutting on a line boundary
/// so the agent never receives half a diff line. Returns the (possibly
/// truncated) text and whether any truncation happened.
fn truncate_diff_text(full: &str, max_bytes: usize, max_lines: Option<usize>) -> (String, bool) {
    let mut text: &str = full;
    let mut truncated = false;

    if let Some(max_lines) = max_lines {
        let mut seen = 0usize;
        let mut cut = text.len();
        for (index, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                seen += 1;
                if seen == max_lines {
                    cut = index + 1;
                    break;
                }
            }
        }
        if cut < text.len() {
            text = &text[..cut];
            truncated = true;
        }
    }

    if text.len() > max_bytes {
        let bytes = text.as_bytes();
        let cut = bytes[..max_bytes]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|index| index + 1)
            .unwrap_or_else(|| {
                // No newline before the cap (one giant line): hard-cut at the
                // nearest UTF-8 char boundary at or below the cap.
                let mut boundary = max_bytes;
                while boundary > 0 && !text.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                boundary
            });
        text = &text[..cut];
        truncated = true;
    }

    (text.to_string(), truncated)
}

fn semantic_fallback_payload(repo_path: &Path, arguments: &Value) -> Value {
    let base = arguments.get("base").and_then(Value::as_str);
    let head = arguments.get("head").and_then(Value::as_str);
    let path = diff_path_filter(arguments, repo_path).map(Value::String);
    json!({
        "supported": false,
        "fallback": "diff.text",
        "reason": "Semantic diff is not available in local sidecar fallback mode.",
        "textDiffArguments": diff_text_arguments(repo_path, base, head, path),
    })
}

fn diff_text_arguments(
    repo_path: &Path,
    base: Option<&str>,
    head: Option<&str>,
    path: Option<Value>,
) -> Value {
    let mut arguments = Map::new();
    arguments.insert("repoPath".into(), json!(repo_path));
    if let Some(base) = base {
        arguments.insert("base".into(), json!(base));
    }
    if let Some(head) = head {
        arguments.insert("head".into(), json!(head));
    }
    if let Some(path) = path.filter(|path| !path.is_null()) {
        arguments.insert("path".into(), path);
    }
    Value::Object(arguments)
}

fn semantic_fallbacks_payload(repo_path: &Path, arguments: &Value) -> Value {
    json!({
        "fallbacks": [{
            "from": "diff.semantic",
            "to": "diff.text",
            "supported": false,
            "reason": "Local fallback uses git diff text because the FluxGit semantic diff engine was not reachable for this call (FluxGit app not running, gateway address not configured, or repository not registered in FluxGit).",
            "repoPath": repo_path,
            "path": diff_path_filter(arguments, repo_path),
        }],
    })
}

/// Cap on changed files sent to the semantic-diff bridge per call. Reported
/// honestly via `filesTruncated: true` when exceeded — the agent can narrow
/// the selection with `path`.
const SEMANTIC_DIFF_MAX_FILES: usize = 25;

/// Map the diff.text-style (base, head) selector onto the diff-engine's
/// (old_ref, new_ref) pair, preserving `git diff` positional semantics:
/// - base + head        → base..head (tree to tree)
/// - base only          → base vs working tree
/// - head only          → head vs working tree (git treats the single
///   positional rev as the OLD side)
/// - neither            → index vs working tree
fn semantic_engine_refs(base: Option<&str>, head: Option<&str>) -> (String, String) {
    match (base, head) {
        (Some(base), Some(head)) => (base.to_string(), head.to_string()),
        (Some(base), None) => (base.to_string(), String::new()),
        (None, Some(head)) => (head.to_string(), String::new()),
        (None, None) => (String::new(), String::new()),
    }
}

/// Enumerate the changed paths for the same selection diff.text would show,
/// capped at [`SEMANTIC_DIFF_MAX_FILES`]. Returns `None` when git itself
/// rejects the selection (bad ref, etc.) so the caller degrades to the
/// documented fallback instead of erroring on a path the fallback contract
/// never errored on.
fn semantic_changed_paths(
    repo_path: &Path,
    base: Option<&str>,
    head: Option<&str>,
    path_filter: Option<&str>,
) -> Option<(Vec<String>, bool)> {
    let mut args = vec!["diff", "--name-only"];
    // Unchecked revs here would be `git diff --output=<file>` — see `checked_rev`.
    // This helper returns Option, so a rejected rev degrades to the documented
    // fallback rather than erroring, consistent with the rest of the function.
    if let Some(base) = checked_rev_opt(base, "base").ok()? {
        args.push(base);
    }
    if let Some(head) = checked_rev_opt(head, "head").ok()? {
        args.push(head);
    }
    if let Some(path) = path_filter {
        args.push("--");
        args.push(path);
    }
    let output = run_git(repo_path, &args).ok()?;
    let mut paths: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    let truncated = paths.len() > SEMANTIC_DIFF_MAX_FILES;
    paths.truncate(SEMANTIC_DIFF_MAX_FILES);
    Some((paths, truncated))
}

/// POST the semantic-diff request to the gateway's read-only bridge
/// (`/v1/mcp/diff/semantic`) and return its parsed body. `None` on any
/// transport, HTTP or parse failure — the caller falls back honestly.
fn fetch_semantic_diff_from_gateway(
    gateway_addr: &str,
    repo_id: &str,
    repo_path: &Path,
    old_ref: &str,
    new_ref: &str,
    paths: &[String],
) -> Option<Value> {
    let base = format!("http://{}", gateway_addr.trim_end_matches('/'));
    let url = format!("{}/v1/mcp/diff/semantic", base);
    let client = loopback_bridge_client(Duration::from_secs(10)).ok()?;
    let response = client
        .post(&url)
        .json(&json!({
            "repoId": repo_id,
            "repoPath": repo_path,
            "baseRef": old_ref,
            "headRef": new_ref,
            "paths": paths,
        }))
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response_json_limited(response).ok()
}

/// Build the enriched `data` payload for diff.semantic /
/// diff.semanticFallbacks from the gateway bridge, or `None` when the
/// enriched path is unavailable so the caller keeps today's honest local
/// fallback byte-for-byte.
fn semantic_gateway_tool_payload(
    kind: ToolKind,
    gateway_addr: &str,
    repo_path: &Path,
    arguments: &Value,
) -> Option<Value> {
    ensure_git_repo(repo_path).ok()?;
    // The diff-engine resolves repositories through the FluxGit run-dir
    // registry; enrichment therefore requires the repo to be registered
    // (opened) in FluxGit, or an explicit repoId argument.
    let repo_id = repo_id_from_arguments_or_registry(arguments, repo_path)?;
    // This path degrades to the documented fallback rather than erroring, so a
    // rejected rev bails out to `None` like any other unusable selection.
    let base = checked_rev_opt(arguments.get("base").and_then(Value::as_str), "base").ok()?;
    let head = checked_rev_opt(arguments.get("head").and_then(Value::as_str), "head").ok()?;
    let path_filter = diff_path_filter(arguments, repo_path);
    let (paths, files_truncated) =
        semantic_changed_paths(repo_path, base, head, path_filter.as_deref())?;
    let (old_ref, new_ref) = semantic_engine_refs(base, head);
    let gateway_body = fetch_semantic_diff_from_gateway(
        gateway_addr,
        &repo_id,
        repo_path,
        &old_ref,
        &new_ref,
        &paths,
    )?;
    let files = gateway_body.get("files")?.as_array()?.clone();

    match kind {
        ToolKind::DiffSemantic => {
            let files: Vec<Value> = files
                .into_iter()
                .map(|mut file| {
                    // Per-file honesty: every file the engine could not parse
                    // ships ready-to-use diff.text arguments, mirroring the
                    // whole-call fallback contract.
                    let fell_back = file
                        .get("fallbackToText")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if fell_back {
                        if let Some(object) = file.as_object_mut() {
                            let file_path = object.get("path").cloned().unwrap_or(Value::Null);
                            object.insert(
                                "textDiffArguments".into(),
                                diff_text_arguments(repo_path, base, head, Some(file_path)),
                            );
                        }
                    }
                    file
                })
                .collect();
            Some(json!({
                "supported": true,
                "engine": "fluxgit-diff-engine",
                "base": base,
                "head": head,
                "path": path_filter,
                "files": files,
                "changedFiles": paths.len(),
                "filesTruncated": files_truncated,
            }))
        }
        ToolKind::DiffSemanticFallbacks => {
            let fallbacks: Vec<Value> = files
                .iter()
                .filter(|file| {
                    file.get("fallbackToText").and_then(Value::as_bool) == Some(true)
                })
                .map(|file| {
                    json!({
                        "from": "diff.semantic",
                        "to": "diff.text",
                        "supported": false,
                        "path": file.get("path").cloned().unwrap_or(Value::Null),
                        "reason": file
                            .get("reason")
                            .cloned()
                            .unwrap_or_else(|| json!(
                                "The semantic engine could not parse this file; use diff.text for it."
                            )),
                        "repoPath": repo_path,
                    })
                })
                .collect();
            Some(json!({
                "fallbacks": fallbacks,
                "engine": "fluxgit-diff-engine",
                "analyzedFiles": paths.len(),
                "filesTruncated": files_truncated,
            }))
        }
        _ => None,
    }
}

fn flux_latest_restore_point_payload(repo_path: &Path, arguments: &Value) -> Value {
    let restore_points = read_flux_restore_points(repo_path, arguments);
    let latest_restore_point = restore_points.first().cloned();

    json!({
        "latestRestorePoint": latest_restore_point,
        "restorePoints": restore_points,
        "restoreCount": restore_points.len(),
        "approvalRequired": true,
        "approvalMessage": "Undo/redo is intentionally not exposed through MCP. Use the FluxGit app, where history checkpoint restore requires explicit user approval.",
    })
}

fn flux_restore_points_payload(repo_path: &Path, arguments: &Value) -> Value {
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 200) as usize;
    let mut restore_points = read_flux_restore_points(repo_path, arguments);
    restore_points.truncate(limit);

    json!({
        "restorePoints": restore_points,
        "restoreCount": restore_points.len(),
        "approvalRequired": true,
        "approvalMessage": "Undo/redo is intentionally not exposed through MCP. Use the FluxGit app, where history checkpoint restore requires explicit user approval.",
    })
}

fn flux_restore_point_details_payload(repo_path: &Path, arguments: &Value) -> Value {
    let restore_points = read_flux_restore_points(repo_path, arguments);
    let restore_point = restore_points.first().cloned();

    json!({
        "restorePoint": restore_point,
        "restoreCount": restore_points.len(),
        "approvalRequired": true,
        "approvalMessage": "Undo/redo is intentionally not exposed through MCP. Use the FluxGit app, where history checkpoint restore requires explicit user approval.",
    })
}

fn read_flux_restore_points(repo_path: &Path, arguments: &Value) -> Vec<Value> {
    let Some(repo_id) = repo_id_from_arguments_or_registry(arguments, repo_path) else {
        return Vec::new();
    };
    let Some(checkpoint_path) = flux_checkpoint_path(&repo_id, arguments) else {
        return Vec::new();
    };
    let Ok(contents) = fs::read_to_string(&checkpoint_path) else {
        return Vec::new();
    };
    let Ok(record) = serde_json::from_str::<Value>(&contents) else {
        return Vec::new();
    };

    vec![flux_restore_point_json(
        repo_path,
        &repo_id,
        checkpoint_path,
        &record,
    )]
}

fn repo_id_from_arguments_or_registry(arguments: &Value, repo_path: &Path) -> Option<String> {
    if let Some(repo_id) = arguments.get("repoId").and_then(Value::as_str) {
        if !repo_id.trim().is_empty() {
            return Some(repo_id.to_string());
        }
    }

    find_repo_id_by_path(repo_path)
}

fn find_repo_id_by_path(repo_path: &Path) -> Option<String> {
    let registry_dir = fluxgit_run_dir()?.join("repos");
    let target = canonicalize_for_match(repo_path);
    let entries = fs::read_dir(registry_dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("path") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        if contents.trim() == target {
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
                return Some(stem.to_string());
            }
        }
    }

    None
}

/// A repo id is a file name component here, never a path.
///
/// `flux_checkpoint_path` joins it straight into `<runDir>/rebase/<id>.json`,
/// and both `repoId` and `runDir` arrive verbatim from agent arguments. A
/// `repoId` of `../../secret` therefore read any JSON file on the machine and
/// echoed its `plan` object back — from tools annotated `readOnlyHint: true`.
/// `repo.scope` already rejected `..` in paths; this is the same guard where it
/// was missing.
fn is_safe_repo_id_component(repo_id: &str) -> bool {
    !repo_id.is_empty()
        && !repo_id.contains('/')
        && !repo_id.contains('\\')
        && !repo_id.contains('\0')
        && repo_id != "."
        && repo_id != ".."
}

fn flux_checkpoint_path(repo_id: &str, arguments: &Value) -> Option<PathBuf> {
    if !is_safe_repo_id_component(repo_id) {
        return None;
    }
    let run_dir = arguments
        .get("runDir")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(fluxgit_run_dir)?;
    Some(run_dir.join("rebase").join(format!("{repo_id}.json")))
}

fn fluxgit_run_dir() -> Option<PathBuf> {
    if let Ok(custom) = env::var("FLUXGIT_RUN_DIR") {
        return Some(PathBuf::from(custom));
    }

    #[cfg(target_os = "windows")]
    {
        env::var("LOCALAPPDATA")
            .ok()
            .map(PathBuf::from)
            .map(|dir| dir.join("FluxGit").join("run"))
    }

    #[cfg(target_os = "macos")]
    {
        env::var("HOME")
            .ok()
            .map(PathBuf::from)
            .map(|dir| dir.join("Library/Application Support/FluxGit/run"))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        env::var("HOME")
            .ok()
            .map(PathBuf::from)
            .map(|dir| dir.join(".local/share/FluxGit/run"))
    }
}

pub fn audit_log_path_for_run_dir(run_dir: &Path) -> PathBuf {
    run_dir.join("audit").join("mcp.jsonl")
}

fn mcp_audit_log_path_checked() -> Result<Option<PathBuf>, AuditLedgerError> {
    if env::var_os("FLUXGIT_MCP_AUDIT_DISABLED").is_some() {
        return Ok(None);
    }
    if let Some(custom) = env::var_os("FLUXGIT_MCP_AUDIT_LOG") {
        if custom.is_empty() {
            return Err(AuditLedgerError::Configuration(
                "FLUXGIT_MCP_AUDIT_LOG is explicitly set but empty".into(),
            ));
        }
        return Ok(Some(PathBuf::from(custom)));
    }
    let run_dir = fluxgit_run_dir().ok_or_else(|| {
        AuditLedgerError::Configuration(
            "cannot resolve the FluxGit run directory for the default audit log".into(),
        )
    })?;
    Ok(Some(audit_log_path_for_run_dir(&run_dir)))
}

/// Load the per-install audit signer from `FLUXGIT_MCP_AUDIT_SIGN_KEY`, if set.
///
/// Signing is opt-in: when the env var is unset, new chained entries remain
/// unsigned for compatibility. Once the variable is explicitly configured,
/// an empty, missing, unsafe, oversized, or invalid key is a startup error;
/// it must never silently downgrade the shared ledger to unsigned entries.
fn load_audit_signer_from_env() -> Result<Option<AuditSigner>, AuditLedgerError> {
    let Some(path) = env::var_os("FLUXGIT_MCP_AUDIT_SIGN_KEY") else {
        return Ok(None);
    };
    if path.is_empty() {
        return Err(AuditLedgerError::Configuration(
            "FLUXGIT_MCP_AUDIT_SIGN_KEY is explicitly set but empty".into(),
        ));
    }
    let path = PathBuf::from(path);
    AuditSigner::from_pem_file(&path)
        .map(Some)
        .map_err(|error| AuditLedgerError::Configuration(error.to_string()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn canonicalize_for_match(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn flux_restore_point_json(
    repo_path: &Path,
    repo_id: &str,
    checkpoint_path: PathBuf,
    record: &Value,
) -> Value {
    let operation = record.get("operation").and_then(Value::as_str);
    let before = record.get("before_commit").and_then(Value::as_str);
    let after = record.get("after_commit").and_then(Value::as_str);
    let branch_ref = record.get("branch_ref").and_then(Value::as_str);
    let undone = record
        .get("undone")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let current_branch_ref = run_git(repo_path, &["symbolic-ref", "-q", "HEAD"])
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let current_head = run_git(repo_path, &["rev-parse", "HEAD"])
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let branch_matches = branch_ref.is_some() && current_branch_ref.as_deref() == branch_ref;
    let can_undo = !undone && branch_matches && after.is_some() && current_head.as_deref() == after;
    let can_redo =
        undone && branch_matches && before.is_some() && current_head.as_deref() == before;

    json!({
        "repoId": repo_id,
        "before": before,
        "after": after,
        "operation": operation,
        "canUndo": can_undo,
        "canRedo": can_redo,
        "approvalRequired": true,
        "approvalMessage": "Undo/redo requires explicit approval in the FluxGit app and is not available as an MCP write tool.",
        "metadata": {
            "checkpointPath": checkpoint_path,
            "createdAt": record.get("created_at").and_then(Value::as_i64),
            "branchRef": branch_ref,
            "undone": undone,
            "beforeRef": record.get("before_ref").and_then(Value::as_str),
            "afterRef": record.get("after_ref").and_then(Value::as_str),
            "upstreamRef": record.get("upstream_ref").and_then(Value::as_str),
            "resetMode": record.get("reset_mode").and_then(Value::as_str),
            "plan": record.get("plan").cloned().unwrap_or(Value::Null),
            "currentBranchRef": current_branch_ref,
            "currentHead": current_head,
        },
    })
}

fn conflict_paths_from_merge_tree(output: &str) -> Vec<String> {
    let mut paths = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(path) = trimmed.strip_prefix("CONFLICT ").and_then(|value| {
            value
                .rsplit_once(" in ")
                .map(|(_, path)| path.trim().to_string())
        }) {
            push_unique_path(&mut paths, path);
            continue;
        }

        if trimmed.starts_with("base ")
            || trimmed.starts_with("our ")
            || trimmed.starts_with("their ")
        {
            let parts = trimmed.split_whitespace().collect::<Vec<_>>();
            if parts.len() >= 4 {
                push_unique_path(&mut paths, parts[3..].join(" "));
            }
        }
    }

    paths.sort();
    paths
}

fn push_unique_path(paths: &mut Vec<String>, path: String) {
    let path = path.trim().to_string();
    if !path.is_empty() && !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn diff_path_filter(arguments: &Value, repo_path: &Path) -> Option<String> {
    let path = arguments.get("path").and_then(Value::as_str)?;
    if Path::new(path) == repo_path {
        None
    } else {
        Some(path.to_string())
    }
}

fn run_git(repo_path: &Path, args: &[&str]) -> Result<String, JsonRpcError> {
    let output = execute_git(
        repo_path,
        args,
        GIT_COMPLETE_STDOUT_MAX_BYTES,
        GIT_COMPLETE_STDOUT_MAX_BYTES,
        GIT_COMMAND_TIMEOUT,
    )?;
    // The one place "read everything and change nothing" was literally
    // false: `git status` and `git diff` opportunistically refresh the stat
    // cache, which rewrites .git/index and takes index.lock. Measured — the
    // index sha256 changed after repo.status. Harmless to content, but it
    // is a write inside .git and the lock can collide with a human
    // operation in progress while an agent polls.

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout.prefix).into_owned())
    } else {
        Err(local_git_error(
            args,
            String::from_utf8_lossy(&output.stderr.prefix)
                .trim()
                .to_string(),
        ))
    }
}

struct BoundedGitOutput {
    prefix: Vec<u8>,
    total_bytes: u64,
    total_lines: u64,
}

/// Stream stdout instead of using `Command::output`, retaining only a bounded
/// prefix while still reporting exact byte/line totals. This prevents a large
/// blob or repository-wide diff from allocating its full output in the MCP
/// process before the response cap is applied.
fn run_git_bounded(
    repo_path: &Path,
    args: &[&str],
    capture_bytes: usize,
) -> Result<BoundedGitOutput, JsonRpcError> {
    if capture_bytes > GIT_BOUNDED_SCAN_MAX_BYTES {
        return Err(local_git_error(
            args,
            format!(
                "requested Git capture is {capture_bytes} bytes; safety maximum is {GIT_BOUNDED_SCAN_MAX_BYTES} bytes"
            ),
        ));
    }
    let output = execute_git(
        repo_path,
        args,
        capture_bytes,
        GIT_BOUNDED_SCAN_MAX_BYTES,
        GIT_COMMAND_TIMEOUT,
    )?;
    if !output.status.success() {
        return Err(local_git_error(
            args,
            String::from_utf8_lossy(&output.stderr.prefix)
                .trim()
                .to_string(),
        ));
    }
    Ok(BoundedGitOutput {
        prefix: output.stdout.prefix,
        total_bytes: output.stdout.total_bytes,
        total_lines: output.stdout.total_lines,
    })
}

struct GitStreamOutput {
    prefix: Vec<u8>,
    total_bytes: u64,
    total_lines: u64,
}

struct GitProcessOutput {
    status: std::process::ExitStatus,
    stdout: GitStreamOutput,
    stderr: GitStreamOutput,
}

static RESOLVED_GIT_EXECUTABLE: OnceLock<Result<PathBuf, String>> = OnceLock::new();

fn resolved_git_executable(repo_path: &Path) -> Result<&'static Path, String> {
    match RESOLVED_GIT_EXECUTABLE.get_or_init(|| resolve_git_executable(repo_path)) {
        Ok(path) => Ok(path.as_path()),
        Err(error) => Err(error.clone()),
    }
}

fn resolve_git_executable(repo_path: &Path) -> Result<PathBuf, String> {
    let current_dir = env::current_dir().map_err(|error| error.to_string())?;
    if let Some(explicit) = env::var_os("FLUXGIT_MCP_GIT_PATH") {
        if explicit.is_empty() {
            return Err("FLUXGIT_MCP_GIT_PATH is explicitly set but empty".into());
        }
        return validate_git_executable_candidate(
            PathBuf::from(explicit),
            repo_path,
            &current_dir,
            true,
        )
        .ok_or_else(|| {
            "FLUXGIT_MCP_GIT_PATH must be an absolute, existing, regular, non-reparse executable outside the repository/current directory"
                .to_string()
        });
    }

    let mut candidates = Vec::<(PathBuf, bool)>::new();
    #[cfg(windows)]
    {
        for root in [
            env::var_os("ProgramFiles"),
            env::var_os("ProgramFiles(x86)"),
        ]
        .into_iter()
        .flatten()
        {
            let root = PathBuf::from(root);
            candidates.push((root.join("Git/cmd/git.exe"), true));
            candidates.push((root.join("Git/bin/git.exe"), true));
        }
    }
    #[cfg(unix)]
    {
        for path in [
            "/usr/bin/git",
            "/usr/local/bin/git",
            "/opt/homebrew/bin/git",
            "/opt/local/bin/git",
        ] {
            candidates.push((PathBuf::from(path), true));
        }
    }

    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path).filter(|entry| entry.is_absolute()) {
            #[cfg(windows)]
            let candidate = directory.join("git.exe");
            #[cfg(not(windows))]
            let candidate = directory.join("git");
            candidates.push((candidate, false));
        }
    }
    for (candidate, trusted_location) in candidates {
        if let Some(validated) =
            validate_git_executable_candidate(candidate, repo_path, &current_dir, trusted_location)
        {
            return Ok(validated);
        }
    }
    Err(
        "no safe absolute Git executable was found in trusted locations or absolute PATH entries"
            .into(),
    )
}

fn validate_git_executable_candidate(
    candidate: PathBuf,
    repo_path: &Path,
    current_dir: &Path,
    explicitly_trusted_location: bool,
) -> Option<PathBuf> {
    if !candidate.is_absolute() {
        return None;
    }
    let metadata = fs::symlink_metadata(&candidate).ok()?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
        if !explicitly_trusted_location {
            let parent = candidate.parent()?;
            let parent_mode = fs::symlink_metadata(parent).ok()?.permissions().mode();
            if parent_mode & 0o022 != 0 {
                return None;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = explicitly_trusted_location;
    let candidate = fs::canonicalize(&candidate).ok()?;
    let canonical_repo = fs::canonicalize(repo_path).unwrap_or_else(|_| repo_path.to_path_buf());
    let canonical_current =
        fs::canonicalize(current_dir).unwrap_or_else(|_| current_dir.to_path_buf());
    if candidate.starts_with(&canonical_repo) || candidate.starts_with(&canonical_current) {
        return None;
    }
    Some(candidate)
}

/// Construct every production Git process through one fail-closed boundary.
/// Inherited `GIT_*` state must not be able to redirect the repository,
/// worktree, index, object database, config, helpers, prompts, pager or diff
/// implementation away from the explicit `-C <repoPath>` target.
fn hardened_git_command(repo_path: &Path, args: &[&str]) -> Result<Command, String> {
    let mut command = Command::new(resolved_git_executable(repo_path)?);
    remove_untrusted_git_environment(&mut command, env::vars_os());

    let null_config = if cfg!(windows) { "NUL" } else { "/dev/null" };
    command
        .arg("--no-pager")
        .arg("--no-optional-locks")
        .arg("--no-replace-objects")
        .arg("--literal-pathspecs")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.untrackedCache=false")
        .arg("-c")
        .arg("diff.external=")
        .arg("-c")
        .arg("core.pager=")
        .arg("-c")
        .arg("color.ui=false")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_config)
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_LITERAL_PATHSPECS", "1")
        .env("GIT_PAGER", "")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    Ok(command)
}

fn remove_untrusted_git_environment(
    command: &mut Command,
    inherited: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) {
    for (key, _) in inherited {
        let normalized = key.to_string_lossy().to_ascii_uppercase();
        if normalized.starts_with("GIT_")
            || normalized.starts_with("GCM_")
            || normalized.starts_with("DYLD_")
            || matches!(
                normalized.as_str(),
                "SSH_ASKPASS"
                    | "SSH_ASKPASS_REQUIRE"
                    | "PAGER"
                    | "LESS"
                    | "LV"
                    | "LD_PRELOAD"
                    | "LD_LIBRARY_PATH"
            )
        {
            command.env_remove(key);
        }
    }
}

struct GitProcessTree {
    #[cfg(unix)]
    process_group: i32,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    root_process_id: u32,
}

impl GitProcessTree {
    fn attach(child: &std::process::Child) -> io::Result<Self> {
        #[cfg(unix)]
        {
            return Ok(Self {
                process_group: child.id() as i32,
            });
        }
        #[cfg(windows)]
        {
            use std::mem::{size_of, zeroed};
            use std::os::windows::io::AsRawHandle;
            use std::ptr;
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            };
            let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                let error = io::Error::last_os_error();
                unsafe {
                    CloseHandle(job);
                }
                return Err(error);
            }
            let process = child.as_raw_handle() as HANDLE;
            if unsafe { AssignProcessToJobObject(job, process) } == 0 {
                let error = io::Error::last_os_error();
                unsafe {
                    CloseHandle(job);
                }
                return Err(error);
            }
            if let Err(error) = resume_suspended_windows_process(child.id()) {
                unsafe {
                    windows_sys::Win32::System::JobObjects::TerminateJobObject(job, 1);
                    CloseHandle(job);
                }
                return Err(error);
            }
            Ok(Self {
                job,
                root_process_id: child.id(),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Ok(Self {})
        }
    }

    fn terminate_descendants(&self) {
        #[cfg(unix)]
        unsafe {
            // The command was spawned as leader of a fresh process group, so
            // this kills Git plus helpers/descendants that inherited its pipes.
            let _ = libc::killpg(self.process_group, libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            let _ = windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
            terminate_windows_descendants(self.root_process_id);
        }
    }

    fn terminate(&self, child: &mut std::process::Child) {
        self.terminate_descendants();
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(windows)]
unsafe fn terminate_windows_descendants(root_process_id: u32) {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == INVALID_HANDLE_VALUE {
        return;
    }
    let mut entry = PROCESSENTRY32 {
        dwSize: size_of::<PROCESSENTRY32>() as u32,
        ..PROCESSENTRY32::default()
    };
    let mut processes = Vec::new();
    let mut found = Process32First(snapshot, &mut entry) != 0;
    while found && processes.len() < 65_536 {
        processes.push((entry.th32ProcessID, entry.th32ParentProcessID));
        found = Process32Next(snapshot, &mut entry) != 0;
    }
    CloseHandle(snapshot);

    let mut descendants = vec![root_process_id];
    loop {
        let before = descendants.len();
        for (process_id, parent_id) in &processes {
            if descendants.contains(parent_id) && !descendants.contains(process_id) {
                descendants.push(*process_id);
            }
        }
        if descendants.len() == before {
            break;
        }
    }
    // Deepest descendants were discovered last. Kill in reverse order so a
    // helper cannot create another child after its parent has been removed.
    for process_id in descendants.into_iter().skip(1).rev() {
        let process = OpenProcess(PROCESS_TERMINATE, 0, process_id);
        if !process.is_null() {
            let _ = TerminateProcess(process, 1);
            CloseHandle(process);
        }
    }
}

#[cfg(windows)]
fn resume_suspended_windows_process(process_id: u32) -> io::Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    let mut found = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while found {
        if entry.th32OwnerProcessID == process_id {
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                let error = io::Error::last_os_error();
                unsafe { CloseHandle(snapshot) };
                return Err(error);
            }
            let previous_count = unsafe { ResumeThread(thread) };
            let resume_error = (previous_count == u32::MAX).then(io::Error::last_os_error);
            unsafe {
                CloseHandle(thread);
                CloseHandle(snapshot);
            }
            return match resume_error {
                Some(error) => Err(error),
                None => Ok(()),
            };
        }
        found = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "cannot find the primary thread of suspended Git process",
    ))
}

#[cfg(windows)]
impl Drop for GitProcessTree {
    fn drop(&mut self) {
        self.terminate_descendants();
        unsafe {
            // KILL_ON_JOB_CLOSE guarantees no helper survives a successful or
            // failing invocation, including descendants that closed stdout.
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

#[cfg(unix)]
impl Drop for GitProcessTree {
    fn drop(&mut self) {
        // The group is unique to this invocation. Kill it even after Git
        // exited cleanly: a helper may have closed both captured pipes and
        // otherwise survive unnoticed in the background.
        self.terminate_descendants();
    }
}

#[cfg(unix)]
fn configure_git_pipe_nonblocking<T: std::os::unix::io::AsRawFd>(pipe: &T) -> io::Result<()> {
    let descriptor = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn configure_git_pipe_nonblocking<T: std::os::windows::io::AsRawHandle>(
    _pipe: &T,
) -> io::Result<()> {
    // Anonymous-pipe read handles do not necessarily have the write-attribute
    // right required by SetNamedPipeHandleState. The Windows reader below
    // uses PeekNamedPipe and calls Read only when bytes are available.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn configure_git_pipe_nonblocking<T>(_pipe: &T) -> io::Result<()> {
    Ok(())
}

fn execute_git(
    repo_path: &Path,
    args: &[&str],
    stdout_capture_bytes: usize,
    stdout_max_bytes: usize,
    timeout: Duration,
) -> Result<GitProcessOutput, JsonRpcError> {
    let command =
        hardened_git_command(repo_path, args).map_err(|error| local_git_error(args, error))?;
    execute_git_command(
        command,
        args,
        stdout_capture_bytes,
        stdout_max_bytes,
        timeout,
    )
}

fn execute_git_command(
    mut command: Command,
    args: &[&str],
    stdout_capture_bytes: usize,
    stdout_max_bytes: usize,
    timeout: Duration,
) -> Result<GitProcessOutput, JsonRpcError> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        // Close the spawn/AssignProcessToJobObject race: Git cannot create a
        // helper until the process is inside its kill-on-close job.
        command.creation_flags(CREATE_SUSPENDED);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| local_git_error(args, error.to_string()))?;

    let process_tree = match GitProcessTree::attach(&child) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(local_git_error(
                args,
                format!("cannot establish isolated Git process tree: {error}"),
            ));
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            process_tree.terminate(&mut child);
            return Err(local_git_error(
                args,
                "failed to capture git stdout".to_string(),
            ));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            process_tree.terminate(&mut child);
            return Err(local_git_error(
                args,
                "failed to capture git stderr".to_string(),
            ));
        }
    };
    if let Err(error) = configure_git_pipe_nonblocking(&stdout)
        .and_then(|_| configure_git_pipe_nonblocking(&stderr))
    {
        process_tree.terminate(&mut child);
        return Err(local_git_error(
            args,
            format!("cannot make Git output pipes cancellation-safe: {error}"),
        ));
    }
    let stop_reason = Arc::new(AtomicU8::new(0));
    let stdout_stop = Arc::clone(&stop_reason);
    let stderr_stop = Arc::clone(&stop_reason);
    let stdout_reader = std::thread::spawn(move || {
        read_git_stream(
            stdout,
            stdout_capture_bytes,
            stdout_max_bytes,
            1,
            stdout_stop,
        )
    });
    let stderr_reader = std::thread::spawn(move || {
        read_git_stream(
            stderr,
            GIT_STDERR_CAPTURE_BYTES,
            GIT_STDERR_MAX_BYTES,
            2,
            stderr_stop,
        )
    });

    let started = Instant::now();
    let mut status = None;
    loop {
        let reason = stop_reason.load(Ordering::Acquire);
        if reason != 0 {
            break;
        }
        if started.elapsed() >= timeout {
            stop_reason.store(3, Ordering::Release);
            break;
        }
        match child.try_wait() {
            Ok(Some(exit_status)) => {
                status = Some(exit_status);
                break;
            }
            Ok(None) => std::thread::sleep(GIT_COMMAND_POLL_INTERVAL),
            Err(_error) => {
                stop_reason.store(4, Ordering::Release);
                break;
            }
        }
    }

    if status.is_none() {
        process_tree.terminate(&mut child);
    }

    if status.is_some() {
        // A hostile helper can outlive the direct child while retaining an
        // inherited pipe. Readers are nonblocking, so the main thread can stop
        // them, terminate the complete tree, and always join them.
        let stream_deadline = Instant::now() + GIT_STREAM_CLOSE_TIMEOUT;
        while !stdout_reader.is_finished() || !stderr_reader.is_finished() {
            if stop_reason.load(Ordering::Acquire) != 0 {
                process_tree.terminate(&mut child);
                break;
            }
            if Instant::now() >= stream_deadline {
                stop_reason.store(5, Ordering::Release);
                process_tree.terminate(&mut child);
                break;
            }
            std::thread::sleep(GIT_COMMAND_POLL_INTERVAL);
        }
    }

    // Nonblocking readers observe stop_reason within one poll and therefore
    // cannot be left detached on any timeout/output-cap/error path.
    let stdout = stdout_reader
        .join()
        .map_err(|_| local_git_error(args, "git stdout reader panicked".to_string()))?
        .map_err(|error| local_git_error(args, format!("cannot read git stdout: {error}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| local_git_error(args, "git stderr reader panicked".to_string()))?
        .map_err(|error| local_git_error(args, format!("cannot read git stderr: {error}")))?;

    let final_reason = stop_reason.load(Ordering::Acquire);
    if final_reason != 0 {
        return Err(git_stop_error(
            args,
            final_reason,
            stdout_max_bytes,
            timeout,
        ));
    }

    let status = status.ok_or_else(|| {
        local_git_error(
            args,
            "git process terminated without an exit status".to_string(),
        )
    })?;
    // Success belongs to the direct Git process only. Helpers are never part
    // of the MCP result and must not survive merely because they closed both
    // output pipes before the direct process exited.
    process_tree.terminate_descendants();
    Ok(GitProcessOutput {
        status,
        stdout,
        stderr,
    })
}

fn git_stop_error(
    args: &[&str],
    reason: u8,
    stdout_max_bytes: usize,
    timeout: Duration,
) -> JsonRpcError {
    let details = match reason {
        1 => format!(
            "git stdout exceeded the {stdout_max_bytes}-byte safety limit; no partial result was returned as complete"
        ),
        2 => format!("git stderr exceeded the {GIT_STDERR_MAX_BYTES}-byte safety limit"),
        3 => format!("git command exceeded the {}-second timeout", timeout.as_secs()),
        4 => "failed while waiting for git process".to_string(),
        5 => "git exited but a descendant retained an output pipe past the safety deadline"
            .to_string(),
        _ => "git process stopped at the hardened execution boundary".to_string(),
    };
    local_git_error(args, details)
}

trait CancellableGitReader: Read {
    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

#[cfg(not(windows))]
impl<T: Read> CancellableGitReader for T {
    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.read(buffer)
    }
}

#[cfg(windows)]
fn windows_read_git_pipe<T: Read + std::os::windows::io::AsRawHandle>(
    reader: &mut T,
    buffer: &mut [u8],
) -> io::Result<usize> {
    use std::ptr;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0u32;
    let result = unsafe {
        PeekNamedPipe(
            reader.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(109 | 232 | 233)) {
            return Ok(0);
        }
        return Err(error);
    }
    if available == 0 {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    let limit = buffer.len().min(available as usize);
    reader.read(&mut buffer[..limit])
}

#[cfg(windows)]
impl CancellableGitReader for std::process::ChildStdout {
    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        windows_read_git_pipe(self, buffer)
    }
}

#[cfg(windows)]
impl CancellableGitReader for std::process::ChildStderr {
    fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        windows_read_git_pipe(self, buffer)
    }
}

fn read_git_stream(
    mut reader: impl CancellableGitReader,
    capture_bytes: usize,
    max_bytes: usize,
    limit_reason: u8,
    stop_reason: Arc<AtomicU8>,
) -> io::Result<GitStreamOutput> {
    let mut prefix = Vec::with_capacity(capture_bytes.min(65_536));
    let mut total_bytes = 0_u64;
    let mut newline_count = 0_u64;
    let mut last_byte = None;
    let mut buffer = [0_u8; 16_384];
    loop {
        if stop_reason.load(Ordering::Acquire) != 0 {
            let total_lines = newline_count
                .saturating_add(u64::from(total_bytes > 0 && last_byte != Some(b'\n')));
            return Ok(GitStreamOutput {
                prefix,
                total_bytes,
                total_lines,
            });
        }
        let read = match reader.read_available(&mut buffer) {
            Ok(read) => read,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::Interrupted
                    || matches!(error.raw_os_error(), Some(232 | 233)) =>
            {
                std::thread::sleep(GIT_COMMAND_POLL_INTERVAL);
                continue;
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            let total_lines = newline_count
                .saturating_add(u64::from(total_bytes > 0 && last_byte != Some(b'\n')));
            return Ok(GitStreamOutput {
                prefix,
                total_bytes,
                total_lines,
            });
        }
        total_bytes = total_bytes.saturating_add(read as u64);
        newline_count = newline_count
            .saturating_add(buffer[..read].iter().filter(|byte| **byte == b'\n').count() as u64);
        last_byte = Some(buffer[read - 1]);
        let remaining = capture_bytes.saturating_sub(prefix.len());
        prefix.extend_from_slice(&buffer[..read.min(remaining)]);
        if total_bytes > max_bytes as u64 {
            let _ =
                stop_reason.compare_exchange(0, limit_reason, Ordering::AcqRel, Ordering::Acquire);
            let total_lines = newline_count
                .saturating_add(u64::from(total_bytes > 0 && last_byte != Some(b'\n')));
            return Ok(GitStreamOutput {
                prefix,
                total_bytes,
                total_lines,
            });
        }
    }
}

fn run_git_optional(repo_path: &Path, args: &[&str]) -> Option<String> {
    run_git(repo_path, args)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn run_git_status(repo_path: &Path, args: &[&str]) -> bool {
    execute_git(
        repo_path,
        args,
        GIT_COMPLETE_STDOUT_MAX_BYTES,
        GIT_COMPLETE_STDOUT_MAX_BYTES,
        GIT_COMMAND_TIMEOUT,
    )
    .map(|output| output.status.success())
    .unwrap_or(false)
}

fn clean_mcp_ref_label(ref_name: &str) -> String {
    ref_name
        .trim()
        .trim_start_matches("refs/heads/")
        .trim_start_matches("refs/remotes/")
        .to_string()
}

fn ahead_behind(repo_path: &Path, left: &str, right: &str) -> Option<(i64, i64)> {
    let range = format!("{left}...{right}");
    let output = run_git_optional(repo_path, &["rev-list", "--left-right", "--count", &range])?;
    let mut parts = output.split_whitespace();
    let ahead = parts.next()?.parse().ok()?;
    let behind = parts.next()?.parse().ok()?;
    Some((ahead, behind))
}

fn resolve_branch_stack_base_ref(
    repo_path: &Path,
    base_candidates: &[String],
    current_ref: Option<&str>,
) -> Option<String> {
    for name in base_candidates {
        for prefix in ["refs/heads/", "refs/remotes/origin/"] {
            let candidate = format!("{prefix}{name}");
            if current_ref == Some(candidate.as_str()) {
                continue;
            }
            if run_git_status(repo_path, &["rev-parse", "--verify", "-q", &candidate]) {
                return Some(candidate);
            }
        }
    }
    None
}

fn discover_related_branch_stack_refs(
    repo_path: &Path,
    current_ref: Option<&str>,
    base_ref: Option<&str>,
    max_related: usize,
) -> Vec<Value> {
    let Some(current_ref) = current_ref else {
        return Vec::new();
    };
    let output = run_git_optional(
        repo_path,
        &[
            "for-each-ref",
            "--format=%(refname)%09%(objectname)%09%(upstream)",
            "refs/heads",
        ],
    )
    .unwrap_or_default();
    let mut related = Vec::new();

    for line in output.lines() {
        let mut parts = line.split('\t');
        let ref_name = parts.next().unwrap_or_default();
        let object = parts.next().unwrap_or_default();
        let upstream = parts.next().filter(|value| !value.is_empty());
        if ref_name.is_empty() || ref_name == current_ref || base_ref == Some(ref_name) {
            continue;
        }

        let relation = if upstream == Some(current_ref) {
            Some("tracks-current")
        } else if run_git_status(
            repo_path,
            &["merge-base", "--is-ancestor", current_ref, ref_name],
        ) {
            Some("descends-from-current")
        } else if let Some(base_ref) = base_ref {
            if upstream == Some(base_ref) {
                Some("shares-base")
            } else {
                None
            }
        } else {
            None
        };

        let Some(relation) = relation else {
            continue;
        };
        let (ahead, behind) = ahead_behind(repo_path, ref_name, current_ref).unwrap_or((0, 0));
        related.push(json!({
            "ref": ref_name,
            "label": clean_mcp_ref_label(ref_name),
            "commit": object,
            "relation": relation,
            "aheadOfCurrent": ahead,
            "behindCurrent": behind,
            "upstream": upstream,
        }));
        if related.len() >= max_related {
            break;
        }
    }

    related
}

fn local_git_error(args: &[&str], details: String) -> JsonRpcError {
    JsonRpcError {
        code: 10010,
        message: "Local git fallback failed".into(),
        data: Some(json!({
            "command": std::iter::once("git")
                .chain(std::iter::once("-C"))
                .chain(std::iter::once("<repoPath>"))
                .chain(args.iter().copied())
                .collect::<Vec<_>>(),
            "details": details,
        })),
    }
}

fn invalid_params_error(details: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: "Invalid params".into(),
        data: Some(json!({ "details": details })),
    }
}

/// Rejects a caller-supplied revision/ref that git would read as an option.
///
/// This is what keeps the read-only guarantee actually true. Every tool here is
/// annotated `read_only_hint: true` and listed in `READ_ONLY_TOOL_KINDS`, but
/// the git commands underneath take option-like positional values: `git diff`,
/// `git log` and `git show` all accept `--output=<file>`, which truncates and
/// writes that file. Without this guard an agent could call `diff.text` with
/// `base: "--output=/home/user/.zshrc"` and turn a read-only tool into an
/// arbitrary file write. git-core guards its own argv the same way (see
/// `commitish_arg_for_repo`); the sidecar had no equivalent.
///
/// Anything starting with `-` is refused outright. A legitimate revision never
/// does — `git rev-parse` itself will not resolve one — so this rejects no real
/// input. Callers that need a literal path use the `--` separator instead.
fn checked_rev<'a>(value: &'a str, field: &str) -> Result<&'a str, JsonRpcError> {
    if value.starts_with('-') {
        return Err(invalid_params_error(&format!(
            "{field} must not start with '-': git would read it as an option rather than a revision"
        )));
    }
    Ok(value)
}

/// `checked_rev` for optional arguments: `None` stays `None`, `Some` is checked.
fn checked_rev_opt<'a>(
    value: Option<&'a str>,
    field: &str,
) -> Result<Option<&'a str>, JsonRpcError> {
    match value {
        Some(value) => checked_rev(value, field).map(Some),
        None => Ok(None),
    }
}

fn parse_status_header(header: &str) -> (Option<String>, i64, i64) {
    let mut ahead = 0;
    let mut behind = 0;
    let branch = header
        .split("...")
        .next()
        .map(|branch| branch.trim().to_string());

    if let Some(metadata) = header
        .split('[')
        .nth(1)
        .and_then(|part| part.strip_suffix(']'))
    {
        for part in metadata.split(',') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("ahead ") {
                ahead = value.parse().unwrap_or(0);
            }
            if let Some(value) = part.strip_prefix("behind ") {
                behind = value.parse().unwrap_or(0);
            }
        }
    }

    (branch, ahead, behind)
}

fn status_entry_json(line: &str) -> Value {
    json!({
        "status": line.get(0..2).unwrap_or(""),
        "path": line.get(3..).unwrap_or(""),
    })
}

fn lines_json(output: String) -> Vec<Value> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| json!(line.trim()))
        .collect()
}

fn parse_history_line(line: &str) -> Option<Value> {
    let parts: Vec<&str> = line.splitn(6, '\x1f').collect();
    if parts.len() != 6 {
        return None;
    }
    Some(json!({
        "hash": parts[0],
        "shortHash": parts[1],
        "authorName": parts[2],
        "authorEmail": parts[3],
        "authorTime": parts[4].parse::<i64>().unwrap_or_default(),
        "subject": parts[5],
    }))
}

fn parse_commit_details(details: &str) -> Value {
    let parts: Vec<&str> = details.splitn(7, '\x1f').collect();
    json!({
        "hash": parts.first().copied().unwrap_or_default(),
        "shortHash": parts.get(1).copied().unwrap_or_default(),
        "authorName": parts.get(2).copied().unwrap_or_default(),
        "authorEmail": parts.get(3).copied().unwrap_or_default(),
        "authorTime": parts.get(4).and_then(|value| value.parse::<i64>().ok()).unwrap_or_default(),
        "parents": parts.get(5).copied().unwrap_or_default().split_whitespace().collect::<Vec<_>>(),
        "message": parts.get(6).copied().unwrap_or_default().trim_end(),
    })
}

fn parse_reflog_line(line: &str) -> Option<Value> {
    let parts: Vec<&str> = line.splitn(7, '\x1f').collect();
    if parts.len() != 7 {
        return None;
    }
    Some(json!({
        "newCommit": parts[0],
        "shortNewCommit": parts[1],
        "selector": parts[2],
        "message": parts[3],
        "authorName": parts[4],
        "authorEmail": parts[5],
        "timestamp": parts[6].parse::<i64>().unwrap_or_default(),
    }))
}

fn parse_name_status(line: &str) -> Value {
    let mut parts = line.split_whitespace();
    json!({
        "status": parts.next().unwrap_or_default(),
        "path": parts.next().unwrap_or_default(),
    })
}

impl InitializeResult {
    fn new() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            capabilities: server_capabilities_json(),
            server_info: ServerInfo {
                name: SERVER_NAME,
                version: SERVER_VERSION,
            },
            instructions: MCP_INSTRUCTIONS,
        }
    }
}

impl ToolKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "safety.timeline" => Some(Self::SafetyTimeline),
            "safety.eventDetails" => Some(Self::SafetyEventDetails),
            "fleet.radar" => Some(Self::FleetRadar),
            "repo.brief" => Some(Self::RepoBrief),
            "repo.scope" => Some(Self::RepoScope),
            "repo.status" => Some(Self::RepoStatus),
            "repo.refs" => Some(Self::RepoRefs),
            "repo.branchStack" => Some(Self::RepoBranchStack),
            "repo.conflictPreflight" => Some(Self::RepoConflictPreflight),
            "conflict.read" => Some(Self::ConflictRead),
            "repo.reflog" => Some(Self::RepoReflog),
            "repo.history" => Some(Self::RepoHistory),
            "commit.details" => Some(Self::CommitDetails),
            "worktree.changes" => Some(Self::WorktreeChanges),
            "worktree.list" => Some(Self::WorktreeList),
            "submodule.status" => Some(Self::SubmoduleStatus),
            "diff.text" => Some(Self::DiffText),
            "diff.semantic" => Some(Self::DiffSemantic),
            "diff.semanticFallbacks" => Some(Self::DiffSemanticFallbacks),
            "flux.latestRestorePoint" => Some(Self::FluxLatestRestorePoint),
            "flux.restorePoints" => Some(Self::FluxRestorePoints),
            "flux.restorePointDetails" => Some(Self::FluxRestorePointDetails),
            "operation.status" => Some(Self::OperationStatus),
            "operation.cancel" => Some(Self::OperationCancel),
            "operation.preview.merge" => Some(Self::OperationPreviewMerge),
            "operation.preview.rebase" => Some(Self::OperationPreviewRebase),
            "operation.preview.discard" => Some(Self::OperationPreviewDiscard),
            "operation.preview.reset" => Some(Self::OperationPreviewReset),
            "operation.preview.patch" => Some(Self::OperationPreviewPatch),
            "operation.preview.plan" => Some(Self::OperationPreviewPlan),
            "operation.preview.worktree" => Some(Self::OperationPreviewWorktree),
            "operation.preview.commit" => Some(Self::OperationPreviewCommit),
            "operation.preview.push" => Some(Self::OperationPreviewPush),
            "operation.preview.branch" => Some(Self::OperationPreviewBranch),
            _ => None,
        }
    }
}

fn read_only_tools() -> Vec<ToolSpec> {
    READ_ONLY_TOOL_KINDS
        .iter()
        .copied()
        .map(|kind| ToolSpec {
            name: kind.as_str(),
            title: tool_title(kind),
            description: tool_description(kind),
            input_schema: tool_input_schema(kind),
            output_schema: tool_output_schema(kind, true),
            annotations: Some(ToolAnnotations {
                read_only_hint: true,
                destructive_hint: None,
                idempotent_hint: true,
                open_world_hint: false,
            }),
        })
        .collect()
}

fn write_handshake_tools() -> Vec<ToolSpec> {
    WRITE_HANDSHAKE_TOOL_KINDS
        .iter()
        .copied()
        .map(|kind| ToolSpec {
            name: kind.as_str(),
            title: tool_title(kind),
            description: tool_description(kind),
            input_schema: tool_input_schema(kind),
            output_schema: tool_output_schema(kind, false),
            annotations: Some(ToolAnnotations {
                read_only_hint: false,
                // Be explicit instead of relying on MCP's destructive=true
                // default. These proposals can rewrite existing refs/files or
                // contain a destructive plan step; additive-only operations
                // and proposal cancellation advertise false.
                destructive_hint: Some(matches!(
                    kind,
                    ToolKind::OperationPreviewMerge
                        | ToolKind::OperationPreviewRebase
                        | ToolKind::OperationPreviewDiscard
                        | ToolKind::OperationPreviewReset
                        | ToolKind::OperationPreviewPatch
                        | ToolKind::OperationPreviewPlan
                        | ToolKind::OperationPreviewPush
                )),
                // Cancellation is idempotent. Preview admission has bounded
                // deduplication, but after lifecycle retention/pruning the same
                // call may create a fresh card and ultimately another Git
                // effect, so MCP's stronger idempotence hint must stay false.
                idempotent_hint: kind == ToolKind::OperationCancel,
                // Only push crosses the local FluxGit/repository boundary.
                open_world_hint: kind == ToolKind::OperationPreviewPush,
            }),
        })
        .collect()
}

fn tool_output_schema(kind: ToolKind, read_only: bool) -> Value {
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "tool": { "const": kind.as_str() },
            "readOnly": { "const": read_only },
            "source": tool_output_source_schema(kind),
            "tier": tool_output_tier_schema(kind),
            "repoPath": { "type": "string" },
            "data": tool_data_schema(kind),
            "error": tool_error_schema(),
            "previewId": preview_id_output_schema(),
            "status": lifecycle_status_schema(true),
            "accepted": { "const": true },
            "nextAction": preview_next_action_schema()
        },
        "required": ["tool", "readOnly"],
        // The envelope and today's stable fields are strict enough for an MCP
        // client to consume directly. Objects remain open for additive fields
        // from a newer FluxGit gateway/desktop, which is important because the
        // sidecar and app can be upgraded independently.
        "additionalProperties": true
    });
    schema["anyOf"] = tool_output_variants(kind);
    schema
}

fn tool_output_source_schema(kind: ToolKind) -> Value {
    match kind {
        ToolKind::DiffSemantic | ToolKind::DiffSemanticFallbacks => {
            json!({ "enum": ["local-git", "fluxgit-gateway"] })
        }
        ToolKind::OperationStatus
        | ToolKind::OperationCancel
        | ToolKind::OperationPreviewMerge
        | ToolKind::OperationPreviewRebase
        | ToolKind::OperationPreviewDiscard
        | ToolKind::OperationPreviewReset
        | ToolKind::OperationPreviewPatch
        | ToolKind::OperationPreviewPlan
        | ToolKind::OperationPreviewWorktree
        | ToolKind::OperationPreviewCommit
        | ToolKind::OperationPreviewPush
        | ToolKind::OperationPreviewBranch => json!({ "const": "fluxgit-app" }),
        _ => json!({ "const": "local-git" }),
    }
}

fn tool_output_tier_schema(kind: ToolKind) -> Value {
    match kind {
        ToolKind::OperationStatus
        | ToolKind::OperationCancel
        | ToolKind::OperationPreviewMerge
        | ToolKind::OperationPreviewRebase
        | ToolKind::OperationPreviewDiscard
        | ToolKind::OperationPreviewReset
        | ToolKind::OperationPreviewPatch
        | ToolKind::OperationPreviewPlan
        | ToolKind::OperationPreviewWorktree
        | ToolKind::OperationPreviewCommit
        | ToolKind::OperationPreviewPush
        | ToolKind::OperationPreviewBranch => {
            json!({ "const": "fluxgit-write-handshake" })
        }
        ToolKind::SafetyTimeline
        | ToolKind::SafetyEventDetails
        | ToolKind::FluxLatestRestorePoint
        | ToolKind::FluxRestorePoints
        | ToolKind::FluxRestorePointDetails => json!({ "const": "fluxgit" }),
        ToolKind::FleetRadar
        | ToolKind::RepoConflictPreflight
        | ToolKind::DiffSemantic
        | ToolKind::DiffSemanticFallbacks => json!({ "const": "hybrid" }),
        _ => json!({ "const": "free" }),
    }
}

fn tool_output_variants(kind: ToolKind) -> Value {
    match kind {
        ToolKind::OperationPreviewMerge
        | ToolKind::OperationPreviewRebase
        | ToolKind::OperationPreviewDiscard
        | ToolKind::OperationPreviewReset
        | ToolKind::OperationPreviewPatch
        | ToolKind::OperationPreviewPlan
        | ToolKind::OperationPreviewWorktree
        | ToolKind::OperationPreviewCommit
        | ToolKind::OperationPreviewPush
        | ToolKind::OperationPreviewBranch => json!([
            {
                "type": "object",
                "properties": { "status": { "const": "completed" } },
                "required": ["source", "tier", "previewId", "status", "data"]
            },
            {
                "type": "object",
                "properties": {
                    "status": live_lifecycle_status_schema(),
                    "accepted": { "const": true }
                },
                "required": ["source", "tier", "previewId", "status", "accepted", "nextAction"]
            },
            {
                "type": "object",
                "properties": {
                    "status": { "enum": ["rejected", "failed", "expired", "cancelled"] }
                },
                "required": ["source", "tier", "previewId", "status", "error"]
            },
            {
                "type": "object",
                "properties": { "status": { "const": "refused" } },
                "required": ["source", "tier", "previewId", "status", "error"]
            },
            {
                "type": "object",
                "required": ["tier", "error"]
            }
        ]),
        ToolKind::OperationStatus => json!([
            {
                "type": "object",
                "required": ["source", "tier", "previewId", "data"]
            },
            {
                "type": "object",
                "required": ["tier", "error"]
            }
        ]),
        ToolKind::OperationCancel => json!([
            {
                "type": "object",
                "properties": { "status": { "const": "cancelled" } },
                "required": ["source", "tier", "previewId", "status", "data"]
            },
            {
                "type": "object",
                "required": ["tier", "error"]
            }
        ]),
        ToolKind::FleetRadar => json!([
            { "type": "object", "required": ["source", "data"] },
            { "type": "object", "required": ["error"] }
        ]),
        _ => json!([
            { "type": "object", "required": ["source", "repoPath", "data"] },
            { "type": "object", "required": ["error"] }
        ]),
    }
}

fn tool_data_schema(kind: ToolKind) -> Value {
    match kind {
        ToolKind::RepoBrief => repo_brief_output_schema(),
        ToolKind::RepoScope => repo_scope_output_schema(),
        ToolKind::SafetyTimeline => safety_timeline_output_schema(),
        ToolKind::SafetyEventDetails => safety_event_details_output_schema(),
        ToolKind::FleetRadar => fleet_radar_output_schema(),
        ToolKind::RepoStatus => repo_status_output_schema(),
        ToolKind::RepoRefs => repo_refs_output_schema(),
        ToolKind::RepoBranchStack => repo_branch_stack_output_schema(),
        ToolKind::RepoConflictPreflight => repo_conflict_preflight_output_schema(),
        ToolKind::ConflictRead => conflict_read_output_schema(),
        ToolKind::RepoReflog => repo_reflog_output_schema(),
        ToolKind::RepoHistory => repo_history_output_schema(),
        ToolKind::CommitDetails => commit_details_output_schema(),
        ToolKind::WorktreeChanges => worktree_changes_output_schema(),
        ToolKind::WorktreeList => worktree_list_output_schema(),
        ToolKind::SubmoduleStatus => submodule_status_output_schema(),
        ToolKind::DiffText => diff_text_output_schema(),
        ToolKind::DiffSemantic => diff_semantic_output_schema(),
        ToolKind::DiffSemanticFallbacks => diff_semantic_fallbacks_output_schema(),
        ToolKind::FluxLatestRestorePoint => flux_latest_restore_point_output_schema(),
        ToolKind::FluxRestorePoints => flux_restore_points_output_schema(),
        ToolKind::FluxRestorePointDetails => flux_restore_point_details_output_schema(),
        ToolKind::OperationStatus => gateway_raw_value_schema(
            operation_status_data_schema(None, None),
            "Official FluxGit status object; non-object JSON remains accepted for compatibility with older/custom loopback bridges.",
        ),
        ToolKind::OperationCancel => gateway_raw_value_schema(
            operation_cancel_data_schema(),
            "Official cancelled proposal object; non-object JSON remains accepted because the sidecar relays any successful loopback bridge body verbatim.",
        ),
        ToolKind::OperationPreviewMerge
        | ToolKind::OperationPreviewRebase
        | ToolKind::OperationPreviewDiscard
        | ToolKind::OperationPreviewReset
        | ToolKind::OperationPreviewPatch
        | ToolKind::OperationPreviewPlan
        | ToolKind::OperationPreviewWorktree
        | ToolKind::OperationPreviewCommit
        | ToolKind::OperationPreviewPush
        | ToolKind::OperationPreviewBranch => {
            operation_status_data_schema(Some(kind), Some("completed"))
        }
    }
}

fn output_object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": true,
    })
}

fn output_array(items: Value) -> Value {
    json!({ "type": "array", "items": items })
}

fn bounded_output_array(items: Value, maximum: usize) -> Value {
    json!({ "type": "array", "items": items, "maxItems": maximum })
}

fn nullable_output_schema(schema: Value) -> Value {
    json!({ "anyOf": [schema, { "type": "null" }] })
}

fn nullable_string_output_schema() -> Value {
    nullable_output_schema(json!({ "type": "string" }))
}

fn non_negative_integer_output_schema() -> Value {
    json!({ "type": "integer", "minimum": 0 })
}

fn preview_id_output_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[A-Za-z0-9_-]+$",
    })
}

fn lifecycle_status_schema(include_refused: bool) -> Value {
    let known = if include_refused {
        json!([
            "pending",
            "approved",
            "executing",
            "completed",
            "rejected",
            "failed",
            "expired",
            "cancelled",
            "refused"
        ])
    } else {
        json!([
            "pending",
            "approved",
            "executing",
            "completed",
            "rejected",
            "failed",
            "expired",
            "cancelled"
        ])
    };
    json!({
        "anyOf": [
            { "enum": known },
            {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z][a-z0-9_-]*$"
            }
        ]
    })
}

fn live_lifecycle_status_schema() -> Value {
    json!({
        "anyOf": [
            { "enum": ["pending", "approved", "executing"] },
            {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[a-z][a-z0-9_-]*$"
            }
        ]
    })
}

fn tool_error_schema() -> Value {
    output_object(
        json!({
            "code": { "type": "integer" },
            "message": { "type": "string" },
            "data": nullable_output_schema(output_object(json!({}), &[])),
        }),
        &["code", "message"],
    )
}

fn preview_next_action_schema() -> Value {
    output_object(
        json!({
            "tool": { "const": "operation.status" },
            "message": { "type": "string", "minLength": 1 },
            "data": output_object(
                json!({
                    "previewId": preview_id_output_schema(),
                    "lastStatus": lifecycle_status_schema(false),
                    "reason": { "type": "string", "minLength": 1 },
                    "agentRecommendation": { "type": "string", "minLength": 1 },
                }),
                &["previewId", "lastStatus", "reason", "agentRecommendation"],
            ),
        }),
        &["tool", "message", "data"],
    )
}

fn status_entry_output_schema() -> Value {
    output_object(
        json!({
            "status": { "type": "string" },
            "path": { "type": "string" },
        }),
        &["status", "path"],
    )
}

fn submodule_entry_output_schema() -> Value {
    output_object(
        json!({
            "state": { "enum": [" ", "-", "+", "U"] },
            "commit": { "type": "string" },
            "path": { "type": "string" },
            "description": { "type": "string" },
        }),
        &["state", "commit", "path", "description"],
    )
}

fn short_commit_output_schema() -> Value {
    output_object(
        json!({
            "sha": { "type": "string" },
            "subject": { "type": "string" },
        }),
        &["sha", "subject"],
    )
}

fn restore_point_output_schema() -> Value {
    output_object(
        json!({
            "repoId": { "type": "string", "minLength": 1 },
            "before": nullable_string_output_schema(),
            "after": nullable_string_output_schema(),
            "operation": nullable_string_output_schema(),
            "canUndo": { "type": "boolean" },
            "canRedo": { "type": "boolean" },
            "approvalRequired": { "const": true },
            "approvalMessage": { "type": "string", "minLength": 1 },
            "metadata": output_object(
                json!({
                    "checkpointPath": { "type": "string" },
                    "createdAt": nullable_output_schema(json!({ "type": "integer" })),
                    "branchRef": nullable_string_output_schema(),
                    "undone": { "type": "boolean" },
                    "beforeRef": nullable_string_output_schema(),
                    "afterRef": nullable_string_output_schema(),
                    "upstreamRef": nullable_string_output_schema(),
                    "resetMode": nullable_string_output_schema(),
                    // Stored checkpoints predate a fixed plan shape and the
                    // sidecar intentionally preserves any JSON value here.
                    "plan": {
                        "description": "Opaque checkpoint plan metadata preserved verbatim for compatibility."
                    },
                    "currentBranchRef": nullable_string_output_schema(),
                    "currentHead": nullable_string_output_schema(),
                }),
                &[
                    "checkpointPath", "createdAt", "branchRef", "undone", "beforeRef",
                    "afterRef", "upstreamRef", "resetMode", "plan", "currentBranchRef",
                    "currentHead",
                ],
            ),
        }),
        &[
            "repoId",
            "before",
            "after",
            "operation",
            "canUndo",
            "canRedo",
            "approvalRequired",
            "approvalMessage",
            "metadata",
        ],
    )
}

fn safety_event_output_schema() -> Value {
    let mut schema = output_object(
        json!({
            "id": { "type": "string", "minLength": 1 },
            "repoLabel": { "type": "string" },
            "source": { "enum": ["restore_point", "reflog"] },
            "kind": { "enum": ["restore_created", "ref_move"] },
            "severity": { "enum": ["info", "warning"] },
            "title": { "type": "string" },
            "summary": { "type": "string" },
            "occurredAtUnix": { "type": "integer" },
            "headBefore": nullable_string_output_schema(),
            "headAfter": nullable_string_output_schema(),
            "restorePoint": restore_point_output_schema(),
            "reflogSelector": { "type": "string" },
            "canCompare": { "type": "boolean" },
            "actions": bounded_output_array(
                json!({
                    "enum": [
                        "openRestorePoint", "openReflogEntry", "compareBeforeAfter",
                        "createRescueBranch", "copyRedactedSummary"
                    ]
                }),
                4,
            ),
            "approvalRequired": { "const": true },
            "networkFetchPerformed": { "const": false },
        }),
        &[
            "id",
            "repoLabel",
            "source",
            "kind",
            "severity",
            "title",
            "summary",
            "occurredAtUnix",
            "headBefore",
            "headAfter",
            "actions",
            "approvalRequired",
            "networkFetchPerformed",
        ],
    );
    schema["anyOf"] = json!([
        {
            "properties": {
                "source": { "const": "restore_point" },
                "kind": { "const": "restore_created" }
            },
            "required": ["restorePoint"]
        },
        {
            "properties": {
                "source": { "const": "reflog" },
                "kind": { "const": "ref_move" }
            },
            "required": ["reflogSelector", "canCompare"]
        }
    ]);
    schema
}

fn repo_brief_output_schema() -> Value {
    output_object(
        json!({
            "head": output_object(
                json!({
                    "branch": nullable_string_output_schema(),
                    "detached": { "type": "boolean" },
                    "sha": nullable_string_output_schema(),
                    "upstream": nullable_string_output_schema(),
                    "ahead": non_negative_integer_output_schema(),
                    "behind": non_negative_integer_output_schema(),
                }),
                &["branch", "detached", "sha", "upstream", "ahead", "behind"],
            ),
            "operationInProgress": nullable_output_schema(json!({
                "enum": ["merge", "rebase", "cherry-pick", "revert", "bisect"]
            })),
            "workingTree": output_object(
                json!({
                    "clean": { "type": "boolean" },
                    "staged": non_negative_integer_output_schema(),
                    "unstaged": non_negative_integer_output_schema(),
                    "untracked": non_negative_integer_output_schema(),
                    "conflicted": non_negative_integer_output_schema(),
                }),
                &["clean", "staged", "unstaged", "untracked", "conflicted"],
            ),
            "stashes": non_negative_integer_output_schema(),
            "submodules": output_object(
                json!({
                    "total": non_negative_integer_output_schema(),
                    "clean": non_negative_integer_output_schema(),
                    "drifted": non_negative_integer_output_schema(),
                    "uninitialized": non_negative_integer_output_schema(),
                    "conflicts": non_negative_integer_output_schema(),
                    "attention": bounded_output_array(submodule_entry_output_schema(), 10),
                    "attentionTruncated": { "type": "boolean" },
                }),
                &[
                    "total", "clean", "drifted", "uninitialized", "conflicts", "attention",
                    "attentionTruncated",
                ],
            ),
            "recentCommits": bounded_output_array(short_commit_output_schema(), 20),
            "conventions": output_object(
                json!({
                    "conventionalCommitRatio": nullable_output_schema(json!({
                        "type": "number", "minimum": 0, "maximum": 1
                    })),
                    "defaultBranch": nullable_string_output_schema(),
                }),
                &["conventionalCommitRatio", "defaultBranch"],
            ),
            "hints": bounded_output_array(json!({ "type": "string" }), 3),
        }),
        &[
            "head",
            "operationInProgress",
            "workingTree",
            "stashes",
            "submodules",
            "recentCommits",
            "conventions",
            "hints",
        ],
    )
}

fn repo_scope_output_schema() -> Value {
    output_object(
        json!({
            "scope": { "type": "string", "minLength": 1 },
            "workingTree": output_object(
                json!({
                    "changed": non_negative_integer_output_schema(),
                    "entries": bounded_output_array(status_entry_output_schema(), 20),
                    "truncated": { "type": "boolean" },
                }),
                &["changed", "entries", "truncated"],
            ),
            "recentCommits": bounded_output_array(short_commit_output_schema(), 20),
            "churn": output_object(
                json!({
                    "days": { "type": "integer", "minimum": 1, "maximum": 365 },
                    "commits": non_negative_integer_output_schema(),
                    "authors": non_negative_integer_output_schema(),
                }),
                &["days", "commits", "authors"],
            ),
            "owners": nullable_output_schema(output_object(
                json!({
                    "source": { "type": "string" },
                    "matchedPattern": nullable_string_output_schema(),
                    "owners": output_array(json!({ "type": "string" })),
                    "matching": { "const": "simplified-prefix (last match wins)" },
                }),
                &["source", "matchedPattern", "owners", "matching"],
            )),
            "hints": bounded_output_array(json!({ "type": "string" }), 3),
        }),
        &[
            "scope",
            "workingTree",
            "recentCommits",
            "churn",
            "owners",
            "hints",
        ],
    )
}

fn safety_timeline_output_schema() -> Value {
    output_object(
        json!({
            "events": bounded_output_array(safety_event_output_schema(), 200),
            "eventCount": { "type": "integer", "minimum": 0, "maximum": 200 },
            "readOnly": { "const": true },
            "approvalRequired": { "const": true },
            "approvalMessage": { "type": "string", "minLength": 1 },
            "networkFetchPerformed": { "const": false },
        }),
        &[
            "events",
            "eventCount",
            "readOnly",
            "approvalRequired",
            "approvalMessage",
            "networkFetchPerformed",
        ],
    )
}

fn safety_event_details_output_schema() -> Value {
    output_object(
        json!({
            "event": nullable_output_schema(safety_event_output_schema()),
            "eventFound": { "type": "boolean" },
            "readOnly": { "const": true },
            "approvalRequired": { "const": true },
            "approvalMessage": { "type": "string", "minLength": 1 },
        }),
        &[
            "event",
            "eventFound",
            "readOnly",
            "approvalRequired",
            "approvalMessage",
        ],
    )
}

fn fleet_entry_output_schema() -> Value {
    output_object(
        json!({
            "repoId": nullable_string_output_schema(),
            "label": { "type": "string" },
            "repoPath": { "type": "string" },
            "status": {
                "enum": [
                    "unknown", "conflict", "potential_conflict", "divergent",
                    "local_changes", "behind", "ahead", "no_upstream", "clean"
                ]
            },
            "priority": { "type": "integer", "minimum": 0, "maximum": 100 },
            "summary": { "type": "string" },
            "dirty": { "type": "boolean" },
            "changedFiles": non_negative_integer_output_schema(),
            "ahead": non_negative_integer_output_schema(),
            "behind": non_negative_integer_output_schema(),
            "hasUpstream": { "type": "boolean" },
            "upstream": nullable_string_output_schema(),
            "branch": nullable_string_output_schema(),
            "head": nullable_string_output_schema(),
            "shortHead": nullable_string_output_schema(),
            "conflictActive": { "type": "boolean" },
            "conflictOperation": nullable_output_schema(json!({
                "enum": ["merge", "rebase", "cherry-pick", "revert"]
            })),
            "potentialConflictActive": { "type": "boolean" },
            "potentialConflictCount": non_negative_integer_output_schema(),
            "potentialConflictTarget": nullable_string_output_schema(),
            "potentialConflictPaths": output_array(json!({ "type": "string" })),
            "lastCommitTimestamp": nullable_output_schema(json!({ "type": "integer" })),
            "elapsedMs": non_negative_integer_output_schema(),
            "error": { "type": "string" },
            "suggestedActions": output_array(json!({ "type": "string" })),
        }),
        &[
            "repoId",
            "label",
            "repoPath",
            "status",
            "priority",
            "summary",
            "dirty",
            "changedFiles",
            "ahead",
            "behind",
            "hasUpstream",
            "upstream",
            "branch",
            "head",
            "shortHead",
            "conflictActive",
            "conflictOperation",
            "potentialConflictActive",
            "potentialConflictCount",
            "potentialConflictTarget",
            "potentialConflictPaths",
            "lastCommitTimestamp",
            "elapsedMs",
            "error",
            "suggestedActions",
        ],
    )
}

fn fleet_attention_output_schema() -> Value {
    output_object(
        json!({
            "repoId": nullable_string_output_schema(),
            "label": { "type": "string" },
            "repoPath": { "type": "string" },
            "status": {
                "enum": [
                    "unknown", "conflict", "potential_conflict", "divergent",
                    "local_changes", "behind", "ahead", "no_upstream"
                ]
            },
            "priority": { "type": "integer", "minimum": 0, "maximum": 100 },
            "summary": { "type": "string" },
            "suggestedActions": output_array(json!({ "type": "string" })),
        }),
        &[
            "repoId",
            "label",
            "repoPath",
            "status",
            "priority",
            "summary",
            "suggestedActions",
        ],
    )
}

fn fleet_radar_output_schema() -> Value {
    output_object(
        json!({
            "entries": bounded_output_array(fleet_entry_output_schema(), 500),
            "attentionStack": bounded_output_array(fleet_attention_output_schema(), 500),
            "requestedCount": non_negative_integer_output_schema(),
            "scannedCount": { "type": "integer", "minimum": 0, "maximum": 500 },
            "failedCount": { "type": "integer", "minimum": 0, "maximum": 500 },
            "dirtyCount": { "type": "integer", "minimum": 0, "maximum": 500 },
            "conflictCount": { "type": "integer", "minimum": 0, "maximum": 500 },
            "truncatedCount": non_negative_integer_output_schema(),
            "elapsedMs": non_negative_integer_output_schema(),
            "network": output_object(
                json!({
                    "fetchPerformed": { "const": false },
                    "remoteStateSource": { "const": "cached local refs only" },
                }),
                &["fetchPerformed", "remoteStateSource"],
            ),
            "guidance": { "type": "string", "minLength": 1 },
        }),
        &[
            "entries",
            "attentionStack",
            "requestedCount",
            "scannedCount",
            "failedCount",
            "dirtyCount",
            "conflictCount",
            "truncatedCount",
            "elapsedMs",
            "network",
            "guidance",
        ],
    )
}

fn repo_status_output_schema() -> Value {
    output_object(
        json!({
            "branch": nullable_string_output_schema(),
            "ahead": non_negative_integer_output_schema(),
            "behind": non_negative_integer_output_schema(),
            "clean": { "type": "boolean" },
            "changedFiles": non_negative_integer_output_schema(),
            "entries": output_array(status_entry_output_schema()),
        }),
        &[
            "branch",
            "ahead",
            "behind",
            "clean",
            "changedFiles",
            "entries",
        ],
    )
}

fn repo_refs_output_schema() -> Value {
    let strings = || output_array(json!({ "type": "string" }));
    output_object(
        json!({
            "head": { "type": "string" },
            "branches": strings(),
            "tags": strings(),
            "remotes": strings(),
            "stashes": strings(),
        }),
        &["head", "branches", "tags", "remotes", "stashes"],
    )
}

fn repo_branch_stack_output_schema() -> Value {
    let distance = || {
        output_object(
            json!({
                "aheadFromBase": non_negative_integer_output_schema(),
                "behindBase": non_negative_integer_output_schema(),
            }),
            &["aheadFromBase", "behindBase"],
        )
    };
    output_object(
        json!({
            "current": output_object(
                json!({
                    "ref": nullable_string_output_schema(),
                    "label": { "type": "string" },
                    "commit": { "type": "string", "minLength": 1 },
                    "ahead": non_negative_integer_output_schema(),
                    "behind": non_negative_integer_output_schema(),
                }),
                &["ref", "label", "commit", "ahead", "behind"],
            ),
            "upstream": nullable_output_schema(output_object(
                json!({
                    "ref": { "type": "string", "minLength": 1 },
                    "label": { "type": "string" },
                    "commit": nullable_string_output_schema(),
                }),
                &["ref", "label", "commit"],
            )),
            "base": nullable_output_schema(output_object(
                json!({
                    "ref": { "type": "string", "minLength": 1 },
                    "label": { "type": "string" },
                    "commit": nullable_string_output_schema(),
                    "distance": nullable_output_schema(distance()),
                }),
                &["ref", "label", "commit", "distance"],
            )),
            "related": bounded_output_array(
                output_object(
                    json!({
                        "ref": { "type": "string", "minLength": 1 },
                        "label": { "type": "string" },
                        "commit": { "type": "string" },
                        "relation": {
                            "enum": ["tracks-current", "descends-from-current", "shares-base"]
                        },
                        "aheadOfCurrent": non_negative_integer_output_schema(),
                        "behindCurrent": non_negative_integer_output_schema(),
                        "upstream": nullable_string_output_schema(),
                    }),
                    &[
                        "ref", "label", "commit", "relation", "aheadOfCurrent",
                        "behindCurrent", "upstream",
                    ],
                ),
                50,
            ),
            "risk": { "enum": ["low", "medium", "high"] },
            "summary": { "type": "string" },
            "guidance": { "type": "string" },
            "suggestedActions": output_array(json!({
                "enum": [
                    "compareWithBase", "showAllBranchContext", "openSafetyTimeline",
                    "prepareGuardedRebasePlan"
                ]
            })),
            "model": { "const": "real-git-refs-no-virtual-branches" },
            "networkFetchPerformed": { "const": false },
            "readOnly": { "const": true },
        }),
        &[
            "current",
            "upstream",
            "base",
            "related",
            "risk",
            "summary",
            "guidance",
            "suggestedActions",
            "model",
            "networkFetchPerformed",
            "readOnly",
        ],
    )
}

fn repo_conflict_preflight_output_schema() -> Value {
    output_object(
        json!({
            "currentRef": { "type": "string", "minLength": 1 },
            "targetRef": { "type": "string", "minLength": 1 },
            "currentOid": { "type": "string", "minLength": 1 },
            "targetOid": { "type": "string", "minLength": 1 },
            "mergeBaseOid": nullable_string_output_schema(),
            "status": {
                "enum": [
                    "unrelated-histories", "already-up-to-date", "fast-forward",
                    "clean-merge", "conflicts"
                ]
            },
            "conflictingPaths": output_array(json!({ "type": "string" })),
            "conflictCount": non_negative_integer_output_schema(),
            "readOnly": { "const": true },
            "networkFetchPerformed": { "const": false },
            "workingTreeMutated": { "const": false },
            "approvalRequiredForMerge": { "const": true },
            "guidance": { "type": "string", "minLength": 1 },
        }),
        &[
            "currentRef",
            "targetRef",
            "currentOid",
            "targetOid",
            "mergeBaseOid",
            "status",
            "conflictingPaths",
            "conflictCount",
            "readOnly",
            "networkFetchPerformed",
            "workingTreeMutated",
            "approvalRequiredForMerge",
            "guidance",
        ],
    )
}

fn conflict_commit_output_schema() -> Value {
    nullable_output_schema(output_object(
        json!({
            "sha": { "type": "string" },
            "subject": { "type": "string" },
        }),
        &["sha", "subject"],
    ))
}

fn conflict_side_output_schema() -> Value {
    let mut side = output_object(
        json!({
            "sha": { "type": "string", "minLength": 1 },
            "size": non_negative_integer_output_schema(),
            "binary": { "const": true },
            "truncated": { "type": "boolean" },
            "content": { "type": "string", "maxLength": DIFF_TEXT_MAX_MAX_BYTES },
            "error": { "type": "string", "minLength": 1 },
        }),
        &["sha"],
    );
    side["anyOf"] = json!([
        { "required": ["error"] },
        { "required": ["binary", "size"] },
        { "required": ["size", "truncated", "content"] }
    ]);
    nullable_output_schema(side)
}

fn conflict_file_output_schema() -> Value {
    output_object(
        json!({
            "path": { "type": "string" },
            "kind": {
                "enum": [
                    "both-modified", "deleted-by-them", "deleted-by-us", "both-added",
                    "added-by-us", "added-by-them", "both-deleted", "unknown"
                ]
            },
            "sides": output_object(
                json!({
                    "base": conflict_side_output_schema(),
                    "ours": conflict_side_output_schema(),
                    "theirs": conflict_side_output_schema(),
                }),
                &["base", "ours", "theirs"],
            ),
            "regions": output_array(output_object(
                json!({
                    "startLine": { "type": "integer", "minimum": 1 },
                    "sepLine": { "type": "integer", "minimum": 1 },
                    "endLine": { "type": "integer", "minimum": 1 },
                }),
                &["startLine", "sepLine", "endLine"],
            )),
        }),
        &["path", "kind", "sides", "regions"],
    )
}

fn conflict_read_output_schema() -> Value {
    json!({
        "anyOf": [
            output_object(
                json!({
                    "inConflict": { "const": false },
                    "hint": { "type": "string", "minLength": 1 },
                }),
                &["inConflict", "hint"],
            ),
            output_object(
                json!({
                    "inConflict": { "const": true },
                    "operation": {
                        "enum": ["merge", "rebase", "cherry-pick", "revert", "unknown"]
                    },
                    "ours": conflict_commit_output_schema(),
                    "theirs": conflict_commit_output_schema(),
                    "conflictedFileCount": non_negative_integer_output_schema(),
                    "files": bounded_output_array(conflict_file_output_schema(), 200),
                    "fileListTruncated": { "type": "boolean" },
                    "maxBytesPerSide": {
                        "type": "integer", "minimum": 1, "maximum": DIFF_TEXT_MAX_MAX_BYTES
                    },
                    "guidance": { "type": "string", "minLength": 1 },
                }),
                &[
                    "inConflict", "operation", "ours", "theirs", "conflictedFileCount",
                    "files", "fileListTruncated", "maxBytesPerSide", "guidance",
                ],
            )
        ]
    })
}

fn repo_reflog_output_schema() -> Value {
    let entry = output_object(
        json!({
            "index": { "type": "integer", "minimum": 0, "maximum": 99 },
            "refName": { "type": "string", "minLength": 1 },
            "selector": { "type": "string" },
            "oldCommit": { "type": "string" },
            "newCommit": { "type": "string" },
            "shortNewCommit": { "type": "string" },
            "message": { "type": "string" },
            "authorName": { "type": "string" },
            "authorEmail": { "type": "string" },
            "timestamp": { "type": "integer" },
            "canCompare": { "type": "boolean" },
        }),
        &[
            "index",
            "refName",
            "selector",
            "oldCommit",
            "newCommit",
            "shortNewCommit",
            "message",
            "authorName",
            "authorEmail",
            "timestamp",
            "canCompare",
        ],
    );
    output_object(
        json!({
            "refName": { "type": "string", "minLength": 1 },
            "entries": bounded_output_array(entry, 100),
            "entryCount": { "type": "integer", "minimum": 0, "maximum": 100 },
            "readOnly": { "const": true },
            "recoveryGuidance": { "type": "string", "minLength": 1 },
        }),
        &[
            "refName",
            "entries",
            "entryCount",
            "readOnly",
            "recoveryGuidance",
        ],
    )
}

fn history_commit_output_schema() -> Value {
    output_object(
        json!({
            "hash": { "type": "string" },
            "shortHash": { "type": "string" },
            "authorName": { "type": "string" },
            "authorEmail": { "type": "string" },
            "authorTime": { "type": "integer" },
            "subject": { "type": "string" },
        }),
        &[
            "hash",
            "shortHash",
            "authorName",
            "authorEmail",
            "authorTime",
            "subject",
        ],
    )
}

fn repo_history_output_schema() -> Value {
    output_object(
        json!({
            "commits": bounded_output_array(history_commit_output_schema(), 200),
            "nextCursor": nullable_string_output_schema(),
        }),
        &["commits", "nextCursor"],
    )
}

fn commit_details_output_schema() -> Value {
    output_object(
        json!({
            "commit": output_object(
                json!({
                    "hash": { "type": "string" },
                    "shortHash": { "type": "string" },
                    "authorName": { "type": "string" },
                    "authorEmail": { "type": "string" },
                    "authorTime": { "type": "integer" },
                    "parents": output_array(json!({ "type": "string" })),
                    "message": { "type": "string" },
                }),
                &[
                    "hash", "shortHash", "authorName", "authorEmail", "authorTime", "parents",
                    "message",
                ],
            ),
            "files": output_array(status_entry_output_schema()),
        }),
        &["commit", "files"],
    )
}

fn worktree_changes_output_schema() -> Value {
    output_object(
        json!({
            "staged": output_array(status_entry_output_schema()),
            "unstaged": output_array(status_entry_output_schema()),
            "untracked": output_array(status_entry_output_schema()),
        }),
        &["staged", "unstaged", "untracked"],
    )
}

fn worktree_list_output_schema() -> Value {
    let worktree = output_object(
        json!({
            "path": { "type": "string" },
            "isMain": { "type": "boolean" },
            "headSha": { "type": "string" },
            "branch": { "type": "string" },
            "detached": { "type": "boolean" },
            "bare": { "type": "boolean" },
            "locked": { "type": "boolean" },
            "lockedReason": { "type": "string" },
            "prunable": { "type": "boolean" },
        }),
        &["path", "isMain", "detached", "locked", "prunable"],
    );
    output_object(
        json!({
            "total": non_negative_integer_output_schema(),
            "worktrees": output_array(worktree),
        }),
        &["total", "worktrees"],
    )
}

fn submodule_status_output_schema() -> Value {
    output_object(
        json!({
            "submodules": bounded_output_array(
                submodule_entry_output_schema(),
                SUBMODULE_STATUS_MAX_ENTRIES,
            ),
        }),
        &["submodules"],
    )
}

fn diff_text_output_schema() -> Value {
    output_object(
        json!({
            "format": { "const": "text" },
            "base": nullable_string_output_schema(),
            "head": nullable_string_output_schema(),
            "path": nullable_string_output_schema(),
            "diff": { "type": "string", "maxLength": DIFF_TEXT_MAX_MAX_BYTES },
            "truncated": { "type": "boolean" },
            "totalBytes": non_negative_integer_output_schema(),
            "totalLines": non_negative_integer_output_schema(),
            "maxBytes": {
                "type": "integer", "minimum": 1, "maximum": DIFF_TEXT_MAX_MAX_BYTES
            },
        }),
        &[
            "format",
            "base",
            "head",
            "path",
            "diff",
            "truncated",
            "totalBytes",
            "totalLines",
            "maxBytes",
        ],
    )
}

fn text_diff_arguments_output_schema() -> Value {
    output_object(
        json!({
            "repoPath": { "type": "string" },
            "base": { "type": "string" },
            "head": { "type": "string" },
            "path": { "type": "string" },
        }),
        &["repoPath"],
    )
}

fn semantic_line_output_schema() -> Value {
    output_object(
        json!({
            "type": { "enum": ["unchanged", "added", "deleted", "modified"] },
            "oldLine": { "type": "integer", "minimum": 1 },
            "newLine": { "type": "integer", "minimum": 1 },
            "content": { "type": "string" },
            "oldContent": { "type": "string" },
            "changedTokens": output_array(json!({ "type": "string" })),
            "oldChangedTokens": output_array(json!({ "type": "string" })),
        }),
        &["type", "content"],
    )
}

fn semantic_file_output_schema() -> Value {
    let hunk = output_object(
        json!({
            "header": { "type": "string" },
            // The gateway emits at most 1,500 semantic lines per file. A
            // per-hunk ceiling of the same value is valid and still useful to
            // streaming clients; `linesTruncated` reports the file-wide cap.
            "lines": bounded_output_array(semantic_line_output_schema(), 1_500),
        }),
        &["header", "lines"],
    );
    json!({
        "anyOf": [
            output_object(
                json!({
                    "path": { "type": "string" },
                    "fallbackToText": { "const": false },
                    "hunks": output_array(hunk),
                    "linesTruncated": { "type": "boolean" },
                }),
                &["path", "fallbackToText", "hunks", "linesTruncated"],
            ),
            output_object(
                json!({
                    "path": { "type": "string" },
                    "fallbackToText": { "const": true },
                    "hunks": { "type": "array", "maxItems": 0 },
                    "reason": { "type": "string", "minLength": 1 },
                    "textDiffArguments": text_diff_arguments_output_schema(),
                }),
                &["path", "fallbackToText", "hunks", "reason", "textDiffArguments"],
            )
        ]
    })
}

fn diff_semantic_output_schema() -> Value {
    json!({
        "anyOf": [
            output_object(
                json!({
                    "supported": { "const": false },
                    "fallback": { "const": "diff.text" },
                    "reason": { "type": "string", "minLength": 1 },
                    "textDiffArguments": text_diff_arguments_output_schema(),
                }),
                &["supported", "fallback", "reason", "textDiffArguments"],
            ),
            output_object(
                json!({
                    "supported": { "const": true },
                    "engine": { "const": "fluxgit-diff-engine" },
                    "base": nullable_string_output_schema(),
                    "head": nullable_string_output_schema(),
                    "path": nullable_string_output_schema(),
                    "files": bounded_output_array(
                        semantic_file_output_schema(),
                        SEMANTIC_DIFF_MAX_FILES,
                    ),
                    "changedFiles": {
                        "type": "integer", "minimum": 0, "maximum": SEMANTIC_DIFF_MAX_FILES
                    },
                    "filesTruncated": { "type": "boolean" },
                }),
                &[
                    "supported", "engine", "base", "head", "path", "files",
                    "changedFiles", "filesTruncated",
                ],
            )
        ]
    })
}

fn semantic_fallback_record_output_schema() -> Value {
    output_object(
        json!({
            "from": { "const": "diff.semantic" },
            "to": { "const": "diff.text" },
            "supported": { "const": false },
            "reason": { "type": "string", "minLength": 1 },
            "repoPath": { "type": "string" },
            "path": nullable_string_output_schema(),
        }),
        &["from", "to", "supported", "reason", "repoPath", "path"],
    )
}

fn diff_semantic_fallbacks_output_schema() -> Value {
    json!({
        "anyOf": [
            output_object(
                json!({
                    "fallbacks": {
                        "type": "array",
                        "items": semantic_fallback_record_output_schema(),
                        "minItems": 1,
                        "maxItems": 1,
                    },
                }),
                &["fallbacks"],
            ),
            output_object(
                json!({
                    "fallbacks": bounded_output_array(
                        semantic_fallback_record_output_schema(),
                        SEMANTIC_DIFF_MAX_FILES,
                    ),
                    "engine": { "const": "fluxgit-diff-engine" },
                    "analyzedFiles": {
                        "type": "integer", "minimum": 0, "maximum": SEMANTIC_DIFF_MAX_FILES
                    },
                    "filesTruncated": { "type": "boolean" },
                }),
                &["fallbacks", "engine", "analyzedFiles", "filesTruncated"],
            )
        ]
    })
}

fn flux_latest_restore_point_output_schema() -> Value {
    output_object(
        json!({
            "latestRestorePoint": nullable_output_schema(restore_point_output_schema()),
            // The current checkpoint store has one newest record; keep the
            // advertised list bound aligned with the public 200-item API cap
            // so additive history support does not break older clients.
            "restorePoints": bounded_output_array(restore_point_output_schema(), 200),
            "restoreCount": { "type": "integer", "minimum": 0, "maximum": 200 },
            "approvalRequired": { "const": true },
            "approvalMessage": { "type": "string", "minLength": 1 },
        }),
        &[
            "latestRestorePoint",
            "restorePoints",
            "restoreCount",
            "approvalRequired",
            "approvalMessage",
        ],
    )
}

fn flux_restore_points_output_schema() -> Value {
    output_object(
        json!({
            "restorePoints": bounded_output_array(restore_point_output_schema(), 200),
            "restoreCount": { "type": "integer", "minimum": 0, "maximum": 200 },
            "approvalRequired": { "const": true },
            "approvalMessage": { "type": "string", "minLength": 1 },
        }),
        &[
            "restorePoints",
            "restoreCount",
            "approvalRequired",
            "approvalMessage",
        ],
    )
}

fn flux_restore_point_details_output_schema() -> Value {
    output_object(
        json!({
            "restorePoint": nullable_output_schema(restore_point_output_schema()),
            "restoreCount": { "type": "integer", "minimum": 0, "maximum": 200 },
            "approvalRequired": { "const": true },
            "approvalMessage": { "type": "string", "minLength": 1 },
        }),
        &[
            "restorePoint",
            "restoreCount",
            "approvalRequired",
            "approvalMessage",
        ],
    )
}

fn operation_type_for_kind(kind: ToolKind) -> Option<&'static str> {
    match kind {
        ToolKind::OperationPreviewMerge => Some("merge"),
        ToolKind::OperationPreviewRebase => Some("rebase"),
        ToolKind::OperationPreviewDiscard => Some("discard"),
        ToolKind::OperationPreviewReset => Some("reset"),
        ToolKind::OperationPreviewPatch => Some("patch"),
        ToolKind::OperationPreviewPlan => Some("plan"),
        ToolKind::OperationPreviewWorktree => Some("worktree"),
        ToolKind::OperationPreviewCommit => Some("commit"),
        ToolKind::OperationPreviewPush => Some("push"),
        ToolKind::OperationPreviewBranch => Some("branch"),
        _ => None,
    }
}

fn operation_restore_point_output_schema() -> Value {
    output_object(
        json!({
            "operation": { "type": "string" },
            "branchRef": { "type": "string" },
            "beforeCommit": { "type": "string" },
            "afterCommit": { "type": "string" },
            "canUndo": { "type": "boolean" },
        }),
        &[
            "operation",
            "branchRef",
            "beforeCommit",
            "afterCommit",
            "canUndo",
        ],
    )
}

fn plan_step_result_output_schema() -> Value {
    output_object(
        json!({
            "operationType": { "enum": ["merge", "rebase", "discard", "reset", "patch"] },
            "status": { "enum": ["completed", "failed", "skipped"] },
            "message": { "type": "string" },
            "restorePoint": operation_restore_point_output_schema(),
        }),
        &["operationType", "status"],
    )
}

fn operation_completion_result_schema(kind: Option<ToolKind>) -> Value {
    let mut properties = json!({
        "status": { "enum": ["completed", "failed"] },
        "message": { "type": "string" },
        "restorePoint": operation_restore_point_output_schema(),
    });
    let object = properties
        .as_object_mut()
        .expect("schema properties object");
    let mut insert = |name: &str, schema: Value| {
        object.insert(name.to_string(), schema);
    };
    match kind {
        Some(ToolKind::OperationPreviewMerge) => {
            insert("mergeCommit", json!({ "type": "string" }));
            insert("summary", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewRebase) => {
            insert("newHeadSha", json!({ "type": "string" }));
            insert("replayedCommits", non_negative_integer_output_schema());
            insert("restorePointId", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewDiscard) => {
            insert(
                "pathsDiscarded",
                bounded_output_array(json!({ "type": "string" }), MCP_MAX_PATH_ITEMS),
            );
            insert("restorePointId", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewReset) => {
            insert("newHeadSha", json!({ "type": "string" }));
            insert("mode", json!({ "enum": ["soft", "mixed", "hard"] }));
            insert("restorePointId", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewPatch) => {
            insert(
                "appliedFiles",
                bounded_output_array(json!({ "type": "string" }), MCP_MAX_PATH_ITEMS),
            );
            insert("stagedToIndex", json!({ "type": "boolean" }));
            insert("restorePointId", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewPlan) => {
            insert(
                "steps",
                bounded_output_array(plan_step_result_output_schema(), 10),
            );
        }
        Some(ToolKind::OperationPreviewWorktree) => {
            insert("worktreePath", json!({ "type": "string" }));
            insert("branch", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewCommit) => {
            insert("commitSha", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewPush) => {
            insert("pushedRef", json!({ "type": "string" }));
            insert("remote", json!({ "type": "string" }));
        }
        Some(ToolKind::OperationPreviewBranch) => {
            insert("branch", json!({ "type": "string" }));
            insert("checkedOut", json!({ "type": "boolean" }));
        }
        None | Some(_) => {
            // operation.status is discriminated by data.operationType rather
            // than one fixed tool kind, so advertise every stable result key.
            for (name, schema) in [
                ("mergeCommit", json!({ "type": "string" })),
                ("summary", json!({ "type": "string" })),
                ("newHeadSha", json!({ "type": "string" })),
                ("replayedCommits", non_negative_integer_output_schema()),
                ("restorePointId", json!({ "type": "string" })),
                (
                    "pathsDiscarded",
                    bounded_output_array(json!({ "type": "string" }), MCP_MAX_PATH_ITEMS),
                ),
                ("mode", json!({ "enum": ["soft", "mixed", "hard"] })),
                (
                    "appliedFiles",
                    bounded_output_array(json!({ "type": "string" }), MCP_MAX_PATH_ITEMS),
                ),
                ("stagedToIndex", json!({ "type": "boolean" })),
                (
                    "steps",
                    bounded_output_array(plan_step_result_output_schema(), 10),
                ),
                ("worktreePath", json!({ "type": "string" })),
                ("branch", json!({ "type": "string" })),
                ("commitSha", json!({ "type": "string" })),
                ("pushedRef", json!({ "type": "string" })),
                ("remote", json!({ "type": "string" })),
                ("checkedOut", json!({ "type": "boolean" })),
            ] {
                insert(name, schema);
            }
        }
    }
    output_object(properties, &[])
}

fn gateway_raw_value_schema(preferred_object: Value, description: &str) -> Value {
    json!({
        "description": description,
        "anyOf": [
            preferred_object,
            { "type": "array" },
            { "type": "string" },
            { "type": "number" },
            { "type": "boolean" },
            { "type": "null" }
        ]
    })
}

fn gateway_completion_value_schema(kind: Option<ToolKind>) -> Value {
    gateway_raw_value_schema(
        operation_completion_result_schema(kind),
        "Operation-specific completion objects are typed below; primitive/array/null results remain accepted because the durable gateway contract preserves an opaque JSON Value across version skew.",
    )
}

fn operation_status_data_schema(kind: Option<ToolKind>, status: Option<&str>) -> Value {
    let operation_type = kind
        .and_then(operation_type_for_kind)
        .map(|operation_type| json!({ "const": operation_type }))
        .unwrap_or_else(|| {
            json!({
                "enum": [
                    "merge", "rebase", "discard", "reset", "patch", "plan", "worktree",
                    "commit", "push", "branch"
                ]
            })
        });
    let status_schema = status
        .map(|status| json!({ "const": status }))
        .unwrap_or_else(|| lifecycle_status_schema(false));
    output_object(
        json!({
            "previewId": preview_id_output_schema(),
            // Old rollout gateways omitted this discriminator. It is fully
            // typed when present but deliberately not required.
            "operationType": operation_type,
            "status": status_schema,
            "result": gateway_completion_value_schema(kind),
            "rejectionReason": { "type": "string" },
            "expiresAt": { "type": "string", "format": "date-time" },
        }),
        &["previewId", "status"],
    )
}

fn operation_cancel_data_schema() -> Value {
    output_object(
        json!({
            "previewId": preview_id_output_schema(),
            "agentId": { "type": "string", "minLength": 1, "maxLength": 128 },
            "repoPath": { "type": "string", "maxLength": MCP_MAX_PATH_CHARS },
            "reason": { "type": "string", "maxLength": MCP_MAX_REASON_CHARS },
            "requestedAt": { "type": "string", "format": "date-time" },
            "expiresAt": { "type": "string", "format": "date-time" },
            "status": { "const": "cancelled" },
            "operationType": {
                "enum": [
                    "merge", "rebase", "discard", "reset", "patch", "plan", "worktree",
                    "commit", "push", "branch"
                ]
            },
            // User overrides are explicitly free-form in the durable gateway
            // contract and must survive sidecar/app version skew.
            "overrides": { "description": "Opaque human-approved overrides." },
            "rejectionReason": { "type": "string" },
            "result": gateway_completion_value_schema(None),
            "idempotencyKey": { "type": "string", "maxLength": 256 },
            "sourceRef": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "targetRef": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "strategy": { "enum": ["merge", "squash", "rebase"] },
            "currentRef": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "ontoRef": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "interactive": { "type": "boolean" },
            "paths": bounded_output_array(
                json!({ "type": "string", "maxLength": MCP_MAX_PATH_CHARS }),
                MCP_MAX_PATH_ITEMS,
            ),
            "mode": { "enum": ["soft", "mixed", "hard"] },
            "patchContent": { "type": "string", "maxLength": MCP_MAX_PATCH_CHARS },
            "applyToIndex": { "type": "boolean" },
            "steps": { "type": "array", "maxItems": 10 },
            "branch": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "path": { "type": "string", "maxLength": MCP_MAX_PATH_CHARS },
            "message": { "type": "string", "maxLength": MCP_MAX_MESSAGE_CHARS },
            "stageAll": { "type": "boolean" },
            "remote": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "setUpstream": { "type": "boolean" },
            "forceWithLease": { "type": "boolean" },
            "name": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "startPoint": { "type": "string", "maxLength": MCP_MAX_REF_CHARS },
            "checkout": { "type": "boolean" },
        }),
        &["previewId", "status"],
    )
}

/// All advertised tools across tiers, used by `tools/list`. Read-only tools come first
/// so MCP hosts that scan in order still see the safer surface up front.
fn all_advertised_tools() -> Vec<ToolSpec> {
    let mut tools = read_only_tools();
    tools.extend(write_handshake_tools());
    tools
}

fn read_only_tool_names() -> Vec<&'static str> {
    READ_ONLY_TOOL_KINDS
        .iter()
        .copied()
        .map(ToolKind::as_str)
        .collect()
}

fn write_handshake_tool_names() -> Vec<&'static str> {
    WRITE_HANDSHAKE_TOOL_KINDS
        .iter()
        .copied()
        .map(ToolKind::as_str)
        .collect()
}

fn tool_description(kind: ToolKind) -> &'static str {
    match kind {
        ToolKind::RepoBrief => {
            "One-call situational awareness for a repository: HEAD/branch/upstream with ahead-behind, any in-progress operation (merge/rebase/cherry-pick/revert/bisect), working-tree summary, stash count, aggregated recursive submodule drift, recent commits and detected commit conventions, plus `hints` with the recommended next step. Call this first in a session; it replaces 6-10 raw git calls and its output is compact by design to preserve agent context."
        }
        ToolKind::WorktreeList => {
            "List all git worktrees of a repository (main + linked), one entry per worktree with path, branch or detached HEAD, head SHA and locked/prunable flags. Use this to coordinate parallel agent worktrees: find an existing worktree for a task, or detect leftovers to clean up. Pair with repo.brief({repoPath: <worktree path>}) to inspect one worktree's state."
        }
        ToolKind::RepoScope => {
            "Monorepo scoping: everything an agent needs about ONE subtree (e.g. packages/api) in a single read-only call — working-tree changes under the path, recent commits touching it, churn (commits and distinct authors over a window), and code owners from CODEOWNERS when present. Use it to work on a scoped task without paying for whole-repo context; pair with repo.brief for the repository-level picture."
        }
        ToolKind::SafetyTimeline => {
            "List Safety Timeline events synthesized from FluxGit restore points and reflog movement — the repository's recoverability narrative. Use it for 'what happened and can we get it back?' questions; recovery itself always runs inside FluxGit with user approval. Returns ordered events with source (restore_point|reflog) and safe UI actions. Requires the FluxGit app."
        }
        ToolKind::SafetyEventDetails => {
            "Read one Safety Timeline event in detail (or the latest when eventId is omitted) plus its safe UI actions, without performing any recovery or mutation. Use it to drill into an event surfaced by safety.timeline before explaining recovery options to the user. Requires the FluxGit app."
        }
        ToolKind::FleetRadar => {
            "Summarize many local repositories into one read-only attention stack — dirty state, divergence and predictive conflict signals per repo — without fetching or mutating disk state. Use it for 'which repo needs me first?' across a fleet; it replaces opening each repo one by one. Returns prioritized entries plus an attentionStack of one-line summaries."
        }
        ToolKind::RepoStatus => {
            "Summarize working-tree cleanliness and branch divergence: current branch, ahead/behind upstream and changed-file count in one compact snapshot. Use it as the cheap freshness check before recommending any operation (repo.brief gives the fuller session-start picture). Returns { branch, ahead, behind, clean, changedFiles }."
        }
        ToolKind::RepoRefs => {
            "List local and remote branches, tags, stashes and where HEAD points. Use it to resolve exact ref names before proposing merges or rebases instead of guessing; it replaces git branch -a + git tag + git stash list. Returns grouped ref-name arrays."
        }
        ToolKind::RepoBranchStack => {
            "Explain the current branch relationship to upstream, base candidates and related local branches without creating virtual branches."
        }
        ToolKind::RepoConflictPreflight => {
            "Predict whether merging a target ref into the current ref will conflict, without mutating HEAD, index or working tree."
        }
        ToolKind::ConflictRead => {
            "Read an ACTIVE merge/rebase/cherry-pick conflict as structured data instead of raw <<<<<<< markers: the in-progress operation, the two producing commits (ours/theirs with sha and subject), and per conflicted file its stage classification (both-modified, deleted-by-them, ...), the base/ours/theirs blob contents (size-capped with explicit truncated flags; binary blobs are flagged, never dumped) and the marker region line ranges from the working tree. Call it when repo.brief reports an in-progress operation or git output shows conflict markers — it replaces hand-parsing marker soup. Returns { inConflict: false } when nothing is in progress (use repo.conflictPreflight to PREDICT conflicts instead). Propose resolutions via operation.preview.patch for user approval in FluxGit — never write conflicted files directly."
        }
        ToolKind::RepoReflog => {
            "Read the local reflog movement timeline for HEAD or another ref — every commit the ref recently pointed at, with per-entry old/new commits. Use it for lost-commit and 'what did that operation actually do?' questions; recovery actions themselves go through FluxGit approval flows, never MCP. Returns up to 100 entries (limit clamps at 100)."
        }
        ToolKind::RepoHistory => {
            "Return paged commit history (newest first) with hash, author and subject per commit. Use it to walk history incrementally instead of dumping the whole log; limit clamps at 200 and the returned nextCursor continues where the page ended."
        }
        ToolKind::CommitDetails => {
            "Inspect one commit: full metadata (author, timestamp, parents, message) plus its changed files with status letters. Use it after repo.history when you need what a specific commit touched; it replaces git show --stat. Requires the commit hash or ref."
        }
        ToolKind::WorktreeChanges => {
            "Summarize the working tree as staged, unstaged and untracked path lists with two-letter status codes. Use it to see exactly what would be committed or lost before proposing commits, patches or discards; it replaces parsing git status --porcelain by hand."
        }
        ToolKind::SubmoduleStatus => {
            "List submodules recursively with their pinned commit and drift state. Use it before recommending operations in repos that vendor submodules — drifted or uninitialized submodules are a common source of surprise diffs. Returns one entry per submodule with state flag, commit and path."
        }
        ToolKind::DiffText => {
            "Return the standard unified text diff between two refs (or against the working tree), optionally scoped to one path. Output is byte-capped (default 64 KiB, truncation on a line boundary reported via truncated:true plus totalBytes/totalLines) so a huge diff cannot flood the agent context; raise maxBytes (max 1 MiB) or set maxLines only when needed."
        }
        ToolKind::DiffSemantic => {
            "Request a semantic (syntax-aware) diff under a strict honesty contract: trust the payload only when data.supported is exactly true. With the FluxGit app running (FLUXGIT_MCP_HANDSHAKE_ADDR or FLUXGIT_GATEWAY_ADDR set) and the repository registered in FluxGit, it returns supported:true with per-file semantic hunks from the FluxGit diff engine — line-level change types (added/deleted/modified) plus the exact tokens that changed — and an honest per-file fallbackToText flag (with ready-to-use textDiffArguments) for files the engine could not parse. Without that connection it returns supported:false plus ready-to-use textDiffArguments for a diff.text fallback — never present a text diff as semantic."
        }
        ToolKind::DiffSemanticFallbacks => {
            "List which paths fell back from semantic to text diff and why. With the FluxGit gateway connected it reports the diff engine's real per-file fallbacks for the same base/head selection; without it, it reports the single documented not-connected fallback record. Use it after diff.semantic when reporting to the user which files got a real semantic explanation and which only got the text fallback. Returns one fallback record per affected path."
        }
        ToolKind::FluxLatestRestorePoint => {
            "Read the newest FluxGit restore point (before/after commits, canUndo/canRedo eligibility) for a repository. Use it to tell the user whether the last risky operation is reversible; undo/redo itself requires explicit approval inside FluxGit and is never exposed through MCP. Requires the FluxGit app."
        }
        ToolKind::FluxRestorePoints => {
            "List FluxGit restore point metadata for a repository without performing any recovery. Use it to explain what recovery options exist before recommending the user act inside FluxGit; limit clamps at 200. Requires the FluxGit app."
        }
        ToolKind::FluxRestorePointDetails => {
            "Read one FluxGit restore point in detail: before/after commits, branch ref, undo/redo eligibility and checkpoint metadata. Use it when the user asks exactly what a restore would do; the restore itself requires approval inside FluxGit. Requires the FluxGit app."
        }
        ToolKind::OperationStatus => {
            "Check the authoritative status of a previously proposed operation by previewId: pending, approved/executing, completed (with the execution result), failed, rejected, expired or cancelled. Preview calls return promptly while human review continues, so poll this tool before claiming the Git operation completed. Read-only; requires the FluxGit desktop app connection."
        }
        ToolKind::OperationCancel => {
            "Withdraw one of YOUR OWN still-pending operation proposals by previewId before the user decides. Use it when your plan changed and the approval card is now stale, so the user cannot approve an operation you no longer want. It only cancels proposals created by this agent, only while pending, and never touches the repository. Requires the FluxGit desktop app connection (FLUXGIT_MCP_HANDSHAKE_ADDR)."
        }
        ToolKind::OperationPreviewMerge => {
            "Propose a merge for human review inside FluxGit. The sidecar never merges. The call returns a previewId promptly; poll operation.status until completed, failed, rejected, expired or cancelled before reporting an outcome. FluxGit executes only after explicit approval through its safety pipeline. Always include a clear `reason`."
        }
        ToolKind::OperationPreviewRebase => {
            "Propose a rebase for human review inside FluxGit. The sidecar never rebases. The call returns a previewId promptly; poll operation.status for the terminal result. FluxGit shows risk, requires explicit approval, executes through its safety pipeline and captures recovery state. Always include a clear `reason`."
        }
        ToolKind::OperationPreviewDiscard => {
            "Propose discarding working-tree changes for selected paths. The call returns a previewId promptly; poll operation.status for the terminal result. FluxGit shows exactly what would be lost, captures recovery state and requires explicit approval before touching files. Always include a clear `reason`."
        }
        ToolKind::OperationPreviewReset => {
            "Propose a soft, mixed or hard reset for human review. The call returns a previewId promptly; poll operation.status for the terminal result. FluxGit shows commits at risk, captures a restore point and requires explicit approval; hard reset receives strong confirmation. Always include a clear `reason`."
        }
        ToolKind::OperationPreviewPatch => {
            "Propose applying an agent-generated patch. The call returns a previewId promptly; poll operation.status for the terminal result. FluxGit shows the resulting diff, runs conflict checks and requires explicit approval before touching the working tree. Always include a clear `reason`."
        }
        ToolKind::OperationPreviewPlan => {
            "Propose a sequence of 1-10 merge/rebase/discard/reset/patch steps as one reviewable plan. The call returns a previewId promptly; poll operation.status for per-step terminal results. FluxGit shows every step, requires one explicit approval, executes in order through its safety pipeline and stops at the first failure. Always include a clear `reason`."
        }
        ToolKind::OperationPreviewWorktree => {
            "Propose creating an isolated Git worktree before editing for a parallel task. Provide `branch`, optional `path`, and a clear `reason`. The call returns a previewId promptly; poll operation.status for the created path. FluxGit requires explicit approval and adds a checkout without rewriting history or deleting files."
        }
        ToolKind::OperationPreviewCommit => {
            "Propose a commit for human review. Provide `message`, a clear `reason`, and optionally `paths` or `stageAll`; omit both staging options to commit exactly what is staged. Amend is intentionally unsupported. The call returns a previewId promptly; poll operation.status for the commit SHA. FluxGit requires approval and uses its hooks, signing and commit policy."
        }
        ToolKind::OperationPreviewPush => {
            "Propose pushing a branch for human review. `remote` defaults to origin, `branch` to the current branch; `setUpstream` publishes tracking and `forceWithLease` explicitly requests a high-risk lease-protected rewrite. The call returns a previewId promptly; poll operation.status for the terminal result. FluxGit requires approval and uses its guarded credential/push pipeline."
        }
        ToolKind::OperationPreviewBranch => {
            "Propose creating a local branch for human review. Provide `name` and `reason`; `startPoint` defaults to HEAD and `checkout` defaults true. The call returns a previewId promptly; poll operation.status for the terminal result. FluxGit requires approval and validates the ref before adding or checking out the branch."
        }
    }
}

fn tool_input_schema(kind: ToolKind) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    // operation.status / operation.cancel address an existing proposal on the
    // gateway handshake bridge — they take a previewId, never a repoPath.
    if matches!(kind, ToolKind::OperationStatus | ToolKind::OperationCancel) {
        let description = if kind == ToolKind::OperationStatus {
            "The previewId returned by an accepted operation.preview.* call."
        } else {
            "The previewId of a still-pending proposal created by this agent. Only the proposing agent can cancel it."
        };
        properties.insert(
            "previewId".into(),
            json!({
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": "^[A-Za-z0-9_-]+$",
                "description": description,
            }),
        );
        return json!({
            "type": "object",
            "properties": properties,
            "required": ["previewId"],
            "additionalProperties": false,
        });
    }

    if kind == ToolKind::FleetRadar {
        properties.insert(
            "repoPaths".into(),
            json!({
                "type": "array",
                "items": { "type": "string", "minLength": 1, "maxLength": 32768 },
                "minItems": 1,
                "maxItems": 500,
                "description": "Absolute local repository paths to scan. No fetch is performed."
            }),
        );
        properties.insert(
            "repositories".into(),
            json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "repoPath": { "type": "string", "minLength": 1, "maxLength": 32768 },
                        "repoId": { "type": "string", "minLength": 1, "maxLength": 256 },
                        "label": { "type": "string", "minLength": 1, "maxLength": 512 }
                    },
                    "required": ["repoPath"],
                    "additionalProperties": false
                },
                "minItems": 1,
                "maxItems": 500,
                "description": "Repository objects with optional FluxGit ids and display labels."
            }),
        );
        properties.insert(
            "maxRepos".into(),
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": 500,
                "default": 200,
                "description": "Maximum repositories to inspect in this read-only call."
            }),
        );

        return json!({
            "type": "object",
            "properties": properties,
            "anyOf": [
                { "required": ["repoPaths"] },
                { "required": ["repositories"] }
            ],
            "additionalProperties": false,
        });
    }

    properties.insert(
        "repoPath".into(),
        json!({
            "type": "string",
            "description": "Absolute local repository path. Required for the current read-only local sidecar contract."
        }),
    );
    properties.insert(
        "repoId".into(),
        json!({
            "type": "string",
            "description": "Optional FluxGit workspace id. Do not use it as a substitute for repoPath in local sidecar calls."
        }),
    );
    if operation_type_for_kind(kind).is_some() {
        properties.insert(
            "idempotencyKey".into(),
            json!({
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": "^[A-Za-z0-9_-]+$",
                "description": "Optional caller-generated key for retrying this same logical proposal without opening a duplicate approval card. Reuse only for retries of one intent; omit it for a new intent even when the other arguments match."
            }),
        );
    }
    required.push("repoPath");

    match kind {
        ToolKind::SafetyTimeline => {
            properties.insert("runDir".into(), json!({ "type": "string" }));
            properties.insert(
                "limit".into(),
                json!({ "type": "integer", "minimum": 1, "maximum": 200 }),
            );
            properties.insert(
                "reflogLimit".into(),
                json!({ "type": "integer", "minimum": 1, "maximum": 100 }),
            );
            properties.insert(
                "includeReflog".into(),
                json!({ "type": "boolean", "default": true }),
            );
            properties.insert(
                "includeRestorePoints".into(),
                json!({ "type": "boolean", "default": true }),
            );
        }
        ToolKind::SafetyEventDetails => {
            properties.insert("runDir".into(), json!({ "type": "string" }));
            properties.insert(
                "eventId".into(),
                json!({
                    "type": "string",
                    "description": "Safety event id returned by safety.timeline. If omitted, the latest event is returned."
                }),
            );
        }
        ToolKind::FleetRadar => {}
        ToolKind::RepoBrief => {
            properties.insert(
                "recentCommits".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "default": 10,
                    "description": "How many recent commits to include as one-line entries."
                }),
            );
        }
        ToolKind::RepoScope => {
            properties.insert(
                "path".into(),
                json!({
                    "type": "string",
                    "description": "Repository-relative subtree to scope to, e.g. 'packages/api'. Must not be absolute or contain '..'."
                }),
            );
            properties.insert(
                "recentCommits".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "default": 10,
                    "description": "How many recent commits touching the scope to include."
                }),
            );
            properties.insert(
                "churnDays".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 365,
                    "default": 90,
                    "description": "Window in days for the churn summary."
                }),
            );
            required.push("path");
        }
        ToolKind::RepoStatus | ToolKind::WorktreeChanges | ToolKind::WorktreeList => {}
        ToolKind::RepoRefs => {}
        ToolKind::RepoBranchStack => {
            properties.insert(
                "baseCandidates".into(),
                json!({
                    "type": "array",
                    "items": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_REF_CHARS },
                    "maxItems": 256,
                    "description": "Optional base branch names to try before default main/master/develop/dev/trunk."
                }),
            );
            properties.insert(
                "maxRelated".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 8
                }),
            );
        }
        ToolKind::RepoConflictPreflight => {
            properties.insert(
                "currentRef".into(),
                json!({
                    "type": "string",
                    "default": "HEAD",
                    "description": "Current ref or commit to simulate from. Defaults to HEAD."
                }),
            );
            properties.insert(
                "targetRef".into(),
                json!({
                    "type": "string",
                    "description": "Target ref or commit to merge into currentRef for the read-only preflight."
                }),
            );
            required.push("targetRef");
        }
        ToolKind::ConflictRead => {
            properties.insert(
                "maxFiles".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 20,
                    "description": "Maximum conflicted files to include with full detail. The total count is always reported."
                }),
            );
            properties.insert(
                "maxBytesPerSide".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1048576,
                    "default": 16384,
                    "description": "Byte cap per base/ours/theirs content. Truncation is flagged explicitly with the full byte size."
                }),
            );
        }
        ToolKind::RepoReflog => {
            properties.insert(
                "refName".into(),
                json!({ "type": "string", "default": "HEAD" }),
            );
            properties.insert(
                "limit".into(),
                json!({ "type": "integer", "minimum": 1, "maximum": 100 }),
            );
        }
        ToolKind::RepoHistory => {
            properties.insert(
                "limit".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                    "description": "Commits per page. Values above 200 are clamped to 200."
                }),
            );
            properties.insert("cursor".into(), json!({ "type": "string" }));
        }
        ToolKind::CommitDetails => {
            properties.insert("commit".into(), json!({ "type": "string" }));
            required.push("commit");
        }
        ToolKind::SubmoduleStatus => {
            properties.insert("path".into(), json!({ "type": "string" }));
        }
        ToolKind::DiffText => {
            properties.insert("base".into(), json!({ "type": "string" }));
            properties.insert("head".into(), json!({ "type": "string" }));
            properties.insert("path".into(), json!({ "type": "string" }));
            properties.insert(
                "maxBytes".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": DIFF_TEXT_MAX_MAX_BYTES,
                    "default": DIFF_TEXT_DEFAULT_MAX_BYTES,
                    "description": "Byte cap on the returned diff text. Truncation happens on a line boundary and is reported honestly via truncated:true plus totalBytes/totalLines — the diff is never silently cut."
                }),
            );
            properties.insert(
                "maxLines".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "description": "Optional line cap applied before the byte cap. Useful for a quick skim of a large diff."
                }),
            );
        }
        ToolKind::DiffSemantic | ToolKind::DiffSemanticFallbacks => {
            properties.insert("base".into(), json!({ "type": "string" }));
            properties.insert("head".into(), json!({ "type": "string" }));
            properties.insert("path".into(), json!({ "type": "string" }));
        }
        ToolKind::FluxLatestRestorePoint => {
            properties.insert("runDir".into(), json!({ "type": "string" }));
        }
        ToolKind::FluxRestorePoints => {
            properties.insert("runDir".into(), json!({ "type": "string" }));
            properties.insert(
                "limit".into(),
                json!({
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                    "description": "Restore points to return. Values above 200 are clamped to 200."
                }),
            );
        }
        ToolKind::FluxRestorePointDetails => {
            properties.insert("runDir".into(), json!({ "type": "string" }));
            properties.insert(
                "restorePointId".into(),
                json!({
                    "type": "string",
                    "description": "Optional restore point selector. Current beta stores one active Flux checkpoint per repo."
                }),
            );
        }
        ToolKind::OperationPreviewMerge => {
            properties.insert(
                "sourceRef".into(),
                json!({
                    "type": "string",
                    "description": "Ref to merge from (e.g. 'feature/login' or commit SHA)."
                }),
            );
            properties.insert(
                "targetRef".into(),
                json!({
                    "type": "string",
                    "description": "Ref to merge into (e.g. 'main')."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Free-text justification the agent provides for the proposed merge. Shown to the user in the approval modal."
                }),
            );
            properties.insert(
                "strategy".into(),
                json!({
                    "type": "string",
                    "enum": ["merge", "squash"],
                    "default": "merge",
                    "description": "Executable merge strategy. Use operation.preview.rebase for rebase semantics."
                }),
            );
            required.push("sourceRef");
            required.push("targetRef");
            required.push("reason");
        }
        ToolKind::OperationPreviewRebase => {
            properties.insert(
                "currentRef".into(),
                json!({
                    "type": "string",
                    "default": "HEAD",
                    "description": "Branch or commit to rebase. Defaults to HEAD."
                }),
            );
            properties.insert(
                "ontoRef".into(),
                json!({
                    "type": "string",
                    "description": "Ref to rebase onto (e.g. 'origin/main')."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Free-text justification shown to the user in the approval modal."
                }),
            );
            properties.insert(
                "interactive".into(),
                json!({
                    "type": "boolean",
                    "const": false,
                    "default": false,
                    "description": "Must be false. Interactive rebase requires the user to author step actions in FluxGit and is not executable through the approval handshake."
                }),
            );
            required.push("ontoRef");
            required.push("reason");
        }
        ToolKind::OperationPreviewDiscard => {
            properties.insert(
                "paths".into(),
                json!({
                    "type": "array",
                    "items": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_PATH_CHARS },
                    "minItems": 1,
                    "maxItems": MCP_MAX_PATH_ITEMS,
                    "description": "Paths whose working-tree changes the agent proposes to discard. FluxGit shows exactly what would be lost."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why these changes should be discarded. Shown to the user."
                }),
            );
            required.push("paths");
            required.push("reason");
        }
        ToolKind::OperationPreviewReset => {
            properties.insert(
                "targetRef".into(),
                json!({
                    "type": "string",
                    "description": "Commit or ref to reset HEAD to."
                }),
            );
            properties.insert(
                "mode".into(),
                json!({
                    "type": "string",
                    "enum": ["soft", "mixed", "hard"],
                    "default": "mixed",
                    "description": "Reset mode. Hard reset always requires strong confirmation in the FluxGit UI."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why the reset is proposed. Shown to the user."
                }),
            );
            required.push("targetRef");
            required.push("reason");
        }
        ToolKind::OperationPreviewPatch => {
            properties.insert(
                "patchContent".into(),
                json!({
                    "type": "string",
                    "description": "The patch text in unified diff format that the agent proposes to apply."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why this patch should be applied. Shown to the user in the approval modal."
                }),
            );
            properties.insert(
                "applyToIndex".into(),
                json!({
                    "type": "boolean",
                    "default": false,
                    "description": "If true, FluxGit will stage the patched files after approval. The user can override this in the UI."
                }),
            );
            required.push("patchContent");
            required.push("reason");
        }
        ToolKind::OperationPreviewPlan => {
            properties.insert(
                "steps".into(),
                json!({
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 10,
                    "items": {
                        "type": "object",
                        "properties": {
                            "operationType": {
                                "type": "string",
                                "enum": ["merge", "rebase", "discard", "reset", "patch"],
                                "description": "Which operation this step performs. A step cannot itself be a plan."
                            },
                            "sourceRef": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_REF_CHARS },
                            "targetRef": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_REF_CHARS },
                            "strategy": {
                                "type": "string",
                                "enum": ["merge", "squash"],
                                "default": "merge"
                            },
                            "currentRef": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_REF_CHARS },
                            "ontoRef": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_REF_CHARS },
                            "interactive": {
                                "type": "boolean",
                                "const": false,
                                "default": false,
                                "description": "Must be false; interactive rebase steps are not executable through a batch approval."
                            },
                            "paths": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": MCP_MAX_PATH_ITEMS,
                                "items": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_PATH_CHARS }
                            },
                            "mode": { "type": "string", "enum": ["soft", "mixed", "hard"] },
                            "patchContent": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_PATCH_CHARS },
                            "applyToIndex": { "type": "boolean" }
                        },
                        "required": ["operationType"],
                        "additionalProperties": false,
                        "oneOf": [
                            {
                                "properties": { "operationType": { "const": "merge" } },
                                "required": ["sourceRef", "targetRef"]
                            },
                            {
                                "properties": { "operationType": { "const": "rebase" } },
                                "required": ["ontoRef"]
                            },
                            {
                                "properties": { "operationType": { "const": "discard" } },
                                "required": ["paths"]
                            },
                            {
                                "properties": { "operationType": { "const": "reset" } },
                                "required": ["targetRef"]
                            },
                            {
                                "properties": { "operationType": { "const": "patch" } },
                                "required": ["patchContent"]
                            }
                        ]
                    },
                    "description": "Ordered steps of the plan. Each step uses the same fields as the corresponding operation.preview.* tool. Executed in order after one approval; execution stops at the first failure."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why this plan should run as one unit. Shown to the user in the approval dialog above the step list."
                }),
            );
            required.push("steps");
            required.push("reason");
        }
        ToolKind::OperationPreviewWorktree => {
            properties.insert(
                "branch".into(),
                json!({
                    "type": "string",
                    "description": "Branch to check out in the new worktree. May be a new branch name (FluxGit creates it) or an existing branch. Each branch can be checked out in only one worktree at a time."
                }),
            );
            properties.insert(
                "path".into(),
                json!({
                    "type": "string",
                    "description": "Optional absolute path for the worktree directory. Omit it and FluxGit picks a sane default next to the repository."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why this worktree should be created. Shown to the user in the approval modal."
                }),
            );
            required.push("branch");
            required.push("reason");
        }
        ToolKind::OperationPreviewCommit => {
            properties.insert(
                "message".into(),
                json!({
                    "type": "string",
                    "description": "Commit message. The first line is the subject; an optional body follows after a blank line."
                }),
            );
            properties.insert(
                "paths".into(),
                json!({
                    "type": "array",
                    "items": { "type": "string", "minLength": 1, "maxLength": MCP_MAX_PATH_CHARS },
                    "maxItems": MCP_MAX_PATH_ITEMS,
                    "description": "Optional paths FluxGit stages before committing. Omit (or pass an empty array) to commit exactly what is already staged."
                }),
            );
            properties.insert(
                "stageAll".into(),
                json!({
                    "type": "boolean",
                    "default": false,
                    "description": "If true, FluxGit stages every unstaged working-tree change before committing. Ignored when `paths` is provided."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why this commit should be created. Shown to the user in the approval modal."
                }),
            );
            // Honest schema note: amend is intentionally NOT an input. Amending
            // rewrites history and is out of scope for this proposal; the user
            // amends inside FluxGit when needed.
            required.push("message");
            required.push("reason");
        }
        ToolKind::OperationPreviewPush => {
            properties.insert(
                "remote".into(),
                json!({
                    "type": "string",
                    "default": "origin",
                    "description": "Remote to push to. Defaults to 'origin'."
                }),
            );
            properties.insert(
                "branch".into(),
                json!({
                    "type": "string",
                    "description": "Branch to push. Defaults to the currently checked-out branch."
                }),
            );
            properties.insert(
                "setUpstream".into(),
                json!({
                    "type": "boolean",
                    "default": false,
                    "description": "If true, FluxGit pushes with --set-upstream so the branch tracks the remote branch afterwards."
                }),
            );
            properties.insert(
                "forceWithLease".into(),
                json!({
                    "type": "boolean",
                    "default": false,
                    "description": "If true, FluxGit pushes with --force-with-lease. The approval card shows a HIGH risk force warning; use only when intentionally rewriting the remote branch."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why this push should happen. Shown to the user in the approval modal."
                }),
            );
            required.push("reason");
        }
        ToolKind::OperationPreviewBranch => {
            properties.insert(
                "name".into(),
                json!({
                    "type": "string",
                    "description": "Name of the branch to create."
                }),
            );
            properties.insert(
                "startPoint".into(),
                json!({
                    "type": "string",
                    "default": "HEAD",
                    "description": "Commit or ref the new branch starts from. Defaults to HEAD."
                }),
            );
            properties.insert(
                "checkout".into(),
                json!({
                    "type": "boolean",
                    "default": true,
                    "description": "If true (the default), FluxGit checks the new branch out after creating it."
                }),
            );
            properties.insert(
                "reason".into(),
                json!({
                    "type": "string",
                    "description": "Why this branch should be created. Shown to the user in the approval modal."
                }),
            );
            required.push("name");
            required.push("reason");
        }
        ToolKind::OperationStatus | ToolKind::OperationCancel => {
            unreachable!("operation.status/operation.cancel use the early previewId-only schema")
        }
    }

    // Make required strings genuinely non-empty, and bound all top-level
    // strings before they can reach Git, the gateway, or the audit log. The
    // stdio frame limit remains the aggregate ceiling; these field ceilings
    // provide clearer client errors and contain accidental payload abuse.
    for field in &required {
        if let Some(schema) = properties.get_mut(*field).and_then(Value::as_object_mut) {
            if schema.get("type").and_then(Value::as_str) == Some("string") {
                schema.entry("minLength").or_insert_with(|| json!(1));
            }
        }
    }
    for (field, schema) in &mut properties {
        if let Some(schema) = schema.as_object_mut() {
            if schema.get("type").and_then(Value::as_str) == Some("string") {
                let maximum = match field.as_str() {
                    "patchContent" => MCP_MAX_PATCH_CHARS,
                    "message" => MCP_MAX_MESSAGE_CHARS,
                    "repoPath" | "runDir" | "path" => MCP_MAX_PATH_CHARS,
                    "reason" => MCP_MAX_REASON_CHARS,
                    _ => MCP_MAX_REF_CHARS,
                };
                schema.entry("maxLength").or_insert_with(|| json!(maximum));
            }
        }
    }

    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

fn validate_and_canonicalize_tool_arguments(
    kind: ToolKind,
    arguments: &Value,
) -> Result<Value, JsonRpcError> {
    let configured = env::var_os(MCP_ALLOWED_ROOTS_ENV);
    validate_and_canonicalize_tool_arguments_with_config(kind, arguments, configured.as_deref())
}

fn validate_and_canonicalize_tool_arguments_with_config(
    kind: ToolKind,
    arguments: &Value,
    configured: Option<&std::ffi::OsStr>,
) -> Result<Value, JsonRpcError> {
    let schema = tool_input_schema(kind);
    validate_json_schema_value(arguments, &schema, "arguments")
        .map_err(|details| invalid_params_error(&details))?;
    canonicalize_repository_arguments_with_config(arguments, configured)
}

#[cfg(test)]
fn validate_repository_access_with_config(
    arguments: &Value,
    configured: Option<&std::ffi::OsStr>,
) -> Result<(), JsonRpcError> {
    canonicalize_repository_arguments_with_config(arguments, configured).map(|_| ())
}

fn canonicalize_repository_arguments_with_config(
    arguments: &Value,
    configured: Option<&std::ffi::OsStr>,
) -> Result<Value, JsonRpcError> {
    let mut canonical_arguments = arguments.clone();

    let roots = match configured {
        Some(configured) => {
            if configured.to_string_lossy().trim().is_empty() {
                return Err(JsonRpcError {
                    code: -32010,
                    message: "Invalid MCP allowed-roots configuration".into(),
                    data: Some(json!({
                        "environmentVariable": MCP_ALLOWED_ROOTS_ENV,
                        "details": "the configured root list is empty",
                    })),
                });
            }
            let roots = env::split_paths(configured)
                .map(|root| {
                    if root.as_os_str().is_empty() || !root.is_absolute() {
                        return Err(JsonRpcError {
                            code: -32010,
                            message: "Invalid MCP allowed-roots configuration".into(),
                            data: Some(json!({
                                "environmentVariable": MCP_ALLOWED_ROOTS_ENV,
                                "details": "each configured root must be a non-empty absolute filesystem path",
                            })),
                        });
                    }
                    root.canonicalize().map_err(|error| JsonRpcError {
                        code: -32010,
                        message: "Invalid MCP allowed-roots configuration".into(),
                        data: Some(json!({
                            "environmentVariable": MCP_ALLOWED_ROOTS_ENV,
                            "root": root,
                            "details": error.to_string(),
                        })),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if roots.is_empty() {
                return Err(JsonRpcError {
                    code: -32010,
                    message: "Invalid MCP allowed-roots configuration".into(),
                    data: Some(json!({
                        "environmentVariable": MCP_ALLOWED_ROOTS_ENV,
                        "details": "the configured root list is empty",
                    })),
                });
            }
            Some(roots)
        }
        None => None,
    };

    let rewrite = |value: &mut Value| -> Result<(), JsonRpcError> {
        let raw_path = value
            .as_str()
            .ok_or_else(|| invalid_params_error("repoPath values must be strings"))?;
        let path = Path::new(raw_path);
        if raw_path.trim().is_empty() || !path.is_absolute() {
            return Err(invalid_params_error(
                "repoPath values must be absolute filesystem paths",
            ));
        }

        // Without an allowlist, retain backward compatibility for absolute
        // paths that do not exist yet (notably write-preview requests), while
        // still canonicalizing every resolvable repository.  With an allowlist
        // configured, resolution is mandatory: containment cannot be proved
        // for a missing path and therefore fails closed.
        let canonical = match path.canonicalize() {
            Ok(canonical) => canonical,
            Err(_) if roots.is_none() => return Ok(()),
            Err(error) => {
                return Err(JsonRpcError {
                    code: -32602,
                    message: "Repository path cannot be resolved".into(),
                    data: Some(json!({ "details": error.to_string() })),
                })
            }
        };
        if let Some(roots) = roots.as_deref() {
            if !canonical_path_is_within_roots(&canonical, roots) {
                return Err(JsonRpcError {
                    code: -32011,
                    message: "Repository path is outside the MCP allowed roots".into(),
                    data: Some(json!({
                        "environmentVariable": MCP_ALLOWED_ROOTS_ENV,
                        "repoPathFingerprint": arguments_fingerprint(&Value::String(raw_path.into())),
                    })),
                });
            }
        }
        *value = Value::String(canonical.to_string_lossy().into_owned());
        Ok(())
    };

    if let Some(object) = canonical_arguments.as_object_mut() {
        if let Some(repo_path) = object.get_mut("repoPath") {
            rewrite(repo_path)?;
        }
        if let Some(repo_paths) = object.get_mut("repoPaths").and_then(Value::as_array_mut) {
            for repo_path in repo_paths {
                rewrite(repo_path)?;
            }
        }
        if let Some(repositories) = object.get_mut("repositories").and_then(Value::as_array_mut) {
            for repository in repositories {
                if let Some(repo_path) = repository
                    .as_object_mut()
                    .and_then(|repository| repository.get_mut("repoPath"))
                {
                    rewrite(repo_path)?;
                }
            }
        }
    }

    Ok(canonical_arguments)
}

fn canonical_path_is_within_roots(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

/// Small, deterministic validator for the JSON-Schema vocabulary used by the
/// sidecar's own tool contracts. Advertising a schema without enforcing it
/// made missing fields and wrong types silently turn into empty strings or
/// defaults before they reached the gateway.
fn validate_json_schema_value(value: &Value, schema: &Value, path: &str) -> Result<(), String> {
    if let Some(options) = schema.get("anyOf").and_then(Value::as_array) {
        if !options
            .iter()
            .any(|option| validate_json_schema_value(value, option, path).is_ok())
        {
            return Err(format!("{path} does not match any allowed schema"));
        }
    }

    if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = options
            .iter()
            .filter(|option| validate_json_schema_value(value, option, path).is_ok())
            .count();
        if matches != 1 {
            return Err(format!(
                "{path} must match exactly one allowed schema (matched {matches})"
            ));
        }
    }

    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        let matches = match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "integer" => value
                .as_number()
                .is_some_and(|number| number.is_i64() || number.is_u64()),
            "number" => value.is_number(),
            "null" => value.is_null(),
            _ => true,
        };
        if !matches {
            return Err(format!("{path} must be {expected}"));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.iter().any(|candidate| candidate == value) {
            return Err(format!("{path} is not one of the allowed values"));
        }
    }
    if let Some(expected) = schema.get("const") {
        if value != expected {
            return Err(format!("{path} must equal the required constant"));
        }
    }

    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    return Err(format!("{path}.{field} is required"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            for field in object.keys() {
                if !properties.is_some_and(|properties| properties.contains_key(field)) {
                    return Err(format!("{path}.{field} is not allowed"));
                }
            }
        }
        if let Some(properties) = properties {
            for (field, field_schema) in properties {
                if let Some(field_value) = object.get(field) {
                    validate_json_schema_value(
                        field_value,
                        field_schema,
                        &format!("{path}.{field}"),
                    )?;
                }
            }
        }
    }

    if let Some(array) = value.as_array() {
        if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64) {
            if array.len() < minimum as usize {
                return Err(format!("{path} must contain at least {minimum} item(s)"));
            }
        }
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64) {
            if array.len() > maximum as usize {
                return Err(format!("{path} must contain at most {maximum} item(s)"));
            }
        }
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in array.iter().enumerate() {
                validate_json_schema_value(item, item_schema, &format!("{path}[{index}]"))?;
            }
        }
    }

    if let Some(string) = value.as_str() {
        let length = string.chars().count() as u64;
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
            if length < minimum {
                return Err(format!(
                    "{path} must contain at least {minimum} character(s)"
                ));
            }
        }
        if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64) {
            if length > maximum {
                return Err(format!(
                    "{path} must contain at most {maximum} character(s)"
                ));
            }
        }
        if schema.get("pattern").and_then(Value::as_str) == Some("^[A-Za-z0-9_-]+$")
            && (string.is_empty()
                || !string
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
        {
            return Err(format!(
                "{path} must contain only ASCII letters, digits, '_' or '-'"
            ));
        }
    }

    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
            if number < minimum {
                return Err(format!("{path} must be at least {minimum}"));
            }
        }
        if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
            if number > maximum {
                return Err(format!("{path} must be at most {maximum}"));
            }
        }
    }

    Ok(())
}

fn gateway_not_configured_error(tool: &str) -> JsonRpcError {
    JsonRpcError {
        code: 10001,
        message: "Gateway is not configured".into(),
        data: Some(json!({
            "tool": tool,
            "tier": "fluxgit",
            "gatewayConfigured": false,
            "reason": "This tool produces FluxGit-powered context (restore points, safety timeline, predictive preflight or multi-repo radar) and requires a running FluxGit app with the MCP gateway configured.",
            "upgradeHint": "Ask the user to install or launch FluxGit, then ensure FLUXGIT_GATEWAY_ADDR is set in the MCP host config. The in-app Agents / MCP settings panel provides a copy-ready config block.",
            "learnMore": "https://fluxgit.com/features/mcp-agent-git/",
            "freeShellAlternative": "Use repo.status, repo.refs, repo.history, repo.reflog, commit.details, worktree.changes, submodule.status, diff.text or diff.semantic (with supported=false fallback) for read-only inspection without FluxGit."
        })),
    }
}

fn gateway_unavailable_error(tool: &str) -> JsonRpcError {
    JsonRpcError {
        code: 10002,
        message: "FluxGit gateway is configured but this call had nothing to serve it with".into(),
        data: Some(json!({
            "tool": tool,
            "gatewayConfigured": true,
            "reason": "The sidecar could not produce this payload: no absolute repoPath argument was provided for the local read-only fallback, and the configured FluxGit gateway did not serve the request.",
            "agentRecommendation": "Retry the call with an absolute `repoPath` argument (the local read-only fallback works for every free-shell tool). If the tool requires FluxGit context, ask the user to confirm the FluxGit app is running and reachable at FLUXGIT_GATEWAY_ADDR.",
            "learnMore": "https://fluxgit.com/features/mcp-agent-git/"
        })),
    }
}

/// Resolve the gateway handshake address per PLAYBOOK §14.2:
/// `FLUXGIT_MCP_HANDSHAKE_ADDR` first, `FLUXGIT_GATEWAY_ADDR` as fallback.
fn resolve_handshake_addr() -> Option<String> {
    [
        "FLUXGIT_MCP_HANDSHAKE_ADDR",
        "FLUXGIT_GATEWAY_ADDR",
        "FLUXGIT_GATEWAY_URL",
    ]
    .iter()
    .find_map(|name| {
        env::var(name)
            .ok()
            .and_then(|value| normalize_loopback_gateway_addr(&value))
    })
}

/// Normalize the bridge location and reject every non-loopback target. The
/// bridge carries repo paths, diffs and write proposals, so accepting an
/// arbitrary host here would turn a poisoned environment variable into SSRF.
fn normalize_loopback_gateway_addr(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let url = reqwest::Url::parse(&candidate).ok()?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?.trim_matches(['[', ']']);
    let address = host.parse::<std::net::IpAddr>().ok()?;
    if !address.is_loopback() {
        return None;
    }
    let port = url.port()?;
    if address.is_ipv6() {
        Some(format!("[{address}]:{port}"))
    } else {
        Some(format!("{address}:{port}"))
    }
}

/// Build every HTTP bridge client with the same SSRF boundary. Environment
/// proxies are ignored because request bodies contain repository paths,
/// patches, and proposal intent; redirects are never followed; both connect
/// and whole-request time are bounded.
fn loopback_bridge_client(
    request_timeout: Duration,
) -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .build()
}

fn response_json_limited(response: reqwest::blocking::Response) -> io::Result<Value> {
    if response
        .content_length()
        .is_some_and(|length| length > MCP_MAX_BRIDGE_RESPONSE_BYTES as u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway response exceeds the safe MCP bridge-response limit",
        ));
    }
    let mut reader = response.take(MCP_MAX_BRIDGE_RESPONSE_BYTES as u64 + 1);
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    if body.len() > MCP_MAX_BRIDGE_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway response exceeds the safe MCP bridge-response limit",
        ));
    }
    serde_json::from_slice(&body).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Dispatch any of the five `operation.preview.*` write-handshake requests through
/// the FluxGit gateway over HTTP and poll for its outcome (PLAYBOOK §10 MVP for
/// merge, §14.7 for the remaining four).
///
/// The caller is responsible for assembling the operation-specific body. This
/// helper only handles the transport: POST to `/v1/mcp/operation/preview/<op>`,
/// then poll the shared `/v1/mcp/operation/status/<previewId>` endpoint.
///
/// Returns `Some(ToolCallResult)` when the dispatch succeeded — even when the user
/// rejected, the operation failed, or the polling timed out — so the caller forwards
/// the structured outcome to the agent. Returns `None` when the gateway is
/// unreachable (POST failed) so the caller falls back to the standard
/// `write_handshake_pending_error` (code 10003), keeping the contract stable for
/// agents during the rollout.
fn dispatch_operation_preview_request(
    tool_name: &'static str,
    op_path_suffix: &str,
    gateway_addr: &str,
    preview_id: &str,
    body: &Value,
) -> Option<ToolCallResult> {
    let base = format!("http://{}", gateway_addr.trim_end_matches('/'));
    let dispatch_url = format!("{}/v1/mcp/operation/preview/{}", base, op_path_suffix);

    let client = match loopback_bridge_client(Duration::from_secs(5)) {
        Ok(client) => client,
        Err(_) => return None,
    };

    let post_response = match client.post(&dispatch_url).json(body).send() {
        Ok(response) => response,
        Err(_) => return None,
    };
    if !post_response.status().is_success() {
        // The gateway answered but refused the proposal (policy 403, pending
        // cap 429, validation 422, ...). Relay the structured, self-guiding
        // body to the agent instead of collapsing it into the generic 10003.
        let http_status = post_response.status().as_u16();
        if let Ok(body) = response_json_limited(post_response) {
            if body.get("error").is_some() {
                return Some(operation_preview_gateway_refusal_result(
                    tool_name,
                    preview_id,
                    http_status,
                    &body,
                ));
            }
        }
        return None;
    }

    // Idempotent replay may return the gateway's already-existing proposal,
    // whose canonical id can differ from the fresh client-generated id. Always
    // follow the server id when present or status polling can watch the wrong
    // proposal forever.
    let post_body = response_json_limited(post_response).unwrap_or(Value::Null);
    let effective_preview_id = match post_body.get("previewId").and_then(Value::as_str) {
        Some(value) if valid_preview_id(value) => value.to_string(),
        Some(_) => {
            return Some(text_tool_result(
                json!({
                    "tool": tool_name,
                    "readOnly": false,
                    "source": "fluxgit-app",
                    "tier": "fluxgit-write-handshake",
                    "error": {
                        "code": 10007,
                        "message": "FluxGit's gateway returned an invalid previewId.",
                    }
                }),
                true,
            ));
        }
        None => preview_id.to_string(),
    };
    let status_url = format!("{}/v1/mcp/operation/status/{}", base, effective_preview_id);

    // Make one bounded status read so gateways that complete synchronously can
    // return the terminal result. Human approval normally takes longer, so a
    // live proposal is returned immediately for operation.status to continue.
    let parsed = client
        .get(&status_url)
        .send()
        .ok()
        .filter(|response| response.status().is_success())
        .and_then(|response| response_json_limited(response).ok());
    if let Some(parsed) = parsed {
        let status_label = parsed
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("pending")
            .to_string();
        match status_label.as_str() {
            "completed" => {
                return Some(operation_preview_success_result(
                    tool_name,
                    &effective_preview_id,
                    &parsed,
                ));
            }
            "rejected" | "failed" | "expired" | "cancelled" => {
                return Some(operation_preview_terminal_error_result(
                    tool_name,
                    op_path_suffix,
                    &effective_preview_id,
                    &status_label,
                    &parsed,
                ));
            }
            _ => {
                return Some(operation_preview_pending_result(
                    tool_name,
                    op_path_suffix,
                    &effective_preview_id,
                    &status_label,
                ));
            }
        }
    }

    Some(operation_preview_pending_result(
        tool_name,
        op_path_suffix,
        &effective_preview_id,
        "pending",
    ))
}

/// Build the merge body and dispatch (PLAYBOOK §14.3).
fn dispatch_operation_preview_merge(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let source_ref = arguments
        .get("sourceRef")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let target_ref = arguments
        .get("targetRef")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let strategy = arguments
        .get("strategy")
        .and_then(Value::as_str)
        .unwrap_or("merge")
        .to_string();
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("merge", arguments),
        "operationType": "merge",
        "repoPath": repo_path,
        "sourceRef": source_ref,
        "targetRef": target_ref,
        "reason": reason,
        "strategy": strategy,
        "requestedAt": requested_at,
    });

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewMerge.as_str(),
        "merge",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the rebase body and dispatch (PLAYBOOK §14.7).
fn dispatch_operation_preview_rebase(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let current_ref = arguments
        .get("currentRef")
        .and_then(Value::as_str)
        .unwrap_or("HEAD")
        .to_string();
    let onto_ref = arguments
        .get("ontoRef")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let interactive = arguments
        .get("interactive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("rebase", arguments),
        "operationType": "rebase",
        "repoPath": repo_path,
        "currentRef": current_ref,
        "ontoRef": onto_ref,
        "reason": reason,
        "interactive": interactive,
        "requestedAt": requested_at,
    });

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewRebase.as_str(),
        "rebase",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the discard body and dispatch (PLAYBOOK §14.7).
fn dispatch_operation_preview_discard(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let paths: Vec<String> = arguments
        .get("paths")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("discard", arguments),
        "operationType": "discard",
        "repoPath": repo_path,
        "paths": paths,
        "reason": reason,
        "requestedAt": requested_at,
    });

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewDiscard.as_str(),
        "discard",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the reset body and dispatch (PLAYBOOK §14.7).
fn dispatch_operation_preview_reset(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let target_ref = arguments
        .get("targetRef")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mode = arguments
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("mixed")
        .to_string();
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("reset", arguments),
        "operationType": "reset",
        "repoPath": repo_path,
        "targetRef": target_ref,
        "mode": mode,
        "reason": reason,
        "requestedAt": requested_at,
    });

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewReset.as_str(),
        "reset",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the patch body and dispatch (PLAYBOOK §14.7).
fn dispatch_operation_preview_patch(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let patch_content = arguments
        .get("patchContent")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let apply_to_index = arguments
        .get("applyToIndex")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("patch", arguments),
        "operationType": "patch",
        "repoPath": repo_path,
        "patchContent": patch_content,
        "reason": reason,
        "applyToIndex": apply_to_index,
        "requestedAt": requested_at,
    });

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewPatch.as_str(),
        "patch",
        gateway_addr,
        &preview_id,
        &body,
    )
}

fn dispatch_operation_preview_plan(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // Steps are passed through verbatim; the gateway validates the shape and
    // bounds (1..=10) and the UI renders each step in the approval card.
    let steps = arguments
        .get("steps")
        .cloned()
        .unwrap_or(Value::Array(vec![]));
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("plan", arguments),
        "operationType": "plan",
        "repoPath": repo_path,
        "steps": steps,
        "reason": reason,
        "requestedAt": requested_at,
    });

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewPlan.as_str(),
        "plan",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the worktree body and dispatch (AGENT_FIRST_ROADMAP P2 / NORTH_STAR
/// vector 5). `path` is optional: when the agent omits it the field is left
/// out of the body and FluxGit picks a sane default location.
fn dispatch_operation_preview_worktree(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let branch = arguments
        .get("branch")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let path = arguments
        .get("path")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string());
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("worktree", arguments),
        "operationType": "worktree",
        "repoPath": repo_path,
        "branch": branch,
        "reason": reason,
        "requestedAt": requested_at,
    });
    if let Some(path) = path {
        body["path"] = Value::String(path);
    }

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewWorktree.as_str(),
        "worktree",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the commit body and dispatch (PLAYBOOK §14.7). `paths` is optional:
/// when the agent omits it the field is left out of the body and FluxGit
/// commits exactly what is already staged (or everything unstaged when
/// `stageAll` is true). Amend is intentionally not supported.
fn dispatch_operation_preview_commit(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let message = arguments
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let paths: Option<Vec<String>> = arguments.get("paths").and_then(Value::as_array).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    });
    let stage_all = arguments
        .get("stageAll")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("commit", arguments),
        "operationType": "commit",
        "repoPath": repo_path,
        "message": message,
        "stageAll": stage_all,
        "reason": reason,
        "requestedAt": requested_at,
    });
    if let Some(paths) = paths {
        body["paths"] = json!(paths);
    }

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewCommit.as_str(),
        "commit",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the push body and dispatch (PLAYBOOK §14.7). `remote` defaults to
/// "origin"; `branch` is optional (omitted → FluxGit pushes the currently
/// checked-out branch). `forceWithLease: true` renders a HIGH risk card.
fn dispatch_operation_preview_push(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let remote = arguments
        .get("remote")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("origin")
        .to_string();
    let branch = arguments
        .get("branch")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string());
    let set_upstream = arguments
        .get("setUpstream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let force_with_lease = arguments
        .get("forceWithLease")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("push", arguments),
        "operationType": "push",
        "repoPath": repo_path,
        "remote": remote,
        "setUpstream": set_upstream,
        "forceWithLease": force_with_lease,
        "reason": reason,
        "requestedAt": requested_at,
    });
    if let Some(branch) = branch {
        body["branch"] = Value::String(branch);
    }

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewPush.as_str(),
        "push",
        gateway_addr,
        &preview_id,
        &body,
    )
}

/// Build the branch-create body and dispatch (PLAYBOOK §14.7). `startPoint`
/// is optional (omitted → HEAD); `checkout` defaults to true.
fn dispatch_operation_preview_branch(
    gateway_addr: &str,
    agent_id: &str,
    arguments: &Value,
) -> Option<ToolCallResult> {
    let preview_id = uuid::Uuid::new_v4().to_string();
    let repo_path = arguments
        .get("repoPath")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let name = arguments
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let start_point = arguments
        .get("startPoint")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string());
    let checkout = arguments
        .get("checkout")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut body = json!({
        "previewId": preview_id,
        "agentId": agent_id,
        "idempotencyKey": idempotency_key_for("branch", arguments),
        "operationType": "branch",
        "repoPath": repo_path,
        "name": name,
        "checkout": checkout,
        "reason": reason,
        "requestedAt": requested_at,
    });
    if let Some(start_point) = start_point {
        body["startPoint"] = Value::String(start_point);
    }

    dispatch_operation_preview_request(
        ToolKind::OperationPreviewBranch.as_str(),
        "branch",
        gateway_addr,
        &preview_id,
        &body,
    )
}

fn operation_preview_success_result(
    tool_name: &'static str,
    preview_id: &str,
    status_body: &Value,
) -> ToolCallResult {
    let payload = json!({
        "tool": tool_name,
        "readOnly": false,
        "source": "fluxgit-app",
        "tier": "fluxgit-write-handshake",
        "previewId": preview_id,
        "status": "completed",
        "data": status_body,
    });
    text_tool_result(payload, false)
}

fn operation_preview_terminal_error_result(
    tool_name: &'static str,
    op_label: &str,
    preview_id: &str,
    status_label: &str,
    status_body: &Value,
) -> ToolCallResult {
    let message = match status_label {
        "rejected" => format!("User rejected the {op_label} preview inside FluxGit."),
        "failed" => format!("FluxGit reported that the {op_label} preview failed."),
        "expired" => format!("The {op_label} preview expired before the user approved it."),
        "cancelled" => format!("The {op_label} proposal was cancelled before a decision."),
        _ => format!("FluxGit returned a non-terminal status before completing the {op_label}."),
    };
    let payload = json!({
        "tool": tool_name,
        "readOnly": false,
        "source": "fluxgit-app",
        "tier": "fluxgit-write-handshake",
        "previewId": preview_id,
        "status": status_label,
        "error": {
            "code": 10004,
            "message": message,
            "data": {
                "previewId": preview_id,
                "status": status_label,
                "statusBody": status_body,
            }
        }
    });
    text_tool_result(payload, true)
}

fn tool_title(kind: ToolKind) -> String {
    let mut title = String::with_capacity(kind.as_str().len() + 4);
    let mut previous_was_lowercase = false;
    for character in kind.as_str().chars() {
        if character == '.' {
            title.push(' ');
            previous_was_lowercase = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_was_lowercase {
            title.push(' ');
        }
        if title.is_empty() || title.ends_with(' ') {
            title.push(character.to_ascii_uppercase());
        } else {
            title.push(character);
        }
        previous_was_lowercase = character.is_ascii_lowercase();
    }
    title
}

/// The proposal was accepted and remains live after the one immediate status
/// read. Return it as a successful asynchronous result; operation.status is
/// the authoritative continuation contract.
fn operation_preview_pending_result(
    tool_name: &'static str,
    op_label: &str,
    preview_id: &str,
    last_status: &str,
) -> ToolCallResult {
    let payload = json!({
        "tool": tool_name,
        "readOnly": false,
        "source": "fluxgit-app",
        "tier": "fluxgit-write-handshake",
        "previewId": preview_id,
        "status": last_status,
        "accepted": true,
        "nextAction": {
            "tool": "operation.status",
            "message": format!(
                "The {op_label} proposal is open in FluxGit for human review."
            ),
            "data": {
                "previewId": preview_id,
                "lastStatus": last_status,
                "reason": "The proposal is open inside FluxGit (proposals live for 5 minutes). The human can approve it asynchronously; this response does not claim the Git operation completed.",
                "agentRecommendation": format!(
                    "Poll operation.status with previewId '{preview_id}' to learn the real outcome before telling the user anything, or call operation.cancel with the same previewId to withdraw the proposal if it is no longer wanted."
                ),
            }
        }
    });
    text_tool_result(payload, false)
}

/// The gateway answered the preview POST with a structured refusal
/// (agent policy 403, per-agent pending cap 429, validation 422, ...).
/// Relay it so the agent sees the gateway's own self-guiding message.
fn operation_preview_gateway_refusal_result(
    tool_name: &'static str,
    preview_id: &str,
    http_status: u16,
    gateway_body: &Value,
) -> ToolCallResult {
    let payload = json!({
        "tool": tool_name,
        "readOnly": false,
        "source": "fluxgit-app",
        "tier": "fluxgit-write-handshake",
        "previewId": preview_id,
        "status": "refused",
        "error": {
            "code": 10006,
            "message": "FluxGit's gateway refused the proposal before opening an approval card.",
            "data": {
                "httpStatus": http_status,
                "gateway": gateway_body,
            }
        }
    });
    text_tool_result(payload, true)
}

/// `operation.status` — read-only lookup of a proposal's lifecycle through
/// the gateway handshake bridge (PLAYBOOK §10.6).
fn checked_preview_id(arguments: &Value) -> Result<&str, JsonRpcError> {
    let preview_id = arguments
        .get("previewId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params_error("missing previewId"))?;
    if !valid_preview_id(preview_id) {
        return Err(invalid_params_error(
            "previewId must be 1-128 ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(preview_id)
}

fn valid_preview_id(preview_id: &str) -> bool {
    !preview_id.is_empty()
        && preview_id.len() <= 128
        && preview_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn operation_status_tool_call(arguments: &Value) -> Result<ToolCallResult, JsonRpcError> {
    let preview_id = checked_preview_id(arguments)?;
    let Some(addr) = resolve_handshake_addr() else {
        return Ok(handshake_unreachable_result(
            ToolKind::OperationStatus,
            true,
        ));
    };
    let base = format!("http://{}", addr.trim_end_matches('/'));
    let status_url = format!("{}/v1/mcp/operation/status/{}", base, preview_id);
    let client = match loopback_bridge_client(Duration::from_secs(5)) {
        Ok(client) => client,
        Err(_) => {
            return Ok(handshake_unreachable_result(
                ToolKind::OperationStatus,
                true,
            ))
        }
    };
    let response = match client.get(&status_url).send() {
        Ok(response) => response,
        Err(_) => {
            return Ok(handshake_unreachable_result(
                ToolKind::OperationStatus,
                true,
            ))
        }
    };
    if response.status().as_u16() == 404 {
        return Ok(preview_not_found_result(
            ToolKind::OperationStatus,
            preview_id,
            true,
        ));
    }
    if !response.status().is_success() {
        return Ok(handshake_unreachable_result(
            ToolKind::OperationStatus,
            true,
        ));
    }
    let body: Value = match response_json_limited(response) {
        Ok(value) => value,
        Err(_) => {
            return Ok(handshake_unreachable_result(
                ToolKind::OperationStatus,
                true,
            ))
        }
    };
    Ok(text_tool_result(
        json!({
            "tool": ToolKind::OperationStatus.as_str(),
            "readOnly": true,
            "source": "fluxgit-app",
            "tier": "fluxgit-write-handshake",
            "previewId": preview_id,
            "data": body,
        }),
        false,
    ))
}

/// `operation.cancel` — withdraw one of this agent's own pending proposals.
fn operation_cancel_tool_call(
    agent_id: &str,
    arguments: &Value,
) -> Result<ToolCallResult, JsonRpcError> {
    let preview_id = checked_preview_id(arguments)?;
    let Some(addr) = resolve_handshake_addr() else {
        return Ok(handshake_unreachable_result(
            ToolKind::OperationCancel,
            false,
        ));
    };
    let base = format!("http://{}", addr.trim_end_matches('/'));
    let cancel_url = format!("{}/v1/mcp/operation/cancel/{}", base, preview_id);
    let client = match loopback_bridge_client(Duration::from_secs(5)) {
        Ok(client) => client,
        Err(_) => {
            return Ok(handshake_unreachable_result(
                ToolKind::OperationCancel,
                false,
            ))
        }
    };
    let response = match client
        .post(&cancel_url)
        .json(&json!({ "agentId": agent_id }))
        .send()
    {
        Ok(response) => response,
        Err(_) => {
            return Ok(handshake_unreachable_result(
                ToolKind::OperationCancel,
                false,
            ))
        }
    };
    let http_status = response.status().as_u16();
    if http_status == 404 {
        return Ok(preview_not_found_result(
            ToolKind::OperationCancel,
            preview_id,
            false,
        ));
    }
    let body: Value = response_json_limited(response).unwrap_or(Value::Null);
    if !(200..300).contains(&http_status) {
        // 403 (not this agent's proposal) or 409 (already decided/expired).
        return Ok(text_tool_result(
            json!({
                "tool": ToolKind::OperationCancel.as_str(),
                "readOnly": false,
                "source": "fluxgit-app",
                "tier": "fluxgit-write-handshake",
                "previewId": preview_id,
                "error": {
                    "code": 10006,
                    "message": "FluxGit's gateway refused to cancel this proposal.",
                    "data": {
                        "httpStatus": http_status,
                        "previewId": preview_id,
                        "gateway": body,
                        "agentRecommendation": "Only the proposing agent can cancel, and only while the proposal is still pending. Poll operation.status with this previewId to learn its current state.",
                    }
                }
            }),
            true,
        ));
    }
    Ok(text_tool_result(
        json!({
            "tool": ToolKind::OperationCancel.as_str(),
            "readOnly": false,
            "source": "fluxgit-app",
            "tier": "fluxgit-write-handshake",
            "previewId": preview_id,
            "status": "cancelled",
            "data": body,
        }),
        false,
    ))
}

/// Shared "the handshake bridge is not reachable" result for
/// operation.status / operation.cancel, reusing the well-known 10003 error.
fn handshake_unreachable_result(kind: ToolKind, read_only: bool) -> ToolCallResult {
    let error = write_handshake_pending_error(kind.as_str());
    text_tool_result(
        json!({
            "error": error,
            "tool": kind.as_str(),
            "readOnly": read_only,
            "tier": "fluxgit-write-handshake",
        }),
        true,
    )
}

/// The gateway does not know this previewId. Proposal lifecycle is journaled
/// durably, so restart alone is not a reason to re-propose or re-run Git;
/// Approved/Executing records are recovered for explicit UI reconciliation.
fn preview_not_found_result(kind: ToolKind, preview_id: &str, read_only: bool) -> ToolCallResult {
    text_tool_result(
        json!({
            "tool": kind.as_str(),
            "readOnly": read_only,
            "tier": "fluxgit-write-handshake",
            "previewId": preview_id,
            "error": {
                "code": 10005,
                "message": format!("No proposal with previewId '{preview_id}' exists on the gateway."),
                "data": {
                    "previewId": preview_id,
                    "reason": "FluxGit journals proposal lifecycle durably. Approved and Executing proposals are recovered after restart for explicit UI reconciliation; this previewId is not present in the gateway's current journal view and may be invalid, never accepted, or already pruned after terminal retention.",
                    "agentRecommendation": "Double-check the previewId and ask the user to inspect Agent Control and Safety Timeline. Do not re-propose or re-run Git blindly: if execution may have started, reconcile the repository outcome in FluxGit first.",
                }
            }
        }),
        true,
    )
}

/// Error returned for write-with-UI-handshake tools (PLAYBOOK §10) that are
/// advertised in `tools/list` when the local FluxGit bridge is unreachable.
fn write_handshake_pending_error(tool: &str) -> JsonRpcError {
    JsonRpcError {
        code: 10003,
        message: "FluxGit desktop is not connected for the write handshake".into(),
        data: Some(json!({
            "tool": tool,
            "tier": "fluxgit-write-handshake",
            "gatewayConfigured": false,
            "reason": "This tool proposes a write that FluxGit must preview and the user must approve in the desktop UI. The sidecar could not reach the FluxGit handshake endpoint: either the FluxGit app is not running, FLUXGIT_MCP_HANDSHAKE_ADDR is not set for this MCP server, or the local handshake request failed.",
            "agentRecommendation": "Tell the user: 'Open FluxGit and connect this agent from Operations > Agent Control (Quick Connect sets the handshake address), then I can propose this change for your approval.' Retry only after the user confirms FluxGit is running and connected.",
            "learnMore": "https://fluxgit.com/features/mcp-agent-git/"
        })),
    }
}

fn serialize_response(response: &JsonRpcResponse) -> Vec<u8> {
    match serde_json::to_vec(response) {
        Ok(serialized) if serialized.len() <= MCP_MAX_FRAME_BYTES => serialized,
        Ok(serialized) => serialize_response_error(
            &response.id,
            "Response exceeds the MCP frame limit",
            json!({
                "details": "The result was replaced before writing stdout so the MCP stdio session can continue safely. Narrow the request or lower its output limit and retry.",
                "limitBytes": MCP_MAX_FRAME_BYTES,
                "serializedBytes": serialized.len(),
                "retryable": true,
            }),
        ),
        Err(error) => serialize_response_error(
            &response.id,
            "Internal response serialization error",
            json!({ "details": error.to_string(), "retryable": false }),
        ),
    }
}

fn serialize_response_error(id: &Value, message: &str, data: Value) -> Vec<u8> {
    let fallback = |id: Value| JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code: -32603,
            message: message.into(),
            data: Some(data.clone()),
        }),
    };

    // Normal request ids are bounded at ingress, so this branch preserves the
    // exact correlation id. The null-id fallback is only a final defense for
    // direct library callers that manually construct an impossible response.
    if let Ok(serialized) = serde_json::to_vec(&fallback(id.clone())) {
        if serialized.len() <= MCP_MAX_FRAME_BYTES {
            return serialized;
        }
    }
    serde_json::to_vec(&fallback(Value::Null)).unwrap_or_else(|_| {
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}"
            .to_vec()
    })
}

fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let first_line = loop {
        let Some(line) = read_bounded_line(reader, MCP_MAX_FRAME_BYTES + 2)? else {
            return Ok(None);
        };
        if !trim_line_ending(&line).iter().all(u8::is_ascii_whitespace) {
            break line;
        }
    };

    let first_trimmed = trim_line_ending(&first_line);
    let Some(first_length) = parse_content_length_header(first_trimmed)? else {
        if first_trimmed.len() > MCP_MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MCP frame exceeds the {MCP_MAX_FRAME_BYTES}-byte limit"),
            ));
        }
        return Ok(Some(first_trimmed.to_vec()));
    };

    if first_trimmed.len() > MCP_MAX_LEGACY_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "legacy MCP header line is too large",
        ));
    }
    let content_length = first_length;
    let mut total_header_bytes = first_line.len();
    loop {
        let Some(line) = read_bounded_line(reader, MCP_MAX_LEGACY_HEADER_BYTES)? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "legacy MCP frame ended before its header terminator",
            ));
        };
        total_header_bytes = total_header_bytes.saturating_add(line.len());
        if total_header_bytes > MCP_MAX_LEGACY_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy MCP header block is too large",
            ));
        }
        let trimmed = trim_line_ending(&line);
        if trimmed.is_empty() {
            break;
        }
        if parse_content_length_header(trimmed)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate Content-Length headers are not allowed",
            ));
        }
    }

    if content_length > MCP_MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MCP frame exceeds the {MCP_MAX_FRAME_BYTES}-byte limit"),
        ));
    }
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MCP_MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MCP frame exceeds the {MCP_MAX_FRAME_BYTES}-byte limit"),
        ));
    }
    if payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "newline-delimited MCP output cannot contain a literal newline",
        ));
    }
    writer.write_all(payload)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn read_bounded_line(reader: &mut impl BufRead, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MCP line exceeds the {limit}-byte limit"),
            ));
        }
        line.extend_from_slice(&available[..take]);
        let ended = available[take - 1] == b'\n';
        reader.consume(take);
        if ended {
            return Ok(Some(line));
        }
    }
}

fn trim_line_ending(mut line: &[u8]) -> &[u8] {
    while line
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        line = &line[..line.len() - 1];
    }
    line
}

fn parse_content_length_header(line: &[u8]) -> io::Result<Option<usize>> {
    let Ok(line) = std::str::from_utf8(line) else {
        return Ok(None);
    };
    let Some((name, value)) = line.split_once(':') else {
        return Ok(None);
    };
    if !name.eq_ignore_ascii_case("Content-Length") {
        return Ok(None);
    }
    let length = value.trim().parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Content-Length: {error}"),
        )
    })?;
    Ok(Some(length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Serializes mutation of process-wide env vars (FLUXGIT_GATEWAY_ADDR) across the
    /// operation.preview.merge dispatch tests so they can't race each other when cargo
    /// runs the test suite in parallel.
    static GATEWAY_ENV_LOCK: Mutex<()> = Mutex::new(());
    static AUDIT_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct AuditEnvGuard {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl AuditEnvGuard {
        fn isolated(run_dir: &Path, signing_key: Option<&Path>) -> Self {
            let guard = AUDIT_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let names = [
                "FLUXGIT_RUN_DIR",
                "FLUXGIT_MCP_AUDIT_LOG",
                "FLUXGIT_MCP_AUDIT_DISABLED",
                "FLUXGIT_MCP_AUDIT_SIGN_KEY",
            ];
            let previous = names
                .iter()
                .map(|name| (*name, env::var_os(name)))
                .collect();
            env::set_var("FLUXGIT_RUN_DIR", run_dir);
            env::remove_var("FLUXGIT_MCP_AUDIT_LOG");
            env::remove_var("FLUXGIT_MCP_AUDIT_DISABLED");
            match signing_key {
                Some(path) => env::set_var("FLUXGIT_MCP_AUDIT_SIGN_KEY", path),
                None => env::remove_var("FLUXGIT_MCP_AUDIT_SIGN_KEY"),
            }
            Self {
                previous,
                _guard: guard,
            }
        }
    }

    impl Drop for AuditEnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.previous {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }

    struct GatewayEnvGuard {
        previous: Option<String>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl GatewayEnvGuard {
        fn set(value: &str) -> Self {
            let guard = GATEWAY_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = env::var("FLUXGIT_GATEWAY_ADDR").ok();
            env::set_var("FLUXGIT_GATEWAY_ADDR", value);
            Self {
                previous,
                _guard: guard,
            }
        }

        fn unset() -> Self {
            let guard = GATEWAY_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = env::var("FLUXGIT_GATEWAY_ADDR").ok();
            env::remove_var("FLUXGIT_GATEWAY_ADDR");
            Self {
                previous,
                _guard: guard,
            }
        }
    }

    impl Drop for GatewayEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => env::set_var("FLUXGIT_GATEWAY_ADDR", value),
                None => env::remove_var("FLUXGIT_GATEWAY_ADDR"),
            }
        }
    }

    fn unique_test_temp_path(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Resolve the temp root before building the path.
        //
        // The audit ledger refuses to write when any directory component is a
        // symlink -- correct, since a link planted in the chain could redirect
        // the log. On macOS `env::temp_dir()` is /var/folders/... and /var is a
        // symlink to /private/var on every Mac, so every audit test refused its
        // own scratch directory. The guard is unix-only, which is why this
        // passed on Windows and could not pass here.
        // Unix only. The problem it solves is a unix one, and on Windows
        // canonicalize returns an extended-length \\?\ path, which changes how
        // ancestors iterate and how paths compare -- a fix on one platform
        // becoming a hazard on another.
        #[cfg(unix)]
        let root = fs::canonicalize(env::temp_dir()).unwrap_or_else(|_| env::temp_dir());
        #[cfg(not(unix))]
        let root = env::temp_dir();
        root.join(format!(
            "{prefix}-{}-{nonce}-{sequence}",
            std::process::id()
        ))
    }

    fn modern_request_meta() -> Value {
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "fluxgit-sidecar-tests",
                    "version": "1.0",
                }
            }
        })
    }

    /// Focused JSON Schema validator for the output-contract keywords emitted
    /// by this crate. Keeping it local to tests avoids raising the Rust 1.75
    /// dependency floor merely to test schemas we construct ourselves.
    fn validate_output_schema(schema: &Value, value: &Value) -> Result<(), String> {
        validate_output_schema_at(schema, value, "$")
    }

    fn validate_output_schema_at(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
        if let Some(expected) = schema.get("const") {
            if value != expected {
                return Err(format!("{path}: expected const {expected}, got {value}"));
            }
        }
        if let Some(variants) = schema.get("enum").and_then(Value::as_array) {
            if !variants.iter().any(|candidate| candidate == value) {
                return Err(format!("{path}: {value} is not in enum {variants:?}"));
            }
        }
        if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
            let matches = match expected_type {
                "object" => value.is_object(),
                "array" => value.is_array(),
                "string" => value.is_string(),
                "integer" => value
                    .as_number()
                    .is_some_and(|number| number.is_i64() || number.is_u64()),
                "number" => value.is_number(),
                "boolean" => value.is_boolean(),
                "null" => value.is_null(),
                other => return Err(format!("{path}: unsupported test schema type {other}")),
            };
            if !matches {
                return Err(format!(
                    "{path}: expected type {expected_type}, got {value}"
                ));
            }
        }

        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            let object = value
                .as_object()
                .ok_or_else(|| format!("{path}: required applies to a non-object"))?;
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    return Err(format!("{path}: missing required property {field}"));
                }
            }
        }
        if let (Some(properties), Some(object)) = (
            schema.get("properties").and_then(Value::as_object),
            value.as_object(),
        ) {
            for (field, field_schema) in properties {
                if let Some(field_value) = object.get(field) {
                    validate_output_schema_at(
                        field_schema,
                        field_value,
                        &format!("{path}.{field}"),
                    )?;
                }
            }
        }

        if let Some(text) = value.as_str() {
            let length = text.chars().count() as u64;
            if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
                if length < minimum {
                    return Err(format!("{path}: string length {length} < {minimum}"));
                }
            }
            if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64) {
                if length > maximum {
                    return Err(format!("{path}: string length {length} > {maximum}"));
                }
            }
            if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
                let matches = match pattern {
                    "^[A-Za-z0-9_-]+$" => text
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
                    "^[a-z][a-z0-9_-]*$" => {
                        let mut bytes = text.bytes();
                        bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
                            && bytes.all(|byte| {
                                byte.is_ascii_lowercase()
                                    || byte.is_ascii_digit()
                                    || matches!(byte, b'-' | b'_')
                            })
                    }
                    other => {
                        return Err(format!("{path}: unsupported test schema pattern {other}"))
                    }
                };
                if !matches {
                    return Err(format!("{path}: string does not match {pattern}"));
                }
            }
            if schema.get("format").and_then(Value::as_str) == Some("date-time")
                && chrono::DateTime::parse_from_rfc3339(text).is_err()
            {
                return Err(format!("{path}: string is not an RFC 3339 date-time"));
            }
        }

        if let Some(number) = value.as_f64() {
            if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
                if number < minimum {
                    return Err(format!("{path}: number {number} < {minimum}"));
                }
            }
            if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
                if number > maximum {
                    return Err(format!("{path}: number {number} > {maximum}"));
                }
            }
        }

        if let Some(items) = value.as_array() {
            if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64) {
                if items.len() < minimum as usize {
                    return Err(format!("{path}: {} items < {minimum}", items.len()));
                }
            }
            if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64) {
                if items.len() > maximum as usize {
                    return Err(format!("{path}: {} items > {maximum}", items.len()));
                }
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate_output_schema_at(item_schema, item, &format!("{path}[{index}]"))?;
                }
            }
        }

        if let Some(branches) = schema.get("anyOf").and_then(Value::as_array) {
            let failures = branches
                .iter()
                .filter_map(|branch| validate_output_schema_at(branch, value, path).err())
                .collect::<Vec<_>>();
            if failures.len() == branches.len() {
                return Err(format!(
                    "{path}: no anyOf branch matched ({})",
                    failures.join(" | ")
                ));
            }
        }

        Ok(())
    }

    fn assert_tool_result_contract(tool_name: &str, response: &Value) {
        let Some(result) = response.get("result") else {
            // Argument/schema failures are JSON-RPC errors, not MCP tool
            // results, and therefore have no structuredContent to validate.
            return;
        };
        let Some(structured) = result.get("structuredContent") else {
            panic!("modern {tool_name} result omitted structuredContent: {response:?}");
        };
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{tool_name} result omitted text content"));
        let parsed_text: Value = serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("{tool_name} text is not JSON: {error}"));
        assert_eq!(
            parsed_text, *structured,
            "{tool_name} text and structuredContent must carry the same payload"
        );

        let kind = ToolKind::from_name(tool_name).expect("known test tool");
        let read_only = READ_ONLY_TOOL_KINDS.contains(&kind);
        let schema = tool_output_schema(kind, read_only);
        if let Err(error) = validate_output_schema(&schema, structured) {
            panic!(
                "{tool_name} structuredContent violated outputSchema: {error}\npayload={structured}\nschema={schema}"
            );
        }

        assert_eq!(
            result["isError"].as_bool(),
            Some(structured.get("error").is_some()),
            "{tool_name} must set isError exactly when its structured payload is an error"
        );
    }

    #[test]
    fn initialize_returns_server_identity_and_tools_capability() {
        let server = McpSidecar::new_for_tests(false);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();

        assert!(response.get("error").is_none());

        let result = &response["result"];
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(result["serverInfo"]["version"], SERVER_VERSION);
        assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
    }

    #[test]
    fn modern_discovery_advertises_dual_era_capabilities() {
        let server = McpSidecar::new_for_tests(false);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": "discover-1",
                "method": "server/discover",
                "params": modern_request_meta(),
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        let result = &response["result"];
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["supportedVersions"][0], LATEST_PROTOCOL_VERSION);
        assert!(result["supportedVersions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|version| version == LEGACY_PROTOCOL_VERSION));
        assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
        assert!(result.get("serverInfo").is_none());
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            SERVER_NAME
        );
        assert_eq!(result["cacheScope"], "public");
        assert!(result["ttlMs"].as_u64().unwrap() > 0);
    }

    #[test]
    fn modern_requests_require_supported_version_and_capabilities() {
        let server = McpSidecar::new_for_tests(false);
        let unsupported = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }}
            }))
            .unwrap();
        let unsupported = serde_json::to_value(unsupported).unwrap();
        assert_eq!(unsupported["error"]["code"], -32022);
        assert_eq!(unsupported["error"]["data"]["requested"], "2099-01-01");

        let missing_capabilities = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                }}
            }))
            .unwrap();
        let missing_capabilities = serde_json::to_value(missing_capabilities).unwrap();
        assert_eq!(missing_capabilities["error"]["code"], -32602);

        let malformed_client_info = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "missing-version" },
                }}
            }))
            .unwrap();
        let malformed_client_info = serde_json::to_value(malformed_client_info).unwrap();
        assert_eq!(malformed_client_info["error"]["code"], -32602);
    }

    #[test]
    fn modern_and_legacy_results_only_expose_members_valid_for_their_era() {
        let server = McpSidecar::new_for_tests(false);
        let legacy = server
            .handle_value(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list"
            }))
            .unwrap();
        let legacy = serde_json::to_value(legacy).unwrap();
        assert!(legacy["result"].get("resultType").is_none());
        let legacy_tools = legacy["result"]["tools"].as_array().unwrap();
        assert_eq!(legacy_tools.len(), 34);
        assert!(legacy_tools
            .iter()
            .all(|tool| tool.get("outputSchema").is_none()));
        assert!(legacy_tools
            .iter()
            .all(|tool| tool.get("annotations").is_none()));

        let modern = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": modern_request_meta(),
            }))
            .unwrap();
        let modern = serde_json::to_value(modern).unwrap();
        assert_eq!(modern["result"]["resultType"], "complete");
        assert_eq!(modern["result"]["cacheScope"], "public");
        assert_eq!(modern["result"]["tools"].as_array().unwrap().len(), 34);
        assert_eq!(
            modern["result"]["tools"][0]["outputSchema"]["type"],
            "object"
        );
        assert_eq!(
            modern["result"]["tools"][0]["annotations"]["readOnlyHint"],
            true
        );
        assert!(modern["result"]["tools"][0]["title"].is_string());
    }

    #[test]
    fn tools_list_rejects_non_empty_cursor_in_both_protocol_eras() {
        let server = McpSidecar::new_for_tests(false);
        let legacy = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": { "cursor": "page-2" },
            }))
            .unwrap();
        let legacy = serde_json::to_value(legacy).unwrap();
        assert_eq!(legacy["error"]["code"], -32602);
        assert!(legacy["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("single complete page"));

        let mut modern_params = modern_request_meta();
        modern_params["cursor"] = json!("page-2");
        let modern = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": modern_params,
            }))
            .unwrap();
        let modern = serde_json::to_value(modern).unwrap();
        assert_eq!(modern["error"]["code"], -32602);

        // Missing/null/empty all mean "the one complete page" and preserve
        // compatibility with hosts that always serialize a cursor member.
        for cursor in [Value::Null, json!("")] {
            let response = server
                .handle_value(json!({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/list",
                    "params": { "cursor": cursor },
                }))
                .unwrap();
            let response = serde_json::to_value(response).unwrap();
            assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 34);
            assert!(response["result"].get("nextCursor").is_none());
        }
    }

    #[test]
    fn notifications_are_silent_and_request_ids_are_strict() {
        let server = McpSidecar::new_for_tests(false);
        assert!(server
            .handle_value(json!({
                "jsonrpc": "2.0", "method": "unknown/notification", "params": {}
            }))
            .is_none());
        assert!(server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": { "name": "operation.preview.reset", "arguments": {} }
            }))
            .is_none());

        for invalid_id in [json!(null), json!(true), json!(1.5), json!({"x": 1})] {
            let response = server
                .handle_value(json!({
                    "jsonrpc": "2.0", "id": invalid_id, "method": "ping"
                }))
                .unwrap();
            let response = serde_json::to_value(response).unwrap();
            assert_eq!(response["error"]["code"], -32600);
            assert!(response["id"].is_null());
        }

        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": "x".repeat(MCP_MAX_REQUEST_ID_BYTES + 1),
                "method": "ping"
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["error"]["code"], -32600);
        assert!(response["id"].is_null());
    }

    #[test]
    fn modern_tool_calls_return_structured_content_and_server_metadata() {
        let repo = fixture_repo();
        let server = McpSidecar::new_for_tests(false);
        let mut params = modern_request_meta();
        params["name"] = json!("repo.status");
        params["arguments"] = json!({ "repoPath": repo.path() });
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": params
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_tool_result_contract("repo.status", &response);
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["tool"],
            "repo.status"
        );
        assert_eq!(
            response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            SERVER_NAME
        );
    }

    #[test]
    fn preview_terminal_error_matches_its_advertised_contract() {
        let result = operation_preview_terminal_error_result(
            ToolKind::OperationPreviewMerge.as_str(),
            "merge",
            "p-terminal-1",
            "rejected",
            &json!({
                "previewId": "p-terminal-1",
                "operationType": "merge",
                "status": "rejected",
                "rejectionReason": "The reviewer chose another approach",
            }),
        );
        let response = json!({ "result": result });
        assert_tool_result_contract(ToolKind::OperationPreviewMerge.as_str(), &response);
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["status"],
            "rejected"
        );
    }

    #[test]
    fn status_and_cancel_schemas_accept_legacy_empty_success_bodies() {
        // Both bridge helpers relay a successful 2xx JSON body verbatim. Old
        // custom loopback bridges sometimes returned JSON null; advertise the
        // official typed object while keeping that real compatibility path.
        for (kind, read_only, status) in [
            (ToolKind::OperationStatus, true, None),
            (ToolKind::OperationCancel, false, Some("cancelled")),
        ] {
            let mut payload = json!({
                "tool": kind.as_str(),
                "readOnly": read_only,
                "source": "fluxgit-app",
                "tier": "fluxgit-write-handshake",
                "previewId": "p-legacy-null",
                "data": null,
            });
            if let Some(status) = status {
                payload["status"] = json!(status);
            }
            validate_output_schema(&tool_output_schema(kind, read_only), &payload)
                .unwrap_or_else(|error| panic!("{} rejected legacy null: {error}", kind.as_str()));
        }
    }

    #[test]
    fn stdio_transport_accepts_newline_delimited_json_rpc_and_writes_mcp_frames() {
        let mut input =
            io::Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n");
        let frame = read_frame(&mut input).unwrap().unwrap();
        assert_eq!(
            String::from_utf8(frame).unwrap(),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"
        );

        let mut output = Vec::new();
        write_frame(
            &mut output,
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n"
        );
    }

    #[test]
    fn stdio_transport_still_accepts_legacy_content_length_frames() {
        let body = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        let framed = format!("Content-Length: {}\r\n\r\n", body.len());
        let mut input = io::Cursor::new([framed.as_bytes(), body].concat());

        let frame = read_frame(&mut input).unwrap().unwrap();
        assert_eq!(frame, body);
    }

    #[test]
    fn stdio_transport_rejects_oversized_or_ambiguous_frames_before_allocating_body() {
        let oversized = format!("Content-Length: {}\r\n\r\n", MCP_MAX_FRAME_BYTES + 1);
        let error = read_frame(&mut io::Cursor::new(oversized.into_bytes())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let ambiguous = b"Content-Length: 2\r\nContent-Length: 3\r\n\r\n{}";
        let error = read_frame(&mut io::Cursor::new(ambiguous)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let duplicate = b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        let error = read_frame(&mut io::Cursor::new(duplicate)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut header_bomb = String::from("Content-Length: 2\r\n");
        for _ in 0..100 {
            header_bomb.push_str("X-Fill: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        header_bomb.push_str("\r\n{}");
        let error = read_frame(&mut io::Cursor::new(header_bomb.into_bytes())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut output = Vec::new();
        let error = write_frame(&mut output, b"{}\n{}").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn outbound_guard_preserves_id_and_keeps_the_stdio_session_writable() {
        let make_response = |id: Value, blob_bytes: usize| {
            let tool_result = text_tool_result(
                json!({
                    "tool": "repo.status",
                    "readOnly": true,
                    "source": "local-git",
                    "repoPath": "C:\\repo",
                    "data": { "blob": "x".repeat(blob_bytes) },
                }),
                false,
            );
            JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!(tool_result)),
                error: None,
            }
        };

        // A bridge response at its own cap still leaves room for both modern
        // representations and preserves the normal text/structured contract.
        let normal = serialize_response(&make_response(
            json!("bridge-near-cap"),
            MCP_MAX_BRIDGE_RESPONSE_BYTES - 1_024,
        ));
        assert!(normal.len() < MCP_MAX_FRAME_BYTES);
        let normal_json: Value = serde_json::from_slice(&normal).unwrap();
        assert!(normal_json.get("error").is_none());
        let normal_text: Value = serde_json::from_str(
            normal_json["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(normal_text, normal_json["result"]["structuredContent"]);

        // A result whose duplicated modern representation crosses the 8 MiB
        // wire ceiling is replaced with a compact correlated error. write_frame
        // then succeeds, and a following response can still be emitted.
        let oversized = serialize_response(&make_response(
            json!("oversized-request-77"),
            MCP_MAX_FRAME_BYTES / 2,
        ));
        assert!(oversized.len() < MCP_MAX_FRAME_BYTES);
        let oversized_json: Value = serde_json::from_slice(&oversized).unwrap();
        assert_eq!(oversized_json["id"], "oversized-request-77");
        assert_eq!(oversized_json["error"]["code"], -32603);
        assert!(oversized_json["error"]["data"]["serializedBytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > MCP_MAX_FRAME_BYTES as u64));

        let mut wire = Vec::new();
        write_frame(&mut wire, &oversized).unwrap();
        let following = serialize_response(&JsonRpcResponse {
            jsonrpc: "2.0",
            id: json!("after-oversized"),
            result: Some(json!({})),
            error: None,
        });
        write_frame(&mut wire, &following).unwrap();
        assert_eq!(wire.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    // A "read-only" tool that hands an agent-supplied rev straight to git as
    // positional argv is not read-only: `git diff`, `git log` and `git show` all
    // accept `--output=<file>`, which truncates and writes that file. These
    // tests pin the guard that keeps the READ_ONLY_TOOL_KINDS promise true.
    #[test]
    fn checked_rev_rejects_option_like_revisions() {
        // The exact shape of the escape: a write dressed as a revision.
        let error = checked_rev("--output=/tmp/pwned", "base").unwrap_err();
        assert_eq!(error.code, -32602);
        let details = error.data.unwrap()["details"].as_str().unwrap().to_string();
        assert!(
            details.contains("base"),
            "error names the offending field: {details}"
        );
        assert!(
            details.contains("'-'"),
            "error explains the rule: {details}"
        );

        assert!(checked_rev("-n1", "commit").is_err());
        assert!(checked_rev("--upload-pack=sh", "head").is_err());
    }

    #[test]
    fn checked_rev_accepts_real_revisions() {
        // Nothing a genuine revision looks like may be rejected.
        for rev in [
            "HEAD",
            "HEAD~3",
            "HEAD^{commit}",
            "main",
            "origin/main",
            "refs/heads/feature/login",
            "v1.2.3",
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
            "main@{yesterday}",
        ] {
            assert!(
                checked_rev(rev, "rev").is_ok(),
                "rejected a real revision: {rev}"
            );
        }

        // The optional variant leaves absent arguments absent.
        assert_eq!(checked_rev_opt(None, "base").unwrap(), None);
        assert_eq!(checked_rev_opt(Some("HEAD"), "base").unwrap(), Some("HEAD"));
        assert!(checked_rev_opt(Some("--output=/tmp/pwned"), "base").is_err());
    }

    #[test]
    fn explicit_idempotency_keys_dedupe_retries_but_unkeyed_calls_are_new_intents() {
        let keyed_args = json!({
            "repoPath": "/tmp/r",
            "sourceRef": "feature",
            "targetRef": "main",
            "idempotencyKey": "intent-42"
        });
        let a = idempotency_key_for("merge", &keyed_args).expect("a key");
        let b = idempotency_key_for("merge", &keyed_args).expect("a key");
        assert_eq!(
            a, b,
            "an explicit retry key must reuse the same gateway proposal"
        );

        // The same caller key cannot alias a different operation type.
        let other_op = idempotency_key_for("rebase", &keyed_args).expect("a key");
        assert_ne!(a, other_op);

        // Two identical calls without an explicit key are new intentions. This
        // prevents a retained terminal record from suppressing a legitimate
        // commit/push after repository state changes.
        let unkeyed_args =
            json!({ "repoPath": "/tmp/r", "sourceRef": "feature", "targetRef": "main" });
        let first_intent = idempotency_key_for("merge", &unkeyed_args).expect("a key");
        let second_intent = idempotency_key_for("merge", &unkeyed_args).expect("a key");
        assert_ne!(first_intent, second_intent);

        // Null arguments carry no key rather than a misleading constant one.
        assert!(idempotency_key_for("merge", &Value::Null).is_none());
    }

    #[test]
    fn the_connected_agent_identifies_itself_instead_of_sharing_one_id() {
        // Every dispatch sent a hardcoded "external-mcp-sidecar", so a policy
        // rule for a named agent could never match, and all agents shared one
        // MAX_PENDING_PER_AGENT budget.
        let sidecar = McpSidecar::new_for_tests(true);
        assert_eq!(
            sidecar.agent_id(),
            "external-mcp-sidecar",
            "an agent that never identified itself keeps the old id, so existing rules still match"
        );

        let init = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "clientInfo": { "name": "claude-code", "version": "1.0" } }
        }))
        .unwrap();
        sidecar.handle_frame(&init);
        assert_eq!(sidecar.agent_id(), "claude-code");

        // A blank or absent name must not overwrite a good one with junk.
        let blank = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "initialize",
            "params": { "clientInfo": { "name": "   " } }
        }))
        .unwrap();
        sidecar.handle_frame(&blank);
        assert_eq!(sidecar.agent_id(), "claude-code");
    }

    #[test]
    fn client_attribution_is_bounded_and_sanitized() {
        assert_eq!(
            client_id_from_info(Some(&json!({ "name": "  claude code\r\nadmin  " }))),
            Some("claude-code-admin".to_string())
        );
        let long = "a".repeat(500);
        let sanitized = client_id_from_info(Some(&json!({ "name": long }))).unwrap();
        assert_eq!(sanitized.len(), 128);
        assert!(client_id_from_info(Some(&json!({ "name": "💥" }))).is_none());
    }

    #[test]
    fn gateway_bridge_accepts_only_explicit_loopback_http_endpoints() {
        assert_eq!(
            normalize_loopback_gateway_addr("127.0.0.1:8765"),
            Some("127.0.0.1:8765".to_string())
        );
        assert_eq!(
            normalize_loopback_gateway_addr("http://[::1]:8765"),
            Some("[::1]:8765".to_string())
        );
        for rejected in [
            "https://127.0.0.1:8765",
            "http://localhost:8765",
            "http://10.0.0.2:8765",
            "http://example.com:8765",
            "http://127.0.0.1",
            "http://127.0.0.1:8765/admin",
            "http://user@127.0.0.1:8765",
        ] {
            assert_eq!(
                normalize_loopback_gateway_addr(rejected),
                None,
                "{rejected}"
            );
        }
    }

    #[test]
    fn loopback_bridge_client_does_not_follow_redirects() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let destination_addr = destination.local_addr().unwrap();
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_addr = redirect.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let (mut stream, _) = redirect.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{destination_addr}/exfiltrate\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let response = loopback_bridge_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{redirect_addr}/proposal"))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), 302);
        responder.join().unwrap();
        assert!(matches!(
            destination.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn loopback_bridge_client_ignores_environment_proxies() {
        use std::sync::atomic::AtomicBool;

        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_addr = target.local_addr().unwrap();
        let (body_tx, body_rx) = std::sync::mpsc::channel();
        let target_server = thread::spawn(move || {
            let (mut stream, _) = target.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let header = header.trim_end_matches(['\r', '\n']);
                if header.is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).unwrap();
            body_tx.send(String::from_utf8(body).unwrap()).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        proxy.set_nonblocking(true).unwrap();
        let proxy_hit = Arc::new(AtomicBool::new(false));
        let proxy_stop = Arc::new(AtomicBool::new(false));
        let hit = Arc::clone(&proxy_hit);
        let stop = Arc::clone(&proxy_stop);
        let proxy_server = thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                match proxy.accept() {
                    Ok((mut stream, _)) => {
                        hit.store(true, Ordering::Release);
                        let _ = stream.write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let proxy_url = format!("http://{proxy_addr}");
        let status = Command::new(env::current_exe().unwrap())
            .arg("tests::loopback_proxy_child_helper")
            .arg("--exact")
            .arg("--nocapture")
            .env("FLUXGIT_TEST_LOOPBACK_PROXY_ROLE", "child")
            .env("FLUXGIT_TEST_LOOPBACK_TARGET", target_addr.to_string())
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .status()
            .unwrap();
        proxy_stop.store(true, Ordering::Release);
        proxy_server.join().unwrap();
        target_server.join().unwrap();
        assert!(status.success());
        assert!(!proxy_hit.load(Ordering::Acquire));
        let body = body_rx.recv().unwrap();
        assert!(body.contains("MCP_PROXY_SECRET_SENTINEL"));
    }

    #[test]
    fn loopback_proxy_child_helper() {
        if env::var("FLUXGIT_TEST_LOOPBACK_PROXY_ROLE").as_deref() != Ok("child") {
            return;
        }
        let target = env::var("FLUXGIT_TEST_LOOPBACK_TARGET").unwrap();
        let response = fetch_semantic_diff_from_gateway(
            &target,
            "repo-proxy-test",
            Path::new("C:/MCP_PROXY_SECRET_SENTINEL/repo"),
            "HEAD~1",
            "HEAD",
            &["MCP_PROXY_SECRET_SENTINEL.txt".to_string()],
        );
        assert_eq!(response, Some(json!({})));
    }

    #[test]
    fn hardened_git_boundary_removes_repo_config_helper_and_pager_overrides() {
        let inherited = [
            ("GIT_DIR", "C:/redirected/.git"),
            ("GIT_WORK_TREE", "C:/redirected"),
            ("GIT_COMMON_DIR", "C:/redirected/common"),
            ("GIT_INDEX_FILE", "C:/redirected/index"),
            ("GIT_OBJECT_DIRECTORY", "C:/redirected/objects"),
            ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "C:/alternate"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.bare"),
            ("GIT_CONFIG_VALUE_0", "true"),
            ("GIT_EXEC_PATH", "C:/helpers"),
            ("GIT_EXTERNAL_DIFF", "malicious-diff"),
            ("GIT_ASKPASS", "malicious-askpass"),
            ("GIT_PAGER", "malicious-pager"),
            ("GCM_INTERACTIVE", "always"),
            ("SSH_ASKPASS", "malicious-ssh-askpass"),
            ("PAGER", "malicious-pager"),
            ("LD_PRELOAD", "malicious-library"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<Vec<(std::ffi::OsString, std::ffi::OsString)>>();
        let mut command = Command::new("git");
        remove_untrusted_git_environment(&mut command, inherited);
        let changes = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().to_ascii_uppercase(),
                    value.map(|value| value.to_os_string()),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_EXEC_PATH",
            "GIT_EXTERNAL_DIFF",
            "GIT_ASKPASS",
            "GIT_PAGER",
            "GCM_INTERACTIVE",
            "SSH_ASKPASS",
            "PAGER",
            "LD_PRELOAD",
        ] {
            assert_eq!(changes.get(key), Some(&None), "{key} must be removed");
        }

        let hardened = hardened_git_command(Path::new("C:/explicit-repo"), &["status"])
            .expect("safe absolute Git executable");
        let controlled = hardened
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().to_ascii_uppercase(),
                    value.map(|value| value.to_string_lossy().to_string()),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            controlled.get("GIT_OPTIONAL_LOCKS"),
            Some(&Some("0".to_string()))
        );
        assert_eq!(
            controlled.get("GIT_TERMINAL_PROMPT"),
            Some(&Some("0".to_string()))
        );
        assert_eq!(
            controlled.get("GIT_CONFIG_NOSYSTEM"),
            Some(&Some("1".to_string()))
        );
        let args = hardened
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        for required in [
            "--no-pager",
            "--no-optional-locks",
            "--no-replace-objects",
            "--literal-pathspecs",
        ] {
            assert!(args.iter().any(|arg| arg == required));
        }
    }

    #[test]
    fn hardened_git_boundary_fails_on_output_cap_and_timeout() {
        let repo = fixture_repo();
        let capped = execute_git(
            repo.path(),
            &["rev-parse", "HEAD"],
            8,
            8,
            Duration::from_secs(2),
        );
        let capped = match capped {
            Err(error) => error,
            Ok(_) => panic!("oversized complete output must fail closed"),
        };
        let capped_details = capped.data.unwrap()["details"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            capped_details.contains("no partial result was returned as complete"),
            "unexpected cap failure: {capped_details}"
        );

        let timed_out = execute_git(
            repo.path(),
            &["rev-parse", "HEAD"],
            128,
            128,
            Duration::ZERO,
        );
        let timed_out = match timed_out {
            Err(error) => error,
            Ok(_) => panic!("zero-duration deadline must terminate Git"),
        };
        assert!(timed_out.data.unwrap()["details"]
            .as_str()
            .unwrap()
            .contains("timeout"));
    }

    #[test]
    fn git_resolution_rejects_a_malicious_executable_in_the_working_directory() {
        let repo = fixture_repo();
        let attacker_dir = TestDir::new("fluxgit-mcp-path-poison");
        let fake_git = attacker_dir
            .path()
            .join(if cfg!(windows) { "git.exe" } else { "git" });
        fs::write(&fake_git, b"malicious executable sentinel").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755)).unwrap();
        }

        assert!(validate_git_executable_candidate(
            fake_git.clone(),
            repo.path(),
            attacker_dir.path(),
            false,
        )
        .is_none());
        let command = hardened_git_command(repo.path(), &["status", "--short"]).unwrap();
        let program = PathBuf::from(command.get_program());
        assert!(program.is_absolute());
        assert_ne!(
            fs::canonicalize(program).unwrap(),
            fs::canonicalize(fake_git).unwrap(),
            "a Git executable from the process working directory was selected"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn descendant_held_output_pipe_is_killed_and_readers_always_join() {
        let test_dir = TestDir::new("fluxgit-mcp-git-descendant");
        let marker = test_dir.path().join("descendant-survived");
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .arg("tests::git_pipe_descendant_parent_helper")
            .arg("--exact")
            .arg("--nocapture")
            .env("FLUXGIT_TEST_GIT_PIPE_ROLE", "parent")
            .env("FLUXGIT_TEST_GIT_PIPE_MARKER", &marker)
            .stdin(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let started = Instant::now();
        let error = match execute_git_command(
            command,
            &["descendant-held-pipe-test"],
            1024,
            1024,
            Duration::from_secs(5),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a descendant-held pipe must fail closed"),
        };
        assert!(error.data.unwrap()["details"]
            .as_str()
            .unwrap()
            .contains("descendant retained an output pipe"));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "pipe cancellation waited for the hostile descendant"
        );
        std::thread::sleep(Duration::from_millis(1_500));
        assert!(
            !marker.exists(),
            "the descendant survived process-tree termination"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn descendant_that_closes_output_is_still_killed_on_successful_git_exit() {
        let test_dir = TestDir::new("fluxgit-mcp-git-closed-pipes");
        let marker = test_dir.path().join("closed-pipe-descendant-survived");
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .arg("tests::git_pipe_descendant_parent_helper")
            .arg("--exact")
            .arg("--nocapture")
            .env("FLUXGIT_TEST_GIT_PIPE_ROLE", "parent")
            .env("FLUXGIT_TEST_GIT_PIPE_MARKER", &marker)
            .env("FLUXGIT_TEST_GIT_PIPE_CLOSE_OUTPUT", "1")
            .env("FLUXGIT_TEST_GIT_PIPE_DELAY_MS", "2000")
            .stdin(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        let output = execute_git_command(
            command,
            &["descendant-closed-pipe-test"],
            1024,
            1024,
            Duration::from_secs(5),
        )
        .expect("the direct helper exits successfully with closed descendant pipes");
        assert!(output.status.success());
        std::thread::sleep(Duration::from_millis(2_500));
        assert!(
            !marker.exists(),
            "a pipe-closing descendant survived the successful command boundary"
        );
    }

    // This helper intentionally detaches its child so the production process
    // boundary, not the test harness, must reap/kill the process tree.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn git_pipe_descendant_parent_helper() {
        if env::var("FLUXGIT_TEST_GIT_PIPE_ROLE").as_deref() != Ok("parent") {
            return;
        }
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .arg("tests::git_pipe_descendant_grandchild_helper")
            .arg("--exact")
            .arg("--nocapture")
            .env("FLUXGIT_TEST_GIT_PIPE_ROLE", "grandchild")
            .env(
                "FLUXGIT_TEST_GIT_PIPE_MARKER",
                env::var_os("FLUXGIT_TEST_GIT_PIPE_MARKER").unwrap(),
            );
        if env::var_os("FLUXGIT_TEST_GIT_PIPE_CLOSE_OUTPUT").is_some() {
            #[cfg(windows)]
            unsafe {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::Foundation::{
                    SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
                };
                // Model a helper that deliberately closes both captured
                // streams instead of retaining inheritable duplicates.
                let _ = SetHandleInformation(
                    std::io::stdout().as_raw_handle() as HANDLE,
                    HANDLE_FLAG_INHERIT,
                    0,
                );
                let _ = SetHandleInformation(
                    std::io::stderr().as_raw_handle() as HANDLE,
                    HANDLE_FLAG_INHERIT,
                    0,
                );
            }
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        command.spawn().expect("spawn process-tree test descendant");
    }

    #[test]
    fn git_pipe_descendant_grandchild_helper() {
        if env::var("FLUXGIT_TEST_GIT_PIPE_ROLE").as_deref() != Ok("grandchild") {
            return;
        }
        let delay = env::var("FLUXGIT_TEST_GIT_PIPE_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10_000);
        std::thread::sleep(Duration::from_millis(delay));
        fs::write(
            PathBuf::from(env::var_os("FLUXGIT_TEST_GIT_PIPE_MARKER").unwrap()),
            b"survived",
        )
        .unwrap();
    }

    #[test]
    fn preview_ids_cannot_escape_gateway_endpoint_paths() {
        for rejected in ["", "../status", "a/b", "a?x=1", "white space"] {
            let error = checked_preview_id(&json!({ "previewId": rejected })).unwrap_err();
            assert_eq!(error.code, -32602);
        }
        assert_eq!(
            checked_preview_id(&json!({ "previewId": "p_123-safe" })).unwrap(),
            "p_123-safe"
        );
    }

    #[test]
    fn a_repo_id_cannot_escape_the_run_directory() {
        // Demonstrated against the real binary before the fix: repoId
        // "../../secret" made flux.restorePoints return restoreCount 1 and echo
        // the target file's entire `plan` object — arbitrary JSON read from a
        // tool annotated readOnlyHint: true, plus a file-existence oracle.
        let args = json!({ "runDir": "/tmp/flux-run" });
        for hostile in ["../../secret", "..", ".", "a/b", "a\\b", ""] {
            assert!(
                flux_checkpoint_path(hostile, &args).is_none(),
                "repoId {hostile:?} was allowed to build a path"
            );
        }

        // A normal id still resolves, or the tools would simply stop working.
        let ok = flux_checkpoint_path("repo-1", &args).expect("a plain id must resolve");
        assert!(ok.ends_with("rebase/repo-1.json"), "got {ok:?}");
    }

    #[test]
    fn canonical_repo_paths_are_constrained_to_configured_roots() {
        let allowed = TestDir::new("fluxgit-mcp-allowed-root");
        let inside = allowed.path().join("team").join("repo");
        fs::create_dir_all(&inside).unwrap();
        let outside = TestDir::new("fluxgit-mcp-outside-root");
        let roots = vec![allowed.path().canonicalize().unwrap()];
        assert!(canonical_path_is_within_roots(
            &inside.canonicalize().unwrap(),
            &roots
        ));
        assert!(!canonical_path_is_within_roots(
            &outside.path().canonicalize().unwrap(),
            &roots
        ));

        let configured = env::join_paths([allowed.path()]).unwrap();
        assert!(validate_repository_access_with_config(
            &json!({ "repoPath": inside }),
            Some(&configured)
        )
        .is_ok());
        let denied = validate_repository_access_with_config(
            &json!({ "repoPath": outside.path() }),
            Some(&configured),
        )
        .unwrap_err();
        assert_eq!(denied.code, -32011);
        assert!(denied.data.unwrap().get("repoPathFingerprint").is_some());

        let relative_config = env::join_paths([Path::new("relative-root")]).unwrap();
        let invalid_config = validate_repository_access_with_config(
            &json!({ "repoPath": inside }),
            Some(&relative_config),
        )
        .unwrap_err();
        assert_eq!(invalid_config.code, -32010);

        let second = allowed.path().join("other-repo");
        fs::create_dir(&second).unwrap();
        let lexical_inside = inside.join("..").join("repo");
        let fleet = validate_and_canonicalize_tool_arguments_with_config(
            ToolKind::FleetRadar,
            &json!({
                "repoPaths": [lexical_inside],
                "repositories": [{ "repoPath": second, "label": "second" }]
            }),
            Some(&configured),
        )
        .unwrap();
        assert_eq!(
            Path::new(fleet["repoPaths"][0].as_str().unwrap()),
            inside.canonicalize().unwrap()
        );
        assert_eq!(
            Path::new(fleet["repositories"][0]["repoPath"].as_str().unwrap()),
            second.canonicalize().unwrap()
        );
    }

    #[test]
    fn canonical_allowed_repo_is_dispatched_even_after_alias_retarget() {
        let allowed = TestDir::new("fluxgit-mcp-canonical-dispatch-root");
        let canonical_repo = allowed.path().join("canonical-repo");
        fs::create_dir(&canonical_repo).unwrap();
        let outside = TestDir::new("fluxgit-mcp-canonical-dispatch-outside");
        let alias = allowed.path().join("repo-alias");
        let alias_was_symlink = match test_symlink_dir(&canonical_repo, &alias) {
            Ok(()) => true,
            Err(error) => {
                // Creating directory symlinks can require an OS capability that
                // is intentionally unavailable on locked-down Windows builders.
                // Such builders still exercise canonical dispatch through a
                // lexical alias; Unix failures remain real test failures.
                #[cfg(windows)]
                {
                    eprintln!("testing lexical alias without symlink privilege: {error}");
                    false
                }
                #[cfg(unix)]
                panic!("create repository alias: {error}");
            }
        };
        let requested_path = if alias_was_symlink {
            alias.clone()
        } else {
            let intermediate = allowed.path().join("intermediate");
            fs::create_dir(&intermediate).unwrap();
            intermediate.join("..").join("canonical-repo")
        };

        let configured = env::join_paths([allowed.path()]).unwrap();
        let arguments = validate_and_canonicalize_tool_arguments_with_config(
            ToolKind::OperationPreviewMerge,
            &json!({
                "repoPath": requested_path,
                "sourceRef": "feature/canonical",
                "targetRef": "main",
                "reason": "prove canonical dispatch"
            }),
            Some(&configured),
        )
        .expect("the alias initially resolves inside the allowed root");
        let expected = canonical_repo.canonicalize().unwrap();
        assert_eq!(Path::new(arguments["repoPath"].as_str().unwrap()), expected);

        // Retarget the original alias outside the allowlist after validation.
        // Dispatch must continue to use the captured canonical target, never
        // look the alias up a second time.
        if alias_was_symlink {
            remove_test_dir_symlink(&alias).unwrap();
            test_symlink_dir(outside.path(), &alias).unwrap();
        }

        let (addr, body_rx) =
            spawn_operation_gateway_mock("merge", "completed", json!({ "ok": true }));
        let result = dispatch_operation_preview_merge(&addr, "canonical-test-agent", &arguments);
        assert!(result.is_some());
        let dispatched = body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive canonical proposal");
        assert_eq!(
            Path::new(dispatched["repoPath"].as_str().unwrap()),
            expected
        );
        assert_ne!(
            Path::new(dispatched["repoPath"].as_str().unwrap()),
            outside.path().canonicalize().unwrap()
        );

        if alias_was_symlink {
            remove_test_dir_symlink(&alias).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_repo_paths_reject_drive_relative_roots_but_accept_absolute_unc() {
        let root_relative =
            validate_repository_access_with_config(&json!({ "repoPath": r"\repo" }), None)
                .unwrap_err();
        assert_eq!(root_relative.code, -32602);
        assert!(root_relative.message.contains("Invalid params"));

        assert!(validate_repository_access_with_config(
            &json!({ "repoPath": r"\\server\share\repo" }),
            None,
        )
        .is_ok());
    }

    #[test]
    fn read_only_tools_reject_option_like_revisions_before_reaching_git() {
        let repo = Path::new("/nonexistent-repo-path");

        // Each of these would otherwise reach git's argv as a positional value.
        // The guard must fire first, so the error is "invalid params", never a
        // git invocation — note the repo path does not even exist, so anything
        // that got as far as running git would fail differently.
        let cases: Vec<(&str, Value)> = vec![
            ("diff.text base", json!({ "base": "--output=/tmp/pwned" })),
            ("diff.text head", json!({ "head": "--output=/tmp/pwned" })),
            ("commit.details", json!({ "commit": "--output=/tmp/pwned" })),
            ("repo.reflog", json!({ "refName": "--output=/tmp/pwned" })),
            // These two were guarded in code but pinned by nothing, so a future
            // edit could drop checked_rev on them without failing a test.
            (
                "repo.conflictPreflight currentRef",
                json!({ "currentRef": "--output=/tmp/pwned", "targetRef": "main" }),
            ),
            (
                "repo.conflictPreflight targetRef",
                json!({ "currentRef": "main", "targetRef": "--output=/tmp/pwned" }),
            ),
        ];

        for (label, arguments) in cases {
            let result = match label {
                l if l.starts_with("diff.text") => diff_text_payload(repo, &arguments),
                "commit.details" => commit_details_payload(repo, &arguments),
                "repo.reflog" => repo_reflog_payload(repo, &arguments),
                l if l.starts_with("repo.conflictPreflight") => {
                    repo_conflict_preflight_payload(repo, &arguments)
                }
                other => panic!("unhandled case {other}"),
            };
            let error = result.expect_err(&format!("{label} accepted an option-like revision"));
            assert_eq!(error.code, -32602, "{label} did not fail as invalid params");
        }
    }

    #[test]
    fn tools_list_returns_read_only_whitelist() {
        let server = McpSidecar::new_for_tests(false);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": modern_request_meta(),
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();

        assert!(
            serde_json::to_vec(&response).unwrap().len() < MCP_MAX_FRAME_BYTES,
            "the fully typed 34-tool catalog must fit in one MCP frame"
        );

        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();

        assert_eq!(
            names,
            vec![
                // Read-only tools first (advertised with readOnlyHint: true).
                // repo.brief leads: it is the recommended first call of a session.
                "repo.brief",
                "repo.scope",
                "safety.timeline",
                "safety.eventDetails",
                "fleet.radar",
                "repo.status",
                "repo.refs",
                "repo.branchStack",
                "repo.conflictPreflight",
                "conflict.read",
                "repo.reflog",
                "repo.history",
                "commit.details",
                "worktree.changes",
                "worktree.list",
                "submodule.status",
                "diff.text",
                "diff.semantic",
                "diff.semanticFallbacks",
                "flux.latestRestorePoint",
                "flux.restorePoints",
                "flux.restorePointDetails",
                // operation.status is read-only: it inspects a proposal's
                // lifecycle over the handshake bridge, mutating nothing.
                "operation.status",
                // Write-with-UI-handshake tools (PLAYBOOK §10) — advertised so agents
                // can discover the contract, but actually executed only via FluxGit UI
                // approval. All annotated readOnlyHint: false.
                "operation.preview.merge",
                "operation.preview.rebase",
                "operation.preview.discard",
                "operation.preview.reset",
                "operation.preview.patch",
                "operation.preview.plan",
                "operation.preview.worktree",
                "operation.preview.commit",
                "operation.preview.push",
                "operation.preview.branch",
                // Write-adjacent: cancels this agent's own pending proposal.
                "operation.cancel",
            ]
        );

        // Advertisement counts pinned: 23 read-only + 11 write-handshake = 34.
        // operation.status is read-only; operation.cancel mutates proposal state.
        assert_eq!(tools.len(), 34, "34 tools must be advertised");
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool["annotations"]["readOnlyHint"] == true)
                .count(),
            23,
            "exactly 23 tools must advertise readOnlyHint: true"
        );
        for tool in tools {
            let output_schema = &tool["outputSchema"];
            assert_eq!(
                output_schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(
                output_schema["properties"]["tool"]["const"], tool["name"],
                "structured output must identify the exact tool"
            );
            assert_eq!(
                output_schema["properties"]["readOnly"]["const"],
                tool["annotations"]["readOnlyHint"],
                "the machine-readable output envelope must match the safety annotation"
            );
            assert_eq!(output_schema["required"], json!(["tool", "readOnly"]));
            let data = &output_schema["properties"]["data"];
            assert_ne!(
                data,
                &json!({}),
                "{} must not advertise generic data",
                tool["name"]
            );
            assert!(
                data.get("type").is_some() || data.get("anyOf").is_some(),
                "{} data schema must describe an object or explicit variants: {data}",
                tool["name"]
            );
            assert!(
                output_schema["anyOf"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty()),
                "{} must advertise success/error lifecycle variants",
                tool["name"]
            );
        }

        // Verify all 11 write-handshake tools advertise readOnlyHint: false
        // (10 operation.preview.* proposals + the write-adjacent cancel).
        for handshake_name in [
            "operation.preview.merge",
            "operation.preview.rebase",
            "operation.preview.discard",
            "operation.preview.reset",
            "operation.preview.patch",
            "operation.preview.plan",
            "operation.preview.worktree",
            "operation.preview.commit",
            "operation.preview.push",
            "operation.preview.branch",
            "operation.cancel",
        ] {
            let tool = tools
                .iter()
                .find(|t| t["name"].as_str() == Some(handshake_name))
                .unwrap_or_else(|| panic!("{handshake_name} must be advertised"));
            assert_eq!(
                tool["annotations"]["readOnlyHint"], false,
                "{handshake_name} must advertise readOnlyHint: false"
            );
            assert_eq!(
                tool["annotations"]["idempotentHint"],
                handshake_name == "operation.cancel",
                "only cancellation is strongly idempotent across lifecycle retention"
            );
            assert_eq!(
                tool["annotations"]["openWorldHint"],
                handshake_name == "operation.preview.push",
                "only push crosses the local FluxGit boundary"
            );
        }

        // Tools still NOT advertised — direct writes outside the handshake protocol
        // and other destructive roadmap items must stay off the surface.
        for blocked_tool in [
            "operation.preview.checkout",
            "patch.apply",
            "reset.run",
            "flux.undo",
            "flux.redo",
        ] {
            assert!(
                !names.contains(&blocked_tool),
                "tool {blocked_tool} must NOT be advertised yet"
            );
        }
        // Read-only tools must advertise readOnlyHint: true. Write-handshake tools
        // (operation.preview.* and operation.cancel) honestly advertise
        // readOnlyHint: false — they're write proposals / proposal mutations,
        // even though the sidecar never performs the write itself.
        assert!(tools
            .iter()
            .filter(|tool| !tool["name"]
                .as_str()
                .unwrap_or_default()
                .starts_with("operation."))
            .all(|tool| tool["annotations"]["readOnlyHint"] == true));
        assert!(tools
            .iter()
            .filter(|tool| !tool["name"]
                .as_str()
                .unwrap_or_default()
                .starts_with("operation."))
            .filter(|tool| tool["name"] != "fleet.radar")
            .all(|tool| tool["inputSchema"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|item| item == "repoPath"))));

        // operation.status: read-only, keyed by previewId (no repoPath).
        let status_tool = tools
            .iter()
            .find(|tool| tool["name"] == "operation.status")
            .expect("operation.status must be advertised");
        assert_eq!(status_tool["annotations"]["readOnlyHint"], true);
        assert_eq!(
            status_tool["inputSchema"]["required"],
            json!(["previewId"]),
            "operation.status requires exactly previewId"
        );

        // operation.cancel: write-adjacent, keyed by previewId (no repoPath).
        let cancel_tool = tools
            .iter()
            .find(|tool| tool["name"] == "operation.cancel")
            .expect("operation.cancel must be advertised");
        assert_eq!(cancel_tool["annotations"]["readOnlyHint"], false);
        assert_eq!(cancel_tool["inputSchema"]["required"], json!(["previewId"]));

        // Pin every write hint explicitly: MCP defaults destructiveHint to
        // true when omitted, so absence would make additive tools ambiguous.
        for (name, expect_destructive) in [
            ("operation.preview.merge", true),
            ("operation.preview.rebase", true),
            ("operation.preview.reset", true),
            ("operation.preview.discard", true),
            ("operation.preview.patch", true),
            ("operation.preview.plan", true),
            ("operation.preview.push", true),
            ("operation.preview.worktree", false),
            ("operation.preview.commit", false),
            ("operation.preview.branch", false),
            ("operation.cancel", false),
        ] {
            let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
            assert_eq!(
                tool["annotations"]["destructiveHint"], expect_destructive,
                "{name} has the wrong destructiveHint"
            );
        }
        let fleet_schema = tools
            .iter()
            .find(|tool| tool["name"] == "fleet.radar")
            .unwrap();
        assert!(fleet_schema["description"]
            .as_str()
            .unwrap()
            .contains("attention stack"));
        assert_eq!(fleet_schema["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            fleet_schema["inputSchema"]["anyOf"][0]["required"],
            json!(["repoPaths"])
        );
        assert_eq!(
            fleet_schema["inputSchema"]["anyOf"][1]["required"],
            json!(["repositories"])
        );
        let stack_schema = tools
            .iter()
            .find(|tool| tool["name"] == "repo.branchStack")
            .unwrap();
        assert!(stack_schema["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "repoPath"));
        assert!(stack_schema["inputSchema"]["properties"]
            .get("baseCandidates")
            .is_some());
        assert!(stack_schema["inputSchema"]["properties"]
            .get("maxRelated")
            .is_some());
        let conflict_schema = tools
            .iter()
            .find(|tool| tool["name"] == "repo.conflictPreflight")
            .unwrap();
        assert!(conflict_schema["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "repoPath"));
        assert!(conflict_schema["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "targetRef"));
        assert!(conflict_schema["inputSchema"]["properties"]
            .get("currentRef")
            .is_some());
        let conflict_read_schema = tools
            .iter()
            .find(|tool| tool["name"] == "conflict.read")
            .unwrap();
        assert!(conflict_read_schema["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "repoPath"));
        assert!(conflict_read_schema["inputSchema"]["properties"]
            .get("maxFiles")
            .is_some());
        assert!(conflict_read_schema["inputSchema"]["properties"]
            .get("maxBytesPerSide")
            .is_some());
        assert!(conflict_read_schema["description"]
            .as_str()
            .unwrap()
            .contains("operation.preview.patch"));
    }

    #[test]
    fn repo_path_uses_local_read_only_fallback_even_when_gateway_is_configured() {
        let repo = fixture_repo();
        let response = call_tool(
            "repo.status",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-configured"
            }),
            true,
        );

        let payload = tool_payload(&response);
        assert_eq!(payload["source"], "local-git");
        assert_eq!(
            Path::new(payload["repoPath"].as_str().unwrap()),
            repo.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn unknown_tool_is_blocked() {
        let server = McpSidecar::new_for_tests(false);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "repo.delete",
                    "arguments": {}
                }
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();

        let error = &response["error"];
        assert_eq!(error["code"], -32602);
        assert!(error["message"].as_str().unwrap().contains("Unknown tool"));
        assert!(error["message"].as_str().unwrap().contains("repo.delete"));
        assert_eq!(error["data"]["tool"], "repo.delete");
        // The error self-describes both surfaces (read + write proposals).
        assert!(error["data"]["readOnlyTools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "repo.status"));
        assert!(error["data"]["writeProposalTools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "operation.preview.merge"));
    }

    #[test]
    fn destructive_git_tools_are_not_exposed_or_invokable() {
        let server = McpSidecar::new_for_tests(false);
        let listed = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/list",
                "params": modern_request_meta(),
            }))
            .unwrap();
        let listed = serde_json::to_value(listed).unwrap();
        let listed_names = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();

        for blocked_tool in [
            "repo.checkout",
            "repo.reset",
            "repo.rebase",
            "repo.discard",
            "repo.push",
            "repo.delete",
            "flux.undo",
            "flux.redo",
        ] {
            assert!(
                !listed_names.contains(&blocked_tool),
                "direct-write tool {blocked_tool} must not be advertised by the safe MCP surface"
            );

            let response = server
                .handle_value(json!({
                    "jsonrpc": "2.0",
                    "id": 31,
                    "method": "tools/call",
                    "params": {
                        "name": blocked_tool,
                        "arguments": {
                            "repoId": "repo-blocked"
                        }
                    }
                }))
                .unwrap();
            let response = serde_json::to_value(response).unwrap();
            assert_eq!(response["error"]["code"], -32602);
            assert_eq!(response["error"]["data"]["tool"], blocked_tool);
            assert!(response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("Unknown tool")));
        }
    }

    #[test]
    fn tools_call_appends_mcp_audit_events() {
        let repo = fixture_repo();
        let audit_dir = TestDir::new("fluxgit-mcp-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(false, audit_log.clone());

        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "repo.status",
                    "arguments": {
                        "repoPath": repo.path(),
                        "repoId": "repo-audit"
                    }
                }
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["result"]["isError"], false);

        let lines = fs::read_to_string(&audit_log).unwrap();
        let event: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        assert_eq!(event["tool"], "repo.status");
        assert_eq!(event["repo_scope"], "repo-audit");
        assert_eq!(event["result"], "success");
        assert_eq!(event["event_type"], "tool_call");
        assert_eq!(event["approval"], "not_required");
        assert_eq!(event["session_id"], "external-mcp-sidecar");
        assert_eq!(event["readOnly"], true);
        assert_eq!(event["sidecarReadOnly"], true);
        assert!(event["args_fingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.starts_with("sha256:")));
    }

    #[test]
    fn audit_append_rejects_records_above_the_verifier_line_limit() {
        let audit_dir = TestDir::new("fluxgit-mcp-audit-line-limit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let ledger = AuditLedger::new(audit_log.clone(), None).unwrap();
        let error = ledger
            .append(json!({ "oversized": "x".repeat(AUDIT_MAX_LINE_BYTES) }))
            .unwrap_err();
        assert!(error.to_string().contains("maximum JSONL line"));
        assert!(!audit_log.exists());
    }

    #[cfg(unix)]
    #[test]
    fn audit_append_uses_private_permissions_and_rejects_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let audit_dir = TestDir::new("fluxgit-mcp-private-audit");
        let nested = audit_dir.path().join("private");
        let audit_log = nested.join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(false, audit_log.clone());
        server.append_audit_event(json!({ "tool": "repo.status" }));
        assert_eq!(
            fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&audit_log).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let target = audit_dir.path().join("target.jsonl");
        fs::write(&target, b"sentinel\n").unwrap();
        let link = audit_dir.path().join("linked.jsonl");
        symlink(&target, &link).unwrap();
        let error = AuditLedger::new(link, None)
            .unwrap()
            .append(json!({ "tool": "must-not-follow" }))
            .unwrap_err();
        assert!(error.to_string().contains("symlink") || error.to_string().contains("reparse"));
        assert_eq!(fs::read(&target).unwrap(), b"sentinel\n");

        let hard_target = audit_dir.path().join("hard-target.jsonl");
        fs::write(&hard_target, b"hardlink-sentinel\n").unwrap();
        let hard_link = audit_dir.path().join("hard-linked.jsonl");
        fs::hard_link(&hard_target, &hard_link).unwrap();
        let error = AuditLedger::new(hard_link, None)
            .unwrap()
            .append(json!({ "tool": "must-not-hardlink" }))
            .unwrap_err();
        // The message is "must not be hard-linked"; asserting "hard link" with a
        // space never matched. This test is unix-only (there is a separate
        // windows variant), so it could not fail on the machine it was written on.
        assert!(error.to_string().contains("hard-linked"), "got: {error}");
        assert_eq!(fs::read(&hard_target).unwrap(), b"hardlink-sentinel\n");
    }

    #[cfg(windows)]
    #[test]
    fn audit_append_rejects_windows_hardlinks() {
        let audit_dir = TestDir::new("fluxgit-mcp-hardlink-audit");
        let target = audit_dir.path().join("target.jsonl");
        fs::write(&target, b"hardlink-sentinel\n").unwrap();
        let link = audit_dir.path().join("linked.jsonl");
        fs::hard_link(&target, &link).unwrap();
        let server = McpSidecar::new_for_tests_with_audit(false, link.clone());
        server.append_audit_event(json!({ "tool": "must-not-hardlink" }));
        assert_eq!(fs::read(&target).unwrap(), b"hardlink-sentinel\n");
    }

    #[test]
    fn mcp_audit_redacts_repo_path_when_repo_id_is_absent() {
        let repo = fixture_repo();
        let audit_dir = TestDir::new("fluxgit-mcp-redacted-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(false, audit_log.clone());

        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 44,
                "method": "tools/call",
                "params": {
                    "name": "repo.status",
                    "arguments": {
                        "repoPath": repo.path()
                    }
                }
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["result"]["isError"], false);

        let lines = fs::read_to_string(&audit_log).unwrap();
        let event: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        let repo_scope = event["repo_scope"].as_str().unwrap();
        assert!(repo_scope.starts_with("repoPath:sha256:"));
        assert!(!repo_scope.contains(&repo.path().to_string_lossy().to_string()));
    }

    #[test]
    fn blocked_tools_call_appends_write_block_audit_event() {
        let audit_dir = TestDir::new("fluxgit-mcp-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(false, audit_log.clone());

        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "repo.delete",
                    "arguments": {
                        "repoId": "repo-audit"
                    }
                }
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["error"]["code"], -32602);

        let lines = fs::read_to_string(&audit_log).unwrap();
        let event: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        assert_eq!(event["tool"], "repo.delete");
        assert_eq!(event["repo_scope"], "repo-audit");
        assert_eq!(event["result"], "blocked");
        assert_eq!(event["event_type"], "write_block");
        assert_eq!(event["approval"], "denied");
        assert_eq!(event["readOnly"], false);
        assert_eq!(event["sidecarReadOnly"], true);
        assert!(event["args_fingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.starts_with("sha256:")));
    }

    #[test]
    fn repo_status_uses_local_git_fallback_when_repo_path_is_present() {
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();
        fs::write(repo.path().join("untracked.txt"), "new\n").unwrap();

        let result = call_tool(
            "repo.status",
            json!({
                "repoPath": repo.path(),
            }),
            false,
        );

        assert_eq!(result["result"]["isError"], false);
        let payload = tool_payload(&result);
        assert_eq!(payload["source"], "local-git");
        assert_eq!(payload["data"]["clean"], false);
        assert_eq!(payload["data"]["changedFiles"], 2);
    }

    #[test]
    fn repo_brief_aggregates_situational_awareness_in_one_call() {
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();
        fs::write(repo.path().join("untracked.txt"), "new\n").unwrap();

        let result = call_tool(
            "repo.brief",
            json!({
                "repoPath": repo.path(),
            }),
            false,
        );

        assert_eq!(result["result"]["isError"], false);
        let payload = tool_payload(&result);
        assert_eq!(payload["source"], "local-git");
        let data = &payload["data"];

        // HEAD identity and working tree summary.
        assert!(data["head"]["sha"]
            .as_str()
            .is_some_and(|sha| !sha.is_empty()));
        assert_eq!(data["head"]["detached"], false);
        assert_eq!(data["workingTree"]["clean"], false);
        assert_eq!(data["workingTree"]["unstaged"], 1);
        assert_eq!(data["workingTree"]["untracked"], 1);
        assert_eq!(data["workingTree"]["conflicted"], 0);

        // No operation in progress in a fresh fixture.
        assert_eq!(data["operationInProgress"], Value::Null);
        assert_eq!(data["stashes"], 0);

        // Submodule aggregate present even with zero submodules.
        assert_eq!(data["submodules"]["total"], 0);
        assert_eq!(data["submodules"]["attentionTruncated"], false);

        // Recent commits as one-liners with sha + subject.
        let commits = data["recentCommits"].as_array().unwrap();
        assert!(!commits.is_empty());
        assert!(commits[0]["sha"]
            .as_str()
            .is_some_and(|sha| !sha.is_empty()));
        assert!(commits[0]["subject"].as_str().is_some());

        // Hints are present (array, possibly empty for a clean repo).
        assert!(data["hints"].is_array());
    }

    #[test]
    fn repo_brief_reports_merge_in_progress_and_conflicts() {
        let repo = fixture_repo();
        let path = repo.path();

        // Build a conflicting merge: two branches editing the same line.
        git(path, &["checkout", "-b", "side"]);
        fs::write(path.join("tracked.txt"), "side change\n").unwrap();
        git(path, &["commit", "-am", "side change"]);
        git(path, &["checkout", "-"]);
        fs::write(path.join("tracked.txt"), "main change\n").unwrap();
        git(path, &["commit", "-am", "main change"]);
        // Merge will conflict; ignore the non-zero exit.
        let _ = std::process::Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["merge", "side"])
            .output();

        let result = call_tool("repo.brief", json!({ "repoPath": path }), false);
        assert_eq!(result["result"]["isError"], false);
        let data = tool_payload(&result)["data"].clone();

        assert_eq!(data["operationInProgress"], "merge");
        assert_eq!(data["workingTree"]["conflicted"], 1);
        let hints = data["hints"].as_array().unwrap();
        assert!(
            hints.iter().any(|hint| hint
                .as_str()
                .is_some_and(|text| text.contains("conflicted"))),
            "expected a conflict hint, got {hints:?}"
        );
    }

    #[test]
    fn repo_brief_detects_commit_conventions() {
        let repo = fixture_repo();
        let path = repo.path();
        for (i, subject) in ["feat: add a", "fix(core): correct b", "docs: explain c"]
            .iter()
            .enumerate()
        {
            fs::write(path.join(format!("file{i}.txt")), "x\n").unwrap();
            git(path, &["add", "."]);
            git(path, &["commit", "-m", subject]);
        }

        let result = call_tool("repo.brief", json!({ "repoPath": path }), false);
        let data = tool_payload(&result)["data"].clone();
        let ratio = data["conventions"]["conventionalCommitRatio"]
            .as_f64()
            .expect("ratio present");
        assert!(
            ratio > 0.5,
            "expected mostly conventional subjects, got {ratio}"
        );
    }

    #[test]
    fn repo_scope_summarizes_one_subtree_with_owners_and_churn() {
        let repo = fixture_repo();
        let path = repo.path();
        fs::create_dir_all(path.join("packages/api")).unwrap();
        fs::create_dir_all(path.join("packages/web")).unwrap();
        fs::create_dir_all(path.join(".github")).unwrap();
        fs::write(
            path.join(".github/CODEOWNERS"),
            "# owners\n* @org/everyone\npackages/api/ @org/api-team @alice\n",
        )
        .unwrap();
        fs::write(path.join("packages/api/main.rs"), "fn main() {}\n").unwrap();
        fs::write(path.join("packages/web/index.ts"), "export {};\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-m", "feat(api): add api package"]);
        fs::write(path.join("packages/api/lib.rs"), "pub fn lib() {}\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-m", "feat(api): add lib"]);
        // Uncommitted change inside the scope + one outside it.
        fs::write(path.join("packages/api/main.rs"), "fn main() { run() }\n").unwrap();
        fs::write(path.join("packages/web/index.ts"), "export const x = 1;\n").unwrap();

        let result = call_tool(
            "repo.scope",
            json!({ "repoPath": path, "path": "packages/api" }),
            false,
        );
        assert_eq!(result["result"]["isError"], false);
        let data = tool_payload(&result)["data"].clone();

        assert_eq!(data["scope"], "packages/api");
        // Only the in-scope change is counted.
        assert_eq!(data["workingTree"]["changed"], 1);
        assert_eq!(data["workingTree"]["truncated"], false);
        assert_eq!(
            data["workingTree"]["entries"][0]["path"],
            "packages/api/main.rs"
        );

        let commits = data["recentCommits"].as_array().unwrap();
        assert_eq!(commits.len(), 2);
        assert!(commits[0]["subject"].as_str().unwrap().contains("api"));

        assert_eq!(data["churn"]["commits"], 2);
        assert_eq!(data["churn"]["authors"], 1);

        // CODEOWNERS: last matching pattern wins.
        assert_eq!(data["owners"]["matchedPattern"], "packages/api/");
        let owners = data["owners"]["owners"].as_array().unwrap();
        assert_eq!(owners.len(), 2);
        assert_eq!(owners[0], "@org/api-team");

        let hints = data["hints"].as_array().unwrap();
        assert!(hints.iter().any(|hint| hint
            .as_str()
            .is_some_and(|text| text.contains("uncommitted"))));
    }

    #[test]
    fn repo_scope_rejects_traversal_and_reports_absent_codeowners_honestly() {
        let repo = fixture_repo();
        let path = repo.path();

        let traversal = call_tool(
            "repo.scope",
            json!({ "repoPath": path, "path": "../outside" }),
            false,
        );
        assert_eq!(traversal["result"]["isError"], true);

        fs::create_dir_all(path.join("src")).unwrap();
        fs::write(path.join("src/a.txt"), "a\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-m", "add src"]);

        let result = call_tool(
            "repo.scope",
            json!({ "repoPath": path, "path": "src" }),
            false,
        );
        let data = tool_payload(&result)["data"].clone();
        // No CODEOWNERS file: the field is null, not an empty fabrication.
        assert_eq!(data["owners"], Value::Null);
    }

    #[test]
    fn repo_brief_handles_a_repo_with_no_commits_yet() {
        let repo = TestRepo::new();
        git(repo.path(), &["init", "-b", "main"]);

        let result = call_tool("repo.brief", json!({ "repoPath": repo.path() }), false);
        assert_eq!(result["result"]["isError"], false);
        let data = tool_payload(&result)["data"].clone();
        // The "## No commits yet on main" header must not garble the branch.
        assert_eq!(data["head"]["branch"], "main");
        assert_eq!(data["head"]["sha"], Value::Null);
        assert_eq!(data["recentCommits"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn repo_scope_codeowners_deeper_pattern_does_not_claim_parent_scope() {
        let repo = fixture_repo();
        let path = repo.path();
        fs::create_dir_all(path.join("api")).unwrap();
        fs::write(path.join("CODEOWNERS"), "api/handlers @team-handlers\n").unwrap();
        fs::write(path.join("api/lib.rs"), "// lib\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-m", "add api"]);

        let result = call_tool(
            "repo.scope",
            json!({ "repoPath": path, "path": "api" }),
            false,
        );
        let data = tool_payload(&result)["data"].clone();
        // The pattern is DEEPER than the scope; it must not own the scope.
        assert_eq!(data["owners"]["matchedPattern"], Value::Null);
        assert_eq!(data["owners"]["owners"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn repo_brief_output_stays_within_its_token_budget() {
        // AGENT_FIRST_ROADMAP design constant: tool output compactness is a
        // product metric. The brief targets < 600 tokens for a busy repo;
        // ~4 chars/token makes 2400 chars a conservative serialized budget.
        let repo = fixture_repo();
        let path = repo.path();
        for i in 0..30 {
            fs::write(path.join("tracked.txt"), format!("rev {i}\n")).unwrap();
            git(
                path,
                &["commit", "-am", &format!("feat: change number {i}")],
            );
        }
        fs::write(path.join("untracked.txt"), "new\n").unwrap();

        let result = call_tool("repo.brief", json!({ "repoPath": path }), false);
        assert_eq!(result["result"]["isError"], false);
        let data = tool_payload(&result)["data"].clone();
        let serialized = serde_json::to_string(&data).unwrap();
        assert!(
            serialized.len() < 2_400,
            "repo.brief payload blew its token budget: {} chars",
            serialized.len()
        );
    }

    #[test]
    fn worktree_list_enumerates_main_and_linked_worktrees() {
        let repo = fixture_repo();
        let path = repo.path();
        let linked = unique_test_temp_path("fluxgit-mcp-sidecar-worktree");
        git(
            path,
            &[
                "worktree",
                "add",
                "-b",
                "agent/task-1",
                linked.to_str().unwrap(),
            ],
        );

        let result = call_tool("worktree.list", json!({ "repoPath": path }), false);
        assert_eq!(result["result"]["isError"], false);
        let data = tool_payload(&result)["data"].clone();

        assert_eq!(data["total"], 2);
        let worktrees = data["worktrees"].as_array().unwrap();
        assert_eq!(worktrees[0]["isMain"], true);
        assert!(worktrees[0]["headSha"]
            .as_str()
            .is_some_and(|sha| !sha.is_empty()));
        assert_eq!(worktrees[1]["isMain"], false);
        assert_eq!(worktrees[1]["branch"], "agent/task-1");
        assert_eq!(worktrees[1]["detached"], false);

        let _ = fs::remove_dir_all(&linked);
    }

    #[test]
    fn fleet_radar_returns_multi_repo_attention_stack_without_fetching() {
        let clean_repo = fixture_repo();
        let dirty_repo = fixture_repo();
        fs::write(dirty_repo.path().join("tracked.txt"), "changed\n").unwrap();
        fs::write(dirty_repo.path().join("new.txt"), "new\n").unwrap();

        let payload = tool_payload(&call_tool(
            "fleet.radar",
            json!({
                "repositories": [
                    {
                        "repoPath": clean_repo.path(),
                        "repoId": "repo-clean",
                        "label": "clean-service"
                    },
                    {
                        "repoPath": dirty_repo.path(),
                        "repoId": "repo-dirty",
                        "label": "dirty-service"
                    }
                ],
                "maxRepos": 10
            }),
            false,
        ));

        assert_eq!(payload["tool"], "fleet.radar");
        assert_eq!(payload["source"], "local-git");
        assert_eq!(payload["readOnly"], true);
        assert_eq!(payload["data"]["requestedCount"], 2);
        assert_eq!(payload["data"]["scannedCount"], 2);
        assert_eq!(payload["data"]["failedCount"], 0);
        assert_eq!(payload["data"]["dirtyCount"], 1);
        assert_eq!(payload["data"]["network"]["fetchPerformed"], false);
        assert_eq!(payload["data"]["entries"][0]["status"], "no_upstream");
        assert_eq!(payload["data"]["entries"][1]["status"], "local_changes");
        assert!(
            payload["data"]["entries"][1]["changedFiles"]
                .as_u64()
                .unwrap()
                >= 2
        );

        let stack = payload["data"]["attentionStack"].as_array().unwrap();
        assert_eq!(stack[0]["repoId"], "repo-dirty");
        assert_eq!(stack[0]["status"], "local_changes");
        assert!(stack[0]["summary"]
            .as_str()
            .unwrap()
            .contains("local file changes"));
    }

    #[test]
    fn fleet_radar_reports_invalid_repositories_without_failing_entire_stack() {
        let repo = fixture_repo();
        let missing = repo.path().join("missing-child");

        let payload = tool_payload(&call_tool(
            "fleet.radar",
            json!({
                "repoPaths": [
                    repo.path(),
                    missing
                ]
            }),
            false,
        ));

        assert_eq!(payload["data"]["requestedCount"], 2);
        assert_eq!(payload["data"]["scannedCount"], 2);
        assert_eq!(payload["data"]["failedCount"], 1);
        assert_eq!(payload["data"]["entries"][1]["status"], "unknown");
        assert!(payload["data"]["entries"][1]["error"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }

    #[test]
    fn fleet_radar_reports_predictive_conflicts_without_fetching() {
        let repo = fixture_repo();
        git(repo.path(), &["branch", "-m", "main"]);
        let base_commit = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://example.invalid/repo.git",
            ],
        );
        git(
            repo.path(),
            &["update-ref", "refs/remotes/origin/main", &base_commit],
        );
        git(
            repo.path(),
            &["branch", "--set-upstream-to=origin/main", "main"],
        );

        fs::write(repo.path().join("tracked.txt"), "local\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "local change"]);

        git(
            repo.path(),
            &["checkout", "-b", "remote-work", &base_commit],
        );
        fs::write(repo.path().join("tracked.txt"), "remote\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "remote change"]);
        let remote_commit = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        git(
            repo.path(),
            &["update-ref", "refs/remotes/origin/main", &remote_commit],
        );
        git(repo.path(), &["checkout", "main"]);

        let payload = tool_payload(&call_tool(
            "fleet.radar",
            json!({
                "repositories": [{
                    "repoPath": repo.path(),
                    "repoId": "repo-conflict",
                    "label": "conflict-service"
                }]
            }),
            false,
        ));

        let entry = &payload["data"]["entries"][0];
        assert_eq!(entry["status"], "potential_conflict");
        assert_eq!(entry["potentialConflictActive"], true);
        assert_eq!(entry["potentialConflictCount"], 1);
        assert_eq!(entry["potentialConflictTarget"], "origin/main");
        assert_eq!(entry["potentialConflictPaths"][0], "tracked.txt");
        assert_eq!(payload["data"]["network"]["fetchPerformed"], false);
    }

    #[test]
    fn fleet_radar_audit_uses_fleet_scope_without_repo_paths_in_event() {
        let repo = fixture_repo();
        let audit_dir = TestDir::new("fluxgit-mcp-fleet-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(false, audit_log.clone());

        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 404,
                "method": "tools/call",
                "params": {
                    "name": "fleet.radar",
                    "arguments": {
                        "repoPaths": [repo.path()]
                    }
                }
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["result"]["isError"], false);

        let lines = fs::read_to_string(&audit_log).unwrap();
        let event: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
        assert_eq!(event["tool"], "fleet.radar");
        assert_eq!(event["repo_scope"], "fleet:1");
        assert_eq!(event["result"], "success");
        assert!(event.get("repoPath").is_none());
    }

    #[test]
    fn repo_branch_stack_explains_upstream_base_and_related_refs_read_only() {
        let repo = fixture_repo();
        git(repo.path(), &["branch", "-m", "main"]);
        let main_commit = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        git(repo.path(), &["checkout", "-b", "feature/demo"]);
        fs::write(repo.path().join("tracked.txt"), "feature\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "feature work"]);
        git(
            repo.path(),
            &["remote", "add", "origin", "https://example.com/repo.git"],
        );
        git(
            repo.path(),
            &[
                "update-ref",
                "refs/remotes/origin/feature/demo",
                &main_commit,
            ],
        );
        git(
            repo.path(),
            &[
                "branch",
                "--set-upstream-to=origin/feature/demo",
                "feature/demo",
            ],
        );
        git(repo.path(), &["checkout", "-b", "feature/child"]);
        fs::write(repo.path().join("child.txt"), "child\n").unwrap();
        git(repo.path(), &["add", "child.txt"]);
        git(repo.path(), &["commit", "-m", "child work"]);
        git(repo.path(), &["checkout", "feature/demo"]);
        let refs_before = git_output(repo.path(), &["for-each-ref", "--format=%(refname)"]);
        let status_before = git_output(repo.path(), &["status", "--porcelain=v1"]);

        let payload = tool_payload(&call_tool(
            "repo.branchStack",
            json!({
                "repoPath": repo.path(),
                "maxRelated": 5,
            }),
            false,
        ));

        assert_eq!(payload["tool"], "repo.branchStack");
        assert_eq!(payload["data"]["readOnly"], true);
        assert_eq!(payload["data"]["networkFetchPerformed"], false);
        assert_eq!(
            git_output(repo.path(), &["for-each-ref", "--format=%(refname)"]),
            refs_before
        );
        assert_eq!(
            git_output(repo.path(), &["status", "--porcelain=v1"]),
            status_before
        );
        assert_eq!(
            payload["data"]["model"],
            "real-git-refs-no-virtual-branches"
        );
        assert_eq!(payload["data"]["current"]["label"], "feature/demo");
        assert_eq!(payload["data"]["current"]["ahead"], 1);
        assert_eq!(payload["data"]["upstream"]["label"], "origin/feature/demo");
        assert_eq!(payload["data"]["base"]["label"], "main");
        assert!(payload["data"]["summary"]
            .as_str()
            .unwrap()
            .contains("1 local commit"));
        assert!(payload["data"]["guidance"]
            .as_str()
            .unwrap()
            .contains("FluxGit UI owns checkpoints"));
        assert!(payload["data"]["suggestedActions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "compareWithBase"));
        assert!(payload["data"]["related"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["label"] == "feature/child"));
    }

    #[test]
    fn repo_conflict_preflight_predicts_conflicts_without_mutating_repo() {
        let repo = fixture_repo();
        git(repo.path(), &["branch", "-m", "main"]);
        git(repo.path(), &["checkout", "-b", "feature/conflict"]);
        fs::write(repo.path().join("tracked.txt"), "incoming\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "incoming change"]);
        git(repo.path(), &["checkout", "main"]);
        fs::write(repo.path().join("tracked.txt"), "current\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "current change"]);

        let head_before = git_output(repo.path(), &["rev-parse", "HEAD"]);
        let status_before = git_output(repo.path(), &["status", "--porcelain=v1"]);

        let payload = tool_payload(&call_tool(
            "repo.conflictPreflight",
            json!({
                "repoPath": repo.path(),
                "currentRef": "HEAD",
                "targetRef": "feature/conflict",
            }),
            false,
        ));

        assert_eq!(payload["tool"], "repo.conflictPreflight");
        assert_eq!(payload["source"], "local-git");
        assert_eq!(payload["data"]["readOnly"], true);
        assert_eq!(payload["data"]["networkFetchPerformed"], false);
        assert_eq!(payload["data"]["workingTreeMutated"], false);
        assert_eq!(payload["data"]["approvalRequiredForMerge"], true);
        assert_eq!(payload["data"]["status"], "conflicts");
        assert_eq!(payload["data"]["conflictCount"], 1);
        assert_eq!(payload["data"]["conflictingPaths"][0], "tracked.txt");
        assert_eq!(git_output(repo.path(), &["rev-parse", "HEAD"]), head_before);
        assert_eq!(
            git_output(repo.path(), &["status", "--porcelain=v1"]),
            status_before
        );
    }

    /// Builds a real merge conflict: both branches edit the same line of
    /// tracked.txt, then `git merge` is run and left in the conflicted state.
    fn conflicted_merge_repo(ours_content: &str, theirs_content: &str) -> TestRepo {
        let repo = fixture_repo();
        git(repo.path(), &["branch", "-m", "main"]);
        git(repo.path(), &["checkout", "-b", "feature/conflict"]);
        fs::write(repo.path().join("tracked.txt"), theirs_content).unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "incoming change"]);
        git(repo.path(), &["checkout", "main"]);
        fs::write(repo.path().join("tracked.txt"), ours_content).unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "current change"]);

        let merge = git_command(repo.path(), &["merge", "feature/conflict"]);
        assert!(
            !merge.status.success(),
            "merge must stop on the conflict so conflict.read has an active operation"
        );
        repo
    }

    #[test]
    fn conflict_read_reports_no_conflict_honestly() {
        let repo = fixture_repo();
        let payload = tool_payload(&call_tool(
            "conflict.read",
            json!({ "repoPath": repo.path() }),
            false,
        ));

        assert_eq!(payload["tool"], "conflict.read");
        assert_eq!(payload["source"], "local-git");
        assert_eq!(payload["data"]["inConflict"], false);
        assert!(payload["data"]["hint"]
            .as_str()
            .unwrap()
            .contains("repo.conflictPreflight"));
        // No invented operation/files when nothing is in progress.
        assert!(payload["data"].get("operation").is_none());
        assert!(payload["data"].get("files").is_none());
    }

    #[test]
    fn conflict_read_returns_structured_merge_conflict() {
        let repo = conflicted_merge_repo("current\n", "incoming\n");

        let payload = tool_payload(&call_tool(
            "conflict.read",
            json!({ "repoPath": repo.path() }),
            false,
        ));
        let data = &payload["data"];

        assert_eq!(data["inConflict"], true);
        assert_eq!(data["operation"], "merge");
        assert_eq!(data["ours"]["subject"], "current change");
        assert_eq!(data["theirs"]["subject"], "incoming change");
        assert!(data["ours"]["sha"].as_str().unwrap().len() >= 40);
        assert!(data["theirs"]["sha"].as_str().unwrap().len() >= 40);
        assert_eq!(data["conflictedFileCount"], 1);
        assert_eq!(data["fileListTruncated"], false);

        let file = &data["files"][0];
        assert_eq!(file["path"], "tracked.txt");
        assert_eq!(file["kind"], "both-modified");
        // All three stages with real, non-empty, untruncated content.
        assert_eq!(file["sides"]["base"]["content"], "initial\n");
        assert_eq!(file["sides"]["ours"]["content"], "current\n");
        assert_eq!(file["sides"]["theirs"]["content"], "incoming\n");
        for side in ["base", "ours", "theirs"] {
            assert_eq!(file["sides"][side]["truncated"], false);
            assert!(file["sides"][side]["size"].as_u64().unwrap() > 0);
            assert!(file["sides"][side]["sha"].as_str().unwrap().len() >= 40);
        }

        // Marker regions map the working-tree hunk: <<<<<<< then ======= then >>>>>>>.
        let regions = file["regions"].as_array().unwrap();
        assert!(!regions.is_empty(), "merge markers must yield a region");
        let region = &regions[0];
        let start = region["startLine"].as_u64().unwrap();
        let sep = region["sepLine"].as_u64().unwrap();
        let end = region["endLine"].as_u64().unwrap();
        assert!(start < sep && sep < end, "{start} < {sep} < {end} expected");

        assert!(data["guidance"]
            .as_str()
            .unwrap()
            .contains("operation.preview.patch"));
    }

    #[test]
    fn conflict_read_classifies_delete_modify_conflicts_with_empty_regions() {
        let repo = fixture_repo();
        git(repo.path(), &["branch", "-m", "main"]);
        git(repo.path(), &["checkout", "-b", "feature/delete"]);
        git(repo.path(), &["rm", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "delete tracked"]);
        git(repo.path(), &["checkout", "main"]);
        fs::write(repo.path().join("tracked.txt"), "modified\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "modify tracked"]);
        let merge = git_command(repo.path(), &["merge", "feature/delete"]);
        assert!(!merge.status.success());

        let payload = tool_payload(&call_tool(
            "conflict.read",
            json!({ "repoPath": repo.path() }),
            false,
        ));
        let file = &payload["data"]["files"][0];

        assert_eq!(payload["data"]["operation"], "merge");
        assert_eq!(file["path"], "tracked.txt");
        assert_eq!(file["kind"], "deleted-by-them");
        assert_eq!(file["sides"]["base"]["content"], "initial\n");
        assert_eq!(file["sides"]["ours"]["content"], "modified\n");
        // The deleted side is honestly absent, not synthesized.
        assert!(file["sides"]["theirs"].is_null());
        // Delete/modify conflicts leave no markers in the working tree.
        assert_eq!(file["regions"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn conflict_read_truncates_each_side_at_max_bytes_with_explicit_flag() {
        let ours = format!("{}\n", "current ".repeat(40)); // > 64 bytes
        let theirs = format!("{}\n", "incoming ".repeat(40));
        let repo = conflicted_merge_repo(&ours, &theirs);

        let payload = tool_payload(&call_tool(
            "conflict.read",
            json!({
                "repoPath": repo.path(),
                "maxBytesPerSide": 64,
            }),
            false,
        ));
        let file = &payload["data"]["files"][0];

        for (side, full) in [("ours", ours.as_str()), ("theirs", theirs.as_str())] {
            assert_eq!(
                file["sides"][side]["truncated"], true,
                "{side} must be flagged as truncated"
            );
            assert_eq!(
                file["sides"][side]["size"].as_u64().unwrap(),
                full.len() as u64,
                "{side} must report the FULL byte size"
            );
            let content = file["sides"][side]["content"].as_str().unwrap();
            assert_eq!(content.len(), 64);
            assert!(full.starts_with(content));
        }
        // The small base blob ("initial\n") stays untruncated.
        assert_eq!(file["sides"]["base"]["truncated"], false);
        assert_eq!(file["sides"]["base"]["content"], "initial\n");
    }

    #[test]
    fn history_commit_details_and_diff_text_return_real_git_data() {
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();

        let history = tool_payload(&call_tool(
            "repo.history",
            json!({
                "repoPath": repo.path(),
                "limit": 1,
            }),
            false,
        ));
        let commit = history["data"]["commits"][0]["hash"].as_str().unwrap();
        assert_eq!(history["data"]["commits"][0]["subject"], "initial");

        let details = tool_payload(&call_tool(
            "commit.details",
            json!({
                "repoPath": repo.path(),
                "commit": commit,
            }),
            false,
        ));
        assert_eq!(details["data"]["commit"]["message"], "initial");

        let diff = tool_payload(&call_tool(
            "diff.text",
            json!({
                "repoPath": repo.path(),
                "path": "tracked.txt",
            }),
            false,
        ));
        assert!(diff["data"]["diff"].as_str().unwrap().contains("-initial"));
        assert!(diff["data"]["diff"].as_str().unwrap().contains("+changed"));
    }

    #[test]
    fn repo_reflog_returns_read_only_local_movement_timeline() {
        let repo = fixture_repo();
        let before = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();
        git(&repo.path, &["add", "tracked.txt"]);
        git(&repo.path, &["commit", "-m", "second"]);
        let after = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();

        let payload = tool_payload(&call_tool(
            "repo.reflog",
            json!({
                "repoPath": repo.path(),
                "refName": "HEAD",
                "limit": 5,
            }),
            false,
        ));

        assert_eq!(payload["tool"], "repo.reflog");
        assert_eq!(payload["data"]["refName"], "HEAD");
        assert_eq!(payload["data"]["entries"][0]["oldCommit"], before);
        assert_eq!(payload["data"]["entries"][0]["newCommit"], after);
        assert_eq!(payload["data"]["entries"][0]["canCompare"], true);
        assert!(payload["data"]["recoveryGuidance"]
            .as_str()
            .unwrap()
            .contains("FluxGit UI approval flows"));
    }

    #[test]
    fn configured_gateway_without_repo_path_is_rejected_by_the_advertised_schema() {
        let result = call_tool(
            "repo.status",
            json!({
                "repoId": "repo-without-local-path",
            }),
            true,
        );

        assert_eq!(result["error"]["code"], -32602);
        assert!(result["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("repoPath"));
    }

    #[test]
    fn enforced_tool_schemas_reject_empty_unknown_and_incomplete_plan_inputs() {
        let empty_ref = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "",
                "targetRef": "main",
                "reason": "validate before dispatch"
            }),
            true,
        );
        assert_eq!(empty_ref["error"]["code"], -32602);
        assert!(empty_ref["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("sourceRef"));

        let unsafe_idempotency_key = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/x",
                "targetRef": "main",
                "reason": "validate retry key before dispatch",
                "idempotencyKey": "not a safe key"
            }),
            true,
        );
        assert_eq!(unsafe_idempotency_key["error"]["code"], -32602);
        assert!(unsafe_idempotency_key["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("idempotencyKey"));

        let unknown = call_tool(
            "repo.status",
            json!({ "repoPath": "/tmp/example", "execute": true }),
            false,
        );
        assert_eq!(unknown["error"]["code"], -32602);
        assert!(unknown["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("execute"));

        let incomplete_plan = call_tool(
            "operation.preview.plan",
            json!({
                "repoPath": "/tmp/example",
                "reason": "missing the merge target",
                "steps": [{ "operationType": "merge", "sourceRef": "feature/x" }]
            }),
            true,
        );
        assert_eq!(incomplete_plan["error"]["code"], -32602);
        assert!(incomplete_plan["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("exactly one"));

        let merge_with_rebase_semantics = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/x",
                "targetRef": "main",
                "strategy": "rebase",
                "reason": "must use the dedicated rebase contract"
            }),
            true,
        );
        assert_eq!(merge_with_rebase_semantics["error"]["code"], -32602);
        assert!(merge_with_rebase_semantics["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("strategy"));

        let plan_with_rebase_merge_strategy = call_tool(
            "operation.preview.plan",
            json!({
                "repoPath": "/tmp/example",
                "reason": "invalid mixed semantics",
                "steps": [{
                    "operationType": "merge",
                    "sourceRef": "feature/x",
                    "targetRef": "main",
                    "strategy": "rebase"
                }]
            }),
            true,
        );
        assert_eq!(plan_with_rebase_merge_strategy["error"]["code"], -32602);
    }

    #[test]
    fn preview_contracts_bound_nested_refs_patches_paths_and_messages() {
        let plan = tool_input_schema(ToolKind::OperationPreviewPlan);
        let step = &plan["properties"]["steps"]["items"]["properties"];
        for field in ["sourceRef", "targetRef", "currentRef", "ontoRef"] {
            assert_eq!(step[field]["minLength"], 1, "{field} must be non-empty");
            assert_eq!(step[field]["maxLength"], MCP_MAX_REF_CHARS);
        }
        assert_eq!(step["patchContent"]["minLength"], 1);
        assert_eq!(step["patchContent"]["maxLength"], MCP_MAX_PATCH_CHARS);
        assert_eq!(step["paths"]["maxItems"], MCP_MAX_PATH_ITEMS);
        assert_eq!(step["paths"]["items"]["maxLength"], MCP_MAX_PATH_CHARS);

        let discard = tool_input_schema(ToolKind::OperationPreviewDiscard);
        assert_eq!(
            discard["properties"]["paths"]["maxItems"],
            MCP_MAX_PATH_ITEMS
        );
        assert_eq!(
            discard["properties"]["paths"]["items"]["maxLength"],
            MCP_MAX_PATH_CHARS
        );
        let commit = tool_input_schema(ToolKind::OperationPreviewCommit);
        assert_eq!(
            commit["properties"]["message"]["maxLength"],
            MCP_MAX_MESSAGE_CHARS
        );
        assert_eq!(
            commit["properties"]["paths"]["maxItems"],
            MCP_MAX_PATH_ITEMS
        );
        let patch = tool_input_schema(ToolKind::OperationPreviewPatch);
        assert_eq!(
            patch["properties"]["patchContent"]["maxLength"],
            MCP_MAX_PATCH_CHARS
        );
        assert_eq!(
            patch["properties"]["reason"]["maxLength"],
            MCP_MAX_REASON_CHARS
        );

        let nested_empty_patch = call_tool(
            "operation.preview.plan",
            json!({
                "repoPath": "/tmp/example",
                "reason": "nested bounds",
                "steps": [{ "operationType": "patch", "patchContent": "" }]
            }),
            true,
        );
        assert_eq!(nested_empty_patch["error"]["code"], -32602);
        assert!(nested_empty_patch["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("patchContent"));

        let oversized_nested_ref = call_tool(
            "operation.preview.plan",
            json!({
                "repoPath": "/tmp/example",
                "reason": "nested bounds",
                "steps": [{
                    "operationType": "merge",
                    "sourceRef": "x".repeat(MCP_MAX_REF_CHARS + 1),
                    "targetRef": "main"
                }]
            }),
            true,
        );
        assert_eq!(oversized_nested_ref["error"]["code"], -32602);

        let invalid_preview_id = call_tool(
            "operation.status",
            json!({ "previewId": "contains/slash" }),
            true,
        );
        assert_eq!(invalid_preview_id["error"]["code"], -32602);
        assert!(invalid_preview_id["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("ASCII"));
    }

    #[test]
    fn semantic_diff_reports_explicit_text_fallback() {
        // Hold the env guard: diff.semantic now reads the handshake address,
        // so a parallel test setting FLUXGIT_GATEWAY_ADDR must not leak in.
        let _env = GatewayEnvGuard::unset();
        let repo = fixture_repo();
        let result = call_tool(
            "diff.semantic",
            json!({
                "repoPath": repo.path(),
                "path": "tracked.txt",
            }),
            false,
        );

        let payload = tool_payload(&result);
        assert_eq!(payload["data"]["supported"], false);
        assert_eq!(payload["data"]["fallback"], "diff.text");
    }

    #[test]
    fn flux_latest_restore_point_reads_checkpoint_metadata_without_mutating() {
        let repo = fixture_repo();
        let run_dir = TestDir::new("fluxgit-mcp-sidecar-run");
        let before = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        fs::write(repo.path().join("tracked.txt"), "after\n").unwrap();
        git(&repo.path, &["add", "tracked.txt"]);
        git(&repo.path, &["commit", "-m", "after"]);
        let after = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let branch_ref = git_output(repo.path(), &["symbolic-ref", "-q", "HEAD"])
            .trim()
            .to_string();
        write_checkpoint(
            run_dir.path(),
            "repo-1",
            &branch_ref,
            &before,
            &after,
            false,
        );

        let payload = tool_payload(&call_tool(
            "flux.latestRestorePoint",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-1",
                "runDir": run_dir.path(),
            }),
            true,
        ));

        let restore_point = &payload["data"]["latestRestorePoint"];
        assert_eq!(restore_point["before"], before);
        assert_eq!(restore_point["after"], after);
        assert_eq!(restore_point["operation"], "rebase");
        assert_eq!(restore_point["canUndo"], true);
        assert_eq!(restore_point["canRedo"], false);
        assert_eq!(restore_point["approvalRequired"], true);
        assert!(restore_point["approvalMessage"]
            .as_str()
            .unwrap()
            .contains("FluxGit app"));
    }

    #[test]
    fn flux_restore_points_reports_redo_when_checkpoint_is_undone() {
        let repo = fixture_repo();
        let run_dir = TestDir::new("fluxgit-mcp-sidecar-run");
        let before = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        fs::write(repo.path().join("tracked.txt"), "after\n").unwrap();
        git(&repo.path, &["add", "tracked.txt"]);
        git(&repo.path, &["commit", "-m", "after"]);
        let after = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let branch_ref = git_output(repo.path(), &["symbolic-ref", "-q", "HEAD"])
            .trim()
            .to_string();
        git(&repo.path, &["reset", "--hard", &before]);
        write_checkpoint(run_dir.path(), "repo-2", &branch_ref, &before, &after, true);

        let payload = tool_payload(&call_tool(
            "flux.restorePoints",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-2",
                "runDir": run_dir.path(),
            }),
            true,
        ));

        let restore_point = &payload["data"]["restorePoints"][0];
        assert_eq!(payload["data"]["restoreCount"], 1);
        assert_eq!(restore_point["canUndo"], false);
        assert_eq!(restore_point["canRedo"], true);
        assert_eq!(payload["data"]["approvalRequired"], true);
    }

    #[test]
    fn safety_timeline_combines_restore_points_and_reflog_without_writes() {
        let repo = fixture_repo();
        let run_dir = TestDir::new("fluxgit-mcp-sidecar-run");
        let before = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        fs::write(repo.path().join("tracked.txt"), "after\n").unwrap();
        git(&repo.path, &["add", "tracked.txt"]);
        git(&repo.path, &["commit", "-m", "after"]);
        let after = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let branch_ref = git_output(repo.path(), &["symbolic-ref", "-q", "HEAD"])
            .trim()
            .to_string();
        write_checkpoint(
            run_dir.path(),
            "repo-safety",
            &branch_ref,
            &before,
            &after,
            false,
        );

        let payload = tool_payload(&call_tool(
            "safety.timeline",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-safety",
                "runDir": run_dir.path(),
                "limit": 20,
                "reflogLimit": 5,
            }),
            true,
        ));

        let events = payload["data"]["events"].as_array().unwrap();
        assert_eq!(payload["data"]["readOnly"], true);
        assert_eq!(payload["data"]["networkFetchPerformed"], false);
        assert!(events.iter().any(|event| event["source"] == "restore_point"
            && event["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action == "openRestorePoint")));
        assert!(events.iter().any(|event| event["source"] == "reflog"
            && event["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action == "createRescueBranch")));
    }

    #[test]
    fn safety_event_details_returns_latest_event_read_only() {
        let repo = fixture_repo();

        let payload = tool_payload(&call_tool(
            "safety.eventDetails",
            json!({
                "repoPath": repo.path(),
            }),
            true,
        ));

        assert_eq!(payload["data"]["readOnly"], true);
        assert_eq!(payload["data"]["approvalRequired"], true);
        assert_eq!(payload["data"]["eventFound"], true);
        assert!(payload["data"]["event"]["id"]
            .as_str()
            .unwrap()
            .starts_with("reflog:"));
    }

    #[test]
    fn flux_restore_point_details_matches_documented_read_only_tool() {
        let repo = fixture_repo();
        let run_dir = TestDir::new("fluxgit-mcp-sidecar-run");
        let before = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        fs::write(repo.path().join("tracked.txt"), "after\n").unwrap();
        git(&repo.path, &["add", "tracked.txt"]);
        git(&repo.path, &["commit", "-m", "after"]);
        let after = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        let branch_ref = git_output(repo.path(), &["symbolic-ref", "-q", "HEAD"])
            .trim()
            .to_string();
        write_checkpoint(
            run_dir.path(),
            "repo-details",
            &branch_ref,
            &before,
            &after,
            false,
        );

        let payload = tool_payload(&call_tool(
            "flux.restorePointDetails",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-details",
                "runDir": run_dir.path(),
            }),
            true,
        ));

        let restore_point = &payload["data"]["restorePoint"];
        assert_eq!(restore_point["before"], before);
        assert_eq!(restore_point["after"], after);
        assert_eq!(restore_point["canUndo"], true);
        assert_eq!(payload["data"]["approvalRequired"], true);
        assert!(payload["data"]["approvalMessage"]
            .as_str()
            .unwrap()
            .contains("FluxGit app"));
    }

    fn platform_test_repo_path(path: &str) -> String {
        if cfg!(windows) && path.starts_with('/') {
            format!("C:{path}")
        } else {
            path.to_string()
        }
    }

    fn normalize_test_repo_paths(value: &mut Value) {
        match value {
            Value::Object(object) => {
                if let Some(Value::String(path)) = object.get_mut("repoPath") {
                    *path = platform_test_repo_path(path);
                }
                for child in object.values_mut() {
                    normalize_test_repo_paths(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    normalize_test_repo_paths(child);
                }
            }
            _ => {}
        }
    }

    fn call_tool(name: &str, mut arguments: Value, gateway_configured: bool) -> Value {
        // Cross-platform fixtures historically use POSIX-looking /tmp paths.
        // Convert only repoPath fields on Windows so production validation can
        // enforce Path::is_absolute without weakening the test contract.
        normalize_test_repo_paths(&mut arguments);
        let server = McpSidecar::new_for_tests(gateway_configured);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                    "name": name,
                    "arguments": arguments,
                }
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_tool_result_contract(name, &response);
        response
    }

    fn tool_payload(response: &Value) -> Value {
        assert_eq!(response["result"]["isError"], false);
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    fn fixture_repo() -> TestRepo {
        let repo = TestRepo::new();
        git(&repo.path, &["init"]);
        git(&repo.path, &["config", "user.email", "test@example.com"]);
        git(&repo.path, &["config", "user.name", "Test User"]);
        fs::write(repo.path.join("tracked.txt"), "initial\n").unwrap();
        git(&repo.path, &["add", "tracked.txt"]);
        git(&repo.path, &["commit", "-m", "initial"]);
        repo
    }

    struct TestRepo {
        path: PathBuf,
    }

    impl TestRepo {
        fn new() -> Self {
            let path = unique_test_temp_path("fluxgit-mcp-sidecar-test");
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let path = unique_test_temp_path(prefix);
            fs::create_dir(&path).unwrap();
            // Private, like the directory production creates for itself.
            //
            // secure_audit_directory only applies 0700 to a directory it just
            // created; one that already exists must already be private or the
            // append is refused. `fs::create_dir` uses the default 0755, so
            // every audit test handed the ledger a directory it was right to
            // reject. Unix-only, which is why this passed on Windows.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn test_symlink_dir(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn test_symlink_dir(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn remove_test_dir_symlink(link: &Path) -> io::Result<()> {
        fs::remove_file(link)
    }

    #[cfg(windows)]
    fn remove_test_dir_symlink(link: &Path) -> io::Result<()> {
        fs::remove_dir(link)
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = git_command(repo, args);
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_output(repo: &Path, args: &[&str]) -> String {
        let output = git_command(repo, args);
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn git_command(repo: &Path, args: &[&str]) -> std::process::Output {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        output
    }

    fn write_checkpoint(
        run_dir: &Path,
        repo_id: &str,
        branch_ref: &str,
        before: &str,
        after: &str,
        undone: bool,
    ) {
        let checkpoint_dir = run_dir.join("rebase");
        fs::create_dir_all(&checkpoint_dir).unwrap();
        fs::write(
            checkpoint_dir.join(format!("{repo_id}.json")),
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "branch_ref": branch_ref,
                "operation": "rebase",
                "before_commit": before,
                "after_commit": after,
                "before_ref": "refs/fluxgit/checkpoints/rebase/repo-1/before",
                "after_ref": "refs/fluxgit/checkpoints/rebase/repo-1/after",
                "created_at": 1_700_000_000_i64,
                "undone": undone,
                "upstream_ref": null,
                "branch_has_upstream": false,
                "before_commit_reachable_from_upstream": false,
                "plan": {
                    "pick_count": 1,
                    "squash_count": 0,
                    "fixup_count": 0,
                    "drop_count": 0
                }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    // ---------------------------------------------------------------------
    // Boundary enforcement: FluxGit-required tools must error without gateway.
    // See `product/mcp/PLAYBOOK.md` §2.
    // ---------------------------------------------------------------------

    #[test]
    fn fluxgit_required_tools_error_when_gateway_not_configured() {
        let repo = fixture_repo();
        let required_tools = [
            "safety.timeline",
            "safety.eventDetails",
            "flux.latestRestorePoint",
            "flux.restorePoints",
            "flux.restorePointDetails",
        ];
        for tool in required_tools {
            let response = call_tool(tool, json!({ "repoPath": repo.path() }), false);
            assert_eq!(
                response["result"]["isError"], true,
                "tool {tool} should error without gateway"
            );
            let text = response["result"]["content"][0]["text"].as_str().unwrap();
            let payload: Value = serde_json::from_str(text).unwrap();
            assert_eq!(payload["error"]["code"], 10001, "tool {tool} wrong code");
            assert_eq!(payload["tier"], "fluxgit", "tool {tool} wrong tier");
            assert_eq!(payload["error"]["data"]["tier"], "fluxgit");
            assert_eq!(payload["error"]["data"]["gatewayConfigured"], false);
            assert!(
                payload["error"]["data"]["upgradeHint"].is_string(),
                "tool {tool} missing upgradeHint"
            );
            assert!(
                payload["error"]["data"]["learnMore"].is_string(),
                "tool {tool} missing learnMore"
            );
            assert!(
                payload["error"]["data"]["freeShellAlternative"].is_string(),
                "tool {tool} missing freeShellAlternative"
            );
        }
    }

    #[test]
    fn free_shell_tools_work_without_gateway_with_repo_path() {
        let repo = fixture_repo();
        let free_tools = [
            "repo.status",
            "repo.refs",
            "repo.reflog",
            "repo.history",
            "worktree.changes",
            "submodule.status",
        ];
        for tool in free_tools {
            let response = call_tool(tool, json!({ "repoPath": repo.path() }), false);
            assert_eq!(
                response["result"]["isError"], false,
                "tool {tool} should work without gateway"
            );
        }
    }

    #[test]
    fn repo_refs_never_exposes_remote_url_credentials_in_any_mcp_or_audit_surface() {
        let repo = fixture_repo();
        let userinfo_secret = "MCP_USERINFO_SECRET_SENTINEL";
        let query_secret = "MCP_QUERY_SECRET_SENTINEL";
        let remote_url = format!(
            "https://alice:{userinfo_secret}@example.invalid/repo.git?access_token={query_secret}#private"
        );
        git(repo.path(), &["remote", "add", "origin", &remote_url]);
        let audit_dir = TestDir::new("fluxgit-mcp-remote-redaction-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(false, audit_log.clone());
        let mut params = modern_request_meta();
        params["name"] = json!("repo.refs");
        params["arguments"] = json!({ "repoPath": repo.path() });
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 991,
                "method": "tools/call",
                "params": params,
            }))
            .unwrap();
        let response_value = serde_json::to_value(response).unwrap();
        assert_eq!(response_value["result"]["isError"], false);
        assert_eq!(
            response_value["result"]["structuredContent"]["data"]["remotes"],
            json!(["origin"])
        );
        let all_response_surfaces = serde_json::to_string(&response_value).unwrap();
        let audit = fs::read_to_string(audit_log).unwrap();
        for secret in [userinfo_secret, query_secret, "alice:"] {
            assert!(
                !all_response_surfaces.contains(secret),
                "repo.refs leaked remote credentials through text, structuredContent, or error"
            );
            assert!(
                !audit.contains(secret),
                "repo.refs leaked remote credentials through audit"
            );
        }
    }

    #[test]
    fn diff_semantic_returns_fallback_payload_without_gateway() {
        // Hold the env guard: diff.semantic now reads the handshake address,
        // so a parallel test setting FLUXGIT_GATEWAY_ADDR must not leak in.
        let _env = GatewayEnvGuard::unset();
        let repo = fixture_repo();
        let response = call_tool(
            "diff.semantic",
            json!({ "repoPath": repo.path(), "base": "HEAD", "head": "HEAD", "path": "tracked.txt" }),
            false,
        );
        assert_eq!(response["result"]["isError"], false);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        // Hybrid tool: degrades gracefully, never errors, but honestly reports supported=false.
        assert_eq!(payload["data"]["supported"], false);
        assert_eq!(payload["data"]["fallback"], "diff.text");
        assert!(payload["data"]["textDiffArguments"].is_object());
    }

    // ---------------------------------------------------------------------
    // diff.semantic enriched tier: served from the FluxGit diff-engine
    // through the gateway's read-only bridge (POST /v1/mcp/diff/semantic).
    // ---------------------------------------------------------------------

    /// Tiny single-shot HTTP mock for the read-only semantic-diff bridge:
    /// accepts one POST /v1/mcp/diff/semantic, captures its JSON body, and
    /// answers 200 with the canned gateway response.
    fn spawn_semantic_diff_gateway_mock(
        response_body: Value,
    ) -> (String, std::sync::mpsc::Receiver<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind semantic mock gateway");
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();

        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                return;
            }
            let mut content_length = 0_usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() {
                    break;
                }
                let trimmed = header.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                if let Some(value) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            let method = parts.first().copied().unwrap_or("");
            let path = parts.get(1).copied().unwrap_or("");
            if method != "POST" || !path.starts_with("/v1/mcp/diff/semantic") {
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                return;
            }
            let mut body_buf = vec![0u8; content_length];
            let _ = reader.read_exact(&mut body_buf);
            let parsed: Value = serde_json::from_slice(&body_buf).unwrap_or(Value::Null);
            let _ = tx.send(parsed);
            let body_text = serde_json::to_string(&response_body).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_text.len(),
                body_text
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        (format!("{}:{}", addr.ip(), addr.port()), rx)
    }

    #[test]
    fn diff_semantic_enriches_with_gateway_semantic_payload() {
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();
        git(&repo.path, &["add", "tracked.txt"]);
        git(&repo.path, &["commit", "-m", "second"]);

        let (addr, body_rx) = spawn_semantic_diff_gateway_mock(json!({
            "repoId": "repo-sem",
            "files": [{
                "path": "tracked.txt",
                "fallbackToText": false,
                "hunks": [{
                    "header": "@@ tracked.txt",
                    "lines": [{
                        "type": "modified",
                        "oldLine": 1,
                        "newLine": 1,
                        "content": "changed",
                        "oldContent": "initial",
                        "changedTokens": ["changed"],
                    }],
                }],
                "linesTruncated": false,
            }],
            "pathsTruncated": false,
        }));
        let _env = GatewayEnvGuard::set(&addr);

        let payload = tool_payload(&call_tool(
            "diff.semantic",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-sem",
                "base": "HEAD~1",
                "head": "HEAD",
            }),
            true,
        ));

        assert_eq!(payload["tool"], "diff.semantic");
        assert_eq!(payload["readOnly"], true);
        assert_eq!(payload["source"], "fluxgit-gateway");
        assert_eq!(payload["data"]["supported"], true);
        assert_eq!(payload["data"]["engine"], "fluxgit-diff-engine");
        assert_eq!(payload["data"]["changedFiles"], 1);
        assert_eq!(payload["data"]["filesTruncated"], false);
        let file = &payload["data"]["files"][0];
        assert_eq!(file["path"], "tracked.txt");
        assert_eq!(file["fallbackToText"], false);
        assert_eq!(file["hunks"][0]["header"], "@@ tracked.txt");
        let line = &file["hunks"][0]["lines"][0];
        assert_eq!(line["type"], "modified");
        assert_eq!(line["oldContent"], "initial");
        assert_eq!(line["changedTokens"][0], "changed");

        // The sidecar enumerated the changed paths locally and dispatched
        // the documented bridge body to the gateway.
        let dispatched = body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the semantic bridge POST in time");
        assert_eq!(dispatched["repoId"], "repo-sem");
        assert_eq!(dispatched["baseRef"], "HEAD~1");
        assert_eq!(dispatched["headRef"], "HEAD");
        assert_eq!(dispatched["paths"], json!(["tracked.txt"]));
    }

    #[test]
    fn diff_semantic_enriched_response_reports_per_file_text_fallback() {
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();
        fs::write(repo.path().join("logo.bin"), [0u8, 159, 146, 150]).unwrap();
        git(&repo.path, &["add", "."]);
        git(&repo.path, &["commit", "-m", "second"]);

        let (addr, _body_rx) = spawn_semantic_diff_gateway_mock(json!({
            "repoId": "repo-sem",
            "files": [
                {
                    "path": "logo.bin",
                    "fallbackToText": true,
                    "hunks": [],
                    "reason": "The semantic engine could not parse this file (unsupported language, binary or unreadable source); use a text diff for it.",
                },
                {
                    "path": "tracked.txt",
                    "fallbackToText": false,
                    "hunks": [],
                    "linesTruncated": false,
                }
            ],
            "pathsTruncated": false,
        }));
        let _env = GatewayEnvGuard::set(&addr);

        let payload = tool_payload(&call_tool(
            "diff.semantic",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-sem",
                "base": "HEAD~1",
                "head": "HEAD",
            }),
            true,
        ));

        // The call as a whole is semantic, with per-file honesty inside it.
        assert_eq!(payload["data"]["supported"], true);
        let files = payload["data"]["files"].as_array().unwrap();
        let binary = files.iter().find(|f| f["path"] == "logo.bin").unwrap();
        assert_eq!(binary["fallbackToText"], true);
        assert!(binary["reason"]
            .as_str()
            .unwrap()
            .contains("could not parse"));
        // Fallback files carry ready-to-use diff.text arguments, mirroring
        // the whole-call fallback contract.
        assert_eq!(binary["textDiffArguments"]["path"], "logo.bin");
        assert_eq!(binary["textDiffArguments"]["base"], "HEAD~1");
        assert_eq!(binary["textDiffArguments"]["head"], "HEAD");
        let parsed = files.iter().find(|f| f["path"] == "tracked.txt").unwrap();
        assert_eq!(parsed["fallbackToText"], false);
        assert!(parsed.get("textDiffArguments").is_none());
    }

    #[test]
    fn diff_semantic_fallbacks_enriched_lists_only_engine_fallbacks() {
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();
        fs::write(repo.path().join("logo.bin"), [0u8, 159, 146, 150]).unwrap();
        git(&repo.path, &["add", "."]);
        git(&repo.path, &["commit", "-m", "second"]);

        let (addr, _body_rx) = spawn_semantic_diff_gateway_mock(json!({
            "repoId": "repo-sem",
            "files": [
                {
                    "path": "logo.bin",
                    "fallbackToText": true,
                    "hunks": [],
                    "reason": "The semantic engine could not parse this file (unsupported language, binary or unreadable source); use a text diff for it.",
                },
                {
                    "path": "tracked.txt",
                    "fallbackToText": false,
                    "hunks": [],
                    "linesTruncated": false,
                }
            ],
            "pathsTruncated": false,
        }));
        let _env = GatewayEnvGuard::set(&addr);

        let payload = tool_payload(&call_tool(
            "diff.semanticFallbacks",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-sem",
                "base": "HEAD~1",
                "head": "HEAD",
            }),
            true,
        ));

        assert_eq!(payload["source"], "fluxgit-gateway");
        assert_eq!(payload["data"]["analyzedFiles"], 2);
        let fallbacks = payload["data"]["fallbacks"].as_array().unwrap();
        assert_eq!(fallbacks.len(), 1, "only the unparsed file falls back");
        assert_eq!(fallbacks[0]["path"], "logo.bin");
        assert_eq!(fallbacks[0]["from"], "diff.semantic");
        assert_eq!(fallbacks[0]["to"], "diff.text");
        assert_eq!(fallbacks[0]["supported"], false);
        assert!(fallbacks[0]["reason"]
            .as_str()
            .unwrap()
            .contains("could not parse"));
    }

    #[test]
    fn diff_semantic_keeps_honest_fallback_when_gateway_unreachable() {
        // Port 1 is reserved; nothing listens there. The enriched path must
        // degrade to the EXACT documented local fallback, never an error and
        // never a synthesized semantic payload.
        let _env = GatewayEnvGuard::set("127.0.0.1:1");
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();

        let payload = tool_payload(&call_tool(
            "diff.semantic",
            json!({
                "repoPath": repo.path(),
                "repoId": "repo-sem",
                "path": "tracked.txt",
            }),
            true,
        ));

        assert_eq!(payload["source"], "local-git");
        assert_eq!(payload["data"]["supported"], false);
        assert_eq!(payload["data"]["fallback"], "diff.text");
        assert_eq!(
            payload["data"]["reason"],
            "Semantic diff is not available in local sidecar fallback mode."
        );
        assert_eq!(payload["data"]["textDiffArguments"]["path"], "tracked.txt");
    }

    #[test]
    fn diff_semantic_keeps_honest_fallback_when_repo_not_registered() {
        // Gateway address is set but the repo has no repoId argument and no
        // FluxGit registry entry: the diff-engine could not resolve it, so
        // the sidecar must not even dispatch — it keeps the honest fallback.
        let (addr, body_rx) = spawn_semantic_diff_gateway_mock(json!({ "files": [] }));
        let _env = GatewayEnvGuard::set(&addr);
        // The fixture lives at a unique temp path that can never appear in
        // the FluxGit run-dir registry, and the call omits repoId.
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();

        let payload = tool_payload(&call_tool(
            "diff.semantic",
            json!({ "repoPath": repo.path(), "path": "tracked.txt" }),
            true,
        ));

        assert_eq!(payload["source"], "local-git");
        assert_eq!(payload["data"]["supported"], false);
        assert!(
            body_rx.try_recv().is_err(),
            "sidecar must not dispatch to the gateway without a resolvable repoId"
        );
    }

    // ---------------------------------------------------------------------
    // Write-with-UI-handshake protocol scaffolding (PLAYBOOK §10).
    // ---------------------------------------------------------------------

    #[test]
    fn operation_preview_merge_advertised_with_required_schema() {
        let server = McpSidecar::new_for_tests(true);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": modern_request_meta(),
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        let tool = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "operation.preview.merge")
            .expect("operation.preview.merge must be advertised");

        // Schema must require sourceRef, targetRef and reason so agents cannot omit
        // the user-facing justification.
        let required: Vec<&str> = tool["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for must_have in ["sourceRef", "targetRef", "reason"] {
            assert!(
                required.contains(&must_have),
                "operation.preview.merge schema must require '{must_have}'"
            );
        }
        // Not read-only — this is a write proposal.
        assert_eq!(tool["annotations"]["readOnlyHint"], false);
    }

    #[test]
    fn operation_preview_merge_returns_write_handshake_pending() {
        // Without FLUXGIT_MCP_HANDSHAKE_ADDR the dispatch bridge is unreachable,
        // so the tool must return the stable fallback (code 10003). With the env
        // set and the app running, the same call round-trips the approval flow.
        let _env = GatewayEnvGuard::unset();
        let response = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/login",
                "targetRef": "main",
                "reason": "Closes ticket #123, all CI green"
            }),
            true,
        );
        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["error"]["code"], 10003);
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
        assert!(payload["error"]["data"]["agentRecommendation"]
            .as_str()
            .unwrap()
            .contains("FluxGit"));
    }

    #[test]
    fn operation_preview_merge_blocks_even_without_gateway() {
        // Without gateway the error is still write_handshake_pending, not
        // gateway_not_configured, because the conceptual blocker is the missing
        // protocol bridge, not a missing FluxGit install.
        let _env = GatewayEnvGuard::unset();
        let response = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "x",
                "targetRef": "y",
                "reason": "test"
            }),
            false,
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["error"]["code"], 10003);
    }

    #[test]
    fn all_write_handshake_operations_return_pending_with_proper_schemas() {
        // Each operation must:
        // 1. Be advertised in tools/list with readOnlyHint: false
        // 2. Require its operation-specific fields plus a `reason`
        // 3. Return write_handshake_pending (code 10003) when no handshake
        //    address is configured (all ten dispatch when it is).
        // Schema requirements per PLAYBOOK §10.
        let _env = GatewayEnvGuard::unset();
        let server = McpSidecar::new_for_tests(true);
        let list_response = server
            .handle_value(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/list",
                "params": modern_request_meta(),
            }))
            .unwrap();
        let list_value = serde_json::to_value(list_response).unwrap();
        let tools = list_value["result"]["tools"].as_array().unwrap();

        let cases: Vec<(&str, &[&str], Value)> = vec![
            (
                "operation.preview.merge",
                &["sourceRef", "targetRef", "reason"],
                json!({
                    "repoPath": "/tmp/x", "sourceRef": "a", "targetRef": "b",
                    "reason": "merge feature"
                }),
            ),
            (
                "operation.preview.rebase",
                &["ontoRef", "reason"],
                json!({
                    "repoPath": "/tmp/x", "ontoRef": "main", "reason": "linearize history"
                }),
            ),
            (
                "operation.preview.discard",
                &["paths", "reason"],
                json!({
                    "repoPath": "/tmp/x", "paths": ["src/a.ts"], "reason": "WIP cleanup"
                }),
            ),
            (
                "operation.preview.reset",
                &["targetRef", "reason"],
                json!({
                    "repoPath": "/tmp/x", "targetRef": "HEAD~3", "mode": "soft",
                    "reason": "undo last 3"
                }),
            ),
            (
                "operation.preview.patch",
                &["patchContent", "reason"],
                json!({
                    "repoPath": "/tmp/x", "patchContent": "@@ ... @@",
                    "reason": "apply suggested fix"
                }),
            ),
            (
                "operation.preview.plan",
                &["steps", "reason"],
                json!({
                    "repoPath": "/tmp/x",
                    "steps": [
                        { "operationType": "rebase", "ontoRef": "origin/main" },
                        { "operationType": "merge", "sourceRef": "feature/x", "targetRef": "main" }
                    ],
                    "reason": "rebase then merge as one reviewed unit"
                }),
            ),
            (
                "operation.preview.worktree",
                &["branch", "reason"],
                json!({
                    "repoPath": "/tmp/x", "branch": "agent/fix-flaky-test",
                    "reason": "isolate the flaky-test fix in its own checkout"
                }),
            ),
            (
                "operation.preview.commit",
                &["message", "reason"],
                json!({
                    "repoPath": "/tmp/x", "message": "fix: handle empty refs",
                    "stageAll": true, "reason": "task is done; commit the staged fix"
                }),
            ),
            (
                "operation.preview.push",
                &["reason"],
                json!({
                    "repoPath": "/tmp/x", "remote": "origin", "branch": "agent/fix",
                    "reason": "publish the reviewed fix branch"
                }),
            ),
            (
                "operation.preview.branch",
                &["name", "reason"],
                json!({
                    "repoPath": "/tmp/x", "name": "agent/fix-empty-refs",
                    "reason": "start the fix on its own branch"
                }),
            ),
            (
                "operation.cancel",
                &["previewId"],
                json!({ "previewId": "p-cancel-schema" }),
            ),
        ];

        for (name, must_require, args) in cases {
            // 1) Advertised + readOnlyHint false
            let tool = tools
                .iter()
                .find(|t| t["name"] == name)
                .unwrap_or_else(|| panic!("{name} must be advertised"));
            assert_eq!(
                tool["annotations"]["readOnlyHint"], false,
                "{name} must advertise readOnlyHint: false"
            );
            assert_eq!(
                tool["annotations"]["idempotentHint"],
                name == "operation.cancel",
                "preview dedupe is bounded and must not be advertised as permanent idempotence"
            );

            // 2) Schema must require its fields
            let required: Vec<&str> = tool["inputSchema"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            for field in must_require {
                assert!(
                    required.contains(field),
                    "{name} schema must require '{field}'"
                );
            }
            if name.starts_with("operation.preview.") {
                let idempotency = &tool["inputSchema"]["properties"]["idempotencyKey"];
                assert_eq!(idempotency["minLength"], 1);
                assert_eq!(idempotency["maxLength"], 128);
                assert_eq!(idempotency["pattern"], "^[A-Za-z0-9_-]+$");
                assert!(
                    !required.contains(&"idempotencyKey"),
                    "{name} must keep retry deduplication opt-in"
                );
            } else {
                assert!(tool["inputSchema"]["properties"]
                    .get("idempotencyKey")
                    .is_none());
            }

            // 3) Calling it returns write_handshake_pending (code 10003)
            let response = call_tool(name, args, true);
            assert_eq!(response["result"]["isError"], true, "{name} must error");
            let text = response["result"]["content"][0]["text"].as_str().unwrap();
            let payload: Value = serde_json::from_str(text).unwrap();
            assert_eq!(payload["error"]["code"], 10003, "{name} wrong error code");
            assert_eq!(payload["tier"], "fluxgit-write-handshake");
            assert_eq!(payload["readOnly"], false);
        }
    }

    // ---------------------------------------------------------------------
    // operation.preview.* gateway dispatch (PLAYBOOK §10).
    // All five operations round-trip through the gateway when the handshake
    // address is configured; without it they fall back to code 10003.
    // ---------------------------------------------------------------------

    /// Tiny single-shot HTTP mock that accepts:
    ///   POST /v1/mcp/operation/preview/<op_path_suffix> -> 200 {"accepted": true}
    ///   GET  /v1/mcp/operation/status/<id>              -> 200 {"previewId": "...", "status": "<status>", "result": {...}}
    /// Returns the parsed POST body via a oneshot channel so tests can assert the
    /// exact JSON the sidecar dispatched. Generalized in 2026-05-28 to accept any
    /// of the five operation path suffixes (merge|rebase|discard|reset|patch) so
    /// the four new operation.preview.* tests reuse the same harness.
    fn spawn_operation_gateway_mock(
        op_path_suffix: &'static str,
        status: &'static str,
        result: Value,
    ) -> (String, std::sync::mpsc::Receiver<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock gateway");
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let expected_post_path = format!("/v1/mcp/operation/preview/{}", op_path_suffix);

        thread::spawn(move || {
            // POST first, then one or more GETs until we see the status request.
            let mut post_body: Option<Value> = None;
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut content_length = 0_usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).is_err() {
                        break;
                    }
                    let trimmed = header.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(value) =
                        trimmed.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                let method = parts.first().copied().unwrap_or("");
                let path = parts.get(1).copied().unwrap_or("");
                if method == "POST" && path.starts_with(&expected_post_path) {
                    let mut body_buf = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut body_buf);
                    let parsed: Value = serde_json::from_slice(&body_buf).unwrap_or(Value::Null);
                    post_body = Some(parsed.clone());
                    let _ = tx.send(parsed);
                    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"accepted\":true}\n";
                    let _ = stream.write_all(response);
                    let _ = stream.flush();
                } else if method == "GET" && path.starts_with("/v1/mcp/operation/status/") {
                    let preview_id = path.trim_start_matches("/v1/mcp/operation/status/");
                    let body = json!({
                        "previewId": preview_id,
                        "status": status,
                        "result": result,
                    });
                    let body_text = serde_json::to_string(&body).unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_text.len(),
                        body_text
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    // After serving status, if the POST already happened we can exit
                    // — but keep accepting in case the sidecar reconnects for another
                    // status poll (it does open a new connection per request).
                    if post_body.is_some() && status != "pending" {
                        return;
                    }
                } else {
                    let response =
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response);
                }
            }
        });

        (format!("{}:{}", addr.ip(), addr.port()), rx)
    }

    /// Backwards-compatible alias for the merge-only helper, kept so the existing
    /// merge tests read unchanged.
    fn spawn_merge_gateway_mock(
        status: &'static str,
        result: Value,
    ) -> (String, std::sync::mpsc::Receiver<Value>) {
        spawn_operation_gateway_mock("merge", status, result)
    }

    #[test]
    fn operation_preview_merge_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_merge_gateway_mock(
            "completed",
            json!({
                "mergeCommit": "abc1234",
                "summary": "Merged feature/login into main",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/login",
                "targetRef": "main",
                "reason": "Closes ticket #123",
                "strategy": "squash"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.merge");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(payload["data"]["status"], "completed");
        assert_eq!(payload["data"]["result"]["mergeCommit"], "abc1234");

        // Verify the POST body matches the HTTP contract exactly.
        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["sourceRef"], "feature/login");
        assert_eq!(dispatched["targetRef"], "main");
        assert_eq!(dispatched["reason"], "Closes ticket #123");
        assert_eq!(dispatched["strategy"], "squash");
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_merge_falls_back_to_pending_when_gateway_unreachable() {
        // Port 1 is reserved (tcpmux) and nothing listens on it on a developer
        // machine. The sidecar must surface the existing write_handshake_pending
        // error (code 10003) when the POST fails, never an opaque 5xx.
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/login",
                "targetRef": "main",
                "reason": "Closes ticket #123"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    // ---------------------------------------------------------------------
    // operation.preview.{rebase,discard,reset,patch} gateway dispatch
    // (PLAYBOOK §14.7). Each operation mirrors the merge MVP: POST to its
    // op-specific path, poll the shared status endpoint. Each body must
    // include the explicit `operationType` field per §14.7.
    // ---------------------------------------------------------------------

    #[test]
    fn operation_preview_rebase_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "rebase",
            "completed",
            json!({
                "newHeadSha": "def5678",
                "replayedCommits": 3,
                "restorePointId": "rp-rebase-1",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.rebase",
            json!({
                "repoPath": "/tmp/example",
                "currentRef": "feature/topic",
                "ontoRef": "main",
                "reason": "Linearize history before merge",
                "interactive": false
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.rebase");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(payload["data"]["status"], "completed");
        assert_eq!(payload["data"]["result"]["newHeadSha"], "def5678");

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "rebase",
            "rebase body must include operationType per §14.7"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["currentRef"], "feature/topic");
        assert_eq!(dispatched["ontoRef"], "main");
        assert_eq!(dispatched["reason"], "Linearize history before merge");
        assert_eq!(dispatched["interactive"], false);
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_rebase_rejects_interactive_mode_before_dispatch() {
        let response = call_tool(
            "operation.preview.rebase",
            json!({
                "repoPath": "/tmp/example",
                "currentRef": "feature/topic",
                "ontoRef": "main",
                "reason": "Rewrite individual commits",
                "interactive": true
            }),
            true,
        );

        assert_eq!(response["error"]["code"], -32602);
        assert!(response["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("arguments.interactive"));

        let plan = call_tool(
            "operation.preview.plan",
            json!({
                "repoPath": "/tmp/example",
                "reason": "Interactive plan",
                "steps": [{
                    "operationType": "rebase",
                    "ontoRef": "main",
                    "interactive": true
                }]
            }),
            true,
        );
        assert_eq!(plan["error"]["code"], -32602);
    }

    #[test]
    fn operation_preview_rebase_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.rebase",
            json!({
                "repoPath": "/tmp/example",
                "ontoRef": "main",
                "reason": "Linearize history"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    #[test]
    fn operation_preview_discard_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "discard",
            "completed",
            json!({
                "pathsDiscarded": ["src/a.ts", "src/b.ts"],
                "restorePointId": "rp-discard-1",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.discard",
            json!({
                "repoPath": "/tmp/example",
                "paths": ["src/a.ts", "src/b.ts"],
                "reason": "Reset WIP after retry"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.discard");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(payload["data"]["result"]["pathsDiscarded"][0], "src/a.ts");

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "discard",
            "discard body must include operationType per §14.7"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["paths"][0], "src/a.ts");
        assert_eq!(dispatched["paths"][1], "src/b.ts");
        assert_eq!(dispatched["reason"], "Reset WIP after retry");
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_discard_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.discard",
            json!({
                "repoPath": "/tmp/example",
                "paths": ["src/a.ts"],
                "reason": "WIP cleanup"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    #[test]
    fn operation_preview_reset_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "reset",
            "completed",
            json!({
                "newHeadSha": "0123456",
                "mode": "soft",
                "restorePointId": "rp-reset-1",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.reset",
            json!({
                "repoPath": "/tmp/example",
                "targetRef": "HEAD~3",
                "mode": "soft",
                "reason": "Undo last 3 commits"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.reset");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(payload["data"]["result"]["newHeadSha"], "0123456");

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "reset",
            "reset body must include operationType per §14.7"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["targetRef"], "HEAD~3");
        assert_eq!(dispatched["mode"], "soft");
        assert_eq!(dispatched["reason"], "Undo last 3 commits");
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_reset_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.reset",
            json!({
                "repoPath": "/tmp/example",
                "targetRef": "HEAD~3",
                "reason": "Undo last 3"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    #[test]
    fn operation_preview_patch_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "patch",
            "completed",
            json!({
                "appliedFiles": ["src/lib.rs"],
                "stagedToIndex": true,
                "restorePointId": "rp-patch-1",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.patch",
            json!({
                "repoPath": "/tmp/example",
                "patchContent": "@@ -1,3 +1,3 @@\n-old\n+new",
                "reason": "Apply suggested fix",
                "applyToIndex": true
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.patch");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(payload["data"]["result"]["appliedFiles"][0], "src/lib.rs");

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "patch",
            "patch body must include operationType per §14.7"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["patchContent"], "@@ -1,3 +1,3 @@\n-old\n+new");
        assert_eq!(dispatched["reason"], "Apply suggested fix");
        assert_eq!(dispatched["applyToIndex"], true);
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_patch_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.patch",
            json!({
                "repoPath": "/tmp/example",
                "patchContent": "@@ -1,3 +1,3 @@\n-old\n+new",
                "reason": "Apply suggested fix"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    // ---------------------------------------------------------------------
    // operation.preview.worktree gateway dispatch
    // (AGENT_FIRST_ROADMAP P2 / NORTH_STAR vector 5). Mirrors the other
    // operations: POST to /v1/mcp/operation/preview/worktree, poll the
    // shared status endpoint. The body must include operationType "worktree".
    // ---------------------------------------------------------------------

    #[test]
    fn operation_preview_worktree_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "worktree",
            "completed",
            json!({
                "worktreePath": "/tmp/example.worktrees/agent-fix",
                "branch": "agent/fix-flaky-test",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.worktree",
            json!({
                "repoPath": "/tmp/example",
                "branch": "agent/fix-flaky-test",
                "path": "/tmp/example.worktrees/agent-fix",
                "reason": "Isolate the flaky-test fix in its own checkout"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.worktree");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(
            payload["data"]["result"]["worktreePath"],
            "/tmp/example.worktrees/agent-fix"
        );

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "worktree",
            "worktree body must include operationType"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["branch"], "agent/fix-flaky-test");
        assert_eq!(dispatched["path"], "/tmp/example.worktrees/agent-fix");
        assert_eq!(
            dispatched["reason"],
            "Isolate the flaky-test fix in its own checkout"
        );
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_worktree_omits_path_when_not_supplied() {
        // When the agent omits `path`, FluxGit picks a default — the sidecar
        // must NOT send an empty path field that the gateway would treat as a
        // literal location.
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "worktree",
            "completed",
            json!({ "worktreePath": "/tmp/example.worktrees/agent-fix" }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.worktree",
            json!({
                "repoPath": "/tmp/example",
                "branch": "agent/fix-flaky-test",
                "reason": "Isolate the fix"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], false);
        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert!(
            dispatched.get("path").is_none(),
            "path must be omitted when the agent does not supply it"
        );
        assert_eq!(dispatched["branch"], "agent/fix-flaky-test");
    }

    #[test]
    fn operation_preview_worktree_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.worktree",
            json!({
                "repoPath": "/tmp/example",
                "branch": "agent/fix-flaky-test",
                "reason": "Isolate the fix"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    // ---------------------------------------------------------------------
    // operation.preview.{commit,push,branch} gateway dispatch (PLAYBOOK
    // §14.7, extended 2026-07-06). Mirror the worktree tests: POST to the
    // op-specific path, poll the shared status endpoint; the body must
    // include the explicit operationType field.
    // ---------------------------------------------------------------------

    #[test]
    fn operation_preview_commit_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "commit",
            "completed",
            json!({
                "commitSha": "c0ffee1",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.commit",
            json!({
                "repoPath": "/tmp/example",
                "message": "fix: handle empty refs\n\nGuards the ref parser against empty input.",
                "paths": ["src/refs.rs", "src/refs_test.rs"],
                "reason": "The fix is complete and its tests pass locally"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.commit");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(payload["data"]["result"]["commitSha"], "c0ffee1");

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "commit",
            "commit body must include operationType"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(
            dispatched["message"],
            "fix: handle empty refs\n\nGuards the ref parser against empty input."
        );
        assert_eq!(
            dispatched["paths"],
            json!(["src/refs.rs", "src/refs_test.rs"])
        );
        assert_eq!(
            dispatched["stageAll"], false,
            "stageAll must default to false"
        );
        assert_eq!(
            dispatched["reason"],
            "The fix is complete and its tests pass locally"
        );
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_commit_omits_paths_when_not_supplied() {
        // Omitted `paths` means "commit exactly what is already staged" — the
        // sidecar must not send an empty array the gateway could misread as
        // an explicit (empty) selection.
        let (addr, post_body_rx) =
            spawn_operation_gateway_mock("commit", "completed", json!({ "commitSha": "c0ffee2" }));
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.commit",
            json!({
                "repoPath": "/tmp/example",
                "message": "chore: commit staged work",
                "stageAll": true,
                "reason": "Wrap up the staged changes"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], false);
        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert!(
            dispatched.get("paths").is_none(),
            "paths must be omitted when the agent does not supply them"
        );
        assert_eq!(dispatched["stageAll"], true);
    }

    #[test]
    fn operation_preview_commit_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.commit",
            json!({
                "repoPath": "/tmp/example",
                "message": "fix: handle empty refs",
                "reason": "Commit the staged fix"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    #[test]
    fn operation_preview_push_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "push",
            "completed",
            json!({
                "pushedRef": "origin/agent/fix-empty-refs",
                "remote": "origin",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.push",
            json!({
                "repoPath": "/tmp/example",
                "remote": "origin",
                "branch": "agent/fix-empty-refs",
                "setUpstream": true,
                "reason": "Publish the reviewed fix branch"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.push");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(
            payload["data"]["result"]["pushedRef"],
            "origin/agent/fix-empty-refs"
        );

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "push",
            "push body must include operationType"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["remote"], "origin");
        assert_eq!(dispatched["branch"], "agent/fix-empty-refs");
        assert_eq!(dispatched["setUpstream"], true);
        assert_eq!(
            dispatched["forceWithLease"], false,
            "forceWithLease must default to false"
        );
        assert_eq!(dispatched["reason"], "Publish the reviewed fix branch");
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_push_defaults_remote_and_omits_branch_when_not_supplied() {
        // Omitted `remote` defaults to origin; omitted `branch` means "the
        // currently checked-out branch" and must not travel as an empty string.
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "push",
            "completed",
            json!({ "pushedRef": "origin/main", "remote": "origin" }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.push",
            json!({
                "repoPath": "/tmp/example",
                "reason": "Push the current branch"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], false);
        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["remote"], "origin",
            "remote must default to origin"
        );
        assert!(
            dispatched.get("branch").is_none(),
            "branch must be omitted when the agent does not supply it"
        );
    }

    #[test]
    fn operation_preview_push_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.push",
            json!({
                "repoPath": "/tmp/example",
                "reason": "Push the current branch"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    #[test]
    fn operation_preview_branch_dispatches_when_gateway_configured() {
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "branch",
            "completed",
            json!({
                "branch": "agent/fix-empty-refs",
                "checkedOut": true,
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.branch",
            json!({
                "repoPath": "/tmp/example",
                "name": "agent/fix-empty-refs",
                "startPoint": "origin/main",
                "checkout": true,
                "reason": "Start the fix on its own branch"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "completed status must return isError: false; full response: {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.preview.branch");
        assert_eq!(payload["source"], "fluxgit-app");
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["status"], "completed");
        let preview_id = payload["previewId"]
            .as_str()
            .expect("previewId must be a string");
        assert!(!preview_id.is_empty(), "previewId must be non-empty");
        assert_eq!(payload["data"]["result"]["branch"], "agent/fix-empty-refs");

        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert_eq!(
            dispatched["previewId"],
            Value::String(preview_id.to_string())
        );
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "branch",
            "branch body must include operationType"
        );
        assert_eq!(
            dispatched["repoPath"],
            platform_test_repo_path("/tmp/example")
        );
        assert_eq!(dispatched["name"], "agent/fix-empty-refs");
        assert_eq!(dispatched["startPoint"], "origin/main");
        assert_eq!(dispatched["checkout"], true);
        assert_eq!(dispatched["reason"], "Start the fix on its own branch");
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
    }

    #[test]
    fn operation_preview_branch_omits_start_point_and_defaults_checkout() {
        // Omitted `startPoint` means HEAD (the gateway applies the default);
        // omitted `checkout` defaults to true.
        let (addr, post_body_rx) = spawn_operation_gateway_mock(
            "branch",
            "completed",
            json!({ "branch": "agent/try-refactor", "checkedOut": true }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.branch",
            json!({
                "repoPath": "/tmp/example",
                "name": "agent/try-refactor",
                "reason": "Branch off HEAD for the refactor"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], false);
        let dispatched = post_body_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("mock gateway did not receive the dispatch POST in time");
        assert!(
            dispatched.get("startPoint").is_none(),
            "startPoint must be omitted when the agent does not supply it"
        );
        assert_eq!(
            dispatched["checkout"], true,
            "checkout must default to true"
        );
    }

    #[test]
    fn operation_preview_branch_falls_back_to_pending_when_gateway_unreachable() {
        let _env = GatewayEnvGuard::set("127.0.0.1:1");

        let response = call_tool(
            "operation.preview.branch",
            json!({
                "repoPath": "/tmp/example",
                "name": "agent/fix-empty-refs",
                "reason": "Start the fix on its own branch"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            payload["error"]["code"], 10003,
            "unreachable gateway must fall back to write_handshake_pending"
        );
        assert_eq!(payload["tier"], "fluxgit-write-handshake");
        assert_eq!(payload["readOnly"], false);
    }

    // ---------------------------------------------------------------------
    // Hardening pass: approved-is-progress polling, gateway refusal relay,
    // operation.status / operation.cancel, diff.text caps, audit labels.
    // ---------------------------------------------------------------------

    /// Mock gateway whose GET /status responses walk a fixed status sequence
    /// (one step per GET; the last status repeats). Used to prove that
    /// `approved` keeps the sidecar polling instead of failing terminally.
    fn spawn_status_sequence_gateway_mock(
        op_path_suffix: &'static str,
        statuses: &'static [&'static str],
        result: Value,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind sequence mock");
        let addr = listener.local_addr().unwrap();
        let expected_post_path = format!("/v1/mcp/operation/preview/{}", op_path_suffix);

        thread::spawn(move || {
            let mut status_index = 0usize;
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut content_length = 0_usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).is_err() {
                        break;
                    }
                    let trimmed = header.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(value) =
                        trimmed.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                let method = parts.first().copied().unwrap_or("");
                let path = parts.get(1).copied().unwrap_or("");
                if method == "POST" && path.starts_with(&expected_post_path) {
                    let mut body_buf = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut body_buf);
                    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"accepted\":true}\n";
                    let _ = stream.write_all(response);
                } else if method == "GET" && path.starts_with("/v1/mcp/operation/status/") {
                    let preview_id = path.trim_start_matches("/v1/mcp/operation/status/");
                    let status = statuses[status_index.min(statuses.len() - 1)];
                    let served_last = status_index >= statuses.len() - 1;
                    if !served_last {
                        status_index += 1;
                    }
                    let body = json!({
                        "previewId": preview_id,
                        "status": status,
                        "result": result,
                    });
                    let body_text = serde_json::to_string(&body).unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_text.len(),
                        body_text
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    if served_last
                        && matches!(
                            status,
                            "completed" | "rejected" | "failed" | "expired" | "cancelled"
                        )
                    {
                        return;
                    }
                } else {
                    let response =
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response);
                }
            }
        });

        format!("{}:{}", addr.ip(), addr.port())
    }

    /// Single-shot mock that answers ANY request with the given HTTP status
    /// and JSON body. Used for gateway refusals (429 cap / 403 policy) and
    /// for cancel responses.
    fn spawn_single_response_gateway_mock(http_status: u16, body: Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind single-response mock");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let reason = match http_status {
                200 => "OK",
                403 => "Forbidden",
                404 => "Not Found",
                409 => "Conflict",
                422 => "Unprocessable Entity",
                429 => "Too Many Requests",
                _ => "OK",
            };
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut content_length = 0usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).is_err() {
                        break;
                    }
                    let trimmed = header.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(value) =
                        trimmed.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body_buf = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body_buf);
                let body_text = serde_json::to_string(&body).unwrap();
                let response = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    http_status,
                    reason,
                    body_text.len(),
                    body_text
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                return;
            }
        });
        format!("{}:{}", addr.ip(), addr.port())
    }

    /// Simulates an idempotent POST replay where the gateway returns the id of
    /// the proposal it admitted previously rather than the fresh caller id.
    fn spawn_replay_gateway_mock(
        canonical_preview_id: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay mock");
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();

        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept replay request");
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut content_length = 0usize;
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let trimmed = header.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(value) =
                        trimmed.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut body = vec![0; content_length];
                    reader.read_exact(&mut body).unwrap();
                }

                let path = request_line.split_whitespace().nth(1).unwrap_or("");
                let body = if request_line.starts_with("POST ") {
                    json!({ "accepted": true, "previewId": canonical_preview_id })
                } else {
                    tx.send(path.to_string()).unwrap();
                    json!({ "previewId": canonical_preview_id, "status": "pending" })
                };
                let body = serde_json::to_string(&body).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        (format!("{}:{}", addr.ip(), addr.port()), rx)
    }

    #[test]
    fn operation_preview_returns_live_proposal_without_blocking_stdio() {
        // Human approval is asynchronous. Perform one immediate status read,
        // then return the stable preview id so operation.status can observe
        // completion without monopolizing the single stdio request loop.
        let addr = spawn_status_sequence_gateway_mock(
            "merge",
            &["pending", "approved", "completed"],
            json!({ "mergeCommit": "cafe123", "restorePointId": "rp-approved-race" }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/x",
                "targetRef": "main",
                "reason": "approved-race regression"
            }),
            true,
        );

        assert_eq!(
            response["result"]["isError"], false,
            "an accepted pending proposal is a successful tool call; got {response:?}"
        );
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["status"], "pending");
        assert_eq!(payload["accepted"], true);
        assert_eq!(payload["nextAction"]["tool"], "operation.status");
        assert_eq!(
            payload["nextAction"]["data"]["previewId"],
            payload["previewId"]
        );
    }

    #[test]
    fn operation_preview_replay_follows_the_gateway_canonical_id() {
        let canonical_id = "p-existing-idempotent-proposal";
        let (addr, status_path_rx) = spawn_replay_gateway_mock(canonical_id);
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/x",
                "targetRef": "main",
                "reason": "idempotent replay regression"
            }),
            true,
        );
        let payload = tool_payload(&response);

        assert_eq!(payload["previewId"], canonical_id);
        assert_eq!(
            payload["nextAction"]["data"]["previewId"], canonical_id,
            "the follow-up contract must expose the gateway's stable id"
        );
        assert_eq!(
            status_path_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            format!("/v1/mcp/operation/status/{canonical_id}"),
            "the immediate status read must not use the discarded caller id"
        );
    }

    #[test]
    fn operation_preview_gateway_refusal_is_relayed_as_structured_error() {
        // A 429 (per-agent pending cap) or 403 (policy) from the gateway must
        // reach the agent with the gateway's own self-guiding body — not be
        // collapsed into the generic 10003.
        let addr = spawn_single_response_gateway_mock(
            429,
            json!({
                "error": "agent_pending_cap_exceeded",
                "message": "Agent 'external-mcp-sidecar' already has 10 pending proposals awaiting review.",
                "agentRecommendation": "Wait for the user to decide, or cancel stale proposals with operation.cancel.",
            }),
        );
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool(
            "operation.preview.merge",
            json!({
                "repoPath": "/tmp/example",
                "sourceRef": "feature/x",
                "targetRef": "main",
                "reason": "cap relay test"
            }),
            true,
        );

        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["error"]["code"], 10006);
        assert_eq!(payload["error"]["data"]["httpStatus"], 429);
        assert_eq!(
            payload["error"]["data"]["gateway"]["error"],
            "agent_pending_cap_exceeded"
        );
    }

    #[test]
    fn operation_status_returns_proposal_status_via_gateway() {
        let (addr, _rx) = spawn_operation_gateway_mock("merge", "rejected", json!({}));
        let _env = GatewayEnvGuard::set(&addr);

        let response = call_tool("operation.status", json!({ "previewId": "p-lost-1" }), true);
        assert_eq!(response["result"]["isError"], false, "{response:?}");
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.status");
        assert_eq!(payload["readOnly"], true);
        assert_eq!(payload["previewId"], "p-lost-1");
        assert_eq!(payload["data"]["status"], "rejected");
    }

    #[test]
    fn operation_status_without_handshake_addr_returns_10003() {
        let _env = GatewayEnvGuard::unset();
        let response = call_tool("operation.status", json!({ "previewId": "p-1" }), false);
        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["error"]["code"], 10003);
        assert_eq!(payload["readOnly"], true);
    }

    #[test]
    fn operation_status_requires_preview_id() {
        let _env = GatewayEnvGuard::unset();
        let response = call_tool("operation.status", json!({}), false);
        assert_eq!(response["error"]["code"], -32602);
        assert!(response["error"]["data"]["details"]
            .as_str()
            .unwrap()
            .contains("previewId"));
    }

    #[test]
    fn operation_status_unknown_preview_id_reports_honest_absence() {
        let addr =
            spawn_single_response_gateway_mock(404, json!({ "error": "previewId not found" }));
        let _env = GatewayEnvGuard::set(&addr);
        let response = call_tool("operation.status", json!({ "previewId": "ghost" }), true);
        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["error"]["code"], 10005);
        assert_eq!(payload["previewId"], "ghost");
        assert!(payload["error"]["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("journals proposal lifecycle durably"));
        assert!(payload["error"]["data"]["agentRecommendation"]
            .as_str()
            .unwrap()
            .contains("Do not re-propose or re-run Git blindly"));
    }

    #[test]
    fn operation_cancel_dispatches_and_reports_cancelled() {
        let addr = spawn_single_response_gateway_mock(
            200,
            json!({ "previewId": "p-stale-9", "status": "cancelled" }),
        );
        let _env = GatewayEnvGuard::set(&addr);
        let response = call_tool(
            "operation.cancel",
            json!({ "previewId": "p-stale-9" }),
            true,
        );
        assert_eq!(response["result"]["isError"], false, "{response:?}");
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["tool"], "operation.cancel");
        assert_eq!(payload["status"], "cancelled");
        assert_eq!(payload["readOnly"], false);
    }

    #[test]
    fn operation_cancel_refusal_is_relayed_with_code_10006() {
        let addr = spawn_single_response_gateway_mock(
            403,
            json!({ "error": "previewId belongs to a different agent" }),
        );
        let _env = GatewayEnvGuard::set(&addr);
        let response = call_tool(
            "operation.cancel",
            json!({ "previewId": "p-foreign" }),
            true,
        );
        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["error"]["code"], 10006);
        assert_eq!(payload["error"]["data"]["httpStatus"], 403);
    }

    #[test]
    fn operation_cancel_without_handshake_addr_returns_10003() {
        let _env = GatewayEnvGuard::unset();
        let response = call_tool("operation.cancel", json!({ "previewId": "p-1" }), false);
        assert_eq!(response["result"]["isError"], true);
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["error"]["code"], 10003);
    }

    #[test]
    fn diff_text_truncates_at_max_bytes_on_a_line_boundary() {
        let repo = fixture_repo();
        let content: String = (0..200)
            .map(|i| format!("line number {i} with enough padding to add up quickly\n"))
            .collect();
        fs::write(repo.path().join("tracked.txt"), &content).unwrap();

        let payload = tool_payload(&call_tool(
            "diff.text",
            json!({ "repoPath": repo.path(), "path": "tracked.txt", "maxBytes": 512 }),
            false,
        ));
        let data = &payload["data"];
        assert_eq!(data["truncated"], true);
        assert_eq!(data["maxBytes"], 512);
        let diff = data["diff"].as_str().unwrap();
        assert!(
            diff.len() <= 512,
            "diff must respect maxBytes, got {}",
            diff.len()
        );
        assert!(
            diff.ends_with('\n'),
            "truncation must land on a line boundary"
        );
        assert!(
            data["totalBytes"].as_u64().unwrap() > 512,
            "totalBytes must report the FULL diff size"
        );
    }

    #[test]
    fn diff_text_respects_max_lines_before_max_bytes() {
        let repo = fixture_repo();
        let content: String = (0..50).map(|i| format!("row {i}\n")).collect();
        fs::write(repo.path().join("tracked.txt"), &content).unwrap();

        let payload = tool_payload(&call_tool(
            "diff.text",
            json!({ "repoPath": repo.path(), "path": "tracked.txt", "maxLines": 6 }),
            false,
        ));
        let data = &payload["data"];
        assert_eq!(data["truncated"], true);
        assert_eq!(data["diff"].as_str().unwrap().lines().count(), 6);
        assert!(data["totalLines"].as_u64().unwrap() > 6);
    }

    #[test]
    fn diff_text_leaves_small_diffs_untouched_with_default_cap() {
        let repo = fixture_repo();
        fs::write(repo.path().join("tracked.txt"), "changed\n").unwrap();
        let payload = tool_payload(&call_tool(
            "diff.text",
            json!({ "repoPath": repo.path(), "path": "tracked.txt" }),
            false,
        ));
        let data = &payload["data"];
        assert_eq!(data["truncated"], false);
        assert_eq!(data["maxBytes"], 65536);
        assert_eq!(
            data["totalBytes"].as_u64().unwrap() as usize,
            data["diff"].as_str().unwrap().len()
        );
        assert!(data["diff"].as_str().unwrap().contains("+changed"));
    }

    #[test]
    fn truncate_diff_text_hard_cuts_a_single_giant_line_on_char_boundary() {
        // One line larger than the cap and no newline before it: the cut must
        // still land on a UTF-8 char boundary instead of panicking.
        let giant = "é".repeat(100); // 200 bytes, no newline
        let (text, truncated) = truncate_diff_text(&giant, 33, None);
        assert!(truncated);
        assert!(text.len() <= 33);
        assert!(giant.starts_with(&text));
    }

    #[test]
    fn write_proposal_tools_are_audited_with_honest_labels() {
        // Regression: write-handshake tools were mislabeled readOnly:true /
        // risk:none / approval:not_required because from_name matched them
        // into the read path.
        let _env = GatewayEnvGuard::unset();
        let audit_dir = TestDir::new("fluxgit-mcp-write-proposal-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(true, audit_log.clone());

        for (tool, mut args) in [
            (
                "operation.preview.merge",
                json!({ "repoPath": "/tmp/x", "sourceRef": "a", "targetRef": "b", "reason": "audit label test" }),
            ),
            (
                "operation.preview.reset",
                json!({ "repoPath": "/tmp/x", "targetRef": "HEAD~1", "mode": "hard", "reason": "audit label test" }),
            ),
            (
                "operation.preview.commit",
                json!({ "repoPath": "/tmp/x", "message": "fix: x", "reason": "audit label test" }),
            ),
            (
                "operation.preview.push",
                json!({ "repoPath": "/tmp/x", "reason": "audit label test" }),
            ),
            (
                "operation.preview.branch",
                json!({ "repoPath": "/tmp/x", "name": "agent/x", "reason": "audit label test" }),
            ),
        ] {
            normalize_test_repo_paths(&mut args);
            let response = server
                .handle_value(json!({
                    "jsonrpc": "2.0",
                    "id": 950,
                    "method": "tools/call",
                    "params": { "name": tool, "arguments": args }
                }))
                .unwrap();
            let response = serde_json::to_value(response).unwrap();
            // Without a handshake address the call errors (10003), but the
            // audit event must still label it as a write proposal.
            assert_eq!(response["result"]["isError"], true);
        }

        let lines = fs::read_to_string(&audit_log).unwrap();
        let events: Vec<Value> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 5);

        let merge_event = &events[0];
        assert_eq!(merge_event["tool"], "operation.preview.merge");
        assert_eq!(merge_event["event_type"], "write_proposal");
        assert_eq!(merge_event["readOnly"], false);
        assert_eq!(merge_event["approval"], "ui_handshake");
        assert_eq!(merge_event["risk"], "medium");
        assert_eq!(merge_event["result"], "error");

        let reset_event = &events[1];
        assert_eq!(reset_event["event_type"], "write_proposal");
        assert_eq!(
            reset_event["risk"], "high",
            "reset must be labeled high risk"
        );

        // The three 2026-07 write proposals carry honest per-op risk labels:
        // commit/branch only add state (low); push mutates remote refs (medium).
        for (event, tool, risk) in [
            (&events[2], "operation.preview.commit", "low"),
            (&events[3], "operation.preview.push", "medium"),
            (&events[4], "operation.preview.branch", "low"),
        ] {
            assert_eq!(event["tool"], tool);
            assert_eq!(event["event_type"], "write_proposal");
            assert_eq!(event["readOnly"], false);
            assert_eq!(event["approval"], "ui_handshake");
            assert_eq!(event["risk"], risk, "{tool} must be labeled {risk} risk");
        }
    }

    #[test]
    fn arguments_fingerprint_is_sha256_of_canonical_arguments() {
        use sha2::{Digest, Sha256};
        let args = json!({ "repoPath": "/tmp/x", "limit": 5 });
        let fingerprint = arguments_fingerprint(&args).expect("fingerprint for non-null args");
        let digest = Sha256::digest(canonical_json_bytes(&args));
        let mut expected = String::from("sha256:");
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(expected, "{:02x}", byte);
        }
        assert_eq!(fingerprint, expected);
        let reordered: Value = serde_json::from_str(r#"{"repoPath":"/tmp/x","limit":5}"#).unwrap();
        assert_eq!(
            fingerprint,
            arguments_fingerprint(&reordered).unwrap(),
            "object key order must not mint a second idempotency key"
        );
        assert_eq!(fingerprint.len(), "sha256:".len() + 64);
        assert!(arguments_fingerprint(&Value::Null).is_none());
    }

    // ---------------------------------------------------------------------
    // Audit log signing tests (§13.3 shipped 2026-05-28)
    // ---------------------------------------------------------------------

    /// Deterministic test keypair. Real installs use a per-install random key
    /// loaded from `FLUXGIT_MCP_AUDIT_SIGN_KEY`; tests use fixed bytes so the
    /// test signer is reproducible without involving an RNG or touching disk.
    fn fixed_test_signer(seed: u8) -> AuditSigner {
        let secret_bytes = [seed; 32];
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        AuditSigner::from_signing_key(signing_key)
    }

    #[test]
    fn audit_signature_roundtrip_verifies_with_matching_pubkey() {
        let signer = fixed_test_signer(7);
        let public = signer.verifying_key();

        let audit_dir = TestDir::new("fluxgit-mcp-signed-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server =
            McpSidecar::new_for_tests_with_signed_audit(false, audit_log.clone(), signer.clone());

        let repo = fixture_repo();
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 901,
                "method": "tools/call",
                "params": {
                    "name": "repo.status",
                    "arguments": {
                        "repoPath": repo.path(),
                        "repoId": "repo-signed"
                    }
                }
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(response["result"]["isError"], false);

        let contents = fs::read_to_string(&audit_log).unwrap();
        let event: Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();

        // Both signature fields must be present and well-formed.
        assert!(
            event["signature"].is_string(),
            "signed audit entry must have a `signature` field"
        );
        assert_eq!(
            event["signatureKeyId"].as_str().unwrap(),
            signer.key_id(),
            "signatureKeyId must match the short hex prefix of the public key"
        );
        assert_eq!(
            event["signatureVersion"], 3,
            "new chained entries must bind key id and entry hash through signature format v3"
        );

        // And it must verify under the matching public key.
        assert!(
            verify_audit_event_signature(&event, &public).unwrap(),
            "round-trip signature must verify"
        );
    }

    #[test]
    fn audit_signature_fails_when_event_is_tampered() {
        let signer = fixed_test_signer(11);
        let public = signer.verifying_key();

        let audit_dir = TestDir::new("fluxgit-mcp-tamper-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_signed_audit(false, audit_log.clone(), signer);

        let repo = fixture_repo();
        server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 902,
                "method": "tools/call",
                "params": {
                    "name": "repo.status",
                    "arguments": {
                        "repoPath": repo.path(),
                        "repoId": "repo-tamper"
                    }
                }
            }))
            .unwrap();

        let contents = fs::read_to_string(&audit_log).unwrap();
        let mut event: Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();

        // Tamper a non-signature field after signing.
        event["tool"] = Value::String("repo.delete".to_string());

        assert!(
            !verify_audit_event_signature(&event, &public).unwrap(),
            "tampered event must fail signature verification (Ok(false))"
        );
    }

    #[test]
    fn audit_signature_v2_binds_the_key_id_but_legacy_entries_still_verify() {
        let signer = fixed_test_signer(12);
        let public = signer.verifying_key();

        let mut v2 = json!({
            "tool": "repo.status",
            "timestamp": 1717000000000u64,
            "signatureKeyId": signer.key_id(),
            "signatureVersion": 2,
        });
        let v2_signature = signer.sign_event(&v2);
        v2["signature"] = Value::String(v2_signature);
        assert!(verify_audit_event_signature(&v2, &public).unwrap());
        v2["signatureKeyId"] = Value::String("untrusted-key-id".to_string());
        assert!(
            !verify_audit_event_signature(&v2, &public).unwrap(),
            "v2 key-id relabelling must invalidate the signature"
        );

        // Compatibility with entries emitted before signatureVersion existed:
        // their key id was metadata attached after signing and was therefore
        // deliberately excluded from the verified canonical bytes.
        let legacy_unsigned = json!({
            "tool": "repo.status",
            "timestamp": 1717000000000u64,
        });
        let legacy_signature = signer.sign_event(&legacy_unsigned);
        let mut legacy = legacy_unsigned;
        legacy["signatureKeyId"] = Value::String(signer.key_id().to_string());
        legacy["signature"] = Value::String(legacy_signature);
        assert!(
            verify_audit_event_signature(&legacy, &public).unwrap(),
            "pre-v2 signed audit entries must remain verifiable"
        );
    }

    #[test]
    fn audit_verify_treats_missing_signature_as_unsigned_not_error_value() {
        let signer = fixed_test_signer(13);
        let public = signer.verifying_key();

        let unsigned_event = json!({
            "tool": "repo.status",
            "ts": 1717000000000u64,
            "result": "success",
        });

        match verify_audit_event_signature(&unsigned_event, &public) {
            Err(AuditVerificationError::MissingSignature) => {
                // Expected: caller treats this as "unsigned entry", not
                // as "tampered". This guarantees backward compatibility
                // with logs written before signing was enabled.
            }
            other => panic!("expected MissingSignature, got {:?}", other),
        }
    }

    #[test]
    fn audit_signature_fails_under_wrong_pubkey() {
        let signer = fixed_test_signer(17);
        let wrong_signer = fixed_test_signer(18);
        let wrong_public = wrong_signer.verifying_key();

        let audit_dir = TestDir::new("fluxgit-mcp-wrongkey-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server =
            McpSidecar::new_for_tests_with_signed_audit(false, audit_log.clone(), signer.clone());

        let repo = fixture_repo();
        server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 903,
                "method": "tools/call",
                "params": {
                    "name": "repo.status",
                    "arguments": {
                        "repoPath": repo.path(),
                        "repoId": "repo-wrong"
                    }
                }
            }))
            .unwrap();

        let contents = fs::read_to_string(&audit_log).unwrap();
        let event: Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();

        // The signature is real and well-formed, but the public key does
        // not match — verification must return Ok(false), not an error.
        assert!(
            !verify_audit_event_signature(&event, &wrong_public).unwrap(),
            "verification under a different public key must return Ok(false)"
        );

        // Sanity: the original key still verifies.
        assert!(verify_audit_event_signature(&event, &signer.verifying_key()).unwrap());
    }

    #[test]
    fn unsigned_audit_path_is_unchanged_when_signer_is_none() {
        // Backward-compat: when no signer is configured, the audit entry
        // MUST NOT carry signature/signatureKeyId fields.
        let audit_dir = TestDir::new("fluxgit-mcp-unsigned-back-compat");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_audit(false, audit_log.clone());

        let repo = fixture_repo();
        server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 904,
                "method": "tools/call",
                "params": {
                    "name": "repo.status",
                    "arguments": {
                        "repoPath": repo.path(),
                        "repoId": "repo-unsigned"
                    }
                }
            }))
            .unwrap();

        let contents = fs::read_to_string(&audit_log).unwrap();
        let event: Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert!(
            event.get("signature").is_none(),
            "unsigned audit entry must NOT have a signature field"
        );
        assert!(
            event.get("signatureKeyId").is_none(),
            "unsigned audit entry must NOT have a signatureKeyId field"
        );
        assert!(
            event.get("signatureVersion").is_none(),
            "unsigned audit entry must NOT have a signatureVersion field"
        );
    }

    #[test]
    fn shared_ledger_concurrent_appenders_keep_one_contiguous_chain() {
        let audit_dir = TestDir::new("fluxgit-mcp-concurrent-ledger");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let signer = fixed_test_signer(31);
        let ledger = AuditLedger::new(audit_log.clone(), Some(signer.clone())).unwrap();
        let mut workers = Vec::new();
        for worker in 0..8 {
            let ledger = ledger.clone();
            workers.push(std::thread::spawn(move || {
                for index in 0..25 {
                    ledger
                        .append(json!({
                            "timestamp": now_ms(),
                            "tool": "repo.status",
                            "repo_scope": format!("worker-{worker}"),
                            "event_type": "tool_call",
                            "risk": "none",
                            "approval": "not_required",
                            "result": "success",
                            "summary": format!("worker {worker} event {index}"),
                        }))
                        .unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let report = verify_audit_ledger(&audit_log, &signer.verifying_key(), true).unwrap();
        assert_eq!(report.entries, 200);
        assert_eq!(report.chained, 200);
        assert_eq!(report.first_sequence, Some(1));
        assert_eq!(report.last_sequence, Some(200));
    }

    #[test]
    fn audit_environment_uses_shared_default_path_and_invalid_explicit_key_fails_closed() {
        let run_dir = TestDir::new("fluxgit-mcp-audit-default-run");
        {
            let _env = AuditEnvGuard::isolated(run_dir.path(), None);
            let ledger = AuditLedger::from_env().unwrap().unwrap();
            assert_eq!(
                ledger.path(),
                audit_log_path_for_run_dir(run_dir.path()),
                "sidecar and gateway must resolve exactly one default ledger path"
            );
        }
        let missing_key = run_dir.path().join("missing-private-key.pem");
        let _env = AuditEnvGuard::isolated(run_dir.path(), Some(&missing_key));
        let error = AuditLedger::from_env()
            .expect_err("an explicitly configured missing signing key must fail closed");
        assert!(error.to_string().contains("cannot read audit signing key"));
    }

    #[test]
    fn ledger_rotation_retention_and_checkpoint_verify_streaming() {
        let audit_dir = TestDir::new("fluxgit-mcp-rotating-ledger");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let signer = fixed_test_signer(32);
        let ledger =
            AuditLedger::with_limits(audit_log.clone(), Some(signer.clone()), 900, 2).unwrap();
        for index in 0..24 {
            ledger
                .append(json!({
                    "timestamp": now_ms(),
                    "tool": "repo.status",
                    "repo_scope": "rotation-test",
                    "event_type": "tool_call",
                    "risk": "none",
                    "approval": "not_required",
                    "result": "success",
                    "summary": format!("rotation event {index} {}", "x".repeat(180)),
                }))
                .unwrap();
        }
        let report =
            scan_audit_ledger(&audit_log, Some(&signer.verifying_key()), true, 900, 2).unwrap();
        assert!(
            report.checkpoint_used,
            "retention prefix was not checkpointed"
        );
        assert!(report.first_sequence.unwrap() > 1);
        let rotated = collect_ledger_files(&audit_log)
            .unwrap()
            .into_iter()
            .filter(|file| matches!(&file.kind, LedgerFileKind::Rotated(_)))
            .count();
        assert!(rotated <= 2);
    }

    #[test]
    fn ledger_verifier_detects_mutation_deletion_duplication_and_reordering() {
        let audit_dir = TestDir::new("fluxgit-mcp-chain-adversarial");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let signer = fixed_test_signer(33);
        let ledger = AuditLedger::new(audit_log.clone(), Some(signer.clone())).unwrap();
        for index in 0..4 {
            ledger
                .append(json!({
                    "timestamp": now_ms(),
                    "tool": "repo.status",
                    "repo_scope": "adversarial",
                    "event_type": "tool_call",
                    "risk": "none",
                    "approval": "not_required",
                    "result": "success",
                    "summary": format!("event {index}"),
                }))
                .unwrap();
        }
        let original = fs::read_to_string(&audit_log).unwrap();
        let lines = original.lines().map(str::to_string).collect::<Vec<_>>();

        let mut mutated: Value = serde_json::from_str(&lines[1]).unwrap();
        mutated["summary"] = Value::String("changed".into());
        let mut mutation_lines = lines.clone();
        mutation_lines[1] = serde_json::to_string(&mutated).unwrap();
        fs::write(&audit_log, format!("{}\n", mutation_lines.join("\n"))).unwrap();
        assert!(verify_audit_ledger(&audit_log, &signer.verifying_key(), true).is_err());

        fs::write(
            &audit_log,
            format!(
                "{}\n",
                [lines[0].clone(), lines[2].clone(), lines[3].clone()].join("\n")
            ),
        )
        .unwrap();
        assert!(verify_audit_ledger(&audit_log, &signer.verifying_key(), true).is_err());

        fs::write(
            &audit_log,
            format!(
                "{}\n",
                [
                    lines[0].clone(),
                    lines[1].clone(),
                    lines[1].clone(),
                    lines[2].clone(),
                    lines[3].clone()
                ]
                .join("\n")
            ),
        )
        .unwrap();
        assert!(verify_audit_ledger(&audit_log, &signer.verifying_key(), true).is_err());

        fs::write(
            &audit_log,
            format!(
                "{}\n",
                [
                    lines[1].clone(),
                    lines[0].clone(),
                    lines[2].clone(),
                    lines[3].clone()
                ]
                .join("\n")
            ),
        )
        .unwrap();
        assert!(verify_audit_ledger(&audit_log, &signer.verifying_key(), true).is_err());
    }

    #[test]
    fn legacy_entries_remain_verifiable_but_are_reported_as_unchained() {
        let audit_dir = TestDir::new("fluxgit-mcp-legacy-chain-boundary");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let signer = fixed_test_signer(34);
        let unsigned_legacy = json!({
            "id": "old-unsigned",
            "timestamp": 1,
            "tool": "repo.status",
            "summary": "legacy unsigned"
        });
        let mut signed_legacy = json!({
            "id": "old-signed",
            "timestamp": 2,
            "tool": "repo.status",
            "summary": "legacy signed",
            "signatureKeyId": signer.key_id(),
            "signatureVersion": 2,
        });
        signed_legacy["signature"] = Value::String(signer.sign_event(&signed_legacy));
        fs::write(
            &audit_log,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&unsigned_legacy).unwrap(),
                serde_json::to_string(&signed_legacy).unwrap()
            ),
        )
        .unwrap();
        let ledger = AuditLedger::new(audit_log.clone(), Some(signer.clone())).unwrap();
        ledger
            .append(json!({
                "timestamp": 3,
                "tool": "repo.status",
                "repo_scope": "legacy-boundary",
                "event_type": "tool_call",
                "risk": "none",
                "approval": "not_required",
                "result": "success",
                "summary": "first chained event"
            }))
            .unwrap();
        let report = verify_audit_ledger(&audit_log, &signer.verifying_key(), false).unwrap();
        assert_eq!(report.legacy, 2);
        assert_eq!(report.chained, 1);
        assert_eq!(report.signed, 2);
        assert_eq!(report.unsigned, 1);
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        // The canonical form is the only thing the verifier and the signer
        // must agree on. Pin its behavior explicitly.
        let event = json!({
            "z": 1,
            "a": { "y": 2, "b": 3 },
            "m": [ { "z": 1, "a": 2 }, 4 ],
        });
        let bytes = canonical_json_bytes(&event);
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(
            s, r#"{"a":{"b":3,"y":2},"m":[{"a":2,"z":1},4],"z":1}"#,
            "canonical form must sort object keys lexicographically and preserve array order"
        );
    }
}
