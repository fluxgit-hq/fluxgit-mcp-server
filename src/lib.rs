use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::env;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SERVER_NAME: &str = "fluxgit-mcp-sidecar";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone)]
pub struct McpSidecar {
    gateway_state: GatewayState,
    audit_log: Option<PathBuf>,
    audit_signer: Option<AuditSigner>,
}

/// Per-install Ed25519 audit signer. Loaded once at startup from
/// `FLUXGIT_MCP_AUDIT_SIGN_KEY` (PEM PKCS8, matching the license-server convention).
/// Signing is opt-in: if the env var is unset, no signing happens. If the env var
/// points to a missing or invalid key, we warn to stderr and continue WITHOUT
/// signing — auditing must never refuse to record an event.
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
        let pem = fs::read_to_string(path).map_err(AuditSignerError::Io)?;
        Self::from_pem_str(&pem)
    }

    /// Load a signer from an in-memory PEM PKCS8 string. Exposed for tests
    /// (so a keypair can be generated and consumed without touching disk).
    pub fn from_pem_str(pem: &str) -> Result<Self, AuditSignerError> {
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

    /// Sign the canonical-JSON form of `event` (event MUST NOT yet contain
    /// a `signature` field). Returns the base64url-no-pad signature.
    fn sign_event(&self, event: &Value) -> String {
        let canonical = canonical_json_bytes(event);
        let sig: Signature = self.signing_key.sign(&canonical);
        BASE64_URL_NO_PAD.encode(sig.to_bytes())
    }
}

/// Reasons an audit signer might fail to load. None of these are fatal at
/// runtime — the sidecar logs a warning and falls back to unsigned audit
/// rather than refusing to record events.
#[derive(Debug)]
pub enum AuditSignerError {
    Io(io::Error),
    Parse(String),
}

impl fmt::Display for AuditSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "cannot read audit signing key file: {err}"),
            Self::Parse(msg) => write!(f, "audit signing key is not a valid PEM PKCS8 Ed25519 key: {msg}"),
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
            Self::MalformedSignature(msg) => write!(f, "signature field is not valid base64url: {msg}"),
            Self::InvalidSignatureLength(n) => write!(f, "signature has wrong length: {n} (expected 64)"),
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

    // Build the canonical form WITHOUT the signature field (and without the
    // signatureKeyId field, which is metadata describing which key signed it
    // and is therefore also not part of the signed payload).
    let mut unsigned = obj.clone();
    unsigned.remove("signature");
    unsigned.remove("signatureKeyId");
    let canonical = canonical_json_bytes(&Value::Object(unsigned));

    Ok(public_key.verify(&canonical, &signature).is_ok())
}

/// Parse a PEM-encoded Ed25519 public key (SubjectPublicKeyInfo, the format
/// emitted by Python `cryptography` and matching license-server convention).
pub fn parse_public_key_pem(pem: &str) -> Result<VerifyingKey, AuditSignerError> {
    VerifyingKey::from_public_key_pem(pem).map_err(|e| AuditSignerError::Parse(e.to_string()))
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
    description: &'static str,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<ToolAnnotations>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct ToolAnnotations {
    #[serde(rename = "readOnlyHint")]
    read_only_hint: bool,
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
}

#[derive(Debug, Serialize, Clone, PartialEq)]
struct ServerInfo {
    name: &'static str,
    version: &'static str,
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
            ToolKind::OperationPreviewMerge => "operation.preview.merge",
            ToolKind::OperationPreviewRebase => "operation.preview.rebase",
            ToolKind::OperationPreviewDiscard => "operation.preview.discard",
            ToolKind::OperationPreviewReset => "operation.preview.reset",
            ToolKind::OperationPreviewPatch => "operation.preview.patch",
            ToolKind::OperationPreviewPlan => "operation.preview.plan",
        }
    }
}

/// Tools that propose a write through the FluxGit UI handshake (PLAYBOOK §10).
/// They are not read-only and they never execute locally. With the FluxGit
/// desktop app running (FLUXGIT_MCP_HANDSHAKE_ADDR set), each call dispatches
/// to the app: FluxGit opens a preview, the user approves or rejects, and the
/// sidecar reports the outcome. Without the app they return
/// `write_handshake_pending` (code 10003) with agent guidance.
const WRITE_HANDSHAKE_TOOL_KINDS: &[ToolKind] = &[
    ToolKind::OperationPreviewMerge,
    ToolKind::OperationPreviewRebase,
    ToolKind::OperationPreviewDiscard,
    ToolKind::OperationPreviewReset,
    ToolKind::OperationPreviewPatch,
    ToolKind::OperationPreviewPlan,
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
    pub fn from_env() -> Self {
        let gateway_state = if env::var("FLUXGIT_GATEWAY_ADDR").is_ok()
            || env::var("FLUXGIT_GATEWAY_URL").is_ok()
        {
            GatewayState::Configured
        } else {
            GatewayState::NotConfigured
        };

        Self {
            gateway_state,
            audit_log: mcp_audit_log_path(),
            audit_signer: load_audit_signer_from_env(),
        }
    }

    pub fn new_for_tests(gateway_configured: bool) -> Self {
        Self {
            gateway_state: if gateway_configured {
                GatewayState::Configured
            } else {
                GatewayState::NotConfigured
            },
            audit_log: None,
            audit_signer: None,
        }
    }

    pub fn new_for_tests_with_audit(gateway_configured: bool, audit_log: PathBuf) -> Self {
        Self {
            gateway_state: if gateway_configured {
                GatewayState::Configured
            } else {
                GatewayState::NotConfigured
            },
            audit_log: Some(audit_log),
            audit_signer: None,
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
            audit_log: Some(audit_log),
            audit_signer: Some(signer),
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
                write_frame(&mut output, &response)?;
            }
        }

        output.flush()?;
        Ok(())
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

        let id = request.id.unwrap_or(Value::Null);
        let response = match request.method.as_str() {
            "initialize" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!(InitializeResult::new())),
                error: None,
            },
            "tools/list" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "tools": all_advertised_tools(),
                })),
                error: None,
            },
            "tools/call" => {
                let audit_context = McpAuditContext::from_params(&request.params);
                match self.handle_tools_call(request.params) {
                    Ok(result) => {
                        self.record_tool_audit(&audit_context, &result);
                        JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: Some(json!(result)),
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
            "notifications/initialized" => return None,
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
        };

        Some(response)
    }

    fn handle_tools_call(&self, params: Value) -> Result<ToolCallResult, JsonRpcError> {
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
            message: "Tool is not on the read-only whitelist".into(),
            data: Some(json!({
                "tool": tool_name,
                "allowedTools": read_only_tool_names(),
            })),
        })?;

        let arguments = object.get("arguments").unwrap_or(&Value::Null);

        // Write-with-UI-handshake tools (PLAYBOOK §10, §14.2, §14.7):
        // All five `operation.preview.*` tools dispatch through the gateway HTTP
        // bridge when the handshake address is configured. Resolution order per
        // playbook §14.2:
        //   1. FLUXGIT_MCP_HANDSHAKE_ADDR (canonical for the handshake server)
        //   2. FLUXGIT_GATEWAY_ADDR (fallback for backward compatibility)
        // When the env is unset, the dispatch POST fails, or polling times out we
        // fall through to the standard `write_handshake_pending_error` (code 10003)
        // so the agent gets the existing, well-known error contract.
        if is_write_handshake(kind) {
            let handshake_addr = env::var("FLUXGIT_MCP_HANDSHAKE_ADDR")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .or_else(|| {
                    env::var("FLUXGIT_GATEWAY_ADDR")
                        .ok()
                        .filter(|v| !v.trim().is_empty())
                });
            if let Some(addr) = handshake_addr {
                let dispatched = match kind {
                    ToolKind::OperationPreviewMerge => {
                        dispatch_operation_preview_merge(&addr, arguments)
                    }
                    ToolKind::OperationPreviewRebase => {
                        dispatch_operation_preview_rebase(&addr, arguments)
                    }
                    ToolKind::OperationPreviewDiscard => {
                        dispatch_operation_preview_discard(&addr, arguments)
                    }
                    ToolKind::OperationPreviewReset => {
                        dispatch_operation_preview_reset(&addr, arguments)
                    }
                    ToolKind::OperationPreviewPatch => {
                        dispatch_operation_preview_patch(&addr, arguments)
                    }
                    ToolKind::OperationPreviewPlan => {
                        dispatch_operation_preview_plan(&addr, arguments)
                    }
                    _ => None,
                };
                if let Some(result) = dispatched {
                    return Ok(result);
                }
            }
            // Fall through to the standard write_handshake_pending error when the
            // gateway is unset, unreachable, or polling times out.
        }
        if is_write_handshake(kind) {
            let error = write_handshake_pending_error(kind.as_str());
            return Ok(ToolCallResult {
                content: vec![ToolCallContent {
                    kind: "text",
                    text: serde_json::to_string_pretty(&json!({
                        "error": error,
                        "tool": kind.as_str(),
                        "readOnly": false,
                        "tier": "fluxgit-write-handshake",
                    }))
                    .unwrap_or_else(|serialize_err| {
                        format!(
                            "{{\"error\":{{\"code\":\"internal_serialization_error\",\"message\":\"{}\"}}}}",
                            serialize_err
                        )
                    }),
                }],
                is_error: true,
            });
        }

        // Enforce the free-shell vs FluxGit-powered boundary (PLAYBOOK §2).
        // Tools that require FluxGit must error out when the gateway is not configured,
        // even if a repoPath was supplied: synthesizing them from local git alone would
        // produce misleading "FluxGit-powered" results and undermine the business model.
        if is_fluxgit_required(kind) && matches!(self.gateway_state, GatewayState::NotConfigured) {
            let error = gateway_not_configured_error(kind.as_str());
            return Ok(ToolCallResult {
                content: vec![ToolCallContent {
                    kind: "text",
                    text: serde_json::to_string_pretty(&json!({
                        "error": error,
                        "tool": kind.as_str(),
                        "readOnly": true,
                        "tier": "fluxgit",
                    }))
                    .unwrap_or_else(|serialize_err| {
                        format!(
                            "{{\"error\":{{\"code\":\"internal_serialization_error\",\"message\":\"{}\"}}}}",
                            serialize_err
                        )
                    }),
                }],
                is_error: true,
            });
        }

        if kind == ToolKind::FleetRadar {
            return Ok(render_fleet_radar_tool_result(arguments));
        }

        if let Some(repo_path) = repo_path_from_arguments(arguments) {
            return Ok(render_local_tool_result(kind, arguments, &repo_path));
        }

        let error = match self.gateway_state {
            GatewayState::NotConfigured => gateway_not_configured_error(kind.as_str()),
            GatewayState::Configured => gateway_unavailable_error(kind.as_str()),
        };

        Ok(ToolCallResult {
            content: vec![ToolCallContent {
                kind: "text",
                text: serde_json::to_string_pretty(&json!({
                    "error": error,
                    "tool": kind.as_str(),
                    "readOnly": true,
                }))
                .unwrap_or_else(|serialize_err| {
                    format!(
                        "{{\"error\":{{\"code\":\"internal_serialization_error\",\"message\":\"{}\"}}}}",
                        serialize_err
                    )
                }),
            }],
            is_error: true,
        })
    }

    fn record_tool_audit(&self, context: &McpAuditContext, result: &ToolCallResult) {
        let event_type = if context.read_only_whitelisted {
            "tool_call"
        } else {
            "write_block"
        };
        let result_label = if result.is_error { "error" } else { "success" };
        let summary = if result.is_error {
            format!(
                "MCP read-only tool {} returned a structured error.",
                context.tool
            )
        } else {
            format!("MCP read-only tool {} completed.", context.tool)
        };
        self.append_audit_event(json!({
            "id": format!("mcp-tool-{}-{}", now_ms(), context.tool.replace('.', "-")),
            "timestamp": now_ms(),
            "tool": context.tool,
            "repo_scope": context.repo_scope,
            "args_fingerprint": context.args_fingerprint,
            "risk": "none",
            "approval": "not_required",
            "result": result_label,
            "event_type": event_type,
            "session_id": "external-mcp-sidecar",
            "duration_ms": 0,
            "summary": summary,
            "readOnly": context.read_only_whitelisted,
            "sidecarReadOnly": true,
        }));
    }

    fn record_tool_error_audit(&self, context: &McpAuditContext, error: &JsonRpcError) {
        self.append_audit_event(json!({
            "id": format!("mcp-block-{}-{}", now_ms(), context.tool.replace('.', "-")),
            "timestamp": now_ms(),
            "tool": context.tool,
            "repo_scope": context.repo_scope,
            "args_fingerprint": context.args_fingerprint,
            "risk": "none",
            "approval": "denied",
            "result": "blocked",
            "event_type": "write_block",
            "session_id": "external-mcp-sidecar",
            "duration_ms": 0,
            "summary": format!("MCP tool {} was blocked: {}", context.tool, error.message),
            "readOnly": context.read_only_whitelisted,
            "sidecarReadOnly": true,
        }));
    }

    fn append_audit_event(&self, event: Value) {
        let Some(path) = &self.audit_log else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // If a per-install signer is configured, sign the canonical form
        // of the event and attach `signature` + `signatureKeyId`. Otherwise
        // write the event as-is (legacy unsigned format, backward compatible).
        let final_event = match &self.audit_signer {
            Some(signer) => {
                let signature = signer.sign_event(&event);
                let mut obj = match event {
                    Value::Object(map) => map,
                    other => {
                        // Audit events are always JSON objects in practice;
                        // if something exotic slips in, write it unsigned.
                        let _ = self.write_audit_line(path, &other);
                        return;
                    }
                };
                obj.insert("signature".to_string(), Value::String(signature));
                obj.insert(
                    "signatureKeyId".to_string(),
                    Value::String(signer.key_id.clone()),
                );
                Value::Object(obj)
            }
            None => event,
        };

        let _ = self.write_audit_line(path, &final_event);
    }

    fn write_audit_line(&self, path: &Path, event: &Value) -> io::Result<()> {
        let line = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{line}")
    }
}

struct McpAuditContext {
    tool: String,
    repo_scope: String,
    args_fingerprint: Option<String>,
    read_only_whitelisted: bool,
}

impl McpAuditContext {
    fn from_params(params: &Value) -> Self {
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
                            .unwrap_or_else(|| "fnv1a64:unavailable".into());
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
            read_only_whitelisted: ToolKind::from_name(&tool).is_some(),
            tool,
            repo_scope,
        }
    }
}

fn arguments_fingerprint(arguments: &Value) -> Option<String> {
    if arguments.is_null() {
        return None;
    }
    let serialized = serde_json::to_vec(arguments).ok()?;
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in serialized {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Some(format!("fnv1a64:{hash:016x}"))
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
    ToolCallResult {
        content: vec![ToolCallContent {
            kind: "text",
            text: serde_json::to_string_pretty(&payload).unwrap_or_else(|serialize_err| {
                format!(
                    "{{\"error\":{{\"code\":\"internal_serialization_error\",\"message\":\"{}\"}}}}",
                    serialize_err
                )
            }),
        }],
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
        | ToolKind::OperationPreviewPlan => {
            // Write-handshake tools are short-circuited in handle_tools_call before
            // reaching here. If execution gets here, something rerouted incorrectly.
            unreachable!(
                "operation.preview.* must be short-circuited by handle_tools_call before local dispatch"
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
    let object = arguments.as_object()?;
    for key in ["repoPath", "repositoryPath", "root"] {
        if let Some(path) = object.get(key).and_then(Value::as_str) {
            return Some(PathBuf::from(path));
        }
    }

    let path = PathBuf::from(object.get("path")?.as_str()?);
    if path.is_dir() {
        Some(path)
    } else {
        None
    }
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
        .map(|input| fleet_radar_entry(input))
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
    let potential_conflict_paths = predict_upstream_conflict_paths(
        &repo_path,
        upstream.as_deref(),
        ahead,
        behind,
    );
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
        let authors: Vec<&str> = output.lines().filter(|line| !line.trim().is_empty()).collect();
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
        let Some(pattern) = parts.next() else { continue };
        let owners: Vec<String> = parts.map(str::to_string).collect();
        if owners.is_empty() {
            continue;
        }
        let normalized = pattern.trim_matches('/').trim_end_matches("/**").trim_end_matches("/*");
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
    let submodules = run_git_optional(repo_path, &["submodule", "status", "--recursive"])
        .map(|output| {
            let mut total = 0u64;
            let mut clean_count = 0u64;
            let mut uninitialized = 0u64;
            let mut drifted = 0u64;
            let mut conflicts = 0u64;
            let mut attention = Vec::new();
            for line in output.lines().filter(|line| !line.trim().is_empty()) {
                total += 1;
                let state = line.chars().next().unwrap_or(' ');
                match state {
                    '-' => uninitialized += 1,
                    '+' => drifted += 1,
                    'U' => conflicts += 1,
                    _ => clean_count += 1,
                }
                if state != ' ' && attention.len() < 10 {
                    attention.push(parse_submodule_line(line));
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
    let submodules_needing_attention = submodules["total"].as_u64().unwrap_or(0)
        - submodules["clean"].as_u64().unwrap_or(0);

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
        run_git_optional(repo_path, &["log", "--pretty=format:%s", "-n50"])
            .and_then(|output| {
                let subjects: Vec<&str> =
                    output.lines().filter(|line| !line.trim().is_empty()).collect();
                if subjects.is_empty() {
                    return None;
                }
                let matches = subjects
                    .iter()
                    .filter(|subject| subject_is_conventional(subject))
                    .count();
                Some((matches as f64 / subjects.len() as f64 * 100.0).round() / 100.0)
            });
    let default_branch =
        run_git_optional(repo_path, &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
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
        "remotes": lines_json(run_git(repo_path, &["remote", "-v"])?),
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
    let base_distance = base_ref.as_deref().and_then(|base| {
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
        Some(json!({
            "aheadFromBase": ahead_from_base,
            "behindBase": behind_base,
        }))
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

    let current_spec = format!("{current_ref}^{{commit}}");
    let target_spec = format!("{target_ref}^{{commit}}");
    let current_oid = run_git(repo_path, &["rev-parse", "--verify", &current_spec])?
        .trim()
        .to_string();
    let target_oid = run_git(repo_path, &["rev-parse", "--verify", &target_spec])?
        .trim()
        .to_string();
    let merge_base_oid = run_git_optional(repo_path, &["merge-base", &current_oid, &target_oid]);

    let target_is_ancestor =
        run_git_status(repo_path, &["merge-base", "--is-ancestor", &target_oid, &current_oid]);
    let current_is_ancestor =
        run_git_status(repo_path, &["merge-base", "--is-ancestor", &current_oid, &target_oid]);

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
        let merge_tree = run_git(repo_path, &["merge-tree", merge_base, &current_oid, &target_oid])?;
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
    for entry in unmerged_output.split('\0').filter(|entry| !entry.is_empty()) {
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
        let (base, ours, theirs) = (slots[0].as_deref(), slots[1].as_deref(), slots[2].as_deref());
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
    let Ok(bytes) = run_git_bytes(repo_path, &["cat-file", "blob", sha]) else {
        return json!({ "sha": sha, "error": "blob unreadable" });
    };
    let size = bytes.len();
    if bytes[..size.min(8000)].contains(&0) {
        return json!({ "sha": sha, "binary": true, "size": size });
    }
    let truncated = size > max_bytes;
    json!({
        "sha": sha,
        "size": size,
        "truncated": truncated,
        "content": String::from_utf8_lossy(&bytes[..size.min(max_bytes)]),
    })
}

/// Parse `<<<<<<<` / `=======` / `>>>>>>>` regions from the checked-out file so
/// the agent can map hunks to line ranges. Returns an empty array when the file
/// is missing, binary, or carries no markers (e.g. rm/rm conflicts).
fn conflict_marker_regions_for_file(file_path: &Path) -> Vec<Value> {
    let Ok(bytes) = fs::read(file_path) else {
        return Vec::new();
    };
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

    let mut flush = |entry: Option<Map<String, Value>>, out: &mut Vec<Value>| {
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
        let Some(map) = current.as_mut() else { continue };
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
    let output = run_git(repo_path, &["submodule", "status", "--recursive"])?;
    Ok(json!({
        "submodules": output.lines().map(parse_submodule_line).collect::<Vec<_>>(),
    }))
}

fn diff_text_payload(repo_path: &Path, arguments: &Value) -> Result<Value, JsonRpcError> {
    let base = arguments.get("base").and_then(Value::as_str);
    let head = arguments.get("head").and_then(Value::as_str);
    let path_filter = diff_path_filter(arguments, repo_path);

    let mut args = vec!["diff"];
    if let Some(base) = base {
        args.push(base);
    }
    if let Some(head) = head {
        args.push(head);
    }
    if let Some(path) = path_filter.as_deref() {
        args.push("--");
        args.push(path);
    }

    Ok(json!({
        "format": "text",
        "base": base,
        "head": head,
        "path": path_filter,
        "diff": run_git(repo_path, &args)?,
    }))
}

fn semantic_fallback_payload(repo_path: &Path, arguments: &Value) -> Value {
    json!({
        "supported": false,
        "fallback": "diff.text",
        "reason": "Semantic diff is not available in local sidecar fallback mode.",
        "textDiffArguments": {
            "repoPath": repo_path,
            "base": arguments.get("base").and_then(Value::as_str),
            "head": arguments.get("head").and_then(Value::as_str),
            "path": diff_path_filter(arguments, repo_path),
        },
    })
}

fn semantic_fallbacks_payload(repo_path: &Path, arguments: &Value) -> Value {
    json!({
        "fallbacks": [{
            "from": "diff.semantic",
            "to": "diff.text",
            "supported": false,
            "reason": "Local fallback uses git diff text because no semantic diff engine is wired in the sidecar.",
            "repoPath": repo_path,
            "path": diff_path_filter(arguments, repo_path),
        }],
    })
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

fn flux_checkpoint_path(repo_id: &str, arguments: &Value) -> Option<PathBuf> {
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

fn mcp_audit_log_path() -> Option<PathBuf> {
    if env::var_os("FLUXGIT_MCP_AUDIT_DISABLED").is_some() {
        return None;
    }
    if let Ok(custom) = env::var("FLUXGIT_MCP_AUDIT_LOG") {
        return Some(PathBuf::from(custom));
    }
    Some(fluxgit_run_dir()?.join("audit").join("mcp.jsonl"))
}

/// Load the per-install audit signer from `FLUXGIT_MCP_AUDIT_SIGN_KEY`, if set.
///
/// Signing is opt-in: when the env var is unset, returns `None` and the audit
/// log is written in the legacy unsigned format. If the env var points to a
/// path that cannot be read or does not contain a valid PEM PKCS8 Ed25519
/// private key, we log a single warning to stderr and return `None` rather
/// than aborting — the audit log MUST keep recording events even if signing
/// is misconfigured.
fn load_audit_signer_from_env() -> Option<AuditSigner> {
    let path = env::var_os("FLUXGIT_MCP_AUDIT_SIGN_KEY")?;
    let path = PathBuf::from(path);
    match AuditSigner::from_pem_file(&path) {
        Ok(signer) => Some(signer),
        Err(err) => {
            eprintln!(
                "fluxgit-mcp-sidecar: audit signing disabled for this session ({}): {}",
                path.display(),
                err
            );
            None
        }
    }
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
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .map_err(|err| local_git_error(args, err.to_string()))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(local_git_error(
            args,
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

/// Raw-byte variant of `run_git` for blob content (`cat-file blob`), where
/// lossy UTF-8 conversion before binary detection would corrupt the signal.
fn run_git_bytes(repo_path: &Path, args: &[&str]) -> Result<Vec<u8>, JsonRpcError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .map_err(|err| local_git_error(args, err.to_string()))?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(local_git_error(
            args,
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

fn run_git_optional(repo_path: &Path, args: &[&str]) -> Option<String> {
    run_git(repo_path, args)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn run_git_status(repo_path: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
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

fn parse_submodule_line(line: &str) -> Value {
    let state = line.chars().next().unwrap_or(' ');
    let mut parts = line.get(1..).unwrap_or("").split_whitespace();
    json!({
        "state": state.to_string(),
        "commit": parts.next().unwrap_or_default(),
        "path": parts.next().unwrap_or_default(),
        "description": parts.collect::<Vec<_>>().join(" "),
    })
}

impl InitializeResult {
    fn new() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            capabilities: json!({
                "tools": {
                    "listChanged": false
                }
            }),
            server_info: ServerInfo {
                name: SERVER_NAME,
                version: SERVER_VERSION,
            },
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
            "operation.preview.merge" => Some(Self::OperationPreviewMerge),
            "operation.preview.rebase" => Some(Self::OperationPreviewRebase),
            "operation.preview.discard" => Some(Self::OperationPreviewDiscard),
            "operation.preview.reset" => Some(Self::OperationPreviewReset),
            "operation.preview.patch" => Some(Self::OperationPreviewPatch),
            "operation.preview.plan" => Some(Self::OperationPreviewPlan),
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
            description: tool_description(kind),
            input_schema: tool_input_schema(kind),
            annotations: Some(ToolAnnotations {
                read_only_hint: true,
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
            description: tool_description(kind),
            input_schema: tool_input_schema(kind),
            annotations: Some(ToolAnnotations {
                read_only_hint: false,
            }),
        })
        .collect()
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
            "List read-only Safety Timeline events synthesized from Flux restore points and reflog movement."
        }
        ToolKind::SafetyEventDetails => {
            "Read one Safety Timeline event and its safe UI actions without performing recovery or mutation."
        }
        ToolKind::FleetRadar => {
            "Summarize multiple local repositories into a read-only attention stack without fetching or mutating disk state."
        }
        ToolKind::RepoStatus => "Summarize repository cleanliness and divergence.",
        ToolKind::RepoRefs => "List refs, remotes, tags, stashes, and HEAD.",
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
            "Read the local reflog movement timeline for HEAD or another ref without recovering or mutating history."
        }
        ToolKind::RepoHistory => "Return paged repository history.",
        ToolKind::CommitDetails => "Inspect commit metadata and changed files.",
        ToolKind::WorktreeChanges => "Summarize staged, unstaged, and untracked worktree changes.",
        ToolKind::SubmoduleStatus => "Inspect submodule state and dirtiness.",
        ToolKind::DiffText => "Return the standard text diff payload.",
        ToolKind::DiffSemantic => "Return the semantic diff payload or fallback metadata.",
        ToolKind::DiffSemanticFallbacks => "List files that fell back from semantic diff.",
        ToolKind::FluxLatestRestorePoint => {
            "Read the latest Flux history restore point metadata, if available."
        }
        ToolKind::FluxRestorePoints => {
            "Read available Flux history restore point metadata without performing undo/redo."
        }
        ToolKind::FluxRestorePointDetails => {
            "Read Flux history restore point details and safety state without performing undo/redo."
        }
        ToolKind::OperationPreviewMerge => {
            "Propose a merge for human review inside FluxGit. The sidecar never merges; FluxGit opens a preview, the user approves or rejects, and FluxGit executes through its safety pipeline. Requires the FluxGit desktop app to be running and connected (FLUXGIT_MCP_HANDSHAKE_ADDR); the call returns the preview outcome (approved, rejected or timed out). Without the app it returns error 10003 with instructions. Always include a clear `reason`: the user reads it in the approval dialog. On completion the result includes the captured restore point (beforeCommit/afterCommit/canUndo) when one was created — tell the user the change is reversible from FluxGit Safety Timeline."
        }
        ToolKind::OperationPreviewRebase => {
            "Propose a rebase for human review inside FluxGit. The sidecar never rebases; FluxGit opens a preview with risk analysis, the user approves or rejects, and FluxGit executes through its safety pipeline with a restore point. Requires the FluxGit desktop app to be running and connected (FLUXGIT_MCP_HANDSHAKE_ADDR); the call returns the preview outcome (approved, rejected or timed out). Without the app it returns error 10003 with instructions. Always include a clear `reason`: the user reads it in the approval dialog. On completion the result includes the captured restore point (beforeCommit/afterCommit/canUndo) when one was created — tell the user the change is reversible from FluxGit Safety Timeline."
        }
        ToolKind::OperationPreviewDiscard => {
            "Propose discarding working tree changes for one or more paths. FluxGit shows exactly what would be lost and requires explicit user approval before any file is touched. Requires the FluxGit desktop app to be running and connected (FLUXGIT_MCP_HANDSHAKE_ADDR); the call returns the preview outcome (approved, rejected or timed out). Without the app it returns error 10003 with instructions. Always include a clear `reason`: the user reads it in the approval dialog."
        }
        ToolKind::OperationPreviewReset => {
            "Propose a reset (soft/mixed/hard) for human review. FluxGit shows commits at risk and creates a restore point before any destructive action. Hard resets always require strong confirmation. Requires the FluxGit desktop app to be running and connected (FLUXGIT_MCP_HANDSHAKE_ADDR); the call returns the preview outcome (approved, rejected or timed out). Without the app it returns error 10003 with instructions. Always include a clear `reason`: the user reads it in the approval dialog. On completion the result includes the captured restore point (beforeCommit/afterCommit/canUndo) when one was created — tell the user the change is reversible from FluxGit Safety Timeline."
        }
        ToolKind::OperationPreviewPatch => {
            "Propose applying a patch generated by the agent. FluxGit shows the resulting diff in the preview UI, runs conflict detection and requires user approval before touching the working tree. Requires the FluxGit desktop app to be running and connected (FLUXGIT_MCP_HANDSHAKE_ADDR); the call returns the preview outcome (approved, rejected or timed out). Without the app it returns error 10003 with instructions. Always include a clear `reason`: the user reads it in the approval dialog."
        }
        ToolKind::OperationPreviewPlan => {
            "Propose a SEQUENCE of operations (1-10 steps of merge/rebase/discard/reset/patch) as one reviewable plan with a single approval. FluxGit shows every step in the approval card; the user approves intent once and FluxGit executes the steps in order through its safety pipeline, stopping at the first failure. The completion result reports per-step status and captured restore points. Use this instead of chaining single proposals when the work is one logical change (e.g. rebase then merge). Requires the FluxGit desktop app to be running and connected (FLUXGIT_MCP_HANDSHAKE_ADDR); without it the call returns error 10003 with instructions. Always include a clear `reason`: the user reads it in the approval dialog."
        }
    }
}

fn tool_input_schema(kind: ToolKind) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    if kind == ToolKind::FleetRadar {
        properties.insert(
            "repoPaths".into(),
            json!({
                "type": "array",
                "items": { "type": "string" },
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
                        "repoPath": { "type": "string" },
                        "repoId": { "type": "string" },
                        "label": { "type": "string" }
                    },
                    "required": ["repoPath"]
                },
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
            "required": ["repoPaths"],
            "additionalProperties": true,
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
                    "items": { "type": "string" },
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
            properties.insert("limit".into(), json!({ "type": "integer", "minimum": 1 }));
            properties.insert("cursor".into(), json!({ "type": "string" }));
        }
        ToolKind::CommitDetails => {
            properties.insert("commit".into(), json!({ "type": "string" }));
            required.push("commit");
        }
        ToolKind::SubmoduleStatus => {
            properties.insert("path".into(), json!({ "type": "string" }));
        }
        ToolKind::DiffText | ToolKind::DiffSemantic | ToolKind::DiffSemanticFallbacks => {
            properties.insert("base".into(), json!({ "type": "string" }));
            properties.insert("head".into(), json!({ "type": "string" }));
            properties.insert("path".into(), json!({ "type": "string" }));
        }
        ToolKind::FluxLatestRestorePoint => {
            properties.insert("runDir".into(), json!({ "type": "string" }));
        }
        ToolKind::FluxRestorePoints => {
            properties.insert("runDir".into(), json!({ "type": "string" }));
            properties.insert("limit".into(), json!({ "type": "integer", "minimum": 1 }));
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
                    "enum": ["merge", "squash", "rebase"],
                    "default": "merge",
                    "description": "Requested merge strategy. The user may override in the FluxGit approval UI."
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
                    "default": false,
                    "description": "Whether to open an interactive rebase plan editor in FluxGit. The user always edits the plan in the UI."
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
                    "items": { "type": "string" },
                    "minItems": 1,
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
                            "sourceRef": { "type": "string" },
                            "targetRef": { "type": "string" },
                            "strategy": { "type": "string" },
                            "currentRef": { "type": "string" },
                            "ontoRef": { "type": "string" },
                            "interactive": { "type": "boolean" },
                            "paths": { "type": "array", "items": { "type": "string" } },
                            "mode": { "type": "string", "enum": ["soft", "mixed", "hard"] },
                            "patchContent": { "type": "string" },
                            "applyToIndex": { "type": "boolean" }
                        },
                        "required": ["operationType"]
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
    }

    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": true,
    })
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
        message: "Gateway transport is not wired yet".into(),
        data: Some(json!({
            "tool": tool,
            "gatewayConfigured": true,
            "reason": "The first sidecar milestone only exposes MCP discovery and structured failures."
        })),
    }
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
    let status_url = format!("{}/v1/mcp/operation/status/{}", base, preview_id);

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(_) => return None,
    };

    let post_response = match client.post(&dispatch_url).json(body).send() {
        Ok(response) => response,
        Err(_) => return None,
    };
    if !post_response.status().is_success() {
        return None;
    }

    // Poll status every 1 second for up to 60 seconds, returning the first terminal
    // outcome we see. `pending` keeps us polling; everything else stops.
    let poll_client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(_) => return None,
    };
    let max_polls = 60;
    let mut last_status: Option<Value> = None;
    let mut last_status_label = String::from("pending");
    for attempt in 0..max_polls {
        let response = match poll_client.get(&status_url).send() {
            Ok(response) => response,
            Err(_) => {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        if !response.status().is_success() {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let parsed: Value = match response.json() {
            Ok(value) => value,
            Err(_) => {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let status_label = parsed
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("pending")
            .to_string();
        last_status = Some(parsed.clone());
        last_status_label = status_label.clone();
        match status_label.as_str() {
            "completed" => {
                return Some(operation_preview_success_result(
                    tool_name, preview_id, &parsed,
                ));
            }
            "approved" | "rejected" | "failed" | "expired" => {
                return Some(operation_preview_terminal_error_result(
                    tool_name,
                    op_path_suffix,
                    preview_id,
                    &status_label,
                    &parsed,
                ));
            }
            _ => {
                // pending or unknown — keep polling unless this was the last attempt.
                if attempt + 1 < max_polls {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    // Polling timed out without a terminal status — fall back to write_handshake_pending
    // so the agent gets the existing, well-known error contract instead of an opaque
    // success. The caller turns `None` into the standard 10003 error.
    let _ = (last_status, last_status_label);
    None
}

/// Build the merge body and dispatch (PLAYBOOK §14.3).
fn dispatch_operation_preview_merge(
    gateway_addr: &str,
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
    let requested_at = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": "external-mcp-sidecar",
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
    let requested_at = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": "external-mcp-sidecar",
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
    let requested_at = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": "external-mcp-sidecar",
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
    let requested_at = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": "external-mcp-sidecar",
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
    let requested_at = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": "external-mcp-sidecar",
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
    let steps = arguments.get("steps").cloned().unwrap_or(Value::Array(vec![]));
    let requested_at = chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "previewId": preview_id,
        "agentId": "external-mcp-sidecar",
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
    ToolCallResult {
        content: vec![ToolCallContent {
            kind: "text",
            text: serde_json::to_string_pretty(&payload).unwrap_or_else(|err| {
                format!(
                    "{{\"error\":{{\"code\":\"internal_serialization_error\",\"message\":\"{}\"}}}}",
                    err
                )
            }),
        }],
        is_error: false,
    }
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
        "approved" => format!(
            "FluxGit approved the {op_label} but execution did not reach a completed state."
        ),
        _ => format!(
            "FluxGit returned a non-terminal status before completing the {op_label}."
        ),
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
    ToolCallResult {
        content: vec![ToolCallContent {
            kind: "text",
            text: serde_json::to_string_pretty(&payload).unwrap_or_else(|err| {
                format!(
                    "{{\"error\":{{\"code\":\"internal_serialization_error\",\"message\":\"{}\"}}}}",
                    err
                )
            }),
        }],
        is_error: true,
    }
}

/// Error returned for write-with-UI-handshake tools (PLAYBOOK §10) that are
/// advertised in `tools/list` but whose gateway dispatch is not yet implemented.
/// The agent should tell the user to perform the action inside FluxGit's UI.
fn write_handshake_pending_error(tool: &str) -> JsonRpcError {
    JsonRpcError {
        code: 10003,
        message: "FluxGit desktop is not connected for the write handshake".into(),
        data: Some(json!({
            "tool": tool,
            "tier": "fluxgit-write-handshake",
            "gatewayConfigured": false,
            "reason": "This tool proposes a write that FluxGit must preview and the user must approve in the desktop UI. The sidecar could not reach the FluxGit handshake endpoint: either the FluxGit app is not running, FLUXGIT_MCP_HANDSHAKE_ADDR is not set for this MCP server, or the request timed out before the user decided.",
            "agentRecommendation": "Tell the user: 'Open FluxGit and connect this agent from Operations > Agent Control (Quick Connect sets the handshake address), then I can propose this change for your approval.' Retry only after the user confirms FluxGit is running and connected.",
            "learnMore": "https://fluxgit.com/features/mcp-agent-git/"
        })),
    }
}

fn serialize_response(response: &JsonRpcResponse) -> Vec<u8> {
    serde_json::to_vec(response).unwrap_or_else(|err| {
        serde_json::to_vec(&JsonRpcResponse {
            jsonrpc: "2.0",
            id: Value::Null,
            result: None,
            error: Some(JsonRpcError {
                code: -32603,
                message: "Internal error".into(),
                data: Some(json!({ "details": err.to_string() })),
            }),
        })
        .unwrap_or_else(|_| b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}".to_vec())
    })
}

fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut first_line = String::new();
    loop {
        first_line.clear();
        let bytes_read = reader.read_line(&mut first_line)?;
        if bytes_read == 0 {
            return Ok(None);
        }
        if !first_line.trim().is_empty() {
            break;
        }
    }

    let first_trimmed = first_line.trim_end_matches(['\r', '\n']);
    if !first_trimmed.starts_with("Content-Length:") {
        return Ok(Some(first_trimmed.as_bytes().to_vec()));
    }

    let mut content_length = None;

    if let Some(value) = first_trimmed.strip_prefix("Content-Length:") {
        let parsed = value.trim().parse::<usize>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid content length: {err}"),
            )
        })?;
        content_length = Some(parsed);
    }

    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(None);
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }

        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            let parsed = value.trim().parse::<usize>().map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid content length: {err}"),
                )
            })?;
            content_length = Some(parsed);
        }
    }

    let content_length = content_length.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length header")
    })?;

    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    write!(writer, "Content-Length: {}\r\n\r\n", payload.len())?;
    writer.write_all(payload)?;
    writer.flush()
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

    struct GatewayEnvGuard {
        previous: Option<String>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl GatewayEnvGuard {
        fn set(value: &str) -> Self {
            let guard = GATEWAY_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = env::var("FLUXGIT_GATEWAY_ADDR").ok();
            env::set_var("FLUXGIT_GATEWAY_ADDR", value);
            Self { previous, _guard: guard }
        }

        fn unset() -> Self {
            let guard = GATEWAY_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = env::var("FLUXGIT_GATEWAY_ADDR").ok();
            env::remove_var("FLUXGIT_GATEWAY_ADDR");
            Self { previous, _guard: guard }
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
        env::temp_dir().join(format!(
            "{prefix}-{}-{nonce}-{sequence}",
            std::process::id()
        ))
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
            "Content-Length: 46\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}"
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
    fn tools_list_returns_read_only_whitelist() {
        let server = McpSidecar::new_for_tests(false);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }))
            .unwrap();
        let response = serde_json::to_value(response).unwrap();

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
                // Write-with-UI-handshake tools (PLAYBOOK §10) — advertised so agents
                // can discover the contract, but actually executed only via FluxGit UI
                // approval. All annotated readOnlyHint: false.
                "operation.preview.merge",
                "operation.preview.rebase",
                "operation.preview.discard",
                "operation.preview.reset",
                "operation.preview.patch",
                "operation.preview.plan",
            ]
        );

        // Verify all 5 write-handshake tools advertise readOnlyHint: false.
        for handshake_name in [
            "operation.preview.merge",
            "operation.preview.rebase",
            "operation.preview.discard",
            "operation.preview.reset",
            "operation.preview.patch",
        ] {
            let tool = tools
                .iter()
                .find(|t| t["name"].as_str() == Some(handshake_name))
                .unwrap_or_else(|| panic!("{handshake_name} must be advertised"));
            assert_eq!(
                tool["annotations"]["readOnlyHint"], false,
                "{handshake_name} must advertise readOnlyHint: false"
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
        // (operation.preview.*) honestly advertise readOnlyHint: false — they're
        // write proposals, even though the sidecar never performs the write itself.
        assert!(tools
            .iter()
            .filter(|tool| !tool["name"].as_str().unwrap_or_default().starts_with("operation.preview."))
            .all(|tool| tool["annotations"]["readOnlyHint"] == true));
        assert!(tools
            .iter()
            .filter(|tool| !tool["name"].as_str().unwrap_or_default().starts_with("operation.preview."))
            .filter(|tool| tool["name"] != "fleet.radar")
            .all(|tool| tool["inputSchema"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|item| item == "repoPath"))));
        let fleet_schema = tools
            .iter()
            .find(|tool| tool["name"] == "fleet.radar")
            .unwrap();
        assert!(fleet_schema["description"]
            .as_str()
            .unwrap()
            .contains("attention stack"));
        assert!(fleet_schema["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "repoPaths"));
        assert!(fleet_schema["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item != "repoPath"));
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
            payload["repoPath"].as_str(),
            Some(repo.path().to_string_lossy().as_ref())
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
        assert!(error["message"].as_str().unwrap().contains("whitelist"));
        assert_eq!(error["data"]["tool"], "repo.delete");
    }

    #[test]
    fn destructive_git_tools_are_not_exposed_or_invokable() {
        let server = McpSidecar::new_for_tests(false);
        let listed = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/list"
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
                "{blocked_tool} must not be advertised by the read-only MCP sidecar"
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
                .is_some_and(|message| message.contains("whitelist")));
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
            .is_some_and(|fingerprint| fingerprint.starts_with("fnv1a64:")));
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
        assert!(repo_scope.starts_with("repoPath:fnv1a64:"));
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
            .is_some_and(|fingerprint| fingerprint.starts_with("fnv1a64:")));
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
        assert!(data["head"]["sha"].as_str().is_some_and(|sha| !sha.is_empty()));
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
        assert!(commits[0]["sha"].as_str().is_some_and(|sha| !sha.is_empty()));
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

        let result = call_tool(
            "repo.brief",
            json!({ "repoPath": path }),
            false,
        );
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
        assert!(ratio > 0.5, "expected mostly conventional subjects, got {ratio}");
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
        assert!(commits[0]["subject"]
            .as_str()
            .unwrap()
            .contains("api"));

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

        let result = call_tool("repo.scope", json!({ "repoPath": path, "path": "api" }), false);
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
            git(path, &["commit", "-am", &format!("feat: change number {i}")]);
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
        assert!(worktrees[0]["headSha"].as_str().is_some_and(|sha| !sha.is_empty()));
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
        git(repo.path(), &["remote", "add", "origin", "https://example.invalid/repo.git"]);
        git(repo.path(), &["update-ref", "refs/remotes/origin/main", &base_commit]);
        git(repo.path(), &["branch", "--set-upstream-to=origin/main", "main"]);

        fs::write(repo.path().join("tracked.txt"), "local\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "local change"]);

        git(repo.path(), &["checkout", "-b", "remote-work", &base_commit]);
        fs::write(repo.path().join("tracked.txt"), "remote\n").unwrap();
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "remote change"]);
        let remote_commit = git_output(repo.path(), &["rev-parse", "HEAD"])
            .trim()
            .to_string();
        git(repo.path(), &["update-ref", "refs/remotes/origin/main", &remote_commit]);
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
    fn configured_gateway_without_repo_path_still_returns_structured_error() {
        let result = call_tool(
            "repo.status",
            json!({
                "repoId": "repo-without-local-path",
            }),
            true,
        );

        assert!(result.get("error").is_none());
        assert_eq!(result["result"]["isError"], true);
        let payload: Value =
            serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(payload["error"]["code"], 10002);
        assert_eq!(payload["error"]["data"]["gatewayConfigured"], true);
    }

    #[test]
    fn semantic_diff_reports_explicit_text_fallback() {
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
                "limit": 5,
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

    fn call_tool(name: &str, arguments: Value, gateway_configured: bool) -> Value {
        let server = McpSidecar::new_for_tests(gateway_configured);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                }
            }))
            .unwrap();
        serde_json::to_value(response).unwrap()
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
            let response = call_tool(
                tool,
                json!({ "repoPath": repo.path(), "eventId": "evt-0", "restorePointId": "rp-0" }),
                false,
            );
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
            let response =
                call_tool(tool, json!({ "repoPath": repo.path() }), false);
            assert_eq!(
                response["result"]["isError"], false,
                "tool {tool} should work without gateway"
            );
        }
    }

    #[test]
    fn diff_semantic_returns_fallback_payload_without_gateway() {
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
    // Write-with-UI-handshake protocol scaffolding (PLAYBOOK §10).
    // ---------------------------------------------------------------------

    #[test]
    fn operation_preview_merge_advertised_with_required_schema() {
        let server = McpSidecar::new_for_tests(true);
        let response = server
            .handle_value(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
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
    fn all_five_write_handshake_operations_return_pending_with_proper_schemas() {
        // Each operation must:
        // 1. Be advertised in tools/list with readOnlyHint: false
        // 2. Require its operation-specific fields plus a `reason`
        // 3. Return write_handshake_pending (code 10003) when no handshake
        //    address is configured (all five dispatch when it is).
        // Schema requirements per PLAYBOOK §10.
        let _env = GatewayEnvGuard::unset();
        let server = McpSidecar::new_for_tests(true);
        let list_response = server
            .handle_value(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
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
                    if let Some(value) = trimmed
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
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
                    let parsed: Value = serde_json::from_slice(&body_buf)
                        .unwrap_or(Value::Null);
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
                    let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
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
        assert_eq!(dispatched["previewId"], Value::String(preview_id.to_string()));
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(dispatched["repoPath"], "/tmp/example");
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
                "interactive": true
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
        assert_eq!(dispatched["previewId"], Value::String(preview_id.to_string()));
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "rebase",
            "rebase body must include operationType per §14.7"
        );
        assert_eq!(dispatched["repoPath"], "/tmp/example");
        assert_eq!(dispatched["currentRef"], "feature/topic");
        assert_eq!(dispatched["ontoRef"], "main");
        assert_eq!(dispatched["reason"], "Linearize history before merge");
        assert_eq!(dispatched["interactive"], true);
        assert!(
            dispatched["requestedAt"].is_string(),
            "requestedAt must be an ISO-8601 string"
        );
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
        assert_eq!(dispatched["previewId"], Value::String(preview_id.to_string()));
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "discard",
            "discard body must include operationType per §14.7"
        );
        assert_eq!(dispatched["repoPath"], "/tmp/example");
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
        assert_eq!(dispatched["previewId"], Value::String(preview_id.to_string()));
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "reset",
            "reset body must include operationType per §14.7"
        );
        assert_eq!(dispatched["repoPath"], "/tmp/example");
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
        assert_eq!(dispatched["previewId"], Value::String(preview_id.to_string()));
        assert_eq!(dispatched["agentId"], "external-mcp-sidecar");
        assert_eq!(
            dispatched["operationType"], "patch",
            "patch body must include operationType per §14.7"
        );
        assert_eq!(dispatched["repoPath"], "/tmp/example");
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
        let server = McpSidecar::new_for_tests_with_signed_audit(
            false,
            audit_log.clone(),
            signer.clone(),
        );

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
        let server = McpSidecar::new_for_tests_with_signed_audit(
            false,
            audit_log.clone(),
            signer,
        );

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

        assert_eq!(
            verify_audit_event_signature(&event, &public).unwrap(),
            false,
            "tampered event must fail signature verification (Ok(false))"
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
            other => panic!(
                "expected MissingSignature, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn audit_signature_fails_under_wrong_pubkey() {
        let signer = fixed_test_signer(17);
        let wrong_signer = fixed_test_signer(18);
        let wrong_public = wrong_signer.verifying_key();

        let audit_dir = TestDir::new("fluxgit-mcp-wrongkey-audit");
        let audit_log = audit_dir.path().join("mcp.jsonl");
        let server = McpSidecar::new_for_tests_with_signed_audit(
            false,
            audit_log.clone(),
            signer.clone(),
        );

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
        assert_eq!(
            verify_audit_event_signature(&event, &wrong_public).unwrap(),
            false,
            "verification under a different public key must return Ok(false)"
        );

        // Sanity: the original key still verifies.
        assert!(
            verify_audit_event_signature(&event, &signer.verifying_key()).unwrap()
        );
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
            s,
            r#"{"a":{"b":3,"y":2},"m":[{"a":2,"z":1},4],"z":1}"#,
            "canonical form must sort object keys lexicographically and preserve array order"
        );
    }
}
