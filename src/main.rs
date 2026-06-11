use std::path::PathBuf;
use std::process::ExitCode;

use fluxgit_mcp_sidecar::{
    parse_public_key_pem, verify_audit_event_signature, AuditVerificationError, McpSidecar,
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("verify-audit") => verify_audit_cli(args.collect::<Vec<_>>()),
        Some("--help" | "-h" | "help") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("fluxgit-mcp-sidecar: unknown subcommand '{other}'");
            print_help();
            ExitCode::from(2)
        }
        None => run_stdio(),
    }
}

fn print_help() {
    eprintln!(
        "fluxgit-mcp-sidecar — MCP server (stdio) and audit log verifier\n\
\n\
USAGE:\n  \
    fluxgit-mcp-sidecar                        Run the MCP server on stdin/stdout\n  \
    fluxgit-mcp-sidecar verify-audit <jsonl> --pubkey <pem>\n\
                                               Verify the signature of every entry in an audit JSONL file\n\
\n\
ENVIRONMENT:\n  \
    FLUXGIT_MCP_AUDIT_LOG       Path to the JSONL audit log (enables auditing)\n  \
    FLUXGIT_MCP_AUDIT_SIGN_KEY  Path to PEM PKCS8 Ed25519 private key for per-install signing\n\
"
    );
}

fn run_stdio() -> ExitCode {
    let server = McpSidecar::from_env();
    if let Err(err) = server.run_stdio() {
        eprintln!("fluxgit-mcp-sidecar: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// `fluxgit-mcp-sidecar verify-audit <path-to-jsonl> --pubkey <pem-path>`
///
/// Reports the number of entries verified, the number that failed, and the
/// line numbers of failures (1-indexed). Exit codes:
///   0  — every signed entry verified
///   3  — at least one entry failed verification
///   2  — usage error
fn verify_audit_cli(args: Vec<String>) -> ExitCode {
    let mut jsonl_path: Option<PathBuf> = None;
    let mut pubkey_path: Option<PathBuf> = None;
    let mut iter = args.into_iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--pubkey" => {
                pubkey_path = iter.next().map(PathBuf::from);
            }
            other if !other.starts_with('-') && jsonl_path.is_none() => {
                jsonl_path = Some(PathBuf::from(other));
            }
            other => {
                eprintln!("verify-audit: unexpected argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }
    let Some(jsonl_path) = jsonl_path else {
        eprintln!("verify-audit: missing <path-to-jsonl>");
        return ExitCode::from(2);
    };
    let Some(pubkey_path) = pubkey_path else {
        eprintln!("verify-audit: missing --pubkey <pem-path>");
        return ExitCode::from(2);
    };

    let pem = match std::fs::read_to_string(&pubkey_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("verify-audit: cannot read pubkey {}: {e}", pubkey_path.display());
            return ExitCode::from(2);
        }
    };
    let public_key = match parse_public_key_pem(&pem) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("verify-audit: invalid pubkey: {e}");
            return ExitCode::from(2);
        }
    };

    let contents = match std::fs::read_to_string(&jsonl_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("verify-audit: cannot read {}: {e}", jsonl_path.display());
            return ExitCode::from(2);
        }
    };

    let mut verified = 0usize;
    let mut failed = 0usize;
    let mut unsigned = 0usize;
    let mut malformed = 0usize;
    let mut failure_lines: Vec<usize> = Vec::new();

    for (idx, line) in contents.lines().enumerate() {
        let line_no = idx + 1;
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                malformed += 1;
                failure_lines.push(line_no);
                continue;
            }
        };
        match verify_audit_event_signature(&event, &public_key) {
            Ok(true) => verified += 1,
            Ok(false) => {
                failed += 1;
                failure_lines.push(line_no);
            }
            Err(AuditVerificationError::MissingSignature) => {
                unsigned += 1;
            }
            Err(_) => {
                malformed += 1;
                failure_lines.push(line_no);
            }
        }
    }

    println!("verified: {verified}");
    println!("failed:   {failed}");
    println!("unsigned: {unsigned}");
    println!("malformed: {malformed}");
    if !failure_lines.is_empty() {
        println!("failure_lines: {failure_lines:?}");
    }

    if failed > 0 || malformed > 0 {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}
