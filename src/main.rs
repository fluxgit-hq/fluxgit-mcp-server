use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use fluxgit_mcp_sidecar::{parse_public_key_pem, verify_audit_ledger, McpSidecar};

const AUDIT_MAX_PUBKEY_BYTES: u64 = 64 * 1024;

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
    fluxgit-mcp-sidecar verify-audit <jsonl> --pubkey <pem> [--require-signed]\n\
                                               Stream-verify the retained ledger chain, rotations and signatures\n\
\n\
ENVIRONMENT:\n  \
    FLUXGIT_RUN_DIR              Base for the default <run_dir>/audit/mcp.jsonl ledger\n  \
    FLUXGIT_MCP_AUDIT_LOG       Optional override for the shared audit ledger path\n  \
    FLUXGIT_MCP_AUDIT_DISABLED  Disable audit appends when explicitly present\n  \
    FLUXGIT_MCP_AUDIT_SIGN_KEY  PEM PKCS8 Ed25519 key; invalid explicit configuration fails closed\n  \
    FLUXGIT_MCP_PRESENCE_DISABLED  Do not write <run_dir>/presence/mcp/<pid>.json (client name/version,\n\
                                 repo path, last call time and tool name, read by the FluxGit desktop)\n\
"
    );
}

fn run_stdio() -> ExitCode {
    let server = match McpSidecar::from_env() {
        Ok(server) => server,
        Err(err) => {
            eprintln!("fluxgit-mcp-sidecar: audit configuration failed closed: {err}");
            return ExitCode::from(1);
        }
    };
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
    let mut require_signed = false;
    let mut iter = args.into_iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--pubkey" => {
                pubkey_path = iter.next().map(PathBuf::from);
            }
            "--require-signed" => require_signed = true,
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

    let pem = match read_bounded_utf8_file(&pubkey_path, AUDIT_MAX_PUBKEY_BYTES) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "verify-audit: cannot read pubkey {}: {e}",
                pubkey_path.display()
            );
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

    let report = match verify_audit_ledger(&jsonl_path, &public_key, require_signed) {
        Ok(report) => report,
        Err(error) => {
            // The error is deliberately metadata-only (segment/line/reason),
            // never the possibly sensitive event body.
            eprintln!("verify-audit: verification failed: {error}");
            return ExitCode::from(3);
        }
    };

    println!("entries:   {}", report.entries);
    println!("chained:   {}", report.chained);
    println!("legacy:    {}", report.legacy);
    println!("signed:    {}", report.signed);
    println!("unsigned:  {}", report.unsigned);
    println!("segments:  {}", report.segments);
    println!(
        "sequence:  {}..{}",
        report.first_sequence.unwrap_or_default(),
        report.last_sequence.unwrap_or_default()
    );
    println!(
        "retention_checkpoint_used: {}",
        report.retention_checkpoint_used
    );
    ExitCode::SUCCESS
}

fn read_bounded_utf8_file(path: &PathBuf, max_bytes: u64) -> io::Result<String> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(8192) as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {max_bytes}-byte safety limit"),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}
