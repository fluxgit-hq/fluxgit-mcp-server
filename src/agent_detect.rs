//! Which coding agents are working in which of the repositories FluxGit is
//! showing. Everything is read locally and nothing leaves the machine.
//!
//! Each finding says where it came from, because the sources differ in
//! certainty:
//! - `process`: a running agent process, or a process it started, has its
//!   working directory inside the repository. Covers any CLI agent.
//! - `session`: the agent's own session store was written recently and names
//!   the repository. For Claude Code, Codex and Qwen Code it also says the
//!   branch, the last tool and which files it touched. For VS Code, Cursor
//!   and Windsurf it means the editor's agent chat (`chatSessions/`) was
//!   written, not just that the folder is open.
//! - `repo-trace`: a file the agent keeps inside the repository changed
//!   recently (aider's chat history, Crush's `.crush/crush.db`).
//! - `ide`: an editor with a built-in agent (Cursor, Windsurf, VS Code) has
//!   the folder open and in use; that is presence, not proof of agent edits.
//! - `mcp`: the agent is connected to FluxGit's own MCP server and called a
//!   tool on this repository. Confirmed by FluxGit itself, not inferred; the
//!   agent name is the client's self-declared MCP `clientInfo`.
//!
//! Which formats were seen on a real machine and which come only from each
//! tool's source or documentation (see
//! `product/AGENT_DETECTION_SOURCES_2026-09-27.md`):
//! - Observed: Claude Code (`~/.claude/projects`), Codex (`~/.codex/sessions`).
//! - From source code: Gemini CLI (`.gemini/tmp/<slug>/.project_root`),
//!   opencode and Kilo (SQLite `session`), Goose (SQLite `sessions`, older
//!   JSONL), Cline (SQLite `sessions`), Zed (SQLite `threads`), Qwen Code
//!   (JSONL), Crush (`.crush/crush.db` in the repository), Continue
//!   (`sessions/*.json`), VS Code-family `workspace.json` and
//!   `chatSessions/`, aider.
//! - From documentation or third-party parsers only: Copilot CLI
//!   (`session-state/*/workspace.yaml`), Amp (`threads/T-*.json`), Cursor CLI
//!   (`chats/*/*/meta.json`).
//!
//! SQLite stores are opened read-only (URI `mode=ro`), never written or
//! created, and only when the file or its `-wal` changed in the last fifteen
//! minutes. Anything that does not match the expected shape is skipped,
//! never guessed.
//!
//! Only repository-relative file paths, tool names and times are returned,
//! never prompts, messages or file contents.
//!
//! This file is shared. It is the `fluxgit-agent-presence` crate, which the
//! desktop (`app/ui/src-tauri`, Tauri command wrapper only) depends on, and
//! the MCP sidecar compiles the same file as a module
//! (`app/core/mcp-sidecar/src/agent_detect.rs`) so the sidecar also builds
//! standalone in its public mirror, where the sync recipe copies this file
//! in place of that shim (`product/mcp/DISTRIBUTION.md`). Keep it one
//! self-contained file: no `mod foo;` children, no `crate::` paths, no
//! dependencies beyond serde, serde_json, sysinfo, rusqlite, dirs, sha2 and
//! chrono, and nothing newer than Rust 1.88.
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RECENT: Duration = Duration::from_secs(15 * 60);
const WORKING: Duration = Duration::from_secs(120);
const TAIL_BYTES: u64 = 256 * 1024;
const MAX_FILES: usize = 8;
const MAX_ROOTS: usize = 600;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentPresence {
    /// Stable id: claude-code, codex, opencode, gemini-cli, aider,
    /// cursor-agent, amp, goose, copilot-cli, qwen-code, crush, kilo, cline,
    /// continue; and for editors with built-in agents: cursor, windsurf,
    /// vscode, zed. MCP clients FluxGit does not know keep their own
    /// sanitized name.
    pub agent: &'static str,
    /// The repository root, exactly as the caller passed it.
    pub root: String,
    /// `working`: activity in the last two minutes or a command running now;
    /// `open`: the agent is running here but quiet; `recent`: its session
    /// touched this repository in the last fifteen minutes.
    pub state: &'static str,
    pub sources: Vec<&'static str>,
    pub pid: Option<u32>,
    pub last_activity_ms: Option<i64>,
    pub branch: Option<String>,
    pub last_tool: Option<String>,
    /// Repository-relative paths the agent wrote most recently.
    pub files: Vec<String>,
    /// Name and version the agent declared to FluxGit's MCP server, when
    /// the `mcp` source found it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_client: Option<McpClient>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpClient {
    pub name: String,
    pub version: Option<String>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

fn mtime_ms(path: &Path) -> Option<i64> {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis() as i64)
}

/// Canonical roots paired with what the caller passed, longest first so a
/// submodule or nested worktree wins over its parent.
struct Roots(Vec<(PathBuf, String)>);

impl Roots {
    fn new(roots: &[String]) -> Self {
        let mut resolved: Vec<(PathBuf, String)> = roots
            .iter()
            .take(MAX_ROOTS)
            .filter(|root| Path::new(root).is_absolute())
            .filter_map(|root| Some((Path::new(root).canonicalize().ok()?, root.clone())))
            .collect();
        resolved.sort_by(|a, b| b.0.as_os_str().len().cmp(&a.0.as_os_str().len()));
        Roots(resolved)
    }

    fn containing(&self, path: &Path) -> Option<(&Path, &str)> {
        // A relative path would resolve against FluxGit's own working
        // directory, which says nothing about where the agent works.
        if !path.is_absolute() {
            return None;
        }
        let path = resolve(path);
        self.0
            .iter()
            .find(|(root, _)| path.starts_with(root))
            .map(|(root, original)| (root.as_path(), original.as_str()))
    }
}

/// Canonical form of a path that may not exist any more (a deleted file):
/// the nearest existing ancestor is resolved and the rest re-appended, so
/// symlinked prefixes such as macOS `/var` -> `/private/var` still match.
fn resolve(path: &Path) -> PathBuf {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        if let Ok(resolved) = current.canonicalize() {
            return missing
                .iter()
                .rev()
                .fold(resolved, |acc, part| acc.join(part));
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name.to_owned());
                current = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Lowercase program name without directories or a Windows `.exe`, whatever
/// the separator: `C:\\Tools\\Codex.EXE` and `/usr/bin/codex` are both `codex`.
fn program_name(name: &str) -> String {
    let name = name.replace('\\', "/").to_ascii_lowercase();
    let base = name.rsplit('/').next().unwrap_or(&name);
    base.strip_suffix(".exe").unwrap_or(base).to_owned()
}

/// Lowercase command line with `/` separators and no `.exe` on its words, so
/// Windows command lines match the same patterns as Unix ones.
fn normalize_cmd(cmd: &str) -> String {
    cmd.replace('\\', "/")
        .to_ascii_lowercase()
        .split(' ')
        .map(|word| word.strip_suffix(".exe").unwrap_or(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Programs that start another program named by their first arguments.
const LAUNCHERS: [&str; 14] = [
    "node", "npx", "npm", "pnpm", "bunx", "bun", "deno", "uvx", "uv", "pipx", "python", "python3",
    "docker", "sh",
];

/// A long-lived stdio MCP server (FluxGit's own sidecar included), which
/// agents keep as a child for the whole session in the project directory.
/// Its presence says the agent is here, not that it is doing something.
fn looks_like_mcp_server(name: &str, cmd: &str) -> bool {
    let cmd = normalize_cmd(cmd);
    let mut candidates = vec![program_name(name)];
    let mut words = cmd.split_whitespace();
    if let Some(arg0) = words.next() {
        let program = program_name(arg0);
        let launcher = LAUNCHERS.contains(&program.as_str());
        candidates.push(program);
        if launcher {
            // `npx -y @scope/some-mcp`, `uvx mcp-server-git`, `uv tool run x`,
            // `node /path/to/server-mcp/index.js`: the first few non-flag
            // words name what actually runs.
            candidates.extend(
                words
                    .filter(|word| !word.starts_with('-'))
                    .filter(|word| !matches!(*word, "run" | "exec" | "x" | "dlx" | "tool" | "-c"))
                    .take(2)
                    .map(|word| word.to_owned()),
            );
        }
    }
    candidates.iter().any(|candidate| {
        candidate.contains("modelcontextprotocol")
            || candidate
                .split(|character: char| !character.is_ascii_alphanumeric())
                .any(|token| token == "mcp")
    })
}

/// Recognises an agent from a process name and its command line.
fn classify_process(name: &str, cmd: &str) -> Option<&'static str> {
    let name = program_name(name);
    let cmd = normalize_cmd(cmd);
    let arg0 = cmd.split_whitespace().next().unwrap_or("");
    let bin = |candidate: &str| {
        name == candidate
            || arg0.ends_with(&format!("/{candidate}"))
            || cmd.contains(&format!("/bin/{candidate} "))
            || cmd.ends_with(&format!("/bin/{candidate}"))
    };
    if bin("claude") || cmd.contains("@anthropic-ai/claude-code") {
        Some("claude-code")
    } else if bin("codex") || cmd.contains("@openai/codex") {
        // The Codex app-server and its daemon run from `/`; the processes
        // that do the work (sandbox, exec, the interactive CLI) run in the
        // repository. The directory check decides, not the name.
        Some("codex")
    } else if bin("opencode") || cmd.contains("opencode-ai") {
        Some("opencode")
    } else if bin("gemini") || cmd.contains("@google/gemini-cli") {
        Some("gemini-cli")
    } else if bin("aider") || cmd.contains("aider-chat") || cmd.contains("/aider ") {
        Some("aider")
    } else if bin("cursor-agent") || cmd.contains("/cursor-agent/versions/") {
        // The installed Cursor CLI binary is called just `agent`; only its
        // install path identifies it, never the bare word.
        Some("cursor-agent")
    } else if bin("kilo") || bin("kilocode") || cmd.contains("@kilocode/cli") {
        Some("kilo")
    } else if cmd.contains("@continuedev/cli") {
        // Continue's CLI is `cn`, too short to trust as a name: only its
        // package path counts.
        Some("continue")
    } else if bin("cline") || cmd.contains("/node_modules/cline/") {
        Some("cline")
    } else if bin("amp") || cmd.contains("@sourcegraph/amp") {
        Some("amp")
    } else if bin("goose") {
        Some("goose")
    } else if bin("copilot") || cmd.contains("@github/copilot") {
        Some("copilot-cli")
    } else if bin("qwen") || cmd.contains("@qwen-code/qwen-code") {
        Some("qwen-code")
    } else if bin("crush") {
        Some("crush")
    } else {
        None
    }
}

#[derive(Default)]
struct Finding {
    sources: Vec<&'static str>,
    pid: Option<u32>,
    busy: bool,
    last_activity_ms: Option<i64>,
    branch: Option<String>,
    last_tool: Option<String>,
    files: Vec<String>,
    idle: bool,
    mcp_client: Option<McpClient>,
}

type Findings = BTreeMap<(&'static str, String), Finding>;

fn note<'a>(
    findings: &'a mut Findings,
    agent: &'static str,
    root: &str,
    source: &'static str,
) -> &'a mut Finding {
    let finding = findings.entry((agent, root.to_owned())).or_default();
    if !finding.sources.contains(&source) {
        finding.sources.push(source);
    }
    finding
}

fn relative(root: &Path, file: &str) -> Option<String> {
    if !Path::new(file).is_absolute() {
        return None;
    }
    let path = resolve(Path::new(file));
    path.strip_prefix(root)
        .ok()
        .map(|rest| rest.to_string_lossy().replace('\\', "/"))
        .filter(|rest| !rest.is_empty())
}

fn push_file(files: &mut Vec<String>, file: String) {
    if !files.contains(&file) && files.len() < MAX_FILES {
        files.push(file);
    }
}

// ---------------------------------------------------------------- processes

struct Proc {
    parent: Option<u32>,
    agent: Option<&'static str>,
    cwd: Option<PathBuf>,
    /// An MCP server or similar session-long helper: never counts as work.
    long_lived: bool,
    /// When the process started, if the OS said.
    started_ms: Option<i64>,
}

/// A child process counts as the agent working only if it started this
/// recently: a dev server or watcher the agent left running is not work.
const BUSY_CHILD_MAX_AGE: Duration = Duration::from_secs(10 * 60);

fn scan_processes(roots: &Roots, findings: &mut Findings) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cwd(UpdateKind::Always)
            .with_cmd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    let procs: HashMap<u32, Proc> = system
        .processes()
        .iter()
        .map(|(pid, process)| {
            let cmd = process
                .cmd()
                .iter()
                .map(|part| part.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let name = process.name().to_string_lossy();
            (
                pid.as_u32(),
                Proc {
                    parent: process.parent().map(|parent| parent.as_u32()),
                    agent: classify_process(&name, &cmd),
                    cwd: process.cwd().map(Path::to_path_buf),
                    long_lived: looks_like_mcp_server(&name, &cmd),
                    started_ms: Some(process.start_time())
                        .filter(|seconds| *seconds > 0)
                        .and_then(|seconds| i64::try_from(seconds).ok())
                        .map(|seconds| seconds.saturating_mul(1000)),
                },
            )
        })
        .collect();
    attribute_processes(&procs, roots, now_ms(), findings);
}

/// A process belongs to the nearest agent among itself and its ancestors, so
/// a shell or build an agent started is counted as that agent working. Only
/// recent, short-lived children count as work: MCP servers the agent keeps
/// for the whole session, and anything started long ago (a dev server, a
/// watcher), only show that the agent is here.
fn attribute_processes(
    procs: &HashMap<u32, Proc>,
    roots: &Roots,
    now: i64,
    findings: &mut Findings,
) {
    for (pid, process) in procs {
        let Some(cwd) = process.cwd.as_deref() else {
            continue;
        };
        let Some((_, root)) = roots.containing(cwd) else {
            continue;
        };
        let mut current = Some(*pid);
        let mut depth = 0;
        let mut owner = None;
        while let Some(id) = current {
            let Some(entry) = procs.get(&id) else { break };
            if let Some(agent) = entry.agent {
                owner = Some((agent, id));
                break;
            }
            depth += 1;
            if depth > 16 {
                break;
            }
            current = entry.parent.filter(|parent| *parent != id);
        }
        let Some((agent, agent_pid)) = owner else {
            continue;
        };
        let root = root.to_owned();
        let finding = note(findings, agent, &root, "process");
        if agent_pid == *pid {
            finding.pid = Some(agent_pid);
        } else {
            let recent = process
                .started_ms
                .is_some_and(|started| now - started <= BUSY_CHILD_MAX_AGE.as_millis() as i64);
            if recent && !process.long_lived {
                // A child doing work right now: a command, test or build.
                finding.busy = true;
            }
            finding.pid.get_or_insert(agent_pid);
        }
    }
}

// ------------------------------------------------------------ session logs

fn read_tail(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    // Drop a partial first line when reading from the middle.
    Some(if start > 0 {
        text.split_once('\n')
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default()
    } else {
        text
    })
}

fn parse_time(value: &Value) -> Option<i64> {
    let text = value.as_str()?;
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|time| time.timestamp_millis())
}

fn recent_files(dir: &Path, extension: &str, cutoff_ms: i64, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() && depth > 0 {
            recent_files(&path, extension, cutoff_ms, depth - 1, out);
        } else if kind.is_file()
            && path.extension().and_then(|ext| ext.to_str()) == Some(extension)
            && mtime_ms(&path).is_some_and(|time| time >= cutoff_ms)
        {
            out.push(path);
        }
    }
}

/// Claude Code writes one JSON line per event with `cwd`, `gitBranch` and
/// `timestamp`; assistant lines carry `tool_use` blocks whose inputs name
/// the files it edits.
fn read_claude_session(text: &str, roots: &Roots, findings: &mut Findings) {
    read_claude_style_session("claude-code", text, roots, findings);
}

/// Tool calls in one session event: Claude's `tool_use` content blocks, or
/// the Gemini-style `functionCall` parts Qwen Code writes. Newest last.
fn tool_calls(event: &Value) -> Vec<(&Value, &Value)> {
    let message = &event["message"];
    let mut calls = Vec::new();
    if let Some(blocks) = message["content"].as_array() {
        calls.extend(
            blocks
                .iter()
                .filter(|block| block["type"] == "tool_use")
                .map(|block| (&block["name"], &block["input"])),
        );
    }
    if let Some(parts) = message["parts"].as_array() {
        calls.extend(
            parts
                .iter()
                .map(|part| &part["functionCall"])
                .filter(|call| call.is_object())
                .map(|call| (&call["name"], &call["args"])),
        );
    }
    calls
}

/// Claude Code and Qwen Code share this JSONL shape.
fn read_claude_style_session(
    agent: &'static str,
    text: &str,
    roots: &Roots,
    findings: &mut Findings,
) {
    let mut root_seen: Option<(PathBuf, String)> = None;
    let mut last_time = None;
    let mut branch = None;
    let mut last_tool = None;
    let mut files: Vec<String> = Vec::new();
    for line in text.lines().rev() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if root_seen.is_none() {
            let Some(cwd) = event["cwd"].as_str() else {
                continue;
            };
            let Some((root, original)) = roots.containing(Path::new(cwd)) else {
                return;
            };
            root_seen = Some((root.to_path_buf(), original.to_owned()));
        }
        let (root, _) = root_seen.as_ref().expect("set above");
        if last_time.is_none() {
            last_time = parse_time(&event["timestamp"]);
        }
        if branch.is_none() {
            branch = event["gitBranch"]
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
        }
        for (name, input) in tool_calls(&event).into_iter().rev() {
            if last_tool.is_none() {
                last_tool = name.as_str().map(str::to_owned);
            }
            for key in ["file_path", "notebook_path", "absolute_path"] {
                if let Some(file) = input[key].as_str().and_then(|file| relative(root, file)) {
                    push_file(&mut files, file);
                }
            }
        }
        if files.len() >= MAX_FILES && last_tool.is_some() && branch.is_some() {
            break;
        }
    }
    let Some((_, original)) = root_seen else {
        return;
    };
    let finding = note(findings, agent, &original, "session");
    finding.last_activity_ms = finding.last_activity_ms.max(last_time);
    finding.branch = finding.branch.take().or(branch);
    finding.last_tool = finding.last_tool.take().or(last_tool);
    for file in files {
        push_file(&mut finding.files, file);
    }
}

/// Codex writes `session_meta` (with `cwd`) first, then timestamped events;
/// `task_complete` ends a turn, and `apply_patch` names the files it edits.
fn read_codex_session(head: &str, tail: &str, roots: &Roots, findings: &mut Findings) {
    let Some(meta) = head.lines().find_map(|line| {
        let event = serde_json::from_str::<Value>(line).ok()?;
        (event["type"] == "session_meta").then_some(event)
    }) else {
        return;
    };
    let Some(cwd) = meta["payload"]["cwd"].as_str() else {
        return;
    };
    let Some((root, original)) = roots.containing(Path::new(cwd)) else {
        return;
    };
    let root = root.to_path_buf();
    let original = original.to_owned();
    let mut last_time = None;
    let mut last_tool = None;
    let mut idle = None;
    let mut files = Vec::new();
    for line in tail.lines().rev() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if last_time.is_none() {
            last_time = parse_time(&event["timestamp"]);
        }
        let payload = &event["payload"];
        if idle.is_none() {
            match payload["type"].as_str() {
                Some("task_complete") => idle = Some(true),
                Some(
                    "task_started" | "function_call" | "custom_tool_call" | "exec_command_begin",
                ) => idle = Some(false),
                _ => {}
            }
        }
        if matches!(
            payload["type"].as_str(),
            Some("function_call" | "custom_tool_call")
        ) {
            if last_tool.is_none() {
                last_tool = payload["name"].as_str().map(str::to_owned);
            }
            let arguments = payload["input"]
                .as_str()
                .or_else(|| payload["arguments"].as_str())
                .unwrap_or("");
            for patch_line in arguments.lines() {
                let file = patch_line
                    .strip_prefix("*** Update File: ")
                    .or_else(|| patch_line.strip_prefix("*** Add File: "))
                    .or_else(|| patch_line.strip_prefix("*** Delete File: "));
                if let Some(file) = file {
                    let absolute = if Path::new(file).is_absolute() {
                        PathBuf::from(file)
                    } else {
                        Path::new(cwd).join(file)
                    };
                    if let Some(file) = relative(&root, &absolute.to_string_lossy()) {
                        push_file(&mut files, file);
                    }
                }
            }
        }
    }
    let finding = note(findings, "codex", &original, "session");
    finding.last_activity_ms = finding.last_activity_ms.max(last_time);
    finding.last_tool = finding.last_tool.take().or(last_tool);
    finding.idle = idle.unwrap_or(false);
    for file in files {
        push_file(&mut finding.files, file);
    }
}

fn claude_home() -> Option<PathBuf> {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".claude")))
}

fn codex_home() -> Option<PathBuf> {
    std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".codex")))
}

fn scan_sessions(
    claude: Option<&Path>,
    codex: Option<&Path>,
    roots: &Roots,
    findings: &mut Findings,
) {
    let cutoff = now_ms() - RECENT.as_millis() as i64;
    if let Some(projects) = claude.map(|home| home.join("projects")) {
        let mut files = Vec::new();
        recent_files(&projects, "jsonl", cutoff, 1, &mut files);
        for file in files {
            if let Some(text) = read_tail(&file) {
                read_claude_session(&text, roots, findings);
            }
        }
    }
    if let Some(sessions) = codex.map(|home| home.join("sessions")) {
        let mut files = Vec::new();
        recent_files(&sessions, "jsonl", cutoff, 3, &mut files);
        for file in files {
            let head = File::open(&file).ok().and_then(|handle| {
                let mut bytes = Vec::new();
                // session_meta can carry long base instructions.
                handle.take(512 * 1024).read_to_end(&mut bytes).ok()?;
                Some(String::from_utf8_lossy(&bytes).into_owned())
            });
            if let (Some(head), Some(tail)) = (head, read_tail(&file)) {
                read_codex_session(&head, &tail, roots, findings);
            }
        }
    }
}

// ----------------------------------------- documented, not observed here
//
// The formats below come from each tool's documentation and source, not from
// a machine where they were observed. They are read defensively: anything
// unexpected is skipped, never guessed.

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn newest_mtime(dir: &Path, depth: usize) -> Option<i64> {
    let mut newest = mtime_ms(dir);
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let time = if kind.is_dir() && depth > 0 {
                newest_mtime(&entry.path(), depth - 1)
            } else if kind.is_file() {
                mtime_ms(&entry.path())
            } else {
                None
            };
            newest = newest.max(time);
        }
    }
    newest
}

const MAX_DIR_ENTRIES: usize = 4096;
const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SMALL_BYTES: u64 = 64 * 1024;
/// Timestamps further ahead than this are a broken clock, not activity.
const FUTURE_SLACK_MS: i64 = 60_000;

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn cutoff_ms() -> i64 {
    now_ms() - RECENT.as_millis() as i64
}

/// A whole file up to `max` bytes; larger files are skipped, not truncated.
fn read_capped(path: &Path, max: u64) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > max {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn read_json(path: &Path, max: u64) -> Option<Value> {
    serde_json::from_str(&read_capped(path, max)?).ok()
}

/// Real subdirectories of `dir` (symlinks skipped), bounded.
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(MAX_DIR_ENTRIES)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect()
}

/// Newest mtime among the files directly in `dir` with one of `extensions`.
fn newest_file_with(dir: &Path, extensions: &[&str]) -> Option<i64> {
    let entries = fs::read_dir(dir).ok()?;
    entries
        .flatten()
        .take(MAX_DIR_ENTRIES)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| extensions.contains(&ext))
        })
        .filter_map(|path| mtime_ms(&path))
        .max()
}

/// A folder as an agent records it: a `file://` URI or an absolute path.
/// Remote URIs (`vscode-remote://`, `ssh://`) are not local folders.
fn folder_from(text: &str) -> Option<PathBuf> {
    let path = if text.contains("://") {
        file_uri_to_path(text)?
    } else {
        PathBuf::from(text)
    };
    path.is_absolute().then_some(path)
}

// ------------------------------------------------------------- Gemini CLI

/// Gemini CLI's state folders. `GEMINI_CLI_HOME` replaces the home
/// directory, so the folder is `$GEMINI_CLI_HOME/.gemini`; inside its
/// sandbox Gemini writes to `~/.cache/.gemini` instead.
fn gemini_dirs(home: &Path, cli_home: Option<PathBuf>) -> Vec<PathBuf> {
    let base = cli_home.unwrap_or_else(|| home.to_path_buf());
    let mut dirs = vec![base.join(".gemini"), home.join(".cache").join(".gemini")];
    dirs.dedup();
    dirs
}

/// `projects.json` maps project paths to their slug:
/// `{ "projects": { "/abs/path": "slug" } }`. Returned as slug -> path.
fn gemini_registry(gemini: &Path) -> HashMap<String, PathBuf> {
    let Some(document) = read_json(&gemini.join("projects.json"), 1024 * 1024) else {
        return HashMap::new();
    };
    let Some(projects) = document["projects"]
        .as_object()
        .or_else(|| document.as_object())
    else {
        return HashMap::new();
    };
    projects
        .iter()
        .filter_map(|(path, slug)| {
            let path = PathBuf::from(path);
            Some((slug.as_str()?.to_owned(), path.clone())).filter(|_| path.is_absolute())
        })
        .collect()
}

/// Gemini CLI keeps per-project state in `<gemini>/tmp/<slug>/`. Since
/// 2026-02-06 the slug is the folder name (`-N` on a clash), `.project_root`
/// holds the project path and `projects.json` maps paths to slugs; activity
/// is the newest `chats/*.jsonl`. Older versions named the folder after the
/// SHA-256 of the root, which is still read, but only as a fallback.
fn scan_gemini(gemini: &Path, roots: &Roots, findings: &mut Findings) {
    let cutoff = cutoff_ms();
    let tmp = gemini.join("tmp");
    let registry = gemini_registry(gemini);
    let mut found = Vec::new();
    for dir in subdirs(&tmp) {
        let Some(time) =
            newest_file_with(&dir.join("chats"), &["jsonl"]).filter(|time| *time >= cutoff)
        else {
            continue;
        };
        let project = read_capped(&dir.join(".project_root"), 4096)
            .map(|text| PathBuf::from(text.trim_end_matches(['\n', '\r'])))
            .filter(|path| path.is_absolute())
            .or_else(|| {
                let slug = dir.file_name()?.to_str()?;
                registry.get(slug).cloned()
            });
        let Some((_, original)) = project.and_then(|path| {
            roots
                .containing(&path)
                .map(|(root, original)| (root.to_path_buf(), original.to_owned()))
        }) else {
            continue;
        };
        let finding = note(findings, "gemini-cli", &original, "session");
        finding.last_activity_ms = finding.last_activity_ms.max(Some(time));
        found.push(original);
    }
    for (root, original) in &roots.0 {
        if found.contains(original) {
            continue;
        }
        let candidates = [sha256_hex(&root.to_string_lossy()), sha256_hex(original)];
        let newest = candidates
            .iter()
            .filter_map(|hash| newest_mtime(&tmp.join(hash), 2))
            .max();
        if let Some(time) = newest.filter(|time| *time >= cutoff) {
            let finding = note(findings, "gemini-cli", original, "session");
            finding.last_activity_ms = finding.last_activity_ms.max(Some(time));
        }
    }
}

// ------------------------------------------------------ older JSON stores

/// opencode before its SQLite store kept one JSON document per session
/// under `<data>/opencode/storage/session/`, with the working `directory`
/// and `time.updated` in milliseconds.
fn scan_opencode(data: &Path, roots: &Roots, findings: &mut Findings) {
    let cutoff = cutoff_ms();
    let mut files = Vec::new();
    recent_files(
        &data.join("storage").join("session"),
        "json",
        cutoff,
        2,
        &mut files,
    );
    for file in files {
        let Some(session) = read_json(&file, MAX_JSON_BYTES) else {
            continue;
        };
        let Some(directory) = session["directory"].as_str() else {
            continue;
        };
        let Some((_, original)) = roots.containing(Path::new(directory)) else {
            continue;
        };
        let time = session["time"]["updated"]
            .as_i64()
            .or_else(|| mtime_ms(&file));
        let original = original.to_owned();
        let finding = note(findings, "opencode", &original, "session");
        finding.last_activity_ms = finding.last_activity_ms.max(time);
    }
}

/// Goose before 1.10 (JSONL sessions) starts each session file with a
/// metadata line that carries `working_dir`.
fn scan_goose(data: &Path, roots: &Roots, findings: &mut Findings) {
    let cutoff = cutoff_ms();
    let mut files = Vec::new();
    recent_files(&data.join("sessions"), "jsonl", cutoff, 0, &mut files);
    for file in files {
        let Some(first) = File::open(&file).ok().and_then(|handle| {
            let mut bytes = Vec::new();
            handle.take(MAX_SMALL_BYTES).read_to_end(&mut bytes).ok()?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            text.lines().next().map(str::to_owned)
        }) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<Value>(&first) else {
            continue;
        };
        let Some(directory) = meta["working_dir"].as_str() else {
            continue;
        };
        let Some((_, original)) = roots.containing(Path::new(directory)) else {
            continue;
        };
        let original = original.to_owned();
        let finding = note(findings, "goose", &original, "session");
        finding.last_activity_ms = finding.last_activity_ms.max(mtime_ms(&file));
    }
}

// ----------------------------------------------------------------- SQLite
//
// opencode, Kilo, Goose (1.10+), Cline and Zed keep sessions in SQLite, most
// in WAL mode. A database is opened only when the file or its `-wal` changed
// in the last fifteen minutes, always through a `mode=ro` URI, and nothing
// is ever written or created: a WAL database without a `-wal` has no writer
// attached and is read as `immutable=1` (no locks, no `-shm`); one with a
// `-wal` but no `-shm` is skipped rather than letting SQLite create it.
// Locked databases wait at most a short busy timeout, and a table without
// the expected columns is skipped.

type SqlValue = rusqlite::types::Value;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const SQLITE_MAX_ROWS: usize = 256;

/// Where one agent's SQLite store says which folder a session works in.
struct SqlSessions {
    agent: &'static str,
    table: &'static str,
    /// Required. Each value may hold several paths, one per line (Zed).
    folders: &'static [&'static str],
    /// Required. Milliseconds, seconds or a date string.
    time: &'static str,
    /// Optional: rows with it set are archived and skipped.
    archived: Option<&'static str>,
    /// Optional: rows with it set are finished sessions.
    ended: Option<&'static str>,
    /// Optional: the process serving the session; alive means open.
    pid: Option<&'static str>,
}

const OPENCODE_DB: SqlSessions = SqlSessions {
    agent: "opencode",
    table: "session",
    folders: &["directory"],
    time: "time_updated",
    archived: Some("time_archived"),
    ended: None,
    pid: None,
};

const KILO_DB: SqlSessions = SqlSessions {
    agent: "kilo",
    ..OPENCODE_DB
};

const GOOSE_DB: SqlSessions = SqlSessions {
    agent: "goose",
    table: "sessions",
    folders: &["working_dir"],
    time: "updated_at",
    archived: None,
    ended: None,
    pid: None,
};

const CLINE_DB: SqlSessions = SqlSessions {
    agent: "cline",
    table: "sessions",
    folders: &["cwd", "workspace_root"],
    time: "updated_at",
    archived: None,
    ended: Some("ended_at"),
    pid: Some("pid"),
};

const ZED_DB: SqlSessions = SqlSessions {
    agent: "zed",
    table: "threads",
    folders: &["folder_paths"],
    time: "updated_at",
    archived: None,
    ended: None,
    pid: None,
};

fn sqlite_sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The cheap check before opening anything: the newest of the database
/// file and its `-wal`.
fn sqlite_touched_ms(db: &Path) -> Option<i64> {
    mtime_ms(db).max(mtime_ms(&sqlite_sidecar(db, "-wal")))
}

/// `file:` URI for SQLite, with the characters URIs reserve escaped and
/// Windows drive paths as `/C:/...`.
fn sqlite_uri(db: &Path, immutable: bool) -> String {
    let text = db.to_string_lossy().replace('\\', "/");
    let mut uri = String::from("file:");
    if !text.starts_with('/') {
        uri.push('/');
    }
    for character in text.chars() {
        match character {
            '%' => uri.push_str("%25"),
            '?' => uri.push_str("%3f"),
            '#' => uri.push_str("%23"),
            _ => uri.push(character),
        }
    }
    uri.push_str("?mode=ro");
    if immutable {
        uri.push_str("&immutable=1");
    }
    uri
}

fn open_sqlite_readonly(db: &Path) -> Option<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    if !fs::symlink_metadata(db).is_ok_and(|meta| meta.is_file()) {
        return None;
    }
    let mut header = [0u8; 20];
    File::open(db).ok()?.read_exact(&mut header).ok()?;
    if &header[..16] != b"SQLite format 3\0" {
        return None;
    }
    // Bytes 18 and 19 are the read and write format versions: 2 is WAL.
    let wal_mode = header[18] == 2 || header[19] == 2;
    let has_wal = sqlite_sidecar(db, "-wal").exists();
    if wal_mode && has_wal && !sqlite_sidecar(db, "-shm").exists() {
        return None;
    }
    let connection = rusqlite::Connection::open_with_flags(
        sqlite_uri(db, wal_mode && !has_wal),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    connection.busy_timeout(SQLITE_BUSY_TIMEOUT).ok()?;
    connection.pragma_update(None, "query_only", true).ok()?;
    Some(connection)
}

fn sqlite_columns(connection: &rusqlite::Connection, table: &str) -> Vec<String> {
    let Ok(mut statement) = connection.prepare("SELECT name FROM pragma_table_info(?1)") else {
        return Vec::new();
    };
    let Ok(rows) = statement.query_map([table], |row| row.get::<_, String>(0)) else {
        return Vec::new();
    };
    rows.flatten().collect()
}

/// Milliseconds since the epoch from an integer or real (milliseconds or
/// seconds, told apart by size) or a date string (RFC 3339, or SQLite's
/// `YYYY-MM-DD HH:MM:SS` in UTC).
fn sql_time_ms(value: &SqlValue) -> Option<i64> {
    let number = |value: f64| -> Option<i64> {
        if !value.is_finite() || value <= 0.0 {
            return None;
        }
        // 1e11 ms is 1973; 1e11 s is the year 5138.
        Some(if value >= 1e11 {
            value as i64
        } else {
            (value * 1000.0) as i64
        })
    };
    match value {
        SqlValue::Integer(value) => number(*value as f64),
        SqlValue::Real(value) => number(*value),
        SqlValue::Text(text) => {
            let text = text.trim();
            if let Ok(value) = text.parse::<f64>() {
                return number(value);
            }
            if let Ok(time) = chrono::DateTime::parse_from_rfc3339(text) {
                return Some(time.timestamp_millis());
            }
            ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
                .iter()
                .find_map(|format| chrono::NaiveDateTime::parse_from_str(text, format).ok())
                .map(|time| time.and_utc().timestamp_millis())
        }
        _ => None,
    }
}

fn pid_alive(pid: u32) -> bool {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    if pid == 0 {
        return false;
    }
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system.process(pid).is_some()
}

fn quote_sql(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The newest sessions of one store into findings. The newest row per
/// repository decides whether its session ended.
fn read_sql_sessions(
    connection: &rusqlite::Connection,
    spec: &SqlSessions,
    roots: &Roots,
    now: i64,
    findings: &mut Findings,
) {
    let columns = sqlite_columns(connection, spec.table);
    let has = |name: &str| {
        columns
            .iter()
            .any(|column| column.eq_ignore_ascii_case(name))
    };
    if !has(spec.time) || !spec.folders.iter().all(|folder| has(folder)) {
        return;
    }
    let archived = spec.archived.filter(|name| has(name));
    let ended = spec.ended.filter(|name| has(name));
    let pid = spec.pid.filter(|name| has(name));
    let mut selected: Vec<&str> = spec.folders.to_vec();
    selected.push(spec.time);
    let ended_index = ended.map(|name| {
        selected.push(name);
        selected.len() - 1
    });
    let pid_index = pid.map(|name| {
        selected.push(name);
        selected.len() - 1
    });
    let time_index = spec.folders.len();
    let sql = format!(
        "SELECT {} FROM {}{} ORDER BY {} DESC LIMIT {}",
        selected
            .iter()
            .map(|name| quote_sql(name))
            .collect::<Vec<_>>()
            .join(", "),
        quote_sql(spec.table),
        archived
            .map(|name| format!(" WHERE {} IS NULL", quote_sql(name)))
            .unwrap_or_default(),
        quote_sql(spec.time),
        SQLITE_MAX_ROWS,
    );
    let Ok(mut statement) = connection.prepare(&sql) else {
        return;
    };
    let Ok(mut rows) = statement.query([]) else {
        return;
    };
    let cutoff = now - RECENT.as_millis() as i64;
    let mut seen: Vec<String> = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        let value = |index: usize| row.get::<_, SqlValue>(index).ok();
        let time = value(time_index)
            .as_ref()
            .and_then(sql_time_ms)
            .filter(|time| *time - now <= FUTURE_SLACK_MS);
        let finished = ended_index
            .and_then(value)
            .is_some_and(|value| !matches!(value, SqlValue::Null));
        let live_pid = pid_index
            .and_then(value)
            .and_then(|value| match value {
                SqlValue::Integer(pid) => u32::try_from(pid).ok(),
                _ => None,
            })
            .filter(|pid| !finished && pid_alive(*pid));
        let fresh = time.is_some_and(|time| time >= cutoff);
        if !fresh && live_pid.is_none() {
            continue;
        }
        let original = (0..spec.folders.len())
            .filter_map(value)
            .filter_map(|value| match value {
                SqlValue::Text(text) => Some(text),
                _ => None,
            })
            .find_map(|text| {
                text.lines()
                    .map(str::trim)
                    .filter_map(folder_from)
                    .find_map(|path| {
                        roots
                            .containing(&path)
                            .map(|(_, original)| original.to_owned())
                    })
            });
        let Some(original) = original else {
            continue;
        };
        let first = !seen.contains(&original);
        let finding = note(findings, spec.agent, &original, "session");
        if fresh {
            finding.last_activity_ms = finding.last_activity_ms.max(time);
        }
        if let Some(pid) = live_pid {
            finding.pid.get_or_insert(pid);
        }
        if first {
            finding.idle = finished;
            seen.push(original);
        }
    }
}

fn scan_sql_sessions(
    dbs: &[PathBuf],
    spec: &SqlSessions,
    roots: &Roots,
    now: i64,
    findings: &mut Findings,
) {
    let cutoff = now - RECENT.as_millis() as i64;
    for db in dbs {
        if !sqlite_touched_ms(db).is_some_and(|time| time >= cutoff) {
            continue;
        }
        if let Some(connection) = open_sqlite_readonly(db) {
            read_sql_sessions(&connection, spec, roots, now, findings);
        }
    }
}

/// `<dir>/<prefix>*.db`: opencode names a channel's store
/// `opencode-<channel>.db`, Kilo likewise.
fn sqlite_files(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(MAX_DIR_ENTRIES)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix) && name.ends_with(".db"))
        })
        .collect()
}

/// Every SQLite store the detector knows, per agent, as documented by each
/// tool's source.
fn sqlite_sources(home: &Path, xdg_data: &Path) -> Vec<(&'static SqlSessions, Vec<PathBuf>)> {
    let mut opencode = sqlite_files(&xdg_data.join("opencode"), "opencode");
    opencode.extend(env_path("OPENCODE_DB").filter(|path| path.is_absolute()));

    let mut goose = vec![xdg_data.join("goose/sessions/sessions.db")];
    goose.extend(env_path("GOOSE_PATH_ROOT").map(|root| root.join("data/sessions/sessions.db")));
    #[cfg(windows)]
    goose.extend(env_path("APPDATA").map(|app| app.join("Block/goose/data/sessions/sessions.db")));

    let mut cline = Vec::new();
    cline.extend(env_path("CLINE_DB_DATA_DIR").map(|dir| dir.join("sessions.db")));
    cline.extend(env_path("CLINE_DATA_DIR").map(|dir| dir.join("db/sessions.db")));
    cline.extend(env_path("CLINE_DIR").map(|dir| dir.join("data/db/sessions.db")));
    cline.push(home.join(".cline/data/db/sessions.db"));

    let mut zed = Vec::new();
    #[cfg(target_os = "macos")]
    zed.extend(dirs::config_dir().map(|dir| dir.join("Zed/threads/threads.db")));
    #[cfg(all(unix, not(target_os = "macos")))]
    zed.push(xdg_data.join("zed/threads/threads.db"));
    #[cfg(windows)]
    zed.extend(dirs::data_local_dir().map(|dir| dir.join("Zed/threads/threads.db")));

    let mut sources = vec![
        (&OPENCODE_DB, opencode),
        (&KILO_DB, sqlite_files(&xdg_data.join("kilo"), "kilo")),
        (&GOOSE_DB, goose),
        (&CLINE_DB, cline),
        (&ZED_DB, zed),
    ];
    for (_, dbs) in &mut sources {
        dbs.dedup();
    }
    sources
}

// -------------------------------------------------- other session stores

/// Qwen Code writes Claude-style JSONL (`cwd`, `gitBranch`, `timestamp`) to
/// `<qwen>/projects/<cwd with non-alphanumerics as '-'>/chats/*.jsonl`.
fn scan_qwen(qwen: &Path, roots: &Roots, findings: &mut Findings) {
    let mut files = Vec::new();
    recent_files(&qwen.join("projects"), "jsonl", cutoff_ms(), 2, &mut files);
    for file in files {
        if let Some(text) = read_tail(&file) {
            read_claude_style_session("qwen-code", &text, roots, findings);
        }
    }
}

/// The few top-level `key: value` scalars of a flat YAML document. Nested,
/// multi-line, flow and escaped values are refused rather than parsed.
fn yaml_scalars<'a>(text: &str, keys: &[&'a str]) -> HashMap<&'a str, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        if line.starts_with([' ', '\t', '#', '-']) {
            continue;
        }
        let Some((key, raw)) = line.split_once(':') else {
            continue;
        };
        let Some(key) = keys.iter().find(|candidate| **candidate == key.trim()) else {
            continue;
        };
        if let Some(value) = yaml_scalar(raw.trim()) {
            out.insert(*key, value);
        }
    }
    out
}

fn yaml_scalar(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.starts_with(['|', '>', '[', '{', '&', '*', '!', '%', '@', '`']) {
        return None;
    }
    if let Some(inner) = raw.strip_prefix('\'') {
        let end = inner.rfind('\'')?;
        return Some(inner[..end].replace("''", "'"));
    }
    if let Some(inner) = raw.strip_prefix('"') {
        let mut out = String::new();
        let mut characters = inner.chars();
        while let Some(character) = characters.next() {
            match character {
                '"' => return Some(out),
                '\\' => match characters.next()? {
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    '/' => out.push('/'),
                    _ => return None,
                },
                _ => out.push(character),
            }
        }
        return None;
    }
    let value = raw.split(" #").next().unwrap_or(raw).trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Copilot CLI events: the newest timestamp, whether the turn ended
/// (`assistant.turn_end`) and the newest tool started.
fn read_copilot_events(tail: &str) -> (Option<i64>, Option<bool>, Option<String>) {
    let mut last_time = None;
    let mut idle = None;
    let mut last_tool = None;
    for line in tail.lines().rev() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if last_time.is_none() {
            last_time = parse_time(&event["timestamp"]);
        }
        let kind = event["type"].as_str().unwrap_or("");
        if idle.is_none() {
            if kind == "assistant.turn_end" {
                idle = Some(true);
            } else if kind.starts_with("assistant.") || kind.starts_with("tool.") {
                idle = Some(false);
            }
        }
        if last_tool.is_none() && kind == "tool.execution_start" {
            last_tool = event["data"]["toolName"]
                .as_str()
                .map(|tool| tool.chars().take(MCP_CLIENT_NAME_MAX).collect());
        }
        if last_time.is_some() && idle.is_some() && last_tool.is_some() {
            break;
        }
    }
    (last_time, idle, last_tool)
}

/// Copilot CLI keeps `<copilot>/session-state/<uuid>/workspace.yaml`
/// (`cwd`, `git_root`, `branch`, `updated_at`) next to `events.jsonl`.
fn scan_copilot(copilot: &Path, roots: &Roots, findings: &mut Findings) {
    let cutoff = cutoff_ms();
    for dir in subdirs(&copilot.join("session-state")) {
        let yaml = dir.join("workspace.yaml");
        let events = dir.join("events.jsonl");
        let Some(touched) = mtime_ms(&yaml)
            .max(mtime_ms(&events))
            .filter(|time| *time >= cutoff)
        else {
            continue;
        };
        let Some(text) = read_capped(&yaml, MAX_SMALL_BYTES) else {
            continue;
        };
        let fields = yaml_scalars(&text, &["cwd", "git_root", "branch", "updated_at"]);
        let Some(original) = ["cwd", "git_root"].iter().find_map(|key| {
            let path = folder_from(fields.get(key)?)?;
            roots
                .containing(&path)
                .map(|(_, original)| original.to_owned())
        }) else {
            continue;
        };
        let updated = fields
            .get("updated_at")
            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
            .map(|time| time.timestamp_millis());
        let (event_time, idle, last_tool) = read_tail(&events)
            .map(|tail| read_copilot_events(&tail))
            .unwrap_or_default();
        let time = updated.max(event_time).or(Some(touched));
        let finding = note(findings, "copilot-cli", &original, "session");
        finding.last_activity_ms = finding.last_activity_ms.max(time);
        finding.branch = finding
            .branch
            .take()
            .or_else(|| fields.get("branch").cloned());
        finding.last_tool = finding.last_tool.take().or(last_tool);
        finding.idle = idle.unwrap_or(false);
    }
}

/// Continue writes `<continue>/sessions/<id>.json` with `workspaceDirectory`
/// (a `file://` URI from the IDE extensions, a path from `cn`).
/// `sessions.json` there is the index, not a session.
fn scan_continue(dir: &Path, roots: &Roots, findings: &mut Findings) {
    let mut files = Vec::new();
    recent_files(&dir.join("sessions"), "json", cutoff_ms(), 0, &mut files);
    for file in files {
        if file.file_name().and_then(|name| name.to_str()) == Some("sessions.json") {
            continue;
        }
        let Some(session) = read_json(&file, MAX_JSON_BYTES) else {
            continue;
        };
        let Some(folder) = session["workspaceDirectory"].as_str().and_then(folder_from) else {
            continue;
        };
        let Some((_, original)) = roots.containing(&folder) else {
            continue;
        };
        let original = original.to_owned();
        let finding = note(findings, "continue", &original, "session");
        finding.last_activity_ms = finding.last_activity_ms.max(mtime_ms(&file));
    }
}

/// Amp keeps `<data>/amp/threads/T-*.json` with the folders of the thread
/// in `env.initial.trees[].uri`.
fn scan_amp(amp: &Path, roots: &Roots, findings: &mut Findings) {
    let mut files = Vec::new();
    recent_files(&amp.join("threads"), "json", cutoff_ms(), 0, &mut files);
    for file in files {
        if !file
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("T-"))
        {
            continue;
        }
        let Some(thread) = read_json(&file, MAX_JSON_BYTES) else {
            continue;
        };
        let Some(trees) = thread["env"]["initial"]["trees"].as_array() else {
            continue;
        };
        let Some(original) = trees.iter().find_map(|tree| {
            let path = folder_from(tree["uri"].as_str()?)?;
            roots
                .containing(&path)
                .map(|(_, original)| original.to_owned())
        }) else {
            continue;
        };
        let finding = note(findings, "amp", &original, "session");
        finding.last_activity_ms = finding.last_activity_ms.max(mtime_ms(&file));
    }
}

/// Cursor CLI keeps `<cursor>/chats/<hash>/<chat id>/meta.json` with `cwd`
/// and `updatedAtMs`, next to the chat's own store.
fn scan_cursor_cli(cursor: &Path, roots: &Roots, findings: &mut Findings) {
    let now = now_ms();
    let cutoff = now - RECENT.as_millis() as i64;
    for group in subdirs(&cursor.join("chats")) {
        for chat in subdirs(&group) {
            let Some(touched) = newest_mtime(&chat, 0).filter(|time| *time >= cutoff) else {
                continue;
            };
            let Some(meta) = read_json(&chat.join("meta.json"), MAX_SMALL_BYTES) else {
                continue;
            };
            let Some(folder) = meta["cwd"].as_str().and_then(folder_from) else {
                continue;
            };
            let Some((_, original)) = roots.containing(&folder) else {
                continue;
            };
            let updated = meta["updatedAtMs"]
                .as_i64()
                .filter(|time| *time - now <= FUTURE_SLACK_MS);
            let original = original.to_owned();
            let finding = note(findings, "cursor-agent", &original, "session");
            finding.last_activity_ms = finding.last_activity_ms.max(updated.max(Some(touched)));
        }
    }
}

// -------------------------------------------------------------- editors

/// `file:///...` from a VS Code workspace record to a local path, including
/// percent-encoding and Windows drive letters (`file:///c%3A/...`).
fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let mut bytes = Vec::with_capacity(rest.len());
    let raw = rest.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' && index + 2 < raw.len() {
            // Decode from the bytes: slicing the &str here panicked when a
            // multi-byte character followed the `%`.
            let hex = |byte: u8| (byte as char).to_digit(16);
            if let (Some(high), Some(low)) = (hex(raw[index + 1]), hex(raw[index + 2])) {
                bytes.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        bytes.push(raw[index]);
        index += 1;
    }
    let decoded = String::from_utf8(bytes).ok()?;
    let windows =
        decoded.len() > 3 && decoded.as_bytes()[0] == b'/' && decoded.as_bytes()[2] == b':';
    Some(PathBuf::from(if windows {
        &decoded[1..]
    } else {
        &decoded
    }))
}

/// Editors with built-in agents (Cursor, Windsurf, VS Code with Copilot or
/// Cline) record each opened folder, or `.code-workspace` file, in
/// `User/workspaceStorage/<id>/workspace.json` and write that folder's state
/// next to it while in use. Alone that says the folder is open, not that its
/// agent wrote anything (`ide`). The agent chat itself is stored in
/// `chatSessions/` there; a recent write to it is agent activity
/// (`session`). Remote folders (`vscode-remote://`) are skipped.
fn scan_ides(config: &Path, roots: &Roots, findings: &mut Findings) {
    let cutoff = cutoff_ms();
    for (app, agent) in [
        ("Cursor", "cursor"),
        ("Windsurf", "windsurf"),
        ("Code", "vscode"),
        ("Code - Insiders", "vscode"),
        ("VSCodium", "vscode"),
    ] {
        let storage = config.join(app).join("User").join("workspaceStorage");
        for dir in subdirs(&storage) {
            let folder_time = newest_mtime(&dir, 0).filter(|time| *time >= cutoff);
            let chat_time = newest_file_with(&dir.join("chatSessions"), &["json", "jsonl"])
                .filter(|time| *time >= cutoff);
            if folder_time.is_none() && chat_time.is_none() {
                continue;
            }
            let Some(workspace) = read_json(&dir.join("workspace.json"), MAX_SMALL_BYTES) else {
                continue;
            };
            let Some(folder) = ["folder", "workspace"]
                .iter()
                .find_map(|key| folder_from(workspace[*key].as_str()?))
            else {
                continue;
            };
            let Some((_, original)) = roots.containing(&folder) else {
                continue;
            };
            let original = original.to_owned();
            let (source, time) = match chat_time {
                Some(time) => ("session", time),
                None => ("ide", folder_time.unwrap_or_default()),
            };
            let finding = note(findings, agent, &original, source);
            finding.last_activity_ms = finding.last_activity_ms.max(Some(time));
        }
    }
}

// ----------------------------------------------------- traces in the repo

/// aider appends to `.aider.chat.history.md` in the repository; Crush keeps
/// its SQLite store in `<repo>/.crush/crush.db`, whose `-wal` changes while it
/// works. Only modification times are read, never the files.
fn scan_repo_traces(roots: &Roots, findings: &mut Findings) {
    let cutoff = now_ms() - RECENT.as_millis() as i64;
    for (root, original) in &roots.0 {
        if let Some(time) =
            mtime_ms(&root.join(".aider.chat.history.md")).filter(|time| *time >= cutoff)
        {
            let finding = note(findings, "aider", original, "repo-trace");
            finding.last_activity_ms = finding.last_activity_ms.max(Some(time));
        }
        let crush = root.join(".crush").join("crush.db");
        if let Some(time) = sqlite_touched_ms(&crush).filter(|time| *time >= cutoff) {
            let finding = note(findings, "crush", original, "repo-trace");
            finding.last_activity_ms = finding.last_activity_ms.max(Some(time));
        }
    }
}

// ------------------------------------------------- FluxGit's own MCP server
//
// Each `fluxgit-mcp-sidecar` process (spawned by an agent over stdio) keeps
// `<run_dir>/presence/mcp/<pid>.json`: the client's `clientInfo` name and
// version, and per repository the canonical `repoPath` of its last tool call,
// the time and the tool name. Written by app/core/mcp-sidecar/src/presence.rs.

const MCP_PRESENCE_SCHEMA: u64 = 1;
const MCP_PRESENCE_MAX_FILES: usize = 256;
const MCP_PRESENCE_MAX_BYTES: u64 = 64 * 1024;
const MCP_PRESENCE_MAX_REPOS: usize = 16;
const MCP_CLIENT_NAME_MAX: usize = 64;
const MCP_INTERNED_NAMES_MAX: usize = 32;
const MCP_UNNAMED_CLIENT: &str = "mcp-client";

/// The FluxGit run directory, resolved exactly as the sidecar resolves it.
fn mcp_presence_dir() -> Option<PathBuf> {
    let run_dir = if let Some(custom) = std::env::var_os("FLUXGIT_RUN_DIR") {
        PathBuf::from(custom)
    } else {
        #[cfg(target_os = "macos")]
        let base = dirs::home_dir()?.join("Library/Application Support/FluxGit/run");
        #[cfg(all(unix, not(target_os = "macos")))]
        let base = dirs::home_dir()?.join(".local/share/FluxGit/run");
        #[cfg(windows)]
        let base = dirs::data_local_dir()?.join("FluxGit").join("run");
        base
    };
    Some(run_dir.join("presence").join("mcp"))
}

/// A self-declared MCP client name to the detector's agent id. Known agents
/// match on a whole leading token so `codex-mcp-client` is Codex but
/// `codexample` is not; anything else keeps its own (sanitized) name.
pub fn mcp_agent_id(client_name: Option<&str>) -> &'static str {
    let Some(name) = client_name
        .map(sanitize_mcp_client_name)
        .filter(|name| !name.is_empty())
    else {
        return MCP_UNNAMED_CLIENT;
    };
    let lower = name.to_ascii_lowercase();
    let leads = |prefix: &str| {
        lower == prefix
            || lower
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(['-', '_', '.', ':']))
    };
    const KNOWN: [(&str, &str); 19] = [
        ("claude-code", "claude-code"),
        ("codex", "codex"),
        ("cursor-agent", "cursor-agent"),
        ("cursor", "cursor"),
        ("gemini-cli", "gemini-cli"),
        ("gemini", "gemini-cli"),
        ("opencode", "opencode"),
        ("windsurf", "windsurf"),
        ("vscode", "vscode"),
        ("visual-studio-code", "vscode"),
        ("aider", "aider"),
        ("goose", "goose"),
        ("qwen-code", "qwen-code"),
        ("crush", "crush"),
        ("kilocode", "kilo"),
        ("kilo", "kilo"),
        ("cline", "cline"),
        ("zed", "zed"),
        ("continue", "continue"),
    ];
    if let Some((_, agent)) = KNOWN.iter().find(|(prefix, _)| leads(prefix)) {
        return agent;
    }
    intern_mcp_client_name(name)
}

fn sanitize_mcp_client_name(raw: &str) -> String {
    let mut out = String::new();
    for character in raw.trim().chars() {
        let mapped = if character.is_ascii_alphanumeric() || "._:-".contains(character) {
            character
        } else {
            '-'
        };
        if mapped == '-' && out.ends_with('-') {
            continue;
        }
        if out.len() >= MCP_CLIENT_NAME_MAX {
            break;
        }
        out.push(mapped);
    }
    out.trim_matches('-').to_owned()
}

/// `AgentPresence::agent` is `&'static str`; unknown client names are
/// interned in a small bounded table (beyond it they share one id), so the
/// memory kept for them is bounded no matter what clients declare.
fn intern_mcp_client_name(name: String) -> &'static str {
    use std::sync::Mutex;
    static NAMES: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let Ok(mut names) = NAMES.lock() else {
        return MCP_UNNAMED_CLIENT;
    };
    if let Some(existing) = names.iter().find(|existing| **existing == name) {
        return existing;
    }
    if names.len() >= MCP_INTERNED_NAMES_MAX {
        return MCP_UNNAMED_CLIENT;
    }
    let leaked: &'static str = Box::leak(name.into_boxed_str());
    names.push(leaked);
    leaked
}

/// One sidecar's presence document into findings. Anything malformed is
/// skipped, never guessed.
fn read_mcp_presence(text: &str, roots: &Roots, now: i64, findings: &mut Findings) {
    let Ok(document) = serde_json::from_str::<Value>(text) else {
        return;
    };
    if document["schemaVersion"].as_u64() != Some(MCP_PRESENCE_SCHEMA) {
        return;
    }
    let client_name = document["client"]["name"].as_str();
    let agent = mcp_agent_id(client_name);
    let client = McpClient {
        name: client_name
            .map(sanitize_mcp_client_name)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| MCP_UNNAMED_CLIENT.to_owned()),
        version: document["client"]["version"]
            .as_str()
            .map(|version| {
                version
                    .chars()
                    .filter(|character| !character.is_control())
                    .take(MCP_CLIENT_NAME_MAX)
                    .collect::<String>()
            })
            .filter(|version| !version.trim().is_empty()),
    };
    let Some(repos) = document["repos"].as_array() else {
        return;
    };
    for repo in repos.iter().take(MCP_PRESENCE_MAX_REPOS) {
        let (Some(path), Some(time)) = (repo["repoPath"].as_str(), repo["lastCallMs"].as_i64())
        else {
            continue;
        };
        // Stale entries, and clocks far in the future, are not presence.
        if now - time > RECENT.as_millis() as i64 || time - now > 60_000 {
            continue;
        }
        if !Path::new(path).is_absolute() {
            continue;
        }
        let Some((_, original)) = roots.containing(Path::new(path)) else {
            continue;
        };
        let original = original.to_owned();
        let newer = finding_is_older(findings, agent, &original, time);
        let finding = note(findings, agent, &original, "mcp");
        if now - time <= WORKING.as_millis() as i64 {
            // A confirmed call in the last two minutes is work, even when a
            // session log says the turn ended.
            finding.busy = true;
        }
        finding.last_activity_ms = finding.last_activity_ms.max(Some(time));
        if finding.last_tool.is_none() {
            finding.last_tool = repo["lastTool"]
                .as_str()
                .map(|tool| tool.chars().take(MCP_CLIENT_NAME_MAX).collect());
        }
        if newer || finding.mcp_client.is_none() {
            finding.mcp_client = Some(client.clone());
        }
    }
}

fn finding_is_older(findings: &Findings, agent: &'static str, root: &str, time: i64) -> bool {
    findings
        .get(&(agent, root.to_owned()))
        .and_then(|finding| finding.last_activity_ms)
        .is_none_or(|last| last < time)
}

fn scan_mcp(dir: &Path, roots: &Roots, now: i64, exclude_pids: &[u32], findings: &mut Findings) {
    let cutoff = now - RECENT.as_millis() as i64;
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten().take(MCP_PRESENCE_MAX_FILES) {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        // Each sidecar owns `<pid>.json`; a caller asking "who else is
        // here?" excludes its own record.
        let owner_pid = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.parse::<u32>().ok());
        if owner_pid.is_some_and(|pid| exclude_pids.contains(&pid)) {
            continue;
        }
        if !mtime_ms(&path).is_some_and(|time| time >= cutoff) {
            continue;
        }
        let Ok(file) = File::open(&path) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file
            .take(MCP_PRESENCE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MCP_PRESENCE_MAX_BYTES
        {
            continue;
        }
        if let Ok(text) = String::from_utf8(bytes) {
            read_mcp_presence(&text, roots, now, findings);
        }
    }
}

#[cfg(test)]
mod mcp_tests {
    use super::*;
    use serde_json::json;

    fn repo() -> (tempfile::TempDir, PathBuf, Roots) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("api");
        fs::create_dir_all(root.join("src")).unwrap();
        let root = root.canonicalize().unwrap();
        let roots = Roots::new(&[root.to_string_lossy().into_owned()]);
        (temp, root, roots)
    }

    fn document(name: Option<&str>, path: &Path, time: i64, tool: &str) -> String {
        json!({
            "schemaVersion": 1,
            "pid": 42,
            "client": { "name": name, "version": "2.1.7" },
            "repos": [{ "repoPath": path, "lastCallMs": time, "lastTool": tool }],
        })
        .to_string()
    }

    #[test]
    fn known_client_names_map_to_detector_ids_and_unknown_keep_their_own() {
        assert_eq!(mcp_agent_id(Some("claude-code")), "claude-code");
        assert_eq!(mcp_agent_id(Some("codex-mcp-client")), "codex");
        assert_eq!(mcp_agent_id(Some("Codex")), "codex");
        assert_eq!(mcp_agent_id(Some("cursor-vscode")), "cursor");
        assert_eq!(mcp_agent_id(Some("cursor-agent")), "cursor-agent");
        assert_eq!(mcp_agent_id(Some("gemini-cli-mcp-client")), "gemini-cli");
        assert_eq!(mcp_agent_id(Some("opencode")), "opencode");
        assert_eq!(mcp_agent_id(Some("Visual Studio Code")), "vscode");
        // A shared prefix is not a match: only whole leading tokens are.
        assert_eq!(mcp_agent_id(Some("codexample")), "codexample");
        assert_eq!(mcp_agent_id(Some("my agent/1")), "my-agent-1");
        assert_eq!(mcp_agent_id(Some("my agent/1")), "my-agent-1");
        assert_eq!(mcp_agent_id(None), "mcp-client");
        assert_eq!(mcp_agent_id(Some("  ")), "mcp-client");
    }

    #[test]
    fn a_recent_mcp_call_is_confirmed_work_in_the_repository() {
        let (_temp, root, roots) = repo();
        let now = now_ms();
        let mut findings = Findings::new();
        let text = document(
            Some("claude-code"),
            &root.join("src"),
            now - 30_000,
            "repo.status",
        );
        read_mcp_presence(&text, &roots, now, &mut findings);
        let result = finish(findings, now);
        assert_eq!(result.len(), 1, "{result:?}");
        let presence = &result[0];
        assert_eq!(presence.agent, "claude-code");
        assert_eq!(presence.root, root.to_string_lossy());
        assert_eq!(presence.state, "working");
        assert_eq!(presence.sources, vec!["mcp"]);
        assert_eq!(presence.last_tool.as_deref(), Some("repo.status"));
        assert_eq!(
            presence.mcp_client,
            Some(McpClient {
                name: "claude-code".into(),
                version: Some("2.1.7".into())
            })
        );
        assert_eq!(presence.pid, None);
    }

    #[test]
    fn mcp_activity_expires_from_working_to_recent_to_gone() {
        let (_temp, root, roots) = repo();
        let now = now_ms();

        let mut quiet = Findings::new();
        let text = document(
            Some("codex-mcp-client"),
            &root,
            now - 5 * 60_000,
            "diff.text",
        );
        read_mcp_presence(&text, &roots, now, &mut quiet);
        let result = finish(quiet, now);
        assert_eq!(result[0].agent, "codex");
        assert_eq!(result[0].state, "recent");

        let mut stale = Findings::new();
        let text = document(Some("codex"), &root, now - 16 * 60_000, "diff.text");
        read_mcp_presence(&text, &roots, now, &mut stale);
        assert!(stale.is_empty());

        let mut elsewhere = Findings::new();
        let text = document(
            Some("codex"),
            Path::new("/somewhere/else"),
            now,
            "diff.text",
        );
        read_mcp_presence(&text, &roots, now, &mut elsewhere);
        assert!(elsewhere.is_empty());

        let mut wrong_schema = Findings::new();
        let text = json!({ "schemaVersion": 2, "client": {}, "repos": [
            { "repoPath": root, "lastCallMs": now, "lastTool": "x" }
        ] })
        .to_string();
        read_mcp_presence(&text, &roots, now, &mut wrong_schema);
        read_mcp_presence("not json", &roots, now, &mut wrong_schema);
        assert!(wrong_schema.is_empty());
    }

    #[test]
    fn mcp_merges_with_other_sources_and_overrides_a_finished_turn() {
        let (_temp, root, roots) = repo();
        let now = now_ms();
        let mut findings = Findings::new();
        let head = json!({ "type": "session_meta", "payload": { "cwd": root } }).to_string();
        let tail = json!({ "timestamp": "2020-01-01T00:00:00Z", "type": "event_msg",
            "payload": { "type": "task_complete" } })
        .to_string();
        read_codex_session(&head, &tail, &roots, &mut findings);
        let text = document(Some("codex-mcp-client"), &root, now - 10_000, "repo.brief");
        read_mcp_presence(&text, &roots, now, &mut findings);
        let result = finish(findings, now);
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].sources, vec!["session", "mcp"]);
        assert_eq!(result[0].state, "working");
        assert_eq!(result[0].last_activity_ms, Some(now - 10_000));
    }

    #[test]
    fn the_presence_directory_is_read_with_bounds() {
        let (temp, root, roots) = repo();
        let dir = temp.path().join("run/presence/mcp");
        fs::create_dir_all(&dir).unwrap();
        let now = now_ms();
        fs::write(
            dir.join("100.json"),
            document(Some("opencode"), &root, now, "repo.status"),
        )
        .unwrap();
        fs::write(
            dir.join("101.json"),
            "x".repeat(MCP_PRESENCE_MAX_BYTES as usize + 1),
        )
        .unwrap();
        fs::write(
            dir.join("102.tmp"),
            document(Some("gemini-cli"), &root, now, "repo.status"),
        )
        .unwrap();
        let mut findings = Findings::new();
        scan_mcp(&dir, &roots, now, &[], &mut findings);
        let result = finish(findings, now);
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].agent, "opencode");
        let serialized = serde_json::to_value(&result[0]).unwrap();
        assert_eq!(serialized["mcpClient"]["name"], "opencode");
    }

    #[test]
    fn the_callers_own_presence_file_is_excluded_by_pid() {
        let (temp, root, _) = repo();
        let dir = temp.path().join("run/presence/mcp");
        fs::create_dir_all(&dir).unwrap();
        let now = now_ms();
        fs::write(
            dir.join("200.json"),
            document(Some("claude-code"), &root, now, "operation.preview.commit"),
        )
        .unwrap();
        fs::write(
            dir.join("201.json"),
            document(Some("codex-mcp-client"), &root, now, "repo.status"),
        )
        .unwrap();
        let options = ScanOptions {
            mcp_presence_dir: Some(dir),
            exclude_mcp_pids: vec![200],
            skip_processes: true,
            skip_user_stores: true,
        };
        let result = scan_with(&[root.to_string_lossy().into_owned()], &options);
        let agents = result.iter().map(|found| found.agent).collect::<Vec<_>>();
        assert_eq!(agents, vec!["codex"], "{result:?}");
        assert_eq!(result[0].sources, vec!["mcp"]);
        assert_eq!(result[0].state, "working");
    }
}

// ------------------------------------------------------------------ result

fn finish(findings: Findings, now: i64) -> Vec<AgentPresence> {
    let mut out: Vec<AgentPresence> = findings
        .into_iter()
        .map(|((agent, root), finding)| {
            let active_recently = finding
                .last_activity_ms
                .is_some_and(|time| now - time <= WORKING.as_millis() as i64);
            let state = if finding.busy || (active_recently && !finding.idle) {
                "working"
            } else if finding.pid.is_some() {
                "open"
            } else {
                "recent"
            };
            AgentPresence {
                agent,
                root,
                state,
                sources: finding.sources,
                pid: finding.pid,
                last_activity_ms: finding.last_activity_ms,
                branch: finding.branch,
                last_tool: finding.last_tool,
                files: finding.files,
                mcp_client: finding.mcp_client,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        let rank = |state: &str| match state {
            "working" => 0,
            "open" => 1,
            _ => 2,
        };
        rank(a.state)
            .cmp(&rank(b.state))
            .then(b.last_activity_ms.cmp(&a.last_activity_ms))
            .then(a.root.cmp(&b.root))
    });
    out
}

/// Options for [`scan_with`]. The default is exactly what [`scan`] does.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Where MCP presence files live; `None` resolves the FluxGit run
    /// directory the same way the sidecar does (`FLUXGIT_RUN_DIR` first).
    pub mcp_presence_dir: Option<PathBuf>,
    /// Sidecar process ids whose own presence file is skipped, so the MCP
    /// server can answer "which other agents are here" without listing the
    /// client that asked.
    pub exclude_mcp_pids: Vec<u32>,
    /// Skip the process table. Only for tests that must not depend on what
    /// happens to be running on the machine.
    pub skip_processes: bool,
    /// Skip every store under the user's home and config directories and
    /// read only the repository traces and the MCP presence directory. Only
    /// for tests that must not depend on the machine's real agent state.
    pub skip_user_stores: bool,
}

/// Which agents are working in which of `roots`.
pub fn scan(roots: &[String]) -> Vec<AgentPresence> {
    scan_with(roots, &ScanOptions::default())
}

/// [`scan`] with options.
pub fn scan_with(roots: &[String], options: &ScanOptions) -> Vec<AgentPresence> {
    let roots = Roots::new(roots);
    if roots.0.is_empty() {
        return Vec::new();
    }
    let mut findings = Findings::new();
    if !options.skip_processes {
        scan_processes(&roots, &mut findings);
    }
    if !options.skip_user_stores {
        scan_sessions(
            claude_home().as_deref(),
            codex_home().as_deref(),
            &roots,
            &mut findings,
        );
    }
    scan_repo_traces(&roots, &mut findings);
    if !options.skip_user_stores {
        scan_user_stores(&roots, &mut findings);
    }
    let mcp_dir = options.mcp_presence_dir.clone().or_else(mcp_presence_dir);
    if let Some(dir) = mcp_dir {
        scan_mcp(
            &dir,
            &roots,
            now_ms(),
            &options.exclude_mcp_pids,
            &mut findings,
        );
    }
    finish(findings, now_ms())
}

/// SQLite databases, other agents' session files and editor state under the
/// user's home and config directories (Claude Code and Codex are read by
/// `scan_sessions`).
fn scan_user_stores(roots: &Roots, findings: &mut Findings) {
    if let Some(home) = dirs::home_dir() {
        for gemini in gemini_dirs(&home, env_path("GEMINI_CLI_HOME")) {
            scan_gemini(&gemini, roots, findings);
        }
        // opencode, Kilo, Goose and Amp use `~/.local/share` on every OS.
        let xdg_data =
            env_path("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local").join("share"));
        scan_opencode(&xdg_data.join("opencode"), roots, findings);
        scan_goose(&xdg_data.join("goose"), roots, findings);
        if let Some(goose_root) = env_path("GOOSE_PATH_ROOT") {
            scan_goose(&goose_root.join("data"), roots, findings);
        }
        let now = now_ms();
        for (spec, dbs) in sqlite_sources(&home, &xdg_data) {
            scan_sql_sessions(&dbs, spec, roots, now, findings);
        }
        scan_qwen(
            &env_path("QWEN_HOME").unwrap_or_else(|| home.join(".qwen")),
            roots,
            findings,
        );
        scan_copilot(
            &env_path("COPILOT_HOME").unwrap_or_else(|| home.join(".copilot")),
            roots,
            findings,
        );
        scan_continue(
            &env_path("CONTINUE_GLOBAL_DIR").unwrap_or_else(|| home.join(".continue")),
            roots,
            findings,
        );
        scan_amp(&xdg_data.join("amp"), roots, findings);
        scan_cursor_cli(&home.join(".cursor"), roots, findings);
    }
    if let Some(config) = dirs::config_dir() {
        scan_ides(&config, roots, findings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn repo() -> (tempfile::TempDir, PathBuf, Roots) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("api");
        fs::create_dir_all(root.join("src")).unwrap();
        let root = root.canonicalize().unwrap();
        let roots = Roots::new(&[root.to_string_lossy().into_owned()]);
        (temp, root, roots)
    }

    #[test]
    fn recognises_agents_by_binary_and_package_not_by_substring_noise() {
        assert_eq!(
            classify_process("claude", "claude --dangerously-skip-permissions"),
            Some("claude-code")
        );
        assert_eq!(
            classify_process(
                "node",
                "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"
            ),
            Some("claude-code")
        );
        assert_eq!(
            classify_process("codex", "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex sandbox -c x"),
            Some("codex")
        );
        assert_eq!(
            classify_process("node", "node /opt/bin/gemini --yolo"),
            Some("gemini-cli")
        );
        assert_eq!(
            classify_process("python3", "python3 /home/me/.local/bin/aider --model x"),
            Some("aider")
        );
        assert_eq!(classify_process("opencode", "opencode"), Some("opencode"));
        assert_eq!(
            classify_process("cursor-agent", "cursor-agent"),
            Some("cursor-agent")
        );
        // Unrelated tools that merely mention a name are not agents.
        assert_eq!(
            classify_process("CursorUIViewService", "/System/.../CursorUIViewService"),
            None
        );
        assert_eq!(classify_process("vim", "vim claude-notes.md"), None);
        assert_eq!(classify_process("zsh", "-zsh"), None);
    }

    #[test]
    fn a_command_started_by_an_agent_counts_as_that_agent_working() {
        let (_temp, root, roots) = repo();
        let mut procs = HashMap::new();
        procs.insert(
            10,
            Proc {
                parent: Some(1),
                agent: Some("claude-code"),
                cwd: Some(root.clone()),
                long_lived: false,
                started_ms: None,
            },
        );
        procs.insert(
            11,
            Proc {
                parent: Some(10),
                agent: None,
                cwd: Some(root.join("src")),
                long_lived: false,
                started_ms: Some(now_ms() - 5_000),
            },
        );
        procs.insert(
            20,
            Proc {
                parent: Some(1),
                agent: Some("codex"),
                cwd: Some(PathBuf::from("/")),
                long_lived: false,
                started_ms: None,
            },
        );
        procs.insert(
            30,
            Proc {
                parent: Some(1),
                agent: None,
                cwd: Some(root.clone()),
                long_lived: false,
                started_ms: None,
            },
        );
        let mut findings = Findings::new();
        attribute_processes(&procs, &roots, now_ms(), &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].agent, "claude-code");
        assert_eq!(result[0].state, "working");
        assert_eq!(result[0].pid, Some(10));
        assert_eq!(result[0].sources, vec!["process"]);
    }

    #[test]
    fn session_long_mcp_servers_and_old_children_do_not_count_as_work() {
        let (_temp, root, roots) = repo();
        let now = now_ms();
        let proc = |parent, agent, long_lived, started_ms| Proc {
            parent,
            agent,
            cwd: Some(root.clone()),
            long_lived,
            started_ms,
        };
        // An idle Claude Code session: its own stdio MCP servers (FluxGit's
        // sidecar among them) run in the project the whole time.
        let mut procs = HashMap::new();
        procs.insert(
            10,
            proc(Some(1), Some("claude-code"), false, Some(now - 3_600_000)),
        );
        procs.insert(11, proc(Some(10), None, true, Some(now - 1_000)));
        // A dev server it started an hour ago.
        procs.insert(12, proc(Some(10), None, false, Some(now - 3_600_000)));
        // A child whose start time the OS did not give.
        procs.insert(13, proc(Some(10), None, false, None));
        let mut findings = Findings::new();
        attribute_processes(&procs, &roots, now, &mut findings);
        let result = finish(findings, now);
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].state, "open");
        assert_eq!(result[0].pid, Some(10));

        // Only the MCP child ties the agent to this repository: still here.
        let mut procs = HashMap::new();
        procs.insert(
            20,
            Proc {
                parent: Some(1),
                agent: Some("codex"),
                cwd: Some(PathBuf::from("/")),
                long_lived: false,
                started_ms: None,
            },
        );
        procs.insert(21, proc(Some(20), None, true, Some(now - 1_000)));
        let mut findings = Findings::new();
        attribute_processes(&procs, &roots, now, &mut findings);
        let result = finish(findings, now);
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].agent, "codex");
        assert_eq!(result[0].state, "open");
    }

    #[test]
    fn mcp_servers_are_recognised_by_their_program_not_by_any_argument() {
        for (name, cmd) in [
            ("fluxgit-mcp-sidecar", "/usr/local/bin/fluxgit-mcp-sidecar"),
            (
                "node",
                "node /Users/me/.npm/_npx/1/node_modules/.bin/mcp-server-filesystem /repo",
            ),
            ("npx", "npx -y @modelcontextprotocol/server-github"),
            ("npm", "npm exec @upstash/context7-mcp"),
            ("uvx", "uvx mcp-server-git --repository ."),
            ("python3", "python3 -m some_mcp.server"),
            (
                "fluxgit-mcp-sidecar.exe",
                "C:\\Tools\\FluxGit\\fluxgit-mcp-sidecar.exe",
            ),
        ] {
            assert!(looks_like_mcp_server(name, cmd), "{name}: {cmd}");
        }
        for (name, cmd) in [
            ("cargo", "cargo test -p fluxgit-mcp-sidecar"),
            ("zsh", "-zsh"),
            ("node", "node server.js"),
            ("git", "git commit -m mcp"),
            ("npm", "npm run dev"),
        ] {
            assert!(!looks_like_mcp_server(name, cmd), "{name}: {cmd}");
        }
    }

    #[test]
    fn windows_process_names_and_command_lines_are_recognised() {
        assert_eq!(
            classify_process(
                "codex.exe",
                "C:\\Users\\me\\AppData\\Local\\codex\\codex.exe exec"
            ),
            Some("codex")
        );
        assert_eq!(classify_process("CLAUDE.EXE", ""), Some("claude-code"));
        assert_eq!(
            classify_process(
                "node.exe",
                "C:\\Program Files\\nodejs\\node.exe C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js"
            ),
            Some("claude-code")
        );
        assert_eq!(
            classify_process(
                "agent.exe",
                "C:\\Users\\me\\AppData\\Local\\cursor-agent\\versions\\2025.09.1\\agent.exe"
            ),
            Some("cursor-agent")
        );
        assert_eq!(
            classify_process("gemini.exe", "C:\\Users\\me\\bin\\gemini.exe --yolo"),
            Some("gemini-cli")
        );
        assert_eq!(
            classify_process("notepad.exe", "C:\\Windows\\notepad.exe claude.txt"),
            None
        );
        assert_eq!(classify_process("agent.exe", "agent.exe"), None);
    }

    #[test]
    fn claude_session_gives_branch_tool_and_files_inside_the_repo_only() {
        let (_temp, root, roots) = repo();
        let now = chrono::Utc::now().to_rfc3339();
        let lines = [
            json!({ "type": "user", "cwd": root, "gitBranch": "main", "timestamp": now, "message": { "content": "secret prompt" } }),
            json!({ "type": "assistant", "cwd": root, "gitBranch": "feature/x", "timestamp": now, "message": { "content": [
                { "type": "tool_use", "name": "Edit", "input": { "file_path": root.join("src/lib.rs"), "old_string": "a" } },
                { "type": "tool_use", "name": "Write", "input": { "file_path": "/etc/hosts" } },
                { "type": "tool_use", "name": "Bash", "input": { "command": "cargo test" } }
            ] } }),
        ]
        .map(|line| line.to_string())
        .join("\n");
        let mut findings = Findings::new();
        read_claude_session(&lines, &roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1);
        let presence = &result[0];
        assert_eq!(presence.state, "working");
        assert_eq!(presence.branch.as_deref(), Some("feature/x"));
        assert_eq!(presence.last_tool.as_deref(), Some("Bash"));
        assert_eq!(presence.files, vec!["src/lib.rs".to_string()]);
        assert!(!serde_json::to_string(presence)
            .unwrap()
            .contains("secret prompt"));
    }

    #[test]
    fn codex_session_reads_cwd_patches_and_turn_end() {
        let (_temp, root, roots) = repo();
        let now = chrono::Utc::now().to_rfc3339();
        let head = json!({ "type": "session_meta", "payload": { "cwd": root } }).to_string();
        let tail = [
            json!({ "timestamp": now, "type": "response_item", "payload": { "type": "custom_tool_call", "name": "apply_patch",
                "input": "*** Begin Patch\n*** Update File: src/main.rs\n@@\n*** Add File: docs/new.md\n*** End Patch" } }),
            json!({ "timestamp": now, "type": "event_msg", "payload": { "type": "task_complete" } }),
        ]
        .map(|line| line.to_string())
        .join("\n");
        let mut findings = Findings::new();
        read_codex_session(&head, &tail, &roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result[0].agent, "codex");
        // The turn completed: recent, not working.
        assert_eq!(result[0].state, "recent");
        assert_eq!(result[0].last_tool.as_deref(), Some("apply_patch"));
        assert_eq!(
            result[0].files,
            vec!["src/main.rs".to_string(), "docs/new.md".to_string()]
        );

        let elsewhere =
            json!({ "type": "session_meta", "payload": { "cwd": "/somewhere/else" } }).to_string();
        let mut none = Findings::new();
        read_codex_session(&elsewhere, &tail, &roots, &mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn sources_merge_per_agent_and_repository_and_nested_roots_win() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let child = parent.join("modules/child");
        fs::create_dir_all(&child).unwrap();
        let roots = Roots::new(&[
            parent.to_string_lossy().into_owned(),
            child.to_string_lossy().into_owned(),
        ]);
        assert_eq!(
            roots
                .containing(&child.join("x"))
                .map(|(_, root)| root.to_owned()),
            Some(child.to_string_lossy().into_owned())
        );

        let mut procs = HashMap::new();
        procs.insert(
            5,
            Proc {
                parent: None,
                agent: Some("claude-code"),
                cwd: Some(child.clone()),
                long_lived: false,
                started_ms: None,
            },
        );
        let mut findings = Findings::new();
        attribute_processes(&procs, &roots, now_ms(), &mut findings);
        let text =
            json!({ "cwd": child, "timestamp": "2020-01-01T00:00:00Z", "gitBranch": "main" })
                .to_string();
        read_claude_session(&text, &roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sources, vec!["process", "session"]);
        // Alive but quiet for years: open, not working.
        assert_eq!(result[0].state, "open");
    }

    #[test]
    fn documented_formats_for_other_agents_are_read_defensively() {
        let (temp, root, roots) = repo();
        let mut findings = Findings::new();

        // Gemini CLI: state folder named after the SHA-256 of the project root.
        let gemini = temp.path().join(".gemini");
        let project = gemini.join("tmp").join(sha256_hex(&root.to_string_lossy()));
        fs::create_dir_all(project.join("chats")).unwrap();
        fs::write(project.join("logs.json"), "[]").unwrap();
        scan_gemini(&gemini, &roots, &mut findings);

        // opencode: session documents with directory and time.updated.
        let opencode = temp.path().join("opencode");
        let sessions = opencode.join("storage/session/project-1");
        fs::create_dir_all(&sessions).unwrap();
        fs::write(
            sessions.join("ses_1.json"),
            json!({ "directory": root, "time": { "updated": now_ms() } }).to_string(),
        )
        .unwrap();
        fs::write(sessions.join("ses_2.json"), "not json").unwrap();
        scan_opencode(&opencode, &roots, &mut findings);

        // Goose: first JSONL line carries working_dir.
        let goose = temp.path().join("goose");
        fs::create_dir_all(goose.join("sessions")).unwrap();
        fs::write(
            goose.join("sessions/s.jsonl"),
            format!("{}\n{{}}", json!({ "working_dir": root })),
        )
        .unwrap();
        scan_goose(&goose, &roots, &mut findings);

        // Cursor: workspace.json with a percent-encoded file URI.
        let config = temp.path().join("config");
        let workspace = config.join("Cursor/User/workspaceStorage/abc");
        fs::create_dir_all(&workspace).unwrap();
        let uri = format!("file://{}", root.to_string_lossy().replace(' ', "%20"));
        fs::write(
            workspace.join("workspace.json"),
            json!({ "folder": uri }).to_string(),
        )
        .unwrap();
        scan_ides(&config, &roots, &mut findings);

        let result = finish(findings, now_ms());
        let agents = result
            .iter()
            .map(|presence| (presence.agent, presence.sources.clone()))
            .collect::<Vec<_>>();
        for expected in [
            ("gemini-cli", "session"),
            ("opencode", "session"),
            ("goose", "session"),
            ("cursor", "ide"),
        ] {
            assert!(
                agents.contains(&(expected.0, vec![expected.1])),
                "{expected:?} missing from {agents:?}"
            );
        }
        assert_eq!(
            file_uri_to_path("file:///c%3A/Users/me/repo"),
            Some(PathBuf::from("c:/Users/me/repo"))
        );
        assert_eq!(
            file_uri_to_path("file:///home/me/my%20repo"),
            Some(PathBuf::from("/home/me/my repo"))
        );
        assert_eq!(file_uri_to_path("vscode-remote://ssh/x"), None);
        // A `%` followed by a multi-byte character used to panic (byte slice
        // off a char boundary); it is kept as a literal instead.
        assert_eq!(
            file_uri_to_path("file:///x%a\u{e9}"),
            Some(PathBuf::from("/x%a\u{e9}"))
        );
        assert_eq!(
            file_uri_to_path("file:///x%\u{e9}\u{e9}"),
            Some(PathBuf::from("/x%\u{e9}\u{e9}"))
        );
        assert_eq!(
            file_uri_to_path("file:///caf%C3%A9"),
            Some(PathBuf::from("/caf\u{e9}"))
        );
    }

    #[test]
    fn aider_history_in_the_repository_is_a_recent_trace() {
        let (_temp, root, roots) = repo();
        fs::write(root.join(".aider.chat.history.md"), "# aider chat").unwrap();
        let mut findings = Findings::new();
        scan_repo_traces(&roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result[0].agent, "aider");
        assert_eq!(result[0].sources, vec!["repo-trace"]);
    }
}

#[cfg(test)]
mod reader_tests {
    use super::*;
    use rusqlite::params;
    use serde_json::json;

    struct Repos {
        temp: tempfile::TempDir,
        api: PathBuf,
        web: PathBuf,
        old: PathBuf,
        roots: Roots,
    }

    fn repos() -> Repos {
        let temp = tempfile::tempdir().unwrap();
        let make = |name: &str| {
            let root = temp.path().join(name);
            fs::create_dir_all(root.join("src")).unwrap();
            root.canonicalize().unwrap()
        };
        let (api, web, old) = (make("api"), make("web"), make("old"));
        let roots = Roots::new(&[&api, &web, &old].map(|root| root.to_string_lossy().into_owned()));
        Repos {
            temp,
            api,
            web,
            old,
            roots,
        }
    }

    fn age(path: &Path, seconds: u64) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(seconds))
            .unwrap();
    }

    fn write(path: &Path, text: impl AsRef<[u8]>) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn sqlite(path: &Path, schema: &str) -> rusqlite::Connection {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let connection = rusqlite::Connection::open(path).unwrap();
        connection
            .execute_batch(&format!("PRAGMA journal_mode=WAL; {schema}"))
            .unwrap();
        connection
    }

    fn by_root(result: &[AgentPresence], agent: &str, root: &Path) -> Option<AgentPresence> {
        result
            .iter()
            .find(|presence| presence.agent == agent && presence.root == root.to_string_lossy())
            .cloned()
    }

    fn uri(path: &Path) -> String {
        format!("file://{}", path.to_string_lossy().replace(' ', "%20"))
    }

    #[test]
    fn classifier_knows_cursor_cli_kilo_continue_and_cline_by_path_not_bare_words() {
        assert_eq!(
            classify_process(
                "agent",
                "/Users/me/.local/share/cursor-agent/versions/2026.09.01/agent --resume"
            ),
            Some("cursor-agent")
        );
        assert_eq!(classify_process("agent", "agent"), None);
        assert_eq!(classify_process("ssh-agent", "/usr/bin/ssh-agent -l"), None);
        assert_eq!(classify_process("kilo", "kilo"), Some("kilo"));
        assert_eq!(
            classify_process(
                "node",
                "node /usr/local/lib/node_modules/@kilocode/cli/index.js"
            ),
            Some("kilo")
        );
        assert_eq!(
            classify_process(
                "node",
                "node /opt/homebrew/lib/node_modules/@continuedev/cli/dist/cn.js"
            ),
            Some("continue")
        );
        // `cn` alone is too common a name to trust.
        assert_eq!(classify_process("cn", "cn --help"), None);
        assert_eq!(classify_process("cline", "cline"), Some("cline"));
        assert_eq!(
            classify_process("node", "node /usr/lib/node_modules/cline/dist/cli.js"),
            Some("cline")
        );
        assert_eq!(classify_process("vim", "vim cline-notes.md"), None);
    }

    #[test]
    fn gemini_home_override_replaces_the_home_directory() {
        let home = Path::new("/home/me");
        assert_eq!(
            gemini_dirs(home, None),
            vec![home.join(".gemini"), home.join(".cache/.gemini")]
        );
        assert_eq!(
            gemini_dirs(home, Some(PathBuf::from("/custom"))),
            vec![
                PathBuf::from("/custom/.gemini"),
                home.join(".cache/.gemini")
            ]
        );
    }

    #[test]
    fn gemini_slug_folders_are_found_by_project_root_or_registry() {
        let repos = repos();
        let gemini = repos.temp.path().join(".gemini");
        let tmp = gemini.join("tmp");
        // Named after the folder, `.project_root` says where it is.
        write(
            &tmp.join("api/.project_root"),
            format!("{}\n", repos.api.to_string_lossy()),
        );
        write(&tmp.join("api/chats/session-1.jsonl"), "{}");
        // A clash suffix without `.project_root`: projects.json maps it.
        write(&tmp.join("web-1/chats/session-2.jsonl"), "{}");
        write(
            &gemini.join("projects.json"),
            json!({ "projects": { repos.web.to_string_lossy(): "web-1" } }).to_string(),
        );
        // Stale chats and projects elsewhere are not presence.
        write(
            &tmp.join("old/.project_root"),
            repos.old.to_string_lossy().as_bytes(),
        );
        write(&tmp.join("old/chats/session-3.jsonl"), "{}");
        age(&tmp.join("old/chats/session-3.jsonl"), 20 * 60);
        write(&tmp.join("else/.project_root"), "/somewhere/else");
        write(&tmp.join("else/chats/session-4.jsonl"), "{}");

        let mut findings = Findings::new();
        scan_gemini(&gemini, &repos.roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 2, "{result:?}");
        assert!(by_root(&result, "gemini-cli", &repos.api).is_some());
        assert!(by_root(&result, "gemini-cli", &repos.web).is_some());
    }

    #[test]
    fn opencode_sqlite_is_read_while_its_writer_is_open_and_skips_archived_sessions() {
        let repos = repos();
        // A space in the path exercises the URI.
        let db = repos.temp.path().join("data home/opencode/opencode.db");
        let writer = sqlite(
            &db,
            "CREATE TABLE session (id TEXT, directory TEXT, time_updated INTEGER, time_archived INTEGER);",
        );
        let now = now_ms();
        for (id, directory, updated, archived) in [
            ("a", repos.api.join("src"), now - 30_000, None),
            ("b", repos.web.clone(), now - 10_000, Some(now)),
            ("c", repos.old.clone(), now - 3_600_000, None),
            ("d", PathBuf::from("/somewhere/else"), now, None),
        ] {
            writer
                .execute(
                    "INSERT INTO session VALUES (?1, ?2, ?3, ?4)",
                    params![id, directory.to_string_lossy(), updated, archived],
                )
                .unwrap();
        }
        assert!(sqlite_sidecar(&db, "-wal").exists());

        let mut findings = Findings::new();
        let dbs = sqlite_files(&db.parent().unwrap(), "opencode");
        assert_eq!(dbs, vec![db.clone()]);
        scan_sql_sessions(&dbs, &OPENCODE_DB, &repos.roots, now, &mut findings);
        let result = finish(findings, now);
        assert_eq!(result.len(), 1, "{result:?}");
        let presence = &result[0];
        assert_eq!(presence.agent, "opencode");
        assert_eq!(presence.root, repos.api.to_string_lossy());
        assert_eq!(presence.sources, vec!["session"]);
        assert_eq!(presence.state, "working");
        assert_eq!(presence.last_activity_ms, Some(now - 30_000));
        drop(writer);
    }

    #[test]
    fn a_checkpointed_database_is_read_without_creating_or_changing_any_file() {
        let repos = repos();
        let db = repos.temp.path().join("goose/sessions/sessions.db");
        let writer = sqlite(
            &db,
            "CREATE TABLE sessions (id TEXT, working_dir TEXT, updated_at TIMESTAMP);",
        );
        let now_text = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        writer
            .execute(
                "INSERT INTO sessions VALUES ('1', ?1, ?2)",
                params![repos.web.to_string_lossy(), now_text],
            )
            .unwrap();
        drop(writer);
        assert!(!sqlite_sidecar(&db, "-wal").exists());
        let before = fs::metadata(&db).unwrap().modified().unwrap();

        let mut findings = Findings::new();
        scan_sql_sessions(
            &[db.clone()],
            &GOOSE_DB,
            &repos.roots,
            now_ms(),
            &mut findings,
        );
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].agent, "goose");
        assert_eq!(result[0].root, repos.web.to_string_lossy());

        assert!(!sqlite_sidecar(&db, "-wal").exists());
        assert!(!sqlite_sidecar(&db, "-shm").exists());
        assert_eq!(fs::metadata(&db).unwrap().modified().unwrap(), before);
        let missing = repos.temp.path().join("nothing/here.db");
        assert!(open_sqlite_readonly(&missing).is_none());
        assert!(!missing.exists());
    }

    #[test]
    fn stale_databases_are_not_opened_and_mismatched_schemas_are_skipped() {
        let repos = repos();
        let now = now_ms();
        let dir = repos.temp.path().join("kilo");
        let schema =
            "CREATE TABLE session (id TEXT, directory TEXT, time_updated INTEGER, time_archived INTEGER);";
        // Rows say "now", but the file has not changed in twenty minutes.
        let stale = dir.join("kilo-beta.db");
        let writer = sqlite(&stale, schema);
        writer
            .execute(
                "INSERT INTO session VALUES ('a', ?1, ?2, NULL)",
                params![repos.api.to_string_lossy(), now],
            )
            .unwrap();
        drop(writer);
        age(&stale, 20 * 60);
        // Right table, wrong column.
        let wrong = dir.join("kilo-wrong.db");
        let writer = sqlite(
            &wrong,
            "CREATE TABLE session (id TEXT, dir TEXT, time_updated INTEGER);",
        );
        writer
            .execute(
                "INSERT INTO session VALUES ('a', ?1, ?2)",
                params![repos.api.to_string_lossy(), now],
            )
            .unwrap();
        drop(writer);
        // No such table, and not a database at all.
        drop(sqlite(
            &dir.join("kilo-empty.db"),
            "CREATE TABLE other (x);",
        ));
        write(&dir.join("kilo-garbage.db"), "not a database");

        let dbs = sqlite_files(&dir, "kilo");
        assert_eq!(dbs.len(), 4);
        let mut findings = Findings::new();
        scan_sql_sessions(&dbs, &KILO_DB, &repos.roots, now, &mut findings);
        assert!(findings.is_empty());

        // The same stale rows in a fresh file are found, as Kilo.
        let fresh = dir.join("kilo.db");
        let writer = sqlite(&fresh, schema);
        writer
            .execute(
                "INSERT INTO session VALUES ('a', ?1, ?2, NULL)",
                params![repos.api.to_string_lossy(), now],
            )
            .unwrap();
        drop(writer);
        scan_sql_sessions(&[fresh], &KILO_DB, &repos.roots, now, &mut findings);
        let result = finish(findings, now);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].agent, "kilo");
    }

    #[test]
    fn cline_live_pid_means_open_and_ended_sessions_are_not_working() {
        let repos = repos();
        let now = now_ms();
        let db = repos.temp.path().join(".cline/data/db/sessions.db");
        let writer = sqlite(
            &db,
            "CREATE TABLE sessions (id TEXT, cwd TEXT, workspace_root TEXT, updated_at INTEGER,
                status TEXT, ended_at INTEGER, pid INTEGER);",
        );
        let me = std::process::id();
        writer
            .execute(
                "INSERT INTO sessions VALUES ('1', ?1, ?1, ?2, 'running', NULL, ?3)",
                params![repos.api.to_string_lossy(), now - 5 * 60_000, me],
            )
            .unwrap();
        writer
            .execute(
                "INSERT INTO sessions VALUES ('2', '/somewhere/else', ?1, ?2, 'completed', ?2, ?3)",
                params![repos.web.to_string_lossy(), now - 10_000, me],
            )
            .unwrap();
        drop(writer);
        let mut findings = Findings::new();
        scan_sql_sessions(&[db], &CLINE_DB, &repos.roots, now, &mut findings);
        let result = finish(findings, now);
        let api = by_root(&result, "cline", &repos.api).expect("api");
        assert_eq!(api.state, "open");
        assert_eq!(api.pid, Some(me));
        // workspace_root is used when cwd is elsewhere; the session ended.
        let web = by_root(&result, "cline", &repos.web).expect("web");
        assert_eq!(web.state, "recent");
        assert_eq!(web.pid, None);
    }

    #[test]
    fn zed_threads_list_several_folders_one_per_line() {
        let repos = repos();
        let db = repos.temp.path().join("Zed/threads/threads.db");
        let writer = sqlite(
            &db,
            "CREATE TABLE threads (id TEXT, summary TEXT, updated_at TEXT, folder_paths TEXT);",
        );
        writer
            .execute(
                "INSERT INTO threads VALUES ('1', 'secret summary', ?1, ?2)",
                params![
                    chrono::Utc::now().to_rfc3339(),
                    format!("/somewhere/else\n{}", repos.old.to_string_lossy())
                ],
            )
            .unwrap();
        writer
            .execute(
                "INSERT INTO threads VALUES ('2', 'x', ?1, NULL)",
                params![chrono::Utc::now().to_rfc3339()],
            )
            .unwrap();
        drop(writer);
        let mut findings = Findings::new();
        scan_sql_sessions(&[db], &ZED_DB, &repos.roots, now_ms(), &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].agent, "zed");
        assert_eq!(result[0].root, repos.old.to_string_lossy());
        assert!(!serde_json::to_string(&result[0])
            .unwrap()
            .contains("secret"));
    }

    #[test]
    fn sql_times_accept_milliseconds_seconds_and_date_strings() {
        assert_eq!(
            sql_time_ms(&SqlValue::Integer(1_790_000_000_000)),
            Some(1_790_000_000_000)
        );
        assert_eq!(
            sql_time_ms(&SqlValue::Integer(1_790_000_000)),
            Some(1_790_000_000_000)
        );
        assert_eq!(
            sql_time_ms(&SqlValue::Text("2026-09-27 10:00:00".into())),
            Some(1_790_503_200_000)
        );
        assert_eq!(
            sql_time_ms(&SqlValue::Text("2026-09-27T10:00:00Z".into())),
            Some(1_790_503_200_000)
        );
        assert_eq!(sql_time_ms(&SqlValue::Null), None);
        assert_eq!(sql_time_ms(&SqlValue::Text("yesterday".into())), None);
        assert_eq!(
            sqlite_uri(Path::new("/a b/c?#%.db"), true),
            "file:/a b/c%3f%23%25.db?mode=ro&immutable=1"
        );
        assert_eq!(
            sqlite_uri(Path::new("C:\\Users\\me\\x.db"), false),
            "file:/C:/Users/me/x.db?mode=ro"
        );
    }

    #[test]
    fn qwen_sessions_read_like_claude_with_function_call_parts() {
        let repos = repos();
        let qwen = repos.temp.path().join(".qwen");
        let line = json!({
            "type": "assistant", "cwd": repos.api, "gitBranch": "dev",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "message": { "role": "model", "parts": [
                { "text": "secret reasoning" },
                { "functionCall": { "name": "edit", "args": {
                    "file_path": repos.api.join("src/a.rs"), "old_string": "secret" } } }
            ] }
        });
        write(
            &qwen.join("projects/-tmp-api/chats/s1.jsonl"),
            format!("{line}\n"),
        );
        let mut findings = Findings::new();
        scan_qwen(&qwen, &repos.roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1, "{result:?}");
        let presence = &result[0];
        assert_eq!(presence.agent, "qwen-code");
        assert_eq!(presence.branch.as_deref(), Some("dev"));
        assert_eq!(presence.last_tool.as_deref(), Some("edit"));
        assert_eq!(presence.files, vec!["src/a.rs".to_string()]);
        assert!(!serde_json::to_string(presence).unwrap().contains("secret"));
    }

    #[test]
    fn crush_store_inside_the_repository_is_a_trace_only_when_recent() {
        let repos = repos();
        write(&repos.api.join(".crush/crush.db"), "");
        write(&repos.api.join(".crush/crush.db-wal"), "");
        age(&repos.api.join(".crush/crush.db"), 3600);
        write(&repos.web.join(".crush/crush.db"), "");
        age(&repos.web.join(".crush/crush.db"), 3600);
        let mut findings = Findings::new();
        scan_repo_traces(&repos.roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1, "{result:?}");
        assert_eq!(result[0].agent, "crush");
        assert_eq!(result[0].root, repos.api.to_string_lossy());
        assert_eq!(result[0].sources, vec!["repo-trace"]);
    }

    #[test]
    fn copilot_workspace_yaml_and_events_give_folder_branch_and_turn_end() {
        let repos = repos();
        let copilot = repos.temp.path().join(".copilot");
        let session = copilot.join("session-state/0b1c");
        write(
            &session.join("workspace.yaml"),
            format!(
                "id: 0b1c\ncwd: \"{}/src\"\ngit_root: '{}'\nbranch: feature/copilot # current\nsummary: |\n  secret\n  cwd: /somewhere/else\nupdated_at: {}\n",
                repos.api.to_string_lossy(),
                repos.api.to_string_lossy(),
                chrono::Utc::now().to_rfc3339()
            ),
        );
        let now = chrono::Utc::now().to_rfc3339();
        write(
            &session.join("events.jsonl"),
            [
                json!({ "type": "user.message", "timestamp": now, "data": { "content": "secret" } }),
                json!({ "type": "tool.execution_start", "timestamp": now, "data": { "toolName": "bash" } }),
                json!({ "type": "assistant.turn_end", "timestamp": now, "data": {} }),
            ]
            .map(|line| line.to_string())
            .join("\n"),
        );
        write(
            &copilot.join("session-state/other/workspace.yaml"),
            "cwd: /somewhere/else\n",
        );
        let mut findings = Findings::new();
        scan_copilot(&copilot, &repos.roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 1, "{result:?}");
        let presence = &result[0];
        assert_eq!(presence.agent, "copilot-cli");
        assert_eq!(presence.root, repos.api.to_string_lossy());
        assert_eq!(presence.state, "recent");
        assert_eq!(presence.branch.as_deref(), Some("feature/copilot"));
        assert_eq!(presence.last_tool.as_deref(), Some("bash"));

        let fields = yaml_scalars(
            "a: 'it''s'\nb: \"c:\\\\x\"\nc: \"line\\nbreak\"\nd: |\n  x\n  e: nested\ne: [1]\n",
            &["a", "b", "c", "d", "e"],
        );
        assert_eq!(fields.get("a").map(String::as_str), Some("it's"));
        assert_eq!(fields.get("b").map(String::as_str), Some("c:\\x"));
        assert!(!fields.contains_key("c"));
        assert!(!fields.contains_key("d"));
        assert!(!fields.contains_key("e"));
    }

    #[test]
    fn continue_amp_and_cursor_cli_name_their_folders() {
        let repos = repos();
        let home = repos.temp.path();
        // Continue: a URI from the IDE; remote folders and the index skipped.
        let sessions = home.join(".continue/sessions");
        write(
            &sessions.join("s1.json"),
            json!({ "workspaceDirectory": uri(&repos.api), "history": [{ "message": "secret" }] })
                .to_string(),
        );
        write(
            &sessions.join("s2.json"),
            json!({ "workspaceDirectory": format!("vscode-remote://ssh-remote+box{}", repos.web.to_string_lossy()) })
                .to_string(),
        );
        write(
            &sessions.join("sessions.json"),
            json!([{ "workspaceDirectory": repos.old }]).to_string(),
        );
        // Amp: the thread's trees; only T-* files.
        let threads = home.join("amp/threads");
        write(
            &threads.join("T-1.json"),
            json!({ "env": { "initial": { "trees": [
                { "uri": "file:///somewhere/else" }, { "uri": uri(&repos.web) }
            ] } } })
            .to_string(),
        );
        write(
            &threads.join("X-2.json"),
            json!({ "env": { "initial": { "trees": [{ "uri": uri(&repos.old) }] } } }).to_string(),
        );
        // Cursor CLI: meta.json per chat.
        let cursor = home.join(".cursor");
        write(
            &cursor.join("chats/h1/c1/meta.json"),
            json!({ "cwd": repos.old, "updatedAtMs": now_ms() - 1_000 }).to_string(),
        );
        write(
            &cursor.join("chats/h1/c2/meta.json"),
            json!({ "cwd": "/somewhere/else", "updatedAtMs": now_ms() }).to_string(),
        );

        let mut findings = Findings::new();
        scan_continue(&home.join(".continue"), &repos.roots, &mut findings);
        scan_amp(&home.join("amp"), &repos.roots, &mut findings);
        scan_cursor_cli(&cursor, &repos.roots, &mut findings);
        let result = finish(findings, now_ms());
        let found = result
            .iter()
            .map(|presence| (presence.agent, presence.root.clone()))
            .collect::<Vec<_>>();
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(by_root(&result, "continue", &repos.api).is_some());
        assert!(by_root(&result, "amp", &repos.web).is_some());
        let cursor_cli = by_root(&result, "cursor-agent", &repos.old).expect("cursor");
        assert_eq!(cursor_cli.sources, vec!["session"]);
    }

    #[test]
    fn editor_chat_sessions_are_agent_activity_and_folders_alone_are_ide() {
        let repos = repos();
        let config = repos.temp.path().join("config");
        let storage = |app: &str, id: &str| config.join(app).join("User/workspaceStorage").join(id);
        // A multi-root workspace file inside the repository, with a recent chat.
        write(
            &storage("Code", "w1").join("workspace.json"),
            json!({ "workspace": uri(&repos.api.join("api.code-workspace")) }).to_string(),
        );
        write(&storage("Code", "w1").join("chatSessions/c.json"), "{}");
        // Folder open, chat stale: presence only.
        write(
            &storage("Code", "w2").join("workspace.json"),
            json!({ "folder": uri(&repos.web) }).to_string(),
        );
        write(&storage("Code", "w2").join("chatSessions/c.jsonl"), "{}");
        age(&storage("Code", "w2").join("chatSessions/c.jsonl"), 3600);
        // Remote folders are not local repositories.
        write(
            &storage("Windsurf", "w3").join("workspace.json"),
            json!({ "folder": format!("vscode-remote://ssh-remote+box{}", repos.old.to_string_lossy()) })
                .to_string(),
        );
        let mut findings = Findings::new();
        scan_ides(&config, &repos.roots, &mut findings);
        let result = finish(findings, now_ms());
        assert_eq!(result.len(), 2, "{result:?}");
        assert_eq!(
            by_root(&result, "vscode", &repos.api).unwrap().sources,
            vec!["session"]
        );
        assert_eq!(
            by_root(&result, "vscode", &repos.web).unwrap().sources,
            vec!["ide"]
        );
    }
}

#[cfg(test)]
mod live_probe {
    /// `FLUXGIT_PRESENCE_PROBE=/path/to/repo cargo test ... live_probe -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_presence_for_a_real_repository() {
        let root = std::env::var("FLUXGIT_PRESENCE_PROBE").expect("set FLUXGIT_PRESENCE_PROBE");
        for presence in super::scan(&[root]) {
            println!("{}", serde_json::to_string(&presence).unwrap());
        }
    }
}
