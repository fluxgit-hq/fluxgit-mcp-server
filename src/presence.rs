//! Local record of which repositories the connected MCP client is using, so
//! the FluxGit desktop app can show "claude-code is working in api" as a
//! confirmed finding instead of a guess from process trees.
//!
//! Each sidecar process (one per connected agent, since the agent spawns it
//! over stdio) owns exactly one file, `<run_dir>/presence/mcp/<pid>.json`,
//! and rewrites it atomically after every tool call that names a
//! `repoPath`. The file holds only:
//! - the client's self-declared `clientInfo` name and version (attribution,
//!   never authentication),
//! - per repository: the canonical repository path the call was validated
//!   against, the time of the last call and the last tool name.
//!
//! Never tool arguments beyond that path, never results, never Git output.
//! The file lives in the user's private FluxGit run directory (0700 dir,
//! 0600 file) and nothing is sent anywhere; the MCP wire contract is
//! unchanged. `FLUXGIT_MCP_PRESENCE_DISABLED` turns it off. Writing is best
//! effort: a failure never affects a tool call.

use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

pub const PRESENCE_SCHEMA_VERSION: u64 = 1;
/// At most this many repositories per sidecar process; the oldest drops out.
pub const PRESENCE_MAX_REPOS: usize = 16;
const PRESENCE_MAX_CLIENT_FIELD_CHARS: usize = 128;
/// Files left behind by sidecars that died without cleaning up are removed
/// by the next sidecar once they are this old.
const PRESENCE_STALE_FILE_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const PRESENCE_MAX_SWEEP_ENTRIES: usize = 512;

/// `<run_dir>/presence/mcp`
pub fn presence_dir_for_run_dir(run_dir: &Path) -> PathBuf {
    run_dir.join("presence").join("mcp")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoActivity {
    repo_path: String,
    last_call_ms: i64,
    last_tool: String,
}

#[derive(Debug, Default)]
struct PresenceState {
    initialize_version: Option<String>,
    client_name: Option<String>,
    client_version: Option<String>,
    repos: Vec<RepoActivity>,
    swept: bool,
    warned: bool,
}

#[derive(Debug)]
pub struct PresenceRecorder {
    dir: PathBuf,
    file: PathBuf,
    state: Mutex<PresenceState>,
}

impl PresenceRecorder {
    /// Recorder for this process under `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Self::with_file_stem(dir, std::process::id().to_string())
    }

    fn with_file_stem(dir: PathBuf, stem: String) -> Self {
        let file = dir.join(format!("{stem}.json"));
        Self {
            dir,
            file,
            state: Mutex::new(PresenceState::default()),
        }
    }

    /// Enabled by default under the FluxGit run directory;
    /// `FLUXGIT_MCP_PRESENCE_DISABLED` (any value) disables it.
    pub fn from_env(run_dir: Option<PathBuf>) -> Option<Self> {
        if std::env::var_os("FLUXGIT_MCP_PRESENCE_DISABLED").is_some() {
            return None;
        }
        run_dir.map(|run_dir| Self::new(presence_dir_for_run_dir(&run_dir)))
    }

    pub fn file_path(&self) -> &Path {
        &self.file
    }

    /// The directory holding every sidecar's presence file.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Remember the version from the `initialize` request's `clientInfo`, for
    /// legacy-era calls that do not repeat it per request.
    pub fn note_initialize_version(&self, version: Option<&str>) {
        if let Ok(mut state) = self.state.lock() {
            state.initialize_version = version.and_then(clean_client_field);
        }
    }

    /// Record one tool call against `repo_path`. `client_name` is `None` when
    /// the client did not identify itself; `request_version` is the version
    /// carried by the request itself (modern era), which wins over the one
    /// remembered from `initialize`.
    pub fn record(
        &self,
        client_name: Option<&str>,
        request_version: Option<&str>,
        repo_path: &Path,
        tool: &str,
        now_ms: i64,
    ) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.client_name = client_name.and_then(clean_client_field);
        state.client_version = request_version
            .and_then(clean_client_field)
            .or_else(|| state.initialize_version.clone());
        let repo_path = repo_path.to_string_lossy().into_owned();
        state.repos.retain(|repo| repo.repo_path != repo_path);
        state.repos.insert(
            0,
            RepoActivity {
                repo_path,
                last_call_ms: now_ms,
                last_tool: tool.to_string(),
            },
        );
        state.repos.truncate(PRESENCE_MAX_REPOS);
        if !state.swept {
            state.swept = true;
            self.sweep_stale_files();
        }
        if let Err(error) = self.write(&state) {
            if !state.warned {
                state.warned = true;
                eprintln!(
                    "fluxgit-mcp-sidecar: cannot write MCP presence file {}: {error}",
                    self.file.display()
                );
            }
        }
    }

    /// Remove this process's file (on clean shutdown).
    pub fn remove(&self) {
        let _ = fs::remove_file(&self.file);
    }

    fn document(&self, state: &PresenceState) -> serde_json::Value {
        json!({
            "schemaVersion": PRESENCE_SCHEMA_VERSION,
            "pid": std::process::id(),
            "client": {
                "name": state.client_name,
                "version": state.client_version,
            },
            "repos": state.repos.iter().map(|repo| json!({
                "repoPath": repo.repo_path,
                "lastCallMs": repo.last_call_ms,
                "lastTool": repo.last_tool,
            })).collect::<Vec<_>>(),
        })
    }

    fn write(&self, state: &PresenceState) -> io::Result<()> {
        create_private_dir(&self.dir)?;
        let bytes = serde_json::to_vec(&self.document(state))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let temp = self.dir.join(format!(
            ".{}.{}.tmp",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let result = (|| {
            let mut file = options.open(&temp)?;
            file.write_all(&bytes)?;
            file.flush()?;
            drop(file);
            // rename replaces a planted symlink itself instead of following it.
            fs::rename(&temp, &self.file)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn sweep_stale_files(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten().take(PRESENCE_MAX_SWEEP_ENTRIES) {
            let path = entry.path();
            if path == self.file {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let old = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= PRESENCE_STALE_FILE_AGE);
            let ours = path
                .extension()
                .is_some_and(|extension| extension == "json" || extension == "tmp");
            if old && ours && metadata.is_file() {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "presence directory must be a real directory",
            ));
        }
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Self-declared names and versions are bounded and stripped of control
/// characters before they reach disk.
fn clean_client_field(value: &str) -> Option<String> {
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(PRESENCE_MAX_CLIENT_FIELD_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The crate has no tempfile dev-dependency; a unique dir under the
    /// system temp dir, removed on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let dir = std::env::temp_dir().join(format!("fluxgit-presence-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir.canonicalize().unwrap())
    }

    fn read(recorder: &PresenceRecorder) -> Value {
        serde_json::from_slice(&fs::read(recorder.file_path()).unwrap()).unwrap()
    }

    #[test]
    fn records_client_repo_time_and_tool_without_arguments() {
        let temp = tempdir();
        let recorder = PresenceRecorder::new(temp.path().join("presence/mcp"));
        recorder.note_initialize_version(Some("2.1.0"));
        recorder.record(
            Some("claude-code"),
            None,
            Path::new("/work/api"),
            "repo.status",
            1_000,
        );
        let document = read(&recorder);
        assert_eq!(document["schemaVersion"], 1);
        assert_eq!(document["client"]["name"], "claude-code");
        assert_eq!(document["client"]["version"], "2.1.0");
        assert_eq!(document["repos"][0]["repoPath"], "/work/api");
        assert_eq!(document["repos"][0]["lastCallMs"], 1_000);
        assert_eq!(document["repos"][0]["lastTool"], "repo.status");
        assert_eq!(document["repos"][0].as_object().unwrap().len(), 3);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(recorder.file_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A request-level version wins; the same repo moves to the front
        // instead of duplicating.
        recorder.record(
            Some("claude-code"),
            Some("2.2.0"),
            Path::new("/work/web"),
            "diff.text",
            2_000,
        );
        recorder.record(
            Some("claude-code"),
            Some("2.2.0"),
            Path::new("/work/api"),
            "operation.preview.commit",
            3_000,
        );
        let document = read(&recorder);
        assert_eq!(document["client"]["version"], "2.2.0");
        let repos = document["repos"].as_array().unwrap();
        assert_eq!(repos.len(), 2);
        assert_eq!(repos[0]["repoPath"], "/work/api");
        assert_eq!(repos[0]["lastTool"], "operation.preview.commit");
        assert_eq!(repos[1]["repoPath"], "/work/web");

        recorder.remove();
        assert!(!recorder.file_path().exists());
    }

    #[test]
    fn repositories_are_bounded_and_unidentified_clients_have_no_name() {
        let temp = tempdir();
        let recorder = PresenceRecorder::new(temp.path().to_path_buf());
        for index in 0..(PRESENCE_MAX_REPOS + 4) {
            recorder.record(
                None,
                Some("\u{7}"),
                Path::new(&format!("/work/r{index}")),
                "repo.brief",
                index as i64,
            );
        }
        let document = read(&recorder);
        assert!(document["client"]["name"].is_null());
        assert!(document["client"]["version"].is_null());
        let repos = document["repos"].as_array().unwrap();
        assert_eq!(repos.len(), PRESENCE_MAX_REPOS);
        assert_eq!(
            repos[0]["repoPath"],
            format!("/work/r{}", PRESENCE_MAX_REPOS + 3)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_presence_directory_is_refused() {
        let temp = tempdir();
        let target = temp.path().join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        let link = temp.path().join("mcp");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let recorder = PresenceRecorder::new(link);
        recorder.record(Some("codex"), None, Path::new("/w"), "repo.status", 1);
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }
}
