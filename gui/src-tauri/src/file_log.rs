//! Persistent GUI log (macOS, Windows, Linux): stderr plus an owner-only file
//! in the platform log directory, rotated once at startup past 5 MiB.
//! `BVAULT_GUI_LOG=off` keeps stderr only. It persists what stderr already
//! carried, so never log a secret, token, pairing bearer or clipboard data.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const APP_DIR: &str = "com.bastionvault.gui";
const LOG_FILE: &str = "bastion-vault-gui.log";
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const DISABLE_ENV: &str = "BVAULT_GUI_LOG";

/// `~/Library/Logs/<id>` on macOS.
#[cfg(target_os = "macos")]
pub fn log_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join("Library").join("Logs").join(APP_DIR))
}

/// `%LOCALAPPDATA%\<id>\logs` on Windows.
#[cfg(target_os = "windows")]
pub fn log_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join(APP_DIR).join("logs"))
}

/// `$XDG_STATE_HOME/<id>`, else `~/.local/state/<id>`, elsewhere.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn log_dir() -> Option<PathBuf> {
    dirs::state_dir().or_else(|| dirs::home_dir().map(|h| h.join(".local").join("state"))).map(|d| d.join(APP_DIR))
}

/// Whether `RUST_LOG` is set: the environment then decides the level.
pub fn env_override() -> bool {
    std::env::var_os("RUST_LOG").is_some()
}

/// The log file path; `None` when file logging is off or there is no home.
pub fn log_path() -> Option<PathBuf> {
    if std::env::var(DISABLE_ENV).is_ok_and(|v| v.eq_ignore_ascii_case("off")) {
        return None;
    }
    log_dir().map(|d| d.join(LOG_FILE))
}

/// Rotates `path` to `<path>.1` when it has reached `max` bytes.
fn rotate_if_needed(path: &Path, max: u64) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(meta) if meta.len() >= max => {
            let mut rotated = path.as_os_str().to_owned();
            rotated.push(".1");
            // Windows `rename` fails on an existing target: remove it first.
            let _ = fs::remove_file(&rotated);
            fs::rename(path, rotated)
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Creates the directory and opens the log for appending, after rotating an
/// oversized one. Directory `0700` and file `0600` on Unix.
fn open_log(path: &Path, max: u64) -> io::Result<File> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    rotate_if_needed(path, max)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Writes every record to stderr and, while it is healthy, to the file.
struct Tee {
    file: Option<File>,
}

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // stderr is authoritative: its result is what the logger sees.
        let written = io::stderr().write(buf)?;
        if let Some(file) = self.file.as_mut() {
            if let Err(e) = file.write_all(&buf[..written]) {
                eprintln!("file_log: log file write failed, continuing on stderr only: {e}");
                self.file = None;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        io::stderr().flush()
    }
}

/// The `env_logger` target and the file it writes to; plain stderr when the
/// file cannot be opened.
pub fn target() -> (env_logger::Target, Option<PathBuf>) {
    let Some(path) = log_path() else {
        return (env_logger::Target::Stderr, None);
    };
    match open_log(&path, MAX_LOG_BYTES) {
        Ok(file) => (env_logger::Target::Pipe(Box::new(Tee { file: Some(file) })), Some(path)),
        Err(e) => {
            eprintln!("file_log: cannot open {}: {e}; logging to stderr only", path.display());
            (env_logger::Target::Stderr, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bv-file-log-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn log_dir_is_under_the_app_identifier_on_every_platform() {
        let dir = log_dir().expect("a home directory exists in the test environment");
        assert!(dir.to_string_lossy().contains(APP_DIR), "{}", dir.display());
    }

    #[test]
    fn open_creates_the_directory_and_appends() {
        let dir = temp_dir("append");
        let path = dir.join("nested").join(LOG_FILE);
        writeln!(open_log(&path, MAX_LOG_BYTES).unwrap(), "first").unwrap();
        writeln!(open_log(&path, MAX_LOG_BYTES).unwrap(), "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\nsecond\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn file_and_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let path = dir.join("logs").join(LOG_FILE);
        open_log(&path, MAX_LOG_BYTES).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "the log file must not be readable by other users");
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_oversized_log_rotates_once_and_replaces_the_previous_rotation() {
        let dir = temp_dir("rotate");
        let path = dir.join(LOG_FILE);
        let rotated = dir.join(format!("{LOG_FILE}.1"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(&rotated, "ancient").unwrap();
        fs::write(&path, "0123456789").unwrap();

        // Under the limit: untouched.
        open_log(&path, 11).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "0123456789");
        assert_eq!(fs::read_to_string(&rotated).unwrap(), "ancient");

        // At the limit: the current file becomes `.1`, the old `.1` is gone.
        let mut file = open_log(&path, 10).unwrap();
        writeln!(file, "fresh").unwrap();
        assert_eq!(fs::read_to_string(&rotated).unwrap(), "0123456789");
        assert_eq!(fs::read_to_string(&path).unwrap(), "fresh\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_log_is_not_an_error_to_rotate() {
        let dir = temp_dir("missing");
        assert!(rotate_if_needed(&dir.join(LOG_FILE), 1).is_ok());
    }

    #[test]
    fn a_dead_file_does_not_stop_the_tee() {
        // A read-only handle fails every write; the tee must drop it.
        let dir = temp_dir("dead");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(LOG_FILE);
        fs::write(&path, "").unwrap();
        let mut tee = Tee { file: Some(File::open(&path).unwrap()) };
        assert_eq!(tee.write(b"x\n").unwrap(), 2);
        assert!(tee.file.is_none(), "a failing file is dropped, not retried on every record");
        let _ = fs::remove_dir_all(&dir);
    }
}
