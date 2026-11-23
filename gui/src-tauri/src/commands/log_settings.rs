//! Settings → Logging: the GUI's log level and where the log file is.

use serde::Serialize;

use crate::error::CommandError;
use crate::file_log;
use crate::preferences::{self, parse_log_level, LOG_LEVELS};

#[derive(Debug, Serialize)]
pub struct LogSettings {
    /// The saved level (`off`, `error`, `warn`, `info`, `debug`, `trace`).
    pub level: String,
    /// Every level the setting accepts, in order of verbosity.
    pub levels: Vec<String>,
    /// The log file, or `None` when file logging is off or unavailable.
    pub path: Option<String>,
    /// `RUST_LOG` is set, so it decides the level and the setting is inert.
    pub env_override: bool,
}

fn current() -> Result<LogSettings, CommandError> {
    Ok(LogSettings {
        level: preferences::load()?.log.level,
        levels: LOG_LEVELS.iter().map(|l| (*l).to_string()).collect(),
        path: file_log::log_path().map(|p| p.display().to_string()),
        env_override: file_log::env_override(),
    })
}

#[tauri::command]
pub async fn get_log_settings() -> Result<LogSettings, CommandError> {
    current()
}

/// Validated before it is written, applied at once, and kept for the next
/// start. Loads strictly: an unreadable preferences file is reported, not
/// overwritten with defaults.
#[tauri::command]
pub async fn set_log_level(level: String) -> Result<LogSettings, CommandError> {
    let filter = parse_log_level(&level).map_err(CommandError::from)?;
    let mut all = preferences::load()?;
    all.log.level = level;
    preferences::save(&all)?;
    if !file_log::env_override() {
        log::set_max_level(filter);
    }
    log::info!("log level set to {filter}");
    current()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_level_parses_and_an_unknown_one_names_itself() {
        for level in LOG_LEVELS {
            assert!(parse_log_level(level).is_ok(), "{level}");
        }
        let err = parse_log_level("verbose").unwrap_err();
        assert!(err.contains("`verbose`") && err.contains("trace"), "{err}");
    }

    #[test]
    fn an_unknown_saved_level_falls_back_to_info_but_does_not_validate() {
        let prefs = preferences::LogPrefs { level: "loud".to_string() };
        assert_eq!(prefs.filter(), log::LevelFilter::Info);
        assert!(parse_log_level(&prefs.level).is_err(), "but a save of it is refused");
    }

    #[test]
    fn a_preferences_file_without_the_key_loads_as_info() {
        let prefs: preferences::Preferences = serde_json::from_str("{}").unwrap();
        assert_eq!(prefs.log, preferences::LogPrefs::default());
        assert_eq!(prefs.log.level, "info");
    }
}
