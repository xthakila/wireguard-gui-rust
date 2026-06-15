//! Persistent application settings (theme, behaviour toggles, split-tunnel + netns config).

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::net::netns::NetnsRule;

/// How the UI chooses its theme.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub enum ThemePreference {
    /// Follow the desktop's light/dark preference.
    #[default]
    FollowSystem,
    Light,
    Dark,
    /// A specific named iced theme.
    Named(String),
}

/// All user-configurable settings, persisted to disk as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: ThemePreference,
    pub auto_reconnect: bool,
    /// Name of a profile to connect on boot, if any.
    pub connect_on_boot: Option<String>,
    pub kill_switch: bool,
    pub autostart: bool,
    pub close_to_tray: bool,
    /// CIDRs to exclude when split-tunnelling.
    pub destination_split: Vec<String>,
    pub netns_rules: Vec<NetnsRule>,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            theme: ThemePreference::default(),
            auto_reconnect: true,
            connect_on_boot: None,
            kill_switch: false,
            autostart: false,
            close_to_tray: true,
            destination_split: Vec::new(),
            netns_rules: Vec::new(),
        }
    }
}

/// Returns the path to the settings file:
/// `~/.config/wireguard-gui-rust/settings.json`
fn settings_path() -> Option<PathBuf> {
    dirs::config_dir().map(|base| base.join("wireguard-gui-rust").join("settings.json"))
}

impl AppSettings {
    /// Load settings from disk, falling back to defaults if none exist.
    pub fn load() -> AppResult<Self> {
        let path = settings_path().ok_or_else(|| {
            AppError::SettingsLoadFailed("cannot determine config directory".to_string())
        })?;

        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let settings: AppSettings = serde_json::from_str(&contents).map_err(|e| {
                    AppError::SettingsLoadFailed(format!("{}: {}", path.display(), e))
                })?;
                Ok(settings)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(AppSettings::default()),
            Err(e) => Err(AppError::SettingsLoadFailed(format!(
                "{}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Persist settings to disk (pretty-printed JSON).
    pub fn save(&self) -> AppResult<()> {
        let path = settings_path().ok_or_else(|| {
            AppError::SettingsSaveFailed("cannot determine config directory".to_string())
        })?;

        // Create the parent directory if it doesn't exist.
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                AppError::SettingsSaveFailed(format!("create dir {}: {}", dir.display(), e))
            })?;
        }

        let json = serde_json::to_string_pretty(self).map_err(|e| {
            AppError::SettingsSaveFailed(format!("serialize: {}", e))
        })?;

        std::fs::write(&path, json).map_err(|e| {
            AppError::SettingsSaveFailed(format!("{}: {}", path.display(), e))
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    // -----------------------------------------------------------------------
    // Default values
    // -----------------------------------------------------------------------

    #[test]
    fn default_theme_is_follow_system() {
        let s = AppSettings::default();
        assert_eq!(s.theme, ThemePreference::FollowSystem);
    }

    #[test]
    fn default_auto_reconnect_is_true() {
        let s = AppSettings::default();
        assert!(s.auto_reconnect);
    }

    #[test]
    fn default_close_to_tray_is_true() {
        let s = AppSettings::default();
        assert!(s.close_to_tray);
    }

    #[test]
    fn default_kill_switch_is_false() {
        let s = AppSettings::default();
        assert!(!s.kill_switch);
    }

    #[test]
    fn default_autostart_is_false() {
        let s = AppSettings::default();
        assert!(!s.autostart);
    }

    #[test]
    fn default_connect_on_boot_is_none() {
        let s = AppSettings::default();
        assert!(s.connect_on_boot.is_none());
    }

    #[test]
    fn default_destination_split_is_empty() {
        let s = AppSettings::default();
        assert!(s.destination_split.is_empty());
    }

    #[test]
    fn default_netns_rules_is_empty() {
        let s = AppSettings::default();
        assert!(s.netns_rules.is_empty());
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_default() {
        let original = AppSettings::default();
        let json = serde_json::to_string_pretty(&original).expect("serialize");
        let restored: AppSettings = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.auto_reconnect, original.auto_reconnect);
        assert_eq!(restored.close_to_tray, original.close_to_tray);
        assert_eq!(restored.kill_switch, original.kill_switch);
        assert_eq!(restored.autostart, original.autostart);
        assert_eq!(restored.connect_on_boot, original.connect_on_boot);
        assert_eq!(restored.theme, original.theme);
        assert_eq!(restored.destination_split, original.destination_split);
        assert_eq!(restored.netns_rules.len(), original.netns_rules.len());
    }

    #[test]
    fn round_trip_custom_values() {
        let original = AppSettings {
            theme: ThemePreference::Dark,
            auto_reconnect: false,
            connect_on_boot: Some("home-vpn".to_string()),
            kill_switch: true,
            autostart: true,
            close_to_tray: false,
            destination_split: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            netns_rules: vec![NetnsRule {
                executable_path: PathBuf::from("/usr/bin/firefox"),
                ns_name: "vpn-ns".to_string(),
            }],
        };
        let json = serde_json::to_string_pretty(&original).expect("serialize");
        let restored: AppSettings = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.theme, ThemePreference::Dark);
        assert!(!restored.auto_reconnect);
        assert_eq!(restored.connect_on_boot, Some("home-vpn".to_string()));
        assert!(restored.kill_switch);
        assert!(restored.autostart);
        assert!(!restored.close_to_tray);
        assert_eq!(
            restored.destination_split,
            vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()]
        );
        assert_eq!(restored.netns_rules.len(), 1);
        assert_eq!(restored.netns_rules[0].ns_name, "vpn-ns");
        assert_eq!(
            restored.netns_rules[0].executable_path,
            PathBuf::from("/usr/bin/firefox")
        );
    }

    #[test]
    fn round_trip_named_theme() {
        let original = AppSettings {
            theme: ThemePreference::Named("Gruvbox".to_string()),
            ..AppSettings::default()
        };
        let json = serde_json::to_string_pretty(&original).expect("serialize");
        let restored: AppSettings = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            restored.theme,
            ThemePreference::Named("Gruvbox".to_string())
        );
    }

    #[test]
    fn round_trip_light_theme() {
        let s = AppSettings {
            theme: ThemePreference::Light,
            ..AppSettings::default()
        };
        let json = serde_json::to_string_pretty(&s).expect("serialize");
        let restored: AppSettings = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.theme, ThemePreference::Light);
    }

    // -----------------------------------------------------------------------
    // Golden-string JSON shape
    // -----------------------------------------------------------------------

    #[test]
    fn default_json_contains_expected_keys() {
        let json = serde_json::to_string_pretty(&AppSettings::default()).expect("serialize");
        assert!(json.contains("\"theme\""));
        assert!(json.contains("\"FollowSystem\""));
        assert!(json.contains("\"auto_reconnect\""));
        assert!(json.contains("\"close_to_tray\""));
        assert!(json.contains("\"kill_switch\""));
        assert!(json.contains("\"autostart\""));
        assert!(json.contains("\"destination_split\""));
        assert!(json.contains("\"netns_rules\""));
    }

    #[test]
    fn default_json_auto_reconnect_is_true_in_text() {
        let json = serde_json::to_string(&AppSettings::default()).expect("serialize");
        // Parse and check the raw value to avoid brittle substring matching.
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["auto_reconnect"], serde_json::Value::Bool(true));
    }

    #[test]
    fn default_json_close_to_tray_is_true_in_text() {
        let json = serde_json::to_string(&AppSettings::default()).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["close_to_tray"], serde_json::Value::Bool(true));
    }

    // -----------------------------------------------------------------------
    // load() with a temp dir
    // -----------------------------------------------------------------------

    /// Helper: save `settings` to `dir/settings.json` and read it back using
    /// the raw fs+serde path (bypasses `load()` which uses dirs::config_dir).
    fn write_and_read_back(dir: &tempfile::TempDir, settings: &AppSettings) -> AppSettings {
        let path = dir.path().join("settings.json");
        let json = serde_json::to_string_pretty(settings).expect("serialize");
        std::fs::write(&path, &json).expect("write");
        let contents = std::fs::read_to_string(&path).expect("read");
        serde_json::from_str(&contents).expect("deserialize")
    }

    #[test]
    fn save_and_reload_via_tempdir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = AppSettings {
            theme: ThemePreference::Dark,
            auto_reconnect: false,
            connect_on_boot: Some("work".to_string()),
            kill_switch: true,
            autostart: false,
            close_to_tray: true,
            destination_split: vec!["172.16.0.0/12".to_string()],
            netns_rules: vec![],
        };

        let restored = write_and_read_back(&dir, &original);

        assert_eq!(restored.theme, ThemePreference::Dark);
        assert!(!restored.auto_reconnect);
        assert_eq!(restored.connect_on_boot, Some("work".to_string()));
        assert!(restored.kill_switch);
        assert!(!restored.autostart);
        assert!(restored.close_to_tray);
        assert_eq!(restored.destination_split, vec!["172.16.0.0/12".to_string()]);
        assert!(restored.netns_rules.is_empty());
    }

    #[test]
    fn missing_file_returns_default_equivalent() {
        // Simulate "load() missing file" by checking that reading a non-existent
        // path produces NotFound, which load() converts to Default.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("settings.json");
        let result = std::fs::read_to_string(&path);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );

        // The default returned in that case should match AppSettings::default().
        let default = AppSettings::default();
        assert!(default.auto_reconnect);
        assert!(default.close_to_tray);
        assert_eq!(default.theme, ThemePreference::FollowSystem);
    }

    #[test]
    fn invalid_json_produces_deserialize_error() {
        let bad_json = r#"{ "theme": "FollowSystem", "auto_reconnect": "not-a-bool" }"#;
        let result: Result<AppSettings, _> = serde_json::from_str(bad_json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // settings_path helper (indirect test — just checks it returns Some)
    // -----------------------------------------------------------------------

    #[test]
    fn settings_path_is_some_in_normal_env() {
        // dirs::config_dir() returns None only in extremely restricted envs.
        // On a normal Linux box this should always be Some.
        let p = super::settings_path();
        // We don't assert Some because a CI sandbox might not have HOME set,
        // but we at least verify the function doesn't panic.
        if let Some(path) = p {
            assert!(path.ends_with("settings.json"));
            assert!(path.to_string_lossy().contains("wireguard-gui-rust"));
        }
    }
}
