//! Autostart on login via an XDG `~/.config/autostart/*.desktop` entry.
//!
//! On GNOME/KDE/XFCE and any XDG-compliant desktop, placing a `.desktop` file in
//! `~/.config/autostart/` with `X-GNOME-Autostart-enabled=true` causes the session
//! manager to launch the application on login.
//!
//! This module writes/removes the file at:
//!   `$HOME/.config/autostart/wireguard-gui-rust.desktop`

use std::fs;
use std::path::PathBuf;

use crate::error::{AppError, AppResult};

/// File name used inside `~/.config/autostart/`.
const DESKTOP_FILENAME: &str = "wireguard-gui-rust.desktop";

/// Reads/writes the autostart `.desktop` file.
pub struct AutostartManager {
    pub desktop_path: PathBuf,
}

impl AutostartManager {
    /// Construct with the default autostart `.desktop` path derived from `$HOME`.
    ///
    /// Returns `AppError::AutostartWriteFailed` if the home directory cannot be
    /// determined.
    pub fn new() -> AppResult<Self> {
        let home = dirs::home_dir().ok_or_else(|| {
            AppError::AutostartWriteFailed("cannot determine home directory".to_string())
        })?;
        let desktop_path = home
            .join(".config")
            .join("autostart")
            .join(DESKTOP_FILENAME);
        Ok(Self { desktop_path })
    }

    /// True if the autostart entry currently exists on disk.
    ///
    /// A file that exists but is malformed (e.g. has `X-GNOME-Autostart-enabled=false`)
    /// is still treated as "enabled" — the file's presence is the canonical signal.
    pub fn is_enabled(&self) -> bool {
        self.desktop_path.exists()
    }

    /// Write the autostart entry.
    ///
    /// Creates `~/.config/autostart/` if it does not yet exist.
    /// The `Exec` line uses the path of the current running executable so that the
    /// correct binary is launched regardless of how the user installed it.
    pub fn enable(&self) -> AppResult<()> {
        // Resolve the current executable path.
        let exe = std::env::current_exe().map_err(|e| {
            AppError::AutostartWriteFailed(format!("cannot resolve current_exe: {e}"))
        })?;

        // Ensure the parent directory exists.
        if let Some(parent) = self.desktop_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::AutostartWriteFailed(format!(
                    "cannot create autostart directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let contents = desktop_file_contents(&exe.to_string_lossy());

        fs::write(&self.desktop_path, &contents).map_err(|e| {
            AppError::AutostartWriteFailed(format!(
                "cannot write {}: {e}",
                self.desktop_path.display()
            ))
        })?;

        Ok(())
    }

    /// Remove the autostart entry.
    ///
    /// If the file does not exist this is a no-op (idempotent).
    pub fn disable(&self) -> AppResult<()> {
        if self.desktop_path.exists() {
            fs::remove_file(&self.desktop_path).map_err(|e| {
                AppError::AutostartWriteFailed(format!(
                    "cannot remove {}: {e}",
                    self.desktop_path.display()
                ))
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pure helper — split out so unit tests can call it without touching the FS.
// ---------------------------------------------------------------------------

/// Build the `.desktop` file contents for the given executable path string.
///
/// Produces a valid [Desktop Entry Specification 1.5] file with:
/// - `Type=Application`
/// - `Name=WireGuard GUI`
/// - `Exec=<exe> --hidden`  (start minimised / tray-only)
/// - `X-GNOME-Autostart-enabled=true`
/// - `Hidden=false`
///
/// [Desktop Entry Specification 1.5]: https://specifications.freedesktop.org/desktop-entry-spec/latest/
pub fn desktop_file_contents(exe_path: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=WireGuard GUI\n\
         Comment=WireGuard VPN manager\n\
         Exec={exe_path} --hidden\n\
         Hidden=false\n\
         X-GNOME-Autostart-enabled=true\n"
    )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Helper: construct an AutostartManager whose desktop_path lives inside a
    // temp directory, without touching the real $HOME.
    // -----------------------------------------------------------------------
    fn manager_in_temp(tmp: &TempDir) -> AutostartManager {
        let desktop_path = tmp
            .path()
            .join(".config")
            .join("autostart")
            .join(DESKTOP_FILENAME);
        AutostartManager { desktop_path }
    }

    // -----------------------------------------------------------------------
    // desktop_file_contents — golden-string tests (pure, no I/O)
    // -----------------------------------------------------------------------

    #[test]
    fn desktop_contents_has_desktop_entry_section() {
        let contents = desktop_file_contents("/usr/bin/wireguard-gui");
        assert!(
            contents.starts_with("[Desktop Entry]\n"),
            "must open with the [Desktop Entry] section header"
        );
    }

    #[test]
    fn desktop_contents_exec_line_uses_hidden_flag() {
        let exe = "/opt/wireguard-gui-rust/wireguard-gui";
        let contents = desktop_file_contents(exe);
        assert!(
            contents.contains(&format!("Exec={exe} --hidden\n")),
            "Exec line must use the given path and append --hidden: got:\n{contents}"
        );
    }

    #[test]
    fn desktop_contents_type_is_application() {
        let contents = desktop_file_contents("/usr/bin/wg-gui");
        assert!(
            contents.contains("Type=Application\n"),
            "Type must be Application"
        );
    }

    #[test]
    fn desktop_contents_autostart_enabled_true() {
        let contents = desktop_file_contents("/usr/bin/wg-gui");
        assert!(
            contents.contains("X-GNOME-Autostart-enabled=true\n"),
            "X-GNOME-Autostart-enabled must be true"
        );
    }

    #[test]
    fn desktop_contents_hidden_false() {
        // Hidden=false means the entry IS shown (not suppressed) by file managers.
        let contents = desktop_file_contents("/usr/bin/wg-gui");
        assert!(
            contents.contains("Hidden=false\n"),
            "Hidden must be false so the entry is active"
        );
    }

    #[test]
    fn desktop_contents_has_name_field() {
        let contents = desktop_file_contents("/usr/bin/wg-gui");
        assert!(
            contents.contains("Name=WireGuard GUI\n"),
            "Name field must be present"
        );
    }

    #[test]
    fn desktop_contents_exe_path_with_spaces() {
        // Paths with spaces are unusual but the format must still be correct.
        let exe = "/home/user/my apps/wireguard-gui";
        let contents = desktop_file_contents(exe);
        assert!(
            contents.contains(&format!("Exec={exe} --hidden\n")),
            "Exec must embed the literal exe string even when it contains spaces"
        );
    }

    // -----------------------------------------------------------------------
    // AutostartManager::new — path construction (overrides HOME)
    // -----------------------------------------------------------------------

    #[test]
    fn new_path_ends_with_expected_filename() {
        // new() uses dirs::home_dir() which reads $HOME. Point it at a temp dir.
        let tmp = TempDir::new().unwrap();
        // Save the original HOME so we can restore it afterwards (don't clobber it for
        // other tests in the same process).
        let original_home = env::var_os("HOME");
        // Override HOME so dirs::home_dir() resolves to our temp dir.
        // SAFETY: mutating the environment is `unsafe` in edition 2024 because it is not
        // thread-safe. No other test in this crate asserts on a HOME-derived path
        // unconditionally, so this transient override does not cause observable races.
        unsafe {
            env::set_var("HOME", tmp.path());
        }

        let mgr = AutostartManager::new().expect("new() must succeed when HOME is set");
        assert!(
            mgr.desktop_path.ends_with(
                std::path::Path::new(".config")
                    .join("autostart")
                    .join(DESKTOP_FILENAME)
            ),
            "desktop_path must end with .config/autostart/{DESKTOP_FILENAME}, got: {}",
            mgr.desktop_path.display()
        );

        // Restore HOME so other tests are not affected.
        // SAFETY: see the note on the set_var call above.
        unsafe {
            match original_home {
                Some(val) => env::set_var("HOME", val),
                None => env::remove_var("HOME"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // is_enabled — file-existence semantics
    // -----------------------------------------------------------------------

    #[test]
    fn is_enabled_returns_false_when_file_absent() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        assert!(!mgr.is_enabled(), "should be disabled when file does not exist");
    }

    #[test]
    fn is_enabled_returns_true_when_file_present() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        // Create the parent directory and file manually.
        fs::create_dir_all(mgr.desktop_path.parent().unwrap()).unwrap();
        fs::write(&mgr.desktop_path, "[Desktop Entry]\n").unwrap();
        assert!(mgr.is_enabled(), "should be enabled when file exists");
    }

    // -----------------------------------------------------------------------
    // enable() — creates directory + writes correct content
    // -----------------------------------------------------------------------

    #[test]
    fn enable_creates_directory_and_file() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);

        // Parent directory must NOT exist yet — enable() must create it.
        assert!(!mgr.desktop_path.parent().unwrap().exists());

        mgr.enable().expect("enable() must succeed");

        assert!(
            mgr.desktop_path.exists(),
            "desktop file must exist after enable()"
        );
    }

    #[test]
    fn enable_sets_is_enabled_true() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        mgr.enable().unwrap();
        assert!(mgr.is_enabled());
    }

    #[test]
    fn enable_writes_valid_desktop_entry_header() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        mgr.enable().unwrap();

        let contents = fs::read_to_string(&mgr.desktop_path).unwrap();
        assert!(
            contents.starts_with("[Desktop Entry]\n"),
            "written file must start with [Desktop Entry] section"
        );
    }

    #[test]
    fn enable_writes_hidden_flag_in_exec_line() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        mgr.enable().unwrap();

        let contents = fs::read_to_string(&mgr.desktop_path).unwrap();
        // We cannot predict the exact exe path in tests, but --hidden must appear.
        assert!(
            contents.contains("--hidden"),
            "Exec line must include --hidden: got:\n{contents}"
        );
    }

    #[test]
    fn enable_writes_autostart_enabled_true() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        mgr.enable().unwrap();

        let contents = fs::read_to_string(&mgr.desktop_path).unwrap();
        assert!(
            contents.contains("X-GNOME-Autostart-enabled=true"),
            "file must contain X-GNOME-Autostart-enabled=true: got:\n{contents}"
        );
    }

    #[test]
    fn enable_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        mgr.enable().unwrap();
        // Calling a second time must not fail or change the is_enabled outcome.
        mgr.enable().expect("second enable() call must succeed");
        assert!(mgr.is_enabled());
    }

    // -----------------------------------------------------------------------
    // disable() — removes file; idempotent
    // -----------------------------------------------------------------------

    #[test]
    fn disable_removes_file() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        mgr.enable().unwrap();
        assert!(mgr.is_enabled());

        mgr.disable().expect("disable() must succeed");
        assert!(
            !mgr.is_enabled(),
            "desktop file must be absent after disable()"
        );
    }

    #[test]
    fn disable_is_idempotent_when_file_absent() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);
        // File never existed — disable() must be a no-op, not an error.
        mgr.disable().expect("disable() must succeed even when file is absent");
        assert!(!mgr.is_enabled());
    }

    #[test]
    fn disable_after_enable_after_disable_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mgr = manager_in_temp(&tmp);

        mgr.enable().unwrap();
        assert!(mgr.is_enabled());

        mgr.disable().unwrap();
        assert!(!mgr.is_enabled());

        mgr.enable().unwrap();
        assert!(mgr.is_enabled());
    }
}
