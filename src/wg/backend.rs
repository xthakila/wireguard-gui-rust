//! Pluggable tunnel backends. `NmBackend` drives NetworkManager; `WgQuickBackend` shells
//! out to `wg-quick`. `detect_backend` picks the best available at runtime.

use std::path::PathBuf;

use tokio::process::Command;

use crate::config::profile::WgProfile;
use crate::error::{AppError, AppResult};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A way to bring a WireGuard tunnel up and down.
#[async_trait::async_trait]
pub trait WgBackend: Send + Sync {
    /// Bring up the tunnel described by `profile`.
    async fn connect(&self, profile: &WgProfile) -> AppResult<()>;

    /// Tear down the tunnel on interface `iface`.
    async fn disconnect(&self, iface: &str) -> AppResult<()>;

    /// The currently-active WireGuard interface name, if any.
    async fn active_interface(&self) -> AppResult<Option<String>>;
}

// ---------------------------------------------------------------------------
// Pure argv builders (testable without any I/O)
// ---------------------------------------------------------------------------

/// Connection name used in NetworkManager for a given profile.
///
/// Always `wg-gui-<profile_name>` so we can reliably find and remove it.
pub fn nm_connection_name(profile_name: &str) -> String {
    format!("wg-gui-{}", profile_name)
}

/// Build the `nmcli connection import` argv for a WireGuard `.conf` file.
///
/// Returns `(import_argv, modify_argv)` where `modify_argv` renames the
/// connection and disables autoconnect.
pub fn nm_import_argv(conf_path: &str, conn_name: &str) -> (Vec<String>, Vec<String>) {
    let import = vec![
        "connection".to_string(),
        "import".to_string(),
        "type".to_string(),
        "wireguard".to_string(),
        "file".to_string(),
        conf_path.to_string(),
    ];
    let modify = vec![
        "connection".to_string(),
        "modify".to_string(),
        conn_name.to_string(),
        "connection.id".to_string(),
        conn_name.to_string(),
        "connection.autoconnect".to_string(),
        "no".to_string(),
    ];
    (import, modify)
}

/// Build the `nmcli connection up <name>` argv.
pub fn nm_up_argv(conn_name: &str) -> Vec<String> {
    vec![
        "connection".to_string(),
        "up".to_string(),
        conn_name.to_string(),
    ]
}

/// Build the `nmcli connection down <name>` argv.
pub fn nm_down_argv(conn_name: &str) -> Vec<String> {
    vec![
        "connection".to_string(),
        "down".to_string(),
        conn_name.to_string(),
    ]
}

/// Build the argv for listing active connections in terse format with fields TYPE,NAME,DEVICE.
pub fn nm_list_active_argv() -> Vec<String> {
    vec![
        "--terse".to_string(),
        "--fields".to_string(),
        "TYPE,NAME,DEVICE".to_string(),
        "connection".to_string(),
        "show".to_string(),
        "--active".to_string(),
    ]
}

/// Build the `wg-quick up <conf_path>` argv (to be launched under pkexec).
pub fn wgquick_up_argv(conf_path: &str) -> Vec<String> {
    vec![
        "wg-quick".to_string(),
        "up".to_string(),
        conf_path.to_string(),
    ]
}

/// Build the `wg-quick down <conf_path>` argv (to be launched under pkexec).
pub fn wgquick_down_argv(conf_path: &str) -> Vec<String> {
    vec![
        "wg-quick".to_string(),
        "down".to_string(),
        conf_path.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

/// Run `nmcli` with `args` and return stdout on success.
async fn run_nmcli(args: &[String]) -> AppResult<String> {
    let output = Command::new("nmcli")
        .args(args)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::WgNotFound
            } else {
                AppError::WgQuickFailed(format!("nmcli spawn error: {}", e))
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::WgQuickFailed(format!(
            "nmcli {:?} failed ({}): {}",
            args.first().map(|s| s.as_str()).unwrap_or(""),
            output.status,
            stderr.trim(),
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run `pkexec` with `args` and return stdout on success.
///
/// pkexec exits 126 when the user cancels the polkit dialog.
async fn run_pkexec(args: &[String]) -> AppResult<String> {
    let output = Command::new("pkexec")
        .args(args)
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::WgNotFound
            } else {
                AppError::WgQuickFailed(format!("pkexec spawn error: {}", e))
            }
        })?;

    if !output.status.success() {
        if output.status.code() == Some(126) {
            return Err(AppError::PermissionDenied);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(AppError::WgQuickFailed(format!(
            "pkexec wg-quick failed ({}): {} {}",
            output.status,
            stderr.trim(),
            stdout.trim(),
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Write a profile's conf text to a temporary file and return the path.
///
/// The caller is responsible for cleanup (we do best-effort removal after
/// each connect/disconnect call).
async fn write_temp_conf(profile: &WgProfile) -> AppResult<PathBuf> {
    use tokio::io::AsyncWriteExt;
    let dir = std::env::temp_dir();
    let path = dir.join(format!("wg-gui-{}.conf", profile.name));
    let mut f = tokio::fs::File::create(&path).await.map_err(|e| {
        AppError::ProfileIo(format!("cannot create temp conf: {}", e))
    })?;
    f.write_all(profile.to_conf_string().as_bytes())
        .await
        .map_err(|e| AppError::ProfileIo(format!("cannot write temp conf: {}", e)))?;
    Ok(path)
}

/// Parse `nmcli --terse --fields TYPE,NAME,DEVICE connection show --active` output.
///
/// Each terse output line has the form `TYPE:NAME:DEVICE`.
/// Returns the first WireGuard device name (not connection name).
pub fn parse_nm_active_wireguard(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() >= 3 {
            let conn_type = parts[0].trim();
            let device = parts[2].trim();
            if conn_type.eq_ignore_ascii_case("wireguard")
                && !device.is_empty()
                && device != "--"
            {
                return Some(device.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// NmBackend
// ---------------------------------------------------------------------------

/// NetworkManager-backed implementation.
///
/// Connect sequence:
///   1. Serialise profile to a temp `.conf` file.
///   2. Import via `nmcli connection import type wireguard file <path>`.
///   3. Rename + set `autoconnect=no` via `nmcli connection modify`.
///   4. Down any other active WireGuard connection first.
///   5. `nmcli connection up <name>`.
pub struct NmBackend;

#[async_trait::async_trait]
impl WgBackend for NmBackend {
    async fn connect(&self, profile: &WgProfile) -> AppResult<()> {
        let conn_name = nm_connection_name(&profile.name);

        // 1. Write temp conf
        let conf_path = write_temp_conf(profile).await?;
        let conf_str = conf_path.to_string_lossy().into_owned();

        // 2. Import
        let (import_args, _) = nm_import_argv(&conf_str, &conn_name);
        run_nmcli(&import_args).await?;

        // 3. Rename + autoconnect off (best-effort — may already be set)
        let (_, modify_args) = nm_import_argv(&conf_str, &conn_name);
        let _ = run_nmcli(&modify_args).await;

        // 4. Bring down any other active WireGuard connection
        if let Ok(Some(active_dev)) = self.active_interface().await {
            let down_args = nm_down_argv(&active_dev);
            let _ = run_nmcli(&down_args).await;
        }

        // 5. Bring up this connection
        run_nmcli(&nm_up_argv(&conn_name)).await?;

        // Cleanup temp file (best-effort)
        let _ = tokio::fs::remove_file(&conf_path).await;

        Ok(())
    }

    async fn disconnect(&self, iface: &str) -> AppResult<()> {
        let args = nm_down_argv(iface);
        run_nmcli(&args).await?;
        Ok(())
    }

    async fn active_interface(&self) -> AppResult<Option<String>> {
        let args = nm_list_active_argv();
        let output = run_nmcli(&args).await?;
        Ok(parse_nm_active_wireguard(&output))
    }
}

// ---------------------------------------------------------------------------
// WgQuickBackend
// ---------------------------------------------------------------------------

/// `wg-quick`-backed implementation (uses `pkexec` for privilege elevation).
///
/// Connect: serialise profile to a temp `.conf`, run `pkexec wg-quick up <path>`.
/// Disconnect: locate system conf, run `pkexec wg-quick down <path>`.
pub struct WgQuickBackend;

impl WgQuickBackend {
    /// Return the `.conf` path for `iface`.
    ///
    /// Checks `/etc/wireguard/<iface>.conf` (system-wide); falls back to that
    /// path even if it does not exist — wg-quick will produce a useful error.
    fn conf_path_for_iface(&self, iface: &str) -> PathBuf {
        PathBuf::from(format!("/etc/wireguard/{}.conf", iface))
    }
}

#[async_trait::async_trait]
impl WgBackend for WgQuickBackend {
    async fn connect(&self, profile: &WgProfile) -> AppResult<()> {
        let conf_path = write_temp_conf(profile).await?;
        let conf_str = conf_path.to_string_lossy().into_owned();
        let args = wgquick_up_argv(&conf_str);
        let result = run_pkexec(&args).await;
        let _ = tokio::fs::remove_file(&conf_path).await;
        result?;
        Ok(())
    }

    async fn disconnect(&self, iface: &str) -> AppResult<()> {
        let conf_path = self.conf_path_for_iface(iface);
        let conf_str = conf_path.to_string_lossy().into_owned();
        let args = wgquick_down_argv(&conf_str);
        run_pkexec(&args).await?;
        Ok(())
    }

    async fn active_interface(&self) -> AppResult<Option<String>> {
        // `wg show interfaces` prints a space-separated list of active WireGuard interfaces.
        let output = Command::new("wg")
            .args(["show", "interfaces"])
            .output()
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    AppError::WgNotFound
                } else {
                    AppError::WgQuickFailed(format!("wg show interfaces: {}", e))
                }
            })?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.split_whitespace().next().map(|s| s.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Backend detection
// ---------------------------------------------------------------------------

/// Detect and return the best available backend for this system.
///
/// Prefers `NmBackend` when `nmcli` is found on PATH; falls back to
/// `WgQuickBackend`.
pub async fn detect_backend() -> Box<dyn WgBackend> {
    if tool_on_path("nmcli").await {
        return Box::new(NmBackend);
    }
    Box::new(WgQuickBackend)
}

/// Return true if `program` is found on PATH via `which`.
async fn tool_on_path(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Unit tests (pure argv builders and output parsers — no I/O, no root)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- nm_connection_name -------------------------------------------------

    #[test]
    fn nm_conn_name_prefix() {
        assert_eq!(nm_connection_name("home"), "wg-gui-home");
        assert_eq!(nm_connection_name("work-vpn"), "wg-gui-work-vpn");
        assert_eq!(nm_connection_name(""), "wg-gui-");
    }

    // --- nm_import_argv -----------------------------------------------------

    #[test]
    fn nm_import_argv_golden() {
        let (import, modify) =
            nm_import_argv("/tmp/wg-gui-home.conf", "wg-gui-home");

        assert_eq!(
            import,
            vec![
                "connection",
                "import",
                "type",
                "wireguard",
                "file",
                "/tmp/wg-gui-home.conf",
            ]
        );

        assert_eq!(
            modify,
            vec![
                "connection",
                "modify",
                "wg-gui-home",
                "connection.id",
                "wg-gui-home",
                "connection.autoconnect",
                "no",
            ]
        );
    }

    #[test]
    fn nm_import_argv_path_with_spaces() {
        // Paths with spaces must land as a single argument — no shell quoting
        // needed because we pass argv arrays directly to Command::args().
        let (import, _) = nm_import_argv("/tmp/my profiles/wg.conf", "wg-gui-x");
        assert_eq!(import[5], "/tmp/my profiles/wg.conf");
    }

    // --- nm_up / nm_down argv -----------------------------------------------

    #[test]
    fn nm_up_argv_golden() {
        assert_eq!(
            nm_up_argv("wg-gui-home"),
            vec!["connection", "up", "wg-gui-home"]
        );
    }

    #[test]
    fn nm_down_argv_golden() {
        assert_eq!(
            nm_down_argv("wg-gui-home"),
            vec!["connection", "down", "wg-gui-home"]
        );
    }

    // --- nm_list_active_argv ------------------------------------------------

    #[test]
    fn nm_list_active_argv_shape() {
        let argv = nm_list_active_argv();
        assert_eq!(argv[0], "--terse");
        assert_eq!(argv[1], "--fields");
        assert_eq!(argv[2], "TYPE,NAME,DEVICE");
        assert_eq!(argv[3], "connection");
        assert_eq!(argv[4], "show");
        assert_eq!(argv[5], "--active");
        assert_eq!(argv.len(), 6);
    }

    // --- parse_nm_active_wireguard ------------------------------------------

    #[test]
    fn parse_nm_active_finds_wg() {
        let raw = "ethernet:Wired connection 1:eth0\nwireguard:wg-gui-home:wg0\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg0".to_string()));
    }

    #[test]
    fn parse_nm_active_no_wg() {
        let raw = "ethernet:Wired connection 1:eth0\n";
        assert_eq!(parse_nm_active_wireguard(raw), None);
    }

    #[test]
    fn parse_nm_active_empty_input() {
        assert_eq!(parse_nm_active_wireguard(""), None);
    }

    #[test]
    fn parse_nm_active_skips_dash_device() {
        // NM shows "--" for connections without a bound device
        let raw = "wireguard:wg-gui-home:--\nwireguard:wg-gui-work:wg0\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg0".to_string()));
    }

    #[test]
    fn parse_nm_active_case_insensitive_type() {
        let raw = "WireGuard:wg-gui-home:wg0\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg0".to_string()));
    }

    #[test]
    fn parse_nm_active_returns_first() {
        let raw = "wireguard:wg-gui-a:wg0\nwireguard:wg-gui-b:wg1\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg0".to_string()));
    }

    // --- wgquick argv builders ----------------------------------------------

    #[test]
    fn wgquick_up_argv_golden() {
        assert_eq!(
            wgquick_up_argv("/etc/wireguard/home.conf"),
            vec!["wg-quick", "up", "/etc/wireguard/home.conf"]
        );
    }

    #[test]
    fn wgquick_down_argv_golden() {
        assert_eq!(
            wgquick_down_argv("/etc/wireguard/home.conf"),
            vec!["wg-quick", "down", "/etc/wireguard/home.conf"]
        );
    }

    #[test]
    fn wgquick_up_argv_temp_path() {
        let path = "/tmp/wg-gui-work-vpn.conf";
        let argv = wgquick_up_argv(path);
        assert_eq!(argv, vec!["wg-quick", "up", path]);
        assert_eq!(argv.len(), 3);
    }

    #[test]
    fn wgquick_down_argv_temp_path() {
        let path = "/tmp/wg-gui-work-vpn.conf";
        let argv = wgquick_down_argv(path);
        assert_eq!(argv, vec!["wg-quick", "down", path]);
        assert_eq!(argv.len(), 3);
    }
}
