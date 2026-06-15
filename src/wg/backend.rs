//! Pluggable tunnel backends. `NmBackend` drives NetworkManager; `WgQuickBackend` shells
//! out to `wg-quick`. `detect_backend` picks the best available at runtime.

use std::path::PathBuf;

use tokio::process::Command;

use crate::config::profile::WgProfile;
use crate::error::{AppError, AppResult};
use crate::net::privilege::{run_privileged, PrivCmd};

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
// Fixed client interface
// ---------------------------------------------------------------------------

/// The single, fixed kernel interface name used for the active client tunnel.
///
/// Linux interface names are capped at 15 chars (`IFNAMSIZ`). Deriving the name
/// from the profile (`wg-gui-<profile_name>`) routinely exceeded that limit —
/// `wg-gui-` is 7 chars and profile names may be up to 15, so the name could be
/// up to 22 chars and `nmcli connection import` / `wg-quick` would reject it.
///
/// The kernel interface name is therefore decoupled from the profile name: the
/// app is a single-active-client, so one fixed name (`wg-gui0`, 7 chars, always
/// `<= 15`, namespaced) is correct. The profile name remains identity/display
/// only (tracked in `app::State::active_profile`) and supplies the conf CONTENT.
pub const CLIENT_IFACE: &str = "wg-gui0";

// ---------------------------------------------------------------------------
// Pure argv builders (testable without any I/O)
// ---------------------------------------------------------------------------

/// Connection name used in NetworkManager for the active client tunnel.
///
/// Always the fixed [`CLIENT_IFACE`] (`wg-gui0`). The kernel interface name is
/// decoupled from the profile name (see [`CLIENT_IFACE`]); the argument is kept
/// only for call-site compatibility and is intentionally ignored.
pub fn nm_connection_name(_profile_name: &str) -> String {
    CLIENT_IFACE.to_string()
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

/// Build the `nmcli connection delete <name>` argv.
///
/// Used to clear a stale connection before (re-)import and to remove the
/// connection on disconnect. Callers ignore its error (a missing connection is
/// not a failure).
pub fn nm_delete_argv(conn_name: &str) -> Vec<String> {
    vec![
        "connection".to_string(),
        "delete".to_string(),
        conn_name.to_string(),
    ]
}

/// Build the `nmcli connection modify <name> connection.autoconnect no` argv.
pub fn nm_autoconnect_off_argv(conn_name: &str) -> Vec<String> {
    vec![
        "connection".to_string(),
        "modify".to_string(),
        conn_name.to_string(),
        "connection.autoconnect".to_string(),
        "no".to_string(),
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

/// Build the `wg-quick up <iface>` argv (to be launched under pkexec).
///
/// Takes the interface NAME ([`CLIENT_IFACE`] = `wg-gui0`), NOT a conf path:
/// `wg-quick` is AppArmor-confined to `/etc/wireguard`, so it can only read
/// `/etc/wireguard/wg-gui0.conf`. The conf is written there first by the helper
/// (`PrivCmd::ClientWriteConf`), and `wg-quick up wg-gui0` then resolves the conf
/// by interface name. Passing a `/run` or `/tmp` path here would fail with
/// `fopen: Permission denied` under AppArmor.
pub fn wgquick_up_argv(iface: &str) -> Vec<String> {
    vec!["wg-quick".to_string(), "up".to_string(), iface.to_string()]
}

/// Build the `wg-quick down <iface>` argv (to be launched under pkexec).
///
/// Takes the interface NAME ([`CLIENT_IFACE`] = `wg-gui0`) — symmetric with
/// [`wgquick_up_argv`]; `wg-quick down wg-gui0` reads `/etc/wireguard/wg-gui0.conf`.
pub fn wgquick_down_argv(iface: &str) -> Vec<String> {
    vec!["wg-quick".to_string(), "down".to_string(), iface.to_string()]
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

/// The stable on-disk path of the active client's `.conf` file.
///
/// The basename MUST be `<CLIENT_IFACE>.conf` (`wg-gui0.conf`): NetworkManager
/// derives the connection + interface name from the conf basename, and
/// `wg-quick down` needs the same path the tunnel was brought up with. The file
/// lives in a `wireguard-gui/` sub-directory under the user's runtime dir (or the
/// system temp dir when no runtime dir is available).
pub fn client_conf_path() -> PathBuf {
    let base = dirs::runtime_dir().unwrap_or_else(std::env::temp_dir);
    base.join("wireguard-gui")
        .join(format!("{}.conf", CLIENT_IFACE))
}

/// Write a profile's conf text to the stable client conf path and return it.
///
/// The file is intentionally KEPT after `connect` (wg-quick down needs it); it is
/// removed on disconnect via [`remove_client_conf`].
async fn write_client_conf(profile: &WgProfile) -> AppResult<PathBuf> {
    use tokio::io::AsyncWriteExt;
    let path = client_conf_path();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            AppError::ProfileIo(format!("cannot create conf dir: {}", e))
        })?;
    }
    let mut f = tokio::fs::File::create(&path).await.map_err(|e| {
        AppError::ProfileIo(format!("cannot create conf file: {}", e))
    })?;
    f.write_all(profile.to_conf_string().as_bytes())
        .await
        .map_err(|e| AppError::ProfileIo(format!("cannot write conf file: {}", e)))?;
    Ok(path)
}

/// Best-effort removal of the stable client conf file (called on disconnect).
async fn remove_client_conf() {
    let _ = tokio::fs::remove_file(client_conf_path()).await;
}

/// Parse `nmcli --terse --fields TYPE,NAME,DEVICE connection show --active` output
/// and report whether OUR client connection ([`CLIENT_IFACE`]) is active.
///
/// Each terse output line has the form `TYPE:NAME:DEVICE`. We only recognise a
/// WireGuard connection whose NAME or DEVICE equals [`CLIENT_IFACE`] — this must
/// NOT report some other (e.g. server) WireGuard interface as the client.
///
/// Returns `Some(CLIENT_IFACE)` when our client connection is active, else `None`.
pub fn parse_nm_active_wireguard(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() >= 3 {
            let conn_type = parts[0].trim();
            let name = parts[1].trim();
            let device = parts[2].trim();
            if conn_type.eq_ignore_ascii_case("wireguard")
                && (name == CLIENT_IFACE || device == CLIENT_IFACE)
            {
                return Some(CLIENT_IFACE.to_string());
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
/// The kernel interface name is fixed ([`CLIENT_IFACE`] = `wg-gui0`), decoupled
/// from the profile name — see [`CLIENT_IFACE`] for why. The conf basename is
/// `wg-gui0.conf`, so NM names the imported connection + interface `wg-gui0`.
///
/// Connect sequence:
///   1. Serialise the profile to the stable `wg-gui0.conf` file.
///   2. Delete any stale `wg-gui0` connection (ignore error) so re-import works.
///   3. Import via `nmcli connection import type wireguard file <path>`.
///   4. Best-effort `connection.autoconnect no` on `wg-gui0`.
///   5. `nmcli connection up wg-gui0`.
///
/// We deliberately do NOT bring down other active WireGuard interfaces — the app
/// must coexist with a future server interface.
pub struct NmBackend;

#[async_trait::async_trait]
impl WgBackend for NmBackend {
    async fn connect(&self, profile: &WgProfile) -> AppResult<()> {
        // 1. Write the conf to the stable wg-gui0.conf path (kept while connected).
        let conf_path = write_client_conf(profile).await?;
        let conf_str = conf_path.to_string_lossy().into_owned();

        // 2. Clear a stale connection so re-import succeeds (ignore "not found").
        let _ = run_nmcli(&nm_delete_argv(CLIENT_IFACE)).await;

        // 3. Import (NM derives the connection + interface name "wg-gui0" from the
        //    conf basename).
        let (import_args, _) = nm_import_argv(&conf_str, CLIENT_IFACE);
        run_nmcli(&import_args).await?;

        // 4. Disable autoconnect (best-effort — we drive up/down explicitly).
        let _ = run_nmcli(&nm_autoconnect_off_argv(CLIENT_IFACE)).await;

        // 5. Bring up our connection. (Do NOT touch other WireGuard interfaces.)
        run_nmcli(&nm_up_argv(CLIENT_IFACE)).await?;

        Ok(())
    }

    async fn disconnect(&self, iface: &str) -> AppResult<()> {
        // Down then delete (ignore errors — either may already be gone), then
        // remove the stable conf file.
        let _ = run_nmcli(&nm_down_argv(iface)).await;
        let _ = run_nmcli(&nm_delete_argv(iface)).await;
        remove_client_conf().await;
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
/// AppArmor confines `wg-quick` to `/etc/wireguard`, so it CANNOT read a conf
/// staged under `/run` or `/tmp` (the old behaviour failed with
/// `fopen: Permission denied` on NetworkManager-less systems). The conf is
/// therefore routed through the root helper EXACTLY like the server path:
///
/// Connect:
///   1. `PrivCmd::ClientWriteConf { conf_text }` → helper writes the conf to
///      `/etc/wireguard/wg-gui0.conf` (0600) — in-band, so the GUI never stages
///      the client private key world-readable.
///   2. `pkexec wg-quick up wg-gui0` (interface NAME, not a path) → wg-quick reads
///      `/etc/wireguard/wg-gui0.conf` from within its AppArmor profile.
///
/// Disconnect:
///   1. `pkexec wg-quick down wg-gui0`.
///   2. `PrivCmd::ClientRemoveConf` → helper removes `/etc/wireguard/wg-gui0.conf`
///      (idempotent).
///
/// The interface is always the fixed [`CLIENT_IFACE`] (`wg-gui0`); the conf
/// CONTENT comes from the profile.
pub struct WgQuickBackend;

#[async_trait::async_trait]
impl WgBackend for WgQuickBackend {
    async fn connect(&self, profile: &WgProfile) -> AppResult<()> {
        // 1. Hand the generated conf TEXT to the helper, which writes it to
        //    /etc/wireguard/wg-gui0.conf (0600) where AppArmor lets wg-quick read it.
        let conf_text = profile.to_conf_string();
        run_privileged(&PrivCmd::ClientWriteConf { conf_text }).await?;

        // 2. Bring the tunnel up by interface NAME so wg-quick resolves
        //    /etc/wireguard/wg-gui0.conf from within its AppArmor profile.
        let args = wgquick_up_argv(CLIENT_IFACE);
        if let Err(e) = run_pkexec(&args).await {
            // Connect failed → nothing is up, so drop the conf the helper wrote.
            let _ = run_privileged(&PrivCmd::ClientRemoveConf).await;
            return Err(e);
        }
        Ok(())
    }

    async fn disconnect(&self, _iface: &str) -> AppResult<()> {
        // 1. Bring the tunnel down by interface NAME (wg-quick reads the same
        //    /etc/wireguard/wg-gui0.conf it came up with).
        let args = wgquick_down_argv(CLIENT_IFACE);
        let result = run_pkexec(&args).await;
        // 2. Remove the helper-owned conf regardless of the down outcome.
        let _ = run_privileged(&PrivCmd::ClientRemoveConf).await;
        result?;
        Ok(())
    }

    async fn active_interface(&self) -> AppResult<Option<String>> {
        // `wg show interfaces` prints a space-separated list of active WireGuard
        // interfaces. Report CLIENT_IFACE iff it is among them — never some other
        // (server) interface.
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
        let active = stdout.split_whitespace().any(|i| i == CLIENT_IFACE);
        Ok(active.then(|| CLIENT_IFACE.to_string()))
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
    if detect_is_nm().await {
        return Box::new(NmBackend);
    }
    Box::new(WgQuickBackend)
}

/// True when the NetworkManager backend would be selected (i.e. `nmcli` is on PATH).
///
/// Used by callers that need to pick the connect-on-boot path (NM client-side
/// autoconnect vs. the privileged wg-quick/systemd unit) without constructing a
/// trait object.
pub async fn detect_is_nm() -> bool {
    tool_on_path("nmcli").await
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

    // --- CLIENT_IFACE invariant ---------------------------------------------

    #[test]
    fn client_iface_is_valid_kernel_name() {
        // Must be <= 15 chars (IFNAMSIZ) and namespaced for this app.
        assert!(CLIENT_IFACE.len() <= 15, "CLIENT_IFACE exceeds IFNAMSIZ");
        assert_eq!(CLIENT_IFACE, "wg-gui0");
    }

    #[test]
    fn client_conf_basename_matches_iface() {
        // NM derives the connection + interface name from the conf basename, so
        // the basename MUST be `<CLIENT_IFACE>.conf`.
        let path = client_conf_path();
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("wg-gui0.conf")
        );
    }

    // --- nm_connection_name -------------------------------------------------

    #[test]
    fn nm_conn_name_is_fixed_client_iface() {
        // Decoupled from the profile name: always the fixed CLIENT_IFACE,
        // regardless of (and short enough whatever) the profile name.
        assert_eq!(nm_connection_name("home"), "wg-gui0");
        assert_eq!(nm_connection_name("work-vpn"), "wg-gui0");
        assert_eq!(nm_connection_name("homeserver-long-name"), "wg-gui0");
        assert_eq!(nm_connection_name(""), "wg-gui0");
    }

    // --- nm_import_argv -----------------------------------------------------

    #[test]
    fn nm_import_argv_golden() {
        let (import, modify) =
            nm_import_argv("/tmp/wg-gui0.conf", "wg-gui0");

        assert_eq!(
            import,
            vec![
                "connection",
                "import",
                "type",
                "wireguard",
                "file",
                "/tmp/wg-gui0.conf",
            ]
        );

        assert_eq!(
            modify,
            vec![
                "connection",
                "modify",
                "wg-gui0",
                "connection.id",
                "wg-gui0",
                "connection.autoconnect",
                "no",
            ]
        );
    }

    #[test]
    fn nm_import_argv_path_with_spaces() {
        // Paths with spaces must land as a single argument — no shell quoting
        // needed because we pass argv arrays directly to Command::args().
        let (import, _) = nm_import_argv("/tmp/my profiles/wg.conf", "wg-gui0");
        assert_eq!(import[5], "/tmp/my profiles/wg.conf");
    }

    // --- nm_up / nm_down / nm_delete / nm_autoconnect_off argv --------------

    #[test]
    fn nm_up_argv_golden() {
        assert_eq!(
            nm_up_argv("wg-gui0"),
            vec!["connection", "up", "wg-gui0"]
        );
    }

    #[test]
    fn nm_down_argv_golden() {
        assert_eq!(
            nm_down_argv("wg-gui0"),
            vec!["connection", "down", "wg-gui0"]
        );
    }

    #[test]
    fn nm_delete_argv_golden() {
        assert_eq!(
            nm_delete_argv("wg-gui0"),
            vec!["connection", "delete", "wg-gui0"]
        );
    }

    #[test]
    fn nm_autoconnect_off_argv_golden() {
        assert_eq!(
            nm_autoconnect_off_argv("wg-gui0"),
            vec![
                "connection",
                "modify",
                "wg-gui0",
                "connection.autoconnect",
                "no",
            ]
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
    fn parse_nm_active_finds_our_client_by_name_and_device() {
        // NM names our connection AND its device "wg-gui0" (from the conf basename).
        let raw = "ethernet:Wired connection 1:eth0\nwireguard:wg-gui0:wg-gui0\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg-gui0".to_string()));
    }

    #[test]
    fn parse_nm_active_finds_our_client_by_name_only() {
        // Match on NAME even if DEVICE column differs.
        let raw = "wireguard:wg-gui0:wg5\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg-gui0".to_string()));
    }

    #[test]
    fn parse_nm_active_finds_our_client_by_device_only() {
        let raw = "wireguard:Some Imported Name:wg-gui0\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg-gui0".to_string()));
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
    fn parse_nm_active_ignores_other_wireguard_interface() {
        // A future SERVER WireGuard interface must NOT be reported as the client.
        let raw = "wireguard:wg-server:wg-server\nethernet:Wired:eth0\n";
        assert_eq!(parse_nm_active_wireguard(raw), None);
    }

    #[test]
    fn parse_nm_active_picks_client_among_others() {
        // Our client coexisting with a server interface — only the client matches.
        let raw = "wireguard:wg-server:wg-server\nwireguard:wg-gui0:wg-gui0\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg-gui0".to_string()));
    }

    #[test]
    fn parse_nm_active_case_insensitive_type() {
        let raw = "WireGuard:wg-gui0:wg-gui0\n";
        assert_eq!(parse_nm_active_wireguard(raw), Some("wg-gui0".to_string()));
    }

    // --- wgquick argv builders ----------------------------------------------

    #[test]
    fn wgquick_up_argv_golden() {
        // wg-quick now takes the interface NAME (wg-gui0), NOT a conf path:
        // AppArmor confines wg-quick to /etc/wireguard, so it reads
        // /etc/wireguard/wg-gui0.conf resolved from the interface name.
        assert_eq!(
            wgquick_up_argv(CLIENT_IFACE),
            vec!["wg-quick", "up", "wg-gui0"]
        );
    }

    #[test]
    fn wgquick_down_argv_golden() {
        assert_eq!(
            wgquick_down_argv(CLIENT_IFACE),
            vec!["wg-quick", "down", "wg-gui0"]
        );
    }

    #[test]
    fn wgquick_up_down_use_same_iface_name() {
        // up and down must reference the SAME interface name so wg-quick brings
        // down exactly what it brought up — and it must be the fixed CLIENT_IFACE
        // (a NAME, never a /run or /tmp path that AppArmor would reject).
        let up = wgquick_up_argv(CLIENT_IFACE);
        let down = wgquick_down_argv(CLIENT_IFACE);
        assert_eq!(up, vec!["wg-quick", "up", CLIENT_IFACE]);
        assert_eq!(down, vec!["wg-quick", "down", CLIENT_IFACE]);
        // Argument is the bare interface name (no path separators), so wg-quick
        // resolves /etc/wireguard/<iface>.conf within its AppArmor profile.
        assert!(!CLIENT_IFACE.contains('/'), "iface must not be a path: {CLIENT_IFACE}");
        assert_eq!(CLIENT_IFACE, "wg-gui0");
    }

    // -----------------------------------------------------------------------
    // Real end-to-end NetworkManager integration test.
    //
    // #[ignore] — needs `nmcli` + `wg` on PATH and a live NM session. Run with:
    //     cargo test --package wireguard-gui-rust nm_connect_real_split_tunnel \
    //         -- --ignored --nocapture
    //
    // SAFETY: this uses a SPLIT tunnel (AllowedIPs = 10.99.99.0/24) pointed at a
    // dummy local endpoint (127.0.0.1:51820). It can never capture the default
    // route or disrupt host networking. The point is to prove the IFNAMSIZ bug is
    // FIXED: the profile name is LONG ("homeserver1", 18+ chars once prefixed),
    // yet the kernel interface is the fixed `wg-gui0`, so import + up succeed.
    // -----------------------------------------------------------------------

    /// Run `wg genkey` / `wg pubkey` to mint a real WireGuard keypair.
    fn gen_real_keypair() -> (String, String) {
        use std::io::Write;
        use std::process::{Command as SyncCommand, Stdio};

        let priv_out = SyncCommand::new("wg")
            .arg("genkey")
            .output()
            .expect("wg genkey should run");
        assert!(priv_out.status.success(), "wg genkey failed");
        let private_key = String::from_utf8(priv_out.stdout)
            .expect("genkey utf8")
            .trim()
            .to_string();

        let mut pub_child = SyncCommand::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("wg pubkey should spawn");
        pub_child
            .stdin
            .as_mut()
            .expect("pubkey stdin")
            .write_all(format!("{private_key}\n").as_bytes())
            .expect("write privkey to pubkey");
        let pub_out = pub_child.wait_with_output().expect("wg pubkey output");
        assert!(pub_out.status.success(), "wg pubkey failed");
        let public_key = String::from_utf8(pub_out.stdout)
            .expect("pubkey utf8")
            .trim()
            .to_string();

        (private_key, public_key)
    }

    #[tokio::test]
    #[ignore = "needs nmcli + wg + a live NetworkManager session"]
    async fn nm_connect_real_split_tunnel() {
        use crate::config::profile::{InterfaceSection, PeerSection, WgProfile};

        // Best-effort pre-clean of any stale connection from a prior failed run.
        let _ = run_nmcli(&nm_delete_argv(CLIENT_IFACE)).await;

        // A real client keypair, and a dummy peer pubkey (its private key is
        // discarded — the peer never needs to actually respond).
        let (client_priv, _client_pub) = gen_real_keypair();
        let (_peer_priv, peer_pub) = gen_real_keypair();

        // LONG profile name proves the IFNAMSIZ bug is fixed: "wg-gui-homeserver1"
        // would be 18 chars and rejected; we use the fixed "wg-gui0" instead.
        let profile = WgProfile {
            name: "homeserver1".to_string(),
            interface: InterfaceSection {
                private_key: client_priv,
                address: vec!["10.99.99.2/24".to_string()],
                dns: vec![],
                listen_port: None,
                mtu: None,
            },
            peers: vec![PeerSection {
                public_key: peer_pub,
                preshared_key: None,
                // SPLIT tunnel — only 10.99.99.0/24 routes through the tunnel.
                endpoint: Some("127.0.0.1:51820".to_string()),
                allowed_ips: vec!["10.99.99.0/24".to_string()],
                persistent_keepalive: None,
            }],
            path: None,
        };

        let backend = NmBackend;

        // Connect, then assert OUR fixed interface is active.
        let connect_result = backend.connect(&profile).await;
        if let Err(e) = &connect_result {
            // Best-effort cleanup before surfacing the failure.
            let _ = run_nmcli(&nm_delete_argv(CLIENT_IFACE)).await;
            remove_client_conf().await;
            panic!("connect(homeserver1) failed: {e}");
        }

        let active = backend.active_interface().await;
        match &active {
            Ok(Some(iface)) if iface == CLIENT_IFACE => {}
            other => {
                let _ = run_nmcli(&nm_delete_argv(CLIENT_IFACE)).await;
                remove_client_conf().await;
                panic!("expected active_interface == Some(\"wg-gui0\"), got {other:?}");
            }
        }

        // Disconnect using the actual interface, then assert nothing is active.
        let disconnect_result = backend.disconnect(CLIENT_IFACE).await;
        if let Err(e) = &disconnect_result {
            let _ = run_nmcli(&nm_delete_argv(CLIENT_IFACE)).await;
            remove_client_conf().await;
            panic!("disconnect(wg-gui0) failed: {e}");
        }

        let active_after = backend.active_interface().await;

        // Final best-effort cleanup regardless of outcome.
        let _ = run_nmcli(&nm_delete_argv(CLIENT_IFACE)).await;
        remove_client_conf().await;

        assert_eq!(
            active_after.expect("active_interface query"),
            None,
            "wg-gui0 should be gone after disconnect"
        );
    }
}
