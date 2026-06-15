//! Privilege boundary — the FROZEN protocol between the unprivileged GUI and the root helper.
//!
//! The GUI process NEVER runs privileged code. Every operation that genuinely needs root
//! (the `wg-quick` fallback, nftables kill-switch, network namespaces, systemd boot units)
//! is expressed as a [`PrivCmd`], serialized to JSON, and handed to the helper binary
//! (`wireguard-gui-helper`) through `pkexec`, which authenticates against the single polkit
//! action `org.wireguardgui.rust.manage`.
//!
//! Design contract (do NOT change the wire shape without bumping the helper in lockstep):
//!   - `PrivCmd` is a serde-tagged enum. The tag is `cmd`; payload fields are inline.
//!   - The GUI builds the argv with [`helper_argv`] (pure, golden-testable) and runs it with
//!     [`run_privileged`].
//!   - The `nmcli` connect path is NOT here — it lives in `wg::backend` and uses NM's own
//!     polkit agent (no root, no helper). This boundary is for root-only ops exclusively.
//!
//! Anything that touches the live host network (arming a real kill-switch, real netns routing,
//! enabling systemd units) is performed ONLY inside the helper, ONLY when it runs as root.

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// Absolute install path of the privileged helper. Must match the
/// `org.freedesktop.policykit.exec.path` annotation in
/// `assets/org.wireguardgui.rust.manage.policy`.
pub const HELPER_PATH: &str = "/usr/lib/wireguard-gui/wireguard-gui-helper";

/// Env var (dev/debug only) that overrides [`HELPER_PATH`] so the freshly-built helper can be
/// exercised without installing it system-wide. Ignored in release builds.
pub const HELPER_BIN_ENV: &str = "WG_GUI_HELPER_BIN";

/// A discrete root-only operation the helper is permitted to perform.
///
/// This is the FROZEN privilege protocol. Serializes as an internally-tagged JSON object,
/// e.g. `{"cmd":"WgQuickUp","iface":"wg-gui-home","conf_path":"/tmp/x.conf"}`.
///
/// The unprivileged GUI constructs these; the root helper deserializes and executes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum PrivCmd {
    /// `wg-quick up <conf_path>` — bring a tunnel up from a generated config (fallback path
    /// when NetworkManager is not driving the tunnel). `iface` is carried for logging/teardown.
    WgQuickUp { iface: String, conf_path: String },

    /// `wg-quick down <iface>` — tear the tunnel down.
    WgQuickDown { iface: String },

    /// Arm the nftables kill-switch (table `inet wg_gui_killswitch`, output policy drop) with a
    /// lockout-prevention allow-list and a bounded lease backed by a root-side dead-man timer.
    ///
    /// Allow-list (order matters, lockout-prevention rules MUST be emitted first):
    /// `oifname lo`, `oifname <iface>`, the wg endpoint UDP (`ip daddr <endpoint_ip>
    /// udp dport <endpoint_port>`), the configurable LAN/RFC1918 `lan_cidrs`,
    /// `ct state established,related`, and the optional per-app netns UDP punch-through
    /// (`netns_endpoint_udp` = `(ip, port)`).
    ///
    /// `lease_secs` bounds a `systemd-run --on-active=<lease>s` dead-man timer that flushes the
    /// table if the GUI stops renewing (survives SIGKILL). Refuse to arm if `iface` is absent.
    KillSwitchArm {
        iface: String,
        endpoint_ip: String,
        endpoint_port: u16,
        lan_cidrs: Vec<String>,
        lease_secs: u64,
        netns_endpoint_udp: Option<(String, u16)>,
    },

    /// Remove the kill-switch: `nft delete table inet wg_gui_killswitch`.
    KillSwitchDisarm,

    /// Build a kernel-isolated per-app network namespace and route it entirely through a
    /// WireGuard interface created inside it (never touches host routes):
    /// `ip netns add <ns>`; `ip link add <wgif> type wireguard`; move it into `<ns>`;
    /// `wg setconf` (only `[Interface]PrivateKey/ListenPort` + `[Peer]`); `ip -n <ns> addr add
    /// <address>`; bring `<wgif>` + `lo` up; default route via `<wgif>`; ns-local DNS written to
    /// `/etc/netns/<ns>/resolv.conf` from `dns`.
    NetnsSetup {
        ns: String,
        wgif: String,
        conf_path: String,
        address: String,
        dns: Vec<String>,
    },

    /// Tear a namespace down: `ip netns del <ns>`; `rm -rf /etc/netns/<ns>`.
    NetnsTeardown { ns: String },

    /// Launch an executable inside a namespace as the unprivileged user:
    /// `ip netns exec <ns> runuser -u <user-for-uid> -- env <env..> <exe> <args..>`.
    /// `env` carries the display/runtime vars (`DISPLAY`, `WAYLAND_DISPLAY`,
    /// `XDG_RUNTIME_DIR`, ...) needed for a GUI app to reach the user's session.
    NetnsLaunch {
        ns: String,
        uid: u32,
        exe: String,
        args: Vec<String>,
        env: Vec<(String, String)>,
    },

    /// Connect-on-boot for the wg-quick path: `systemctl enable wg-quick@<iface>`.
    BootEnableSystemd { iface: String },

    /// Disable connect-on-boot: `systemctl disable wg-quick@<iface>`.
    BootDisableSystemd { iface: String },

    // ── SERVER mode (root-only) ───────────────────────────────────────────────
    //
    // SAFETY: these bring up a real server interface / change host packet
    // forwarding + NAT. The helper performs them only when running as root; the GUI
    // only constructs + dispatches them. They operate on the fixed SERVER interface
    // (`wg-gui-srv0`), distinct from the client interface, so the two coexist.
    /// Write the generated server `.conf` text to the helper-owned server conf path
    /// (`wg-gui-srv0.conf`, 0600) so a subsequent `ServerUp` can bring it up. The
    /// conf is delivered in-band (not a path) so the unprivileged GUI never has to
    /// stage a world-readable file holding the server's private key.
    ServerWriteConf { conf_text: String },

    /// Bring the server interface up from the previously-written conf:
    /// `wg-quick up <server_conf_path>` on the fixed server interface.
    ServerUp,

    /// Tear the server interface down: `wg-quick down <server_conf_path>`.
    ServerDown,

    /// Enable source-NAT for the tunnel `subnet` out the host `egress_iface` and turn
    /// on IPv4 forwarding: `sysctl -w net.ipv4.ip_forward=1` + an nft masquerade rule
    /// in the uniquely-named `inet wg_gui_srv_nat` table (mirrors the kill-switch
    /// lease/table pattern so it never collides with a user firewall).
    NatEnable {
        subnet: String,
        egress_iface: String,
    },

    /// Remove the NAT masquerade: `nft delete table inet wg_gui_srv_nat`. IPv4
    /// forwarding is left as-is (other services may rely on it). Idempotent.
    NatDisable,
}

/// Build the argv for invoking the helper through `pkexec`, given the JSON `payload`.
///
/// Pure and side-effect-free so it is golden-testable WITHOUT executing anything. The helper
/// path honours the [`HELPER_BIN_ENV`] override in debug builds; release builds always use the
/// installed [`HELPER_PATH`].
///
/// Shape: `["pkexec", <helper_path>, "--json", <payload>]`.
pub fn helper_argv(payload: &str) -> Vec<String> {
    vec![
        "pkexec".to_string(),
        helper_path(),
        "--json".to_string(),
        payload.to_string(),
    ]
}

/// Resolve the helper binary path: the [`HELPER_BIN_ENV`] override (debug only) or the
/// installed [`HELPER_PATH`].
fn helper_path() -> String {
    #[cfg(debug_assertions)]
    if let Ok(p) = std::env::var(HELPER_BIN_ENV) {
        if !p.is_empty() {
            return p;
        }
    }
    HELPER_PATH.to_string()
}

/// Serialize `cmd` to the wire JSON the helper expects. Pure; testable without execution.
pub fn encode(cmd: &PrivCmd) -> AppResult<String> {
    serde_json::to_string(cmd)
        .map_err(|e| AppError::IpcFailed(format!("encode PrivCmd: {}", e)))
}

/// Execute a privileged command by serializing it and invoking the helper via `pkexec`.
///
/// The GUI never gains privilege itself — `pkexec` re-executes the helper as root after the
/// polkit prompt. `pkexec` exits 126 when the user cancels the dialog (mapped to
/// [`AppError::PermissionDenied`]) and 127 when not authorised.
pub async fn run_privileged(cmd: &PrivCmd) -> AppResult<()> {
    let payload = encode(cmd)?;
    let argv = helper_argv(&payload);
    // argv[0] is the program, the rest are arguments.
    let output = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::WgNotFound
            } else {
                AppError::IpcFailed(format!("pkexec spawn error: {}", e))
            }
        })?;

    if !output.status.success() {
        match output.status.code() {
            // pkexec: dialog dismissed / not authorised.
            Some(126) | Some(127) => return Err(AppError::PermissionDenied),
            _ => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                return Err(AppError::IpcFailed(format!(
                    "helper failed ({}): {} {}",
                    output.status,
                    stderr.trim(),
                    stdout.trim(),
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests — pure, no execution, no root. Freeze the wire protocol.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `HELPER_BIN_ENV` is a process-global env var; tests that read or mutate it must
    // not run concurrently or they race (one test's remove_var clears another's
    // set_var mid-flight). Serialize every env-touching test on this guard. Cargo
    // runs tests on multiple threads by default, so this is load-bearing.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    // --- helper_argv (golden, no execution) ---------------------------------

    #[test]
    fn helper_argv_golden_shape() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        // With no env override the installed path is used (release shape).
        // Clear any override the test environment might carry.
        unsafe {
            std::env::remove_var(HELPER_BIN_ENV);
        }
        let argv = helper_argv(r#"{"cmd":"KillSwitchDisarm"}"#);
        assert_eq!(argv.len(), 4);
        assert_eq!(argv[0], "pkexec");
        assert_eq!(argv[1], HELPER_PATH);
        assert_eq!(argv[2], "--json");
        assert_eq!(argv[3], r#"{"cmd":"KillSwitchDisarm"}"#);
    }

    #[test]
    fn helper_argv_payload_is_single_arg() {
        // A payload with spaces must remain ONE argument (argv array, no shell quoting).
        let payload = r#"{"cmd":"WgQuickUp","iface":"wg gui","conf_path":"/tmp/a b.conf"}"#;
        let argv = helper_argv(payload);
        assert_eq!(argv[3], payload);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn helper_argv_honours_env_override_in_debug() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::set_var(HELPER_BIN_ENV, "/home/dev/target/debug/wireguard-gui-helper");
        }
        let argv = helper_argv("{}");
        assert_eq!(argv[1], "/home/dev/target/debug/wireguard-gui-helper");
        unsafe {
            std::env::remove_var(HELPER_BIN_ENV);
        }
    }

    // --- PrivCmd encode round-trips (freeze the wire shape) ------------------

    #[test]
    fn encode_wgquick_up_is_tagged() {
        let cmd = PrivCmd::WgQuickUp {
            iface: "wg-gui-home".into(),
            conf_path: "/tmp/wg-gui-home.conf".into(),
        };
        let json = encode(&cmd).unwrap();
        assert!(json.contains(r#""cmd":"WgQuickUp""#), "json = {json}");
        assert!(json.contains(r#""iface":"wg-gui-home""#));
        assert!(json.contains(r#""conf_path":"/tmp/wg-gui-home.conf""#));
    }

    #[test]
    fn encode_killswitch_disarm_unit_variant() {
        let json = encode(&PrivCmd::KillSwitchDisarm).unwrap();
        assert_eq!(json, r#"{"cmd":"KillSwitchDisarm"}"#);
    }

    #[test]
    fn killswitch_arm_round_trip() {
        let cmd = PrivCmd::KillSwitchArm {
            iface: "wg-gui0".into(),
            endpoint_ip: "203.0.113.7".into(),
            endpoint_port: 51820,
            lan_cidrs: vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()],
            lease_secs: 30,
            netns_endpoint_udp: Some(("203.0.113.7".into(), 51820)),
        };
        let json = encode(&cmd).unwrap();
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn killswitch_arm_optional_netns_none_round_trip() {
        let cmd = PrivCmd::KillSwitchArm {
            iface: "wg-gui0".into(),
            endpoint_ip: "198.51.100.1".into(),
            endpoint_port: 13231,
            lan_cidrs: vec![],
            lease_secs: 60,
            netns_endpoint_udp: None,
        };
        let json = encode(&cmd).unwrap();
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn netns_setup_round_trip() {
        let cmd = PrivCmd::NetnsSetup {
            ns: "wg-gui-app".into(),
            wgif: "wg-gui-ns0".into(),
            conf_path: "/run/wg-gui/ns.conf".into(),
            address: "10.2.0.2/32".into(),
            dns: vec!["1.1.1.1".into(), "1.0.0.1".into()],
        };
        let json = encode(&cmd).unwrap();
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn netns_launch_round_trip_preserves_env_and_args() {
        let cmd = PrivCmd::NetnsLaunch {
            ns: "wg-gui-app".into(),
            uid: 1000,
            exe: "/usr/bin/firefox".into(),
            args: vec!["--new-instance".into(), "--profile".into(), "p".into()],
            env: vec![
                ("DISPLAY".into(), ":0".into()),
                ("WAYLAND_DISPLAY".into(), "wayland-0".into()),
                ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()),
            ],
        };
        let json = encode(&cmd).unwrap();
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn netns_teardown_round_trip() {
        let cmd = PrivCmd::NetnsTeardown { ns: "wg-gui-app".into() };
        let back: PrivCmd = serde_json::from_str(&encode(&cmd).unwrap()).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn boot_systemd_variants_round_trip() {
        let en = PrivCmd::BootEnableSystemd { iface: "wg-gui-home".into() };
        let dis = PrivCmd::BootDisableSystemd { iface: "wg-gui-home".into() };
        assert_eq!(en, serde_json::from_str::<PrivCmd>(&encode(&en).unwrap()).unwrap());
        assert_eq!(dis, serde_json::from_str::<PrivCmd>(&encode(&dis).unwrap()).unwrap());
        // The two are distinct on the wire (tag differs).
        assert_ne!(encode(&en).unwrap(), encode(&dis).unwrap());
    }

    #[test]
    fn wgquick_down_round_trip() {
        let cmd = PrivCmd::WgQuickDown { iface: "wg-gui-home".into() };
        let back: PrivCmd = serde_json::from_str(&encode(&cmd).unwrap()).unwrap();
        assert_eq!(cmd, back);
    }

    // ── SERVER-mode variants (freeze the wire shape) ─────────────────────────

    #[test]
    fn server_write_conf_round_trip() {
        let cmd = PrivCmd::ServerWriteConf {
            conf_text: "[Interface]\nPrivateKey = x\nListenPort = 51820\n".into(),
        };
        let json = encode(&cmd).unwrap();
        assert!(json.contains(r#""cmd":"ServerWriteConf""#), "json = {json}");
        assert!(json.contains(r#""conf_text""#), "json = {json}");
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn server_up_down_unit_variants() {
        assert_eq!(encode(&PrivCmd::ServerUp).unwrap(), r#"{"cmd":"ServerUp"}"#);
        assert_eq!(encode(&PrivCmd::ServerDown).unwrap(), r#"{"cmd":"ServerDown"}"#);
        // The two are distinct on the wire.
        assert_ne!(
            encode(&PrivCmd::ServerUp).unwrap(),
            encode(&PrivCmd::ServerDown).unwrap()
        );
        assert_eq!(
            PrivCmd::ServerUp,
            serde_json::from_str::<PrivCmd>(r#"{"cmd":"ServerUp"}"#).unwrap()
        );
        assert_eq!(
            PrivCmd::ServerDown,
            serde_json::from_str::<PrivCmd>(r#"{"cmd":"ServerDown"}"#).unwrap()
        );
    }

    #[test]
    fn nat_enable_round_trip() {
        let cmd = PrivCmd::NatEnable {
            subnet: "10.7.0.0/24".into(),
            egress_iface: "eth0".into(),
        };
        let json = encode(&cmd).unwrap();
        assert!(json.contains(r#""cmd":"NatEnable""#), "json = {json}");
        assert!(json.contains(r#""subnet":"10.7.0.0/24""#), "json = {json}");
        assert!(json.contains(r#""egress_iface":"eth0""#), "json = {json}");
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn nat_disable_unit_variant() {
        assert_eq!(encode(&PrivCmd::NatDisable).unwrap(), r#"{"cmd":"NatDisable"}"#);
        let back: PrivCmd = serde_json::from_str(r#"{"cmd":"NatDisable"}"#).unwrap();
        assert_eq!(PrivCmd::NatDisable, back);
    }
}
