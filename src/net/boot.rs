//! Connect-on-boot argv builders for the two supported backend paths.
//!
//! # Two paths, two privilege models
//!
//! ## NetworkManager path (non-root, client-side)
//! `nmcli connection modify wg-gui-<n> connection.autoconnect yes|no`
//!
//! NetworkManager handles its own polkit authentication when operating on connections that belong
//! to the calling user.  No helper, no pkexec, no root required.  The connection name convention
//! `wg-gui-<profile_name>` matches [`crate::wg::backend::nm_connection_name`].
//!
//! Call [`nm_autoconnect_argv`] to obtain the ready-to-exec argv array, then pass it to
//! `tokio::process::Command` — this module does NOT execute anything.
//!
//! ## wg-quick / systemd path (root via helper)
//! `systemctl enable wg-quick@wg-gui-<n>` / `systemctl disable wg-quick@wg-gui-<n>`
//!
//! These operations require root and are therefore expressed as a [`PrivCmd`] that the caller
//! hands to [`crate::net::privilege::run_privileged`].  This module only *constructs* the
//! command; it never runs it.
//!
//! Call [`systemd_boot_cmd`] to build the appropriate [`PrivCmd`] variant.
//!
//! # No execution
//! Every public function in this module is pure and free of side-effects: no I/O, no process
//! spawning, no filesystem access.  That makes the entire module golden-testable without root
//! and without any network state.

use crate::net::privilege::PrivCmd;

// ---------------------------------------------------------------------------
// NetworkManager path — non-root, client-side
// ---------------------------------------------------------------------------

/// Whether to enable or disable connect-on-boot for the NM path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootAction {
    Enable,
    Disable,
}

/// Build the `nmcli connection modify` argv that sets `connection.autoconnect` for a
/// NetworkManager-managed WireGuard connection.
///
/// The connection name follows the `wg-gui-<profile_name>` convention established by
/// [`crate::wg::backend::nm_connection_name`].
///
/// Shape: `["nmcli", "connection", "modify", "wg-gui-<profile_name>",
///          "connection.autoconnect", "yes"|"no"]`
///
/// This argv is safe to pass directly to `Command::new("nmcli").args(&argv[1..])` — no shell
/// quoting needed because the arguments are in an array, not a shell string.
///
/// # Arguments
/// * `profile_name` — the profile name (bare, without the `wg-gui-` prefix).
/// * `action` — [`BootAction::Enable`] sets `connection.autoconnect yes`;
///              [`BootAction::Disable`] sets `connection.autoconnect no`.
pub fn nm_autoconnect_argv(profile_name: &str, action: BootAction) -> Vec<String> {
    let conn_name = format!("wg-gui-{}", profile_name);
    let value = match action {
        BootAction::Enable => "yes",
        BootAction::Disable => "no",
    };
    vec![
        "nmcli".to_string(),
        "connection".to_string(),
        "modify".to_string(),
        conn_name,
        "connection.autoconnect".to_string(),
        value.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// wg-quick / systemd path — root required, dispatched via helper
// ---------------------------------------------------------------------------

/// Build the [`PrivCmd`] that asks the root helper to enable or disable the
/// `wg-quick@wg-gui-<iface>` systemd unit for connect-on-boot.
///
/// The returned command is NOT executed here.  Pass it to
/// [`crate::net::privilege::run_privileged`] when you want to apply it.
///
/// The `iface` parameter is the WireGuard interface name as it appears in the systemd unit name,
/// e.g. `"wg-gui-home"` produces unit `wg-quick@wg-gui-home`.
///
/// # Arguments
/// * `iface` — the full WireGuard interface name (e.g. `"wg-gui-home"`).
/// * `action` — [`BootAction::Enable`] → [`PrivCmd::BootEnableSystemd`];
///              [`BootAction::Disable`] → [`PrivCmd::BootDisableSystemd`].
pub fn systemd_boot_cmd(iface: &str, action: BootAction) -> PrivCmd {
    match action {
        BootAction::Enable => PrivCmd::BootEnableSystemd { iface: iface.to_string() },
        BootAction::Disable => PrivCmd::BootDisableSystemd { iface: iface.to_string() },
    }
}

// ---------------------------------------------------------------------------
// Unit tests — pure, no I/O, no root, no execution
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::privilege::{encode, PrivCmd};

    // -----------------------------------------------------------------------
    // nm_autoconnect_argv — golden string tests
    // -----------------------------------------------------------------------

    /// Enable: the argv must be exactly the six-element shape with `yes`.
    #[test]
    fn nm_autoconnect_enable_golden() {
        let argv = nm_autoconnect_argv("home", BootAction::Enable);
        assert_eq!(
            argv,
            vec![
                "nmcli",
                "connection",
                "modify",
                "wg-gui-home",
                "connection.autoconnect",
                "yes",
            ],
            "argv = {argv:?}",
        );
    }

    /// Disable: the only difference from enable is `no` at the end.
    #[test]
    fn nm_autoconnect_disable_golden() {
        let argv = nm_autoconnect_argv("home", BootAction::Disable);
        assert_eq!(
            argv,
            vec![
                "nmcli",
                "connection",
                "modify",
                "wg-gui-home",
                "connection.autoconnect",
                "no",
            ],
            "argv = {argv:?}",
        );
    }

    /// A profile name that contains hyphens must be preserved verbatim inside the
    /// connection name.
    #[test]
    fn nm_autoconnect_hyphenated_profile_name() {
        let argv = nm_autoconnect_argv("work-vpn", BootAction::Enable);
        assert_eq!(argv[3], "wg-gui-work-vpn");
        assert_eq!(argv[5], "yes");
    }

    /// Profile names with spaces are unusual but must survive the round-trip as a
    /// single argument — no shell quoting because argv is an array.
    #[test]
    fn nm_autoconnect_profile_name_with_spaces_is_single_arg() {
        let argv = nm_autoconnect_argv("my tunnel", BootAction::Enable);
        assert_eq!(argv[3], "wg-gui-my tunnel",
            "spaces must stay in one arg; argv = {argv:?}");
        assert_eq!(argv.len(), 6);
    }

    /// An empty profile name yields `wg-gui-` (degenerate but must not panic).
    #[test]
    fn nm_autoconnect_empty_profile_name() {
        let argv = nm_autoconnect_argv("", BootAction::Disable);
        assert_eq!(argv[3], "wg-gui-");
        assert_eq!(argv[5], "no");
        assert_eq!(argv.len(), 6);
    }

    /// The argv always starts with `nmcli` as argv[0] and has exactly 6 elements.
    #[test]
    fn nm_autoconnect_argv_length_and_program() {
        for action in [BootAction::Enable, BootAction::Disable] {
            let argv = nm_autoconnect_argv("test", action);
            assert_eq!(argv.len(), 6, "action={action:?} argv={argv:?}");
            assert_eq!(argv[0], "nmcli");
            assert_eq!(argv[1], "connection");
            assert_eq!(argv[2], "modify");
            assert_eq!(argv[4], "connection.autoconnect");
        }
    }

    /// Enable and disable differ ONLY in the last element.
    #[test]
    fn nm_autoconnect_enable_vs_disable_only_last_differs() {
        let en = nm_autoconnect_argv("test", BootAction::Enable);
        let dis = nm_autoconnect_argv("test", BootAction::Disable);
        assert_eq!(en[..5], dis[..5], "first five elements must be identical");
        assert_ne!(en[5], dis[5]);
        assert_eq!(en[5], "yes");
        assert_eq!(dis[5], "no");
    }

    // -----------------------------------------------------------------------
    // systemd_boot_cmd — PrivCmd variant and wire shape
    // -----------------------------------------------------------------------

    /// Enable produces BootEnableSystemd with the correct iface.
    #[test]
    fn systemd_boot_cmd_enable_variant() {
        let cmd = systemd_boot_cmd("wg-gui-home", BootAction::Enable);
        assert_eq!(
            cmd,
            PrivCmd::BootEnableSystemd { iface: "wg-gui-home".to_string() },
        );
    }

    /// Disable produces BootDisableSystemd with the correct iface.
    #[test]
    fn systemd_boot_cmd_disable_variant() {
        let cmd = systemd_boot_cmd("wg-gui-home", BootAction::Disable);
        assert_eq!(
            cmd,
            PrivCmd::BootDisableSystemd { iface: "wg-gui-home".to_string() },
        );
    }

    /// The two variants must produce distinct JSON (the `cmd` tag differs).
    #[test]
    fn systemd_boot_cmd_enable_and_disable_wire_shapes_differ() {
        let en = encode(&systemd_boot_cmd("wg-gui-home", BootAction::Enable)).unwrap();
        let dis = encode(&systemd_boot_cmd("wg-gui-home", BootAction::Disable)).unwrap();
        assert_ne!(en, dis);
        assert!(en.contains(r#""BootEnableSystemd""#), "en = {en}");
        assert!(dis.contains(r#""BootDisableSystemd""#), "dis = {dis}");
    }

    /// Wire JSON round-trips back to the same PrivCmd (freeze the protocol).
    #[test]
    fn systemd_boot_cmd_enable_round_trips() {
        let cmd = systemd_boot_cmd("wg-gui-work-vpn", BootAction::Enable);
        let json = encode(&cmd).unwrap();
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    /// Wire JSON round-trips back to the same PrivCmd (freeze the protocol).
    #[test]
    fn systemd_boot_cmd_disable_round_trips() {
        let cmd = systemd_boot_cmd("wg-gui-work-vpn", BootAction::Disable);
        let json = encode(&cmd).unwrap();
        let back: PrivCmd = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    /// The iface field in the PrivCmd must be the verbatim string passed in.
    #[test]
    fn systemd_boot_cmd_iface_passed_through_verbatim() {
        let iface = "wg-gui-my-special-tunnel";
        let en = systemd_boot_cmd(iface, BootAction::Enable);
        let dis = systemd_boot_cmd(iface, BootAction::Disable);
        if let PrivCmd::BootEnableSystemd { iface: i } = en {
            assert_eq!(i, iface);
        } else {
            panic!("expected BootEnableSystemd");
        }
        if let PrivCmd::BootDisableSystemd { iface: i } = dis {
            assert_eq!(i, iface);
        } else {
            panic!("expected BootDisableSystemd");
        }
    }

    /// The wire JSON contains the iface string literally.
    #[test]
    fn systemd_boot_cmd_wire_json_contains_iface() {
        let json = encode(&systemd_boot_cmd("wg-gui-home", BootAction::Enable)).unwrap();
        assert!(json.contains(r#""iface":"wg-gui-home""#), "json = {json}");
    }

    // -----------------------------------------------------------------------
    // Cross-path: NM and systemd produce completely independent artefacts
    // -----------------------------------------------------------------------

    /// Verify there is no confusion between the NM argv and the systemd PrivCmd.
    /// They operate on the same connection name convention but are used differently.
    #[test]
    fn nm_argv_program_is_not_pkexec() {
        let argv = nm_autoconnect_argv("home", BootAction::Enable);
        assert_ne!(argv[0], "pkexec",
            "NM path must NOT go through pkexec; it uses NM's own polkit agent");
        assert_eq!(argv[0], "nmcli");
    }
}
