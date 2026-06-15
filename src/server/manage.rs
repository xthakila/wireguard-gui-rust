//! Server lifecycle management — start/stop the server interface, query peer status,
//! and detect the host's egress interface.
//!
//! ============================ SAFETY / PRIVILEGE NOTICE ============================
//! This module is **GUI-side**. The actual root-only work (writing + bringing up the
//! server interface, applying the NAT masquerade, enabling IP forwarding) is performed
//! ONLY inside the `wireguard-gui-helper` binary, reached via the
//! [`crate::net::privilege::PrivCmd`] protocol over `pkexec`. The functions here build
//! those `PrivCmd`s and dispatch them; they never bring an interface up, apply NAT, or
//! enable forwarding on this host themselves.
//!
//! [`detect_egress_iface`] is the one pure, safe-to-run-anywhere helper: it shells out
//! to the READ-ONLY `ip route show default` and parses the egress interface name. It
//! changes nothing.
//!
//! [`detect_egress_iface_from`] is the pure, testable inner parser exercised by golden
//! tests without any I/O.
//! ====================================================================================
//!
//! # MANAGE stage implementation
//!
//! `start` / `stop` dispatch privileged `PrivCmd`s.
//! `status` reads `wg show wg-gui-srv0 dump` (read-only, no root required on most
//! distributions where the `wg` tool is installed 4755 or the user is in the
//! appropriate group).  Falls back to an empty vec rather than an error when the
//! interface is absent or permission is refused.
//! `detect_egress_iface` / `detect_egress_iface_from` parse `ip route show default`.
//!
//! ## Defined types
//!
//! [`ServerPeerStatus`] is a named-peer view of live stats (name + last_handshake +
//! rx/tx).  It is produced by [`map_peers`] (pure, testable) and returned by the
//! convenience wrapper [`status_named`].  The frozen `status` signature returns
//! `Vec<PeerStatus>` (from `wg::status`) to match `app::Message::ServerStatusResult`.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::error::AppResult;
use crate::net::privilege::{run_privileged, PrivCmd};
use crate::server::ServerConfig;
use crate::wg::status::{parse_wg_show_dump, PeerStatus};

/// The single, fixed kernel interface name used for the SERVER tunnel.
///
/// Deliberately DIFFERENT from the client's [`crate::wg::backend::CLIENT_IFACE`]
/// (`wg-gui0`) so a server and a client tunnel can be active on the same host without
/// colliding. `wg-gui-srv0` is 10 chars — within the 15-char `IFNAMSIZ` limit — and is
/// namespaced to this app.
pub const SERVER_IFACE: &str = "wg-gui-srv0";

// ─────────────────────────────────────────────────────────────────────────────
// Named-peer status (manage layer, not in wg::status so as not to pollute that
// module with server-side naming concerns)
// ─────────────────────────────────────────────────────────────────────────────

/// Live status for a single provisioned server peer, enriched with its display name.
///
/// Produced by [`map_peers`] / [`status_named`] by joining the raw `wg show dump`
/// output against the configured [`crate::server::ServerPeer`] list on public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPeerStatus {
    /// Display name from [`crate::server::ServerPeer::name`] (e.g. "phone").
    /// Falls back to the first 12 chars of the public key when no matching peer is found
    /// in the config (e.g. a peer added outside the GUI).
    pub name: String,
    /// The raw public key identifying this peer in the wg dump.
    pub public_key: String,
    /// Time of the last successful handshake, or `None` if this peer has never connected.
    pub last_handshake: Option<SystemTime>,
    /// Bytes received by the server from this peer.
    pub rx_bytes: u64,
    /// Bytes sent by the server to this peer.
    pub tx_bytes: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers (no I/O — golden-testable)
// ─────────────────────────────────────────────────────────────────────────────

/// Map a slice of raw [`PeerStatus`] rows to [`ServerPeerStatus`] by looking each
/// peer's `public_key` up in `config.peers`.
///
/// Peers not found in the config get a fallback name of `<first 12 chars of pubkey>…`
/// so the UI always has something to display.
///
/// Pure and side-effect-free — takes the already-parsed wg dump rows and the server
/// config's peer list.
pub fn map_peers(raw: &[PeerStatus], config: &ServerConfig) -> Vec<ServerPeerStatus> {
    // Build a pubkey → name lookup so the map is O(n) overall.
    let name_map: HashMap<&str, &str> = config
        .peers
        .iter()
        .map(|p| (p.public_key.as_str(), p.name.as_str()))
        .collect();

    raw.iter()
        .map(|ps| {
            let name = match name_map.get(ps.public_key.as_str()) {
                Some(n) => n.to_string(),
                None => {
                    // Fallback: truncate the pubkey for a human-recognizable label.
                    let truncated = &ps.public_key[..ps.public_key.len().min(12)];
                    format!("{truncated}…")
                }
            };
            ServerPeerStatus {
                name,
                public_key: ps.public_key.clone(),
                last_handshake: ps.last_handshake,
                rx_bytes: ps.rx_bytes,
                tx_bytes: ps.tx_bytes,
            }
        })
        .collect()
}

/// Parse the `dev <iface>` token from the output of `ip route show default`.
///
/// Recognises both the common single-line form:
/// ```text
/// default via 192.168.1.1 dev eth0 proto dhcp metric 100
/// ```
/// and multi-line / ECMP output where the `dev` token may appear anywhere on the
/// first default-route line.
///
/// Returns `None` when there is no default route line or no `dev` token.
///
/// Pure: takes the raw command output as a string — no I/O.  Exercised directly by
/// golden tests in the `tests` module.
pub fn detect_egress_iface_from(ip_route_output: &str) -> Option<String> {
    // Find the first line that starts with "default" (possibly with leading whitespace
    // from multi-path ECMP dumps, but the primary line is never indented).
    let default_line = ip_route_output
        .lines()
        .find(|l| l.trim_start().starts_with("default"))?;

    // Split on whitespace and find the token immediately after "dev".
    let tokens: Vec<&str> = default_line.split_whitespace().collect();
    let dev_pos = tokens.iter().position(|&t| t == "dev")?;
    tokens.get(dev_pos + 1).map(|s| s.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Frozen public API — signatures match the CORE stage stubs exactly
// ─────────────────────────────────────────────────────────────────────────────

/// Bring the WireGuard server up:
///   1. Generate the server `.conf` ([`ServerConfig::to_server_conf`]).
///   2. Hand it to the helper to write + `wg-quick up` on [`SERVER_IFACE`]
///      ([`PrivCmd::ServerWriteConf`] then [`PrivCmd::ServerUp`]).
///
/// NAT (`NatEnable`) is a **separate** explicit user toggle and is NOT applied here.
///
/// SAFETY: every step that changes host networking is performed in the root helper.
/// This function only builds and dispatches `PrivCmd`s over `pkexec`.
pub async fn start(config: &ServerConfig) -> AppResult<()> {
    // Step 1: deliver the generated .conf text to the helper so it can write it as root.
    let conf_text = config.to_server_conf();
    run_privileged(&PrivCmd::ServerWriteConf { conf_text }).await?;

    // Step 2: bring the interface up from the file the helper just wrote.
    run_privileged(&PrivCmd::ServerUp).await?;

    Ok(())
}

/// Tear the WireGuard server down: dispatch [`PrivCmd::ServerDown`].
///
/// NAT (`NatDisable`) is a separate explicit toggle and is NOT automatically applied
/// here — the caller (`app::update`) handles it when NAT is currently armed.
///
/// SAFETY: the actual teardown happens in the root helper.
pub async fn stop() -> AppResult<()> {
    run_privileged(&PrivCmd::ServerDown).await
}

/// Query live per-peer status for the running server interface.
///
/// Attempts `wg show wg-gui-srv0 dump` as the unprivileged GUI user.  On most
/// systems the `wg` tool is installed set-uid or the user is in the `wireguard`
/// group, so this works without root.  If the command fails for any reason
/// (permission denied, interface absent, `wg` not on PATH) the function returns an
/// **empty vec** rather than an error — the UI should treat this as "server is not up
/// or not yet visible" rather than a hard failure.
///
/// Each [`PeerStatus`] row's `public_key` can be joined to [`ServerConfig::peers`] via
/// [`map_peers`] to obtain the client display name.  The return type is `Vec<PeerStatus>`
/// (matching `app::Message::ServerStatusResult`) rather than `Vec<ServerPeerStatus>` —
/// use [`status_named`] when you want the enriched form (name + handshake + rx/tx).
pub async fn status(_config: &ServerConfig) -> AppResult<Vec<PeerStatus>> {
    // Run `wg show <SERVER_IFACE> dump` as the unprivileged GUI user.
    // Return empty on any failure — the UI degrades gracefully.
    let output = tokio::process::Command::new("wg")
        .args(["show", SERVER_IFACE, "dump"])
        .output()
        .await;

    let raw_stdout = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return Ok(Vec::new()),
    };

    if raw_stdout.trim().is_empty() {
        return Ok(Vec::new());
    }

    // Re-use the frozen wg::status parser (already golden-tested). Endpoint info
    // is preserved in the PeerStatus rows so the UI can show it if desired.
    match parse_wg_show_dump(SERVER_IFACE, raw_stdout.trim()) {
        Ok(live) => Ok(live.peers),
        // Parse errors treated as "no data" rather than hard failures.
        Err(_) => Ok(Vec::new()),
    }
}

/// Like [`status`] but returns the richer [`ServerPeerStatus`] (includes client name).
///
/// Shells out to `wg show wg-gui-srv0 dump`, parses with the frozen
/// [`parse_wg_show_dump`] parser, then enriches each row via [`map_peers`].
/// Returns an empty vec on any failure (interface absent, permission refused, etc.).
pub async fn status_named(config: &ServerConfig) -> AppResult<Vec<ServerPeerStatus>> {
    // Run `wg show <SERVER_IFACE> dump` as the unprivileged GUI user.
    // We deliberately do NOT use run_privileged here: the dump is read-only and
    // should not require root on a correctly-configured system.  If it does fail
    // we return empty rather than an error so the UI degrades gracefully.
    let output = tokio::process::Command::new("wg")
        .args(["show", SERVER_IFACE, "dump"])
        .output()
        .await;

    let raw_stdout = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        // Any failure (not found, permission denied, interface absent) → empty.
        _ => return Ok(Vec::new()),
    };

    if raw_stdout.trim().is_empty() {
        return Ok(Vec::new());
    }

    // Re-use the frozen wg::status parser (already golden-tested).
    let live = match parse_wg_show_dump(SERVER_IFACE, raw_stdout.trim()) {
        Ok(ls) => ls,
        // Parse error is treated as "no data" at this layer.
        Err(_) => return Ok(Vec::new()),
    };

    Ok(map_peers(&live.peers, config))
}

/// Detect the host's egress (internet-facing) interface by running the READ-ONLY
/// `ip route show default` command and extracting the `dev <iface>` token.
///
/// Returns `None` when there is no default route, `ip` is not on PATH, or the command
/// fails for any other reason.
///
/// SAFETY: `ip route show` only reads the routing table; it never changes anything.
pub fn detect_egress_iface() -> Option<String> {
    // Synchronous: called from the GUI thread during server-create setup, before
    // async tasks are needed.  The command is fast (kernel route table lookup).
    use std::process::Command;
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    detect_egress_iface_from(&raw)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure only (no root, no live wg interface, no I/O).
// Root-requiring tests are marked #[ignore].
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::server::{ServerPeer, DEFAULT_CLIENT_ALLOWED_IPS, DEFAULT_LISTEN_PORT};
    use crate::wg::status::parse_wg_show_dump;

    // ─────────────────────────────────────────────────────────────────────────
    // SERVER_IFACE invariant
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn server_iface_is_valid_kernel_name_and_distinct_from_client() {
        // <= 15 chars (IFNAMSIZ), namespaced, and NOT the client interface.
        assert!(SERVER_IFACE.len() <= 15, "SERVER_IFACE exceeds IFNAMSIZ");
        assert_eq!(SERVER_IFACE, "wg-gui-srv0");
        assert_ne!(
            SERVER_IFACE,
            crate::wg::backend::CLIENT_IFACE,
            "server and client interfaces MUST differ so they can coexist"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // detect_egress_iface_from — golden `ip route` samples
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn egress_iface_simple_eth0() {
        // Typical single-line default route.
        let raw = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n";
        assert_eq!(detect_egress_iface_from(raw), Some("eth0".to_string()));
    }

    #[test]
    fn egress_iface_ens3() {
        // Cloud VM interface name.
        let raw = "default via 10.0.0.1 dev ens3\n";
        assert_eq!(detect_egress_iface_from(raw), Some("ens3".to_string()));
    }

    #[test]
    fn egress_iface_wlan0() {
        // Wireless interface.
        let raw = "default via 192.168.0.1 dev wlan0 proto dhcp src 192.168.0.100 metric 600\n";
        assert_eq!(detect_egress_iface_from(raw), Some("wlan0".to_string()));
    }

    #[test]
    fn egress_iface_with_extra_non_default_lines() {
        // The default line is present among other routes.
        let raw = "\
10.0.0.0/8 via 10.0.0.1 dev eth0 proto static
172.16.0.0/12 via 172.16.0.1 dev eth0 proto static
default via 192.168.1.1 dev eth0 proto dhcp metric 100
192.168.1.0/24 dev eth0 proto kernel scope link\n";
        assert_eq!(detect_egress_iface_from(raw), Some("eth0".to_string()));
    }

    #[test]
    fn egress_iface_no_default_route() {
        // No "default" line — no egress detected.
        let raw = "10.0.0.0/8 via 10.0.0.1 dev eth0\n";
        assert_eq!(detect_egress_iface_from(raw), None);
    }

    #[test]
    fn egress_iface_empty_output() {
        assert_eq!(detect_egress_iface_from(""), None);
    }

    #[test]
    fn egress_iface_default_line_no_dev_token() {
        // Degenerate: "default" line without "dev" (unusual but possible in some
        // kernel/tool versions).
        let raw = "default unreachable\n";
        assert_eq!(detect_egress_iface_from(raw), None);
    }

    #[test]
    fn egress_iface_dev_is_last_token() {
        // "dev" at the very end of the line, but no token after it — malformed.
        let raw = "default via 1.2.3.4 dev\n";
        assert_eq!(detect_egress_iface_from(raw), None);
    }

    #[test]
    fn egress_iface_longer_interface_name() {
        // Interface names can be up to 15 chars.
        let raw = "default via 10.1.2.3 dev enp0s31f6 proto dhcp metric 100\n";
        assert_eq!(detect_egress_iface_from(raw), Some("enp0s31f6".to_string()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // map_peers — pubkey → name mapping from a sample dump
    // ─────────────────────────────────────────────────────────────────────────

    // A syntactically valid base64-encoded 32-byte key (32 zero bytes).
    const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // A second, distinct key (32 bytes of 0x01).
    const ONE_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    // A third key (32 bytes of 0x02) — no matching configured peer.
    const TWO_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    /// Build a minimal `ServerConfig` with two configured peers.
    fn sample_config() -> ServerConfig {
        ServerConfig {
            name: "test-server".into(),
            private_key: ZERO_KEY.into(),
            public_key: ZERO_KEY.into(),
            listen_port: DEFAULT_LISTEN_PORT,
            address: "10.7.0.1/24".into(),
            subnet: "10.7.0.0/24".into(),
            endpoint_host: "vpn.example.com".into(),
            dns: vec!["1.1.1.1".into()],
            egress_iface: Some("eth0".into()),
            peers: vec![
                ServerPeer {
                    name: "phone".into(),
                    public_key: ZERO_KEY.into(),
                    private_key: None,
                    assigned_ip: "10.7.0.2".into(),
                    preshared_key: None,
                    client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.into(),
                },
                ServerPeer {
                    name: "laptop".into(),
                    public_key: ONE_KEY.into(),
                    private_key: None,
                    assigned_ip: "10.7.0.3".into(),
                    preshared_key: None,
                    client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.into(),
                },
            ],
        }
    }

    /// Build a `wg show dump` output string for the SERVER_IFACE with the given peers.
    /// Interface line: `<privkey>\t<pubkey>\t<port>\t(none)`
    /// Peer line: `<pubkey>\t(none)\t<endpoint>\t<allowed_ips>\t<handshake_secs>\t<rx>\t<tx>\toff`
    fn make_dump(peers: &[(&str, u64, u64, u64)]) -> String {
        // Interface line
        let mut lines = vec![format!(
            "{ZERO_KEY}\t{ZERO_KEY}\t51820\t(none)"
        )];
        // Peer lines: (pubkey, handshake_secs, rx_bytes, tx_bytes)
        for (pubkey, handshake, rx, tx) in peers {
            lines.push(format!(
                "{pubkey}\t(none)\t(none)\t10.7.0.0/24\t{handshake}\t{rx}\t{tx}\toff"
            ));
        }
        lines.join("\n")
    }

    #[test]
    fn map_peers_assigns_names_by_pubkey() {
        let dump = make_dump(&[(ZERO_KEY, 1_710_000_000, 1024, 2048), (ONE_KEY, 0, 0, 0)]);
        let live = parse_wg_show_dump(SERVER_IFACE, &dump).expect("parse");
        let config = sample_config();
        let named = map_peers(&live.peers, &config);

        assert_eq!(named.len(), 2);
        assert_eq!(named[0].name, "phone");
        assert_eq!(named[0].public_key, ZERO_KEY);
        assert_eq!(named[0].rx_bytes, 1024);
        assert_eq!(named[0].tx_bytes, 2048);
        let hs = named[0].last_handshake.expect("phone has handshake");
        assert_eq!(
            hs.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_710_000_000
        );

        assert_eq!(named[1].name, "laptop");
        assert_eq!(named[1].public_key, ONE_KEY);
        assert!(named[1].last_handshake.is_none());
        assert_eq!(named[1].rx_bytes, 0);
        assert_eq!(named[1].tx_bytes, 0);
    }

    #[test]
    fn map_peers_fallback_name_for_unknown_pubkey() {
        // TWO_KEY is NOT in the config — must get a truncated-key fallback name.
        let dump = make_dump(&[(TWO_KEY, 1_710_000_000, 512, 256)]);
        let live = parse_wg_show_dump(SERVER_IFACE, &dump).expect("parse");
        let config = sample_config();
        let named = map_peers(&live.peers, &config);

        assert_eq!(named.len(), 1);
        // The name must start with the first 12 chars of TWO_KEY.
        let fallback = &named[0].name;
        assert!(
            fallback.starts_with(&TWO_KEY[..12]),
            "expected fallback to start with first 12 chars of pubkey, got: {fallback:?}"
        );
        assert!(
            fallback.ends_with('…'),
            "expected fallback to end with '…', got: {fallback:?}"
        );
    }

    #[test]
    fn map_peers_empty_dump_produces_empty_vec() {
        let dump = make_dump(&[]);
        let live = parse_wg_show_dump(SERVER_IFACE, &dump).expect("parse");
        let config = sample_config();
        let named = map_peers(&live.peers, &config);
        assert!(named.is_empty());
    }

    #[test]
    fn map_peers_mixed_known_and_unknown() {
        // First peer is known (ZERO_KEY = "phone"), second is unknown (TWO_KEY).
        let dump = make_dump(&[
            (ZERO_KEY, 1_710_100_000, 4096, 8192),
            (TWO_KEY, 0, 0, 0),
        ]);
        let live = parse_wg_show_dump(SERVER_IFACE, &dump).expect("parse");
        let config = sample_config();
        let named = map_peers(&live.peers, &config);

        assert_eq!(named.len(), 2);
        assert_eq!(named[0].name, "phone");
        assert_eq!(named[0].rx_bytes, 4096);

        // Unknown peer gets fallback name.
        assert!(named[1].name.starts_with(&TWO_KEY[..12]));
    }

    #[test]
    fn map_peers_all_three_ordered_correctly() {
        // Dump has ZERO, ONE, TWO in that order — check order is preserved.
        let dump = make_dump(&[
            (ZERO_KEY, 1_000_000, 10, 20),
            (ONE_KEY, 2_000_000, 30, 40),
            (TWO_KEY, 3_000_000, 50, 60),
        ]);
        let live = parse_wg_show_dump(SERVER_IFACE, &dump).expect("parse");
        let config = sample_config();
        let named = map_peers(&live.peers, &config);

        assert_eq!(named.len(), 3);
        assert_eq!(named[0].name, "phone");
        assert_eq!(named[1].name, "laptop");
        // Third has fallback.
        assert!(named[2].name.starts_with(&TWO_KEY[..12]));

        // Byte counts are correct.
        assert_eq!(named[0].rx_bytes, 10);
        assert_eq!(named[1].rx_bytes, 30);
        assert_eq!(named[2].rx_bytes, 50);
    }

    #[test]
    fn map_peers_handshake_times_correct() {
        let dump = make_dump(&[
            (ZERO_KEY, 1_710_000_000, 0, 0),
            (ONE_KEY, 0, 0, 0), // never handshaked
        ]);
        let live = parse_wg_show_dump(SERVER_IFACE, &dump).expect("parse");
        let config = sample_config();
        let named = map_peers(&live.peers, &config);

        let hs0 = named[0].last_handshake.expect("phone has handshake");
        assert_eq!(
            hs0.duration_since(UNIX_EPOCH).unwrap(),
            Duration::from_secs(1_710_000_000)
        );
        assert!(named[1].last_handshake.is_none(), "laptop never handshaked");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tests that would need root — documented and marked #[ignore]
    // ─────────────────────────────────────────────────────────────────────────

    /// Bring the server interface up and verify `status_named` returns live data.
    ///
    /// Requires root (`pkexec` + helper binary) and a working WireGuard module.
    /// Run manually:
    ///   cargo test -- --ignored server_start_and_status_named_live
    #[tokio::test]
    #[ignore = "requires root (pkexec + helper) and a live WireGuard kernel module"]
    async fn server_start_and_status_named_live() {
        let config = sample_config();
        // This will panic with todo!() until ServerConfig::to_server_conf is implemented.
        start(&config).await.expect("server start");
        let peers = status_named(&config).await.expect("status_named");
        // No clients connected yet, but the call must succeed.
        let _ = peers;
        stop().await.expect("server stop");
    }
}
