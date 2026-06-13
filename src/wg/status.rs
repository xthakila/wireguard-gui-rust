//! Live tunnel status, parsed from `wg show <iface> dump`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// A snapshot of an interface's live status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStatus {
    pub interface: String,
    pub public_key: String,
    pub peers: Vec<PeerStatus>,
    pub fetched_at: SystemTime,
}

/// Live status of a single peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

// ---------------------------------------------------------------------------
// `wg show <iface> dump` format
//
// Line 1  (interface): privkey\tpubkey\tport\tfwmark
// Line 2+ (peer):      pubkey\tpsk\tendpoint\tallowed-ips\tlatest-handshake\trx\ttx\tkeepalive
//
// Sentinel values used by wg(8):
//   - "(none)"  for missing psk, fwmark
//   - "(none)"  for missing endpoint
//   - 0         for latest-handshake when never seen
//   - "off"     for persistent-keepalive disabled
// ---------------------------------------------------------------------------

/// Parse the tab-separated output of `wg show <iface> dump`.
pub fn parse_wg_show_dump(iface: &str, raw: &str) -> AppResult<LiveStatus> {
    let mut lines = raw.lines();

    // --- interface line (first, required) -----------------------------------
    let iface_line = lines.next().ok_or_else(|| {
        AppError::WgShowParseFailed("empty output — no interface line".into())
    })?;

    let iface_fields: Vec<&str> = iface_line.split('\t').collect();
    if iface_fields.len() < 4 {
        return Err(AppError::WgShowParseFailed(format!(
            "interface line has {} field(s), expected at least 4: {:?}",
            iface_fields.len(),
            iface_line,
        )));
    }
    // iface_fields[0] = private key (we don't expose it)
    let public_key = iface_fields[1].to_string();
    // iface_fields[2] = listen port
    // iface_fields[3] = fwmark

    // --- peer lines (zero or more) ------------------------------------------
    let mut peers = Vec::new();
    for (idx, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let peer = parse_peer_line(line).map_err(|e| {
            AppError::WgShowParseFailed(format!("peer line {} — {}", idx + 2, e))
        })?;
        peers.push(peer);
    }

    Ok(LiveStatus {
        interface: iface.to_string(),
        public_key,
        peers,
        fetched_at: SystemTime::now(),
    })
}

/// Parse a single peer line from `wg show <iface> dump`.
///
/// Format: pubkey\tpsk\tendpoint\tallowed-ips\tlatest-handshake\trx\ttx\tkeepalive
fn parse_peer_line(line: &str) -> Result<PeerStatus, String> {
    let f: Vec<&str> = line.split('\t').collect();
    if f.len() < 8 {
        return Err(format!(
            "expected 8 tab-separated fields, got {}: {:?}",
            f.len(),
            line,
        ));
    }

    let public_key = f[0].to_string();

    // endpoint: "(none)" → None
    let endpoint = if f[2] == "(none)" {
        None
    } else {
        Some(f[2].to_string())
    };

    // latest-handshake: unix timestamp seconds; 0 means never
    let handshake_secs: u64 = f[4].parse().map_err(|_| {
        format!("cannot parse latest-handshake {:?} as u64", f[4])
    })?;
    let last_handshake = if handshake_secs == 0 {
        None
    } else {
        Some(UNIX_EPOCH + Duration::from_secs(handshake_secs))
    };

    // rx/tx bytes
    let rx_bytes: u64 = f[5]
        .parse()
        .map_err(|_| format!("cannot parse rx_bytes {:?}", f[5]))?;
    let tx_bytes: u64 = f[6]
        .parse()
        .map_err(|_| format!("cannot parse tx_bytes {:?}", f[6]))?;

    Ok(PeerStatus {
        public_key,
        endpoint,
        last_handshake,
        rx_bytes,
        tx_bytes,
    })
}

// ---------------------------------------------------------------------------
// Async fetch
// ---------------------------------------------------------------------------

/// Fetch live status for `iface`. Returns `None` when the interface does not
/// exist (i.e. `wg show` exits non-zero with "No such device").
///
/// Shells out to `wg show <iface> dump` via `tokio::process::Command`.
pub async fn fetch_status(iface: Option<&str>) -> AppResult<Option<LiveStatus>> {
    use tokio::process::Command;

    let target = iface.unwrap_or("all");

    let output = Command::new("wg")
        .args(["show", target, "dump"])
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::WgNotFound
            } else {
                AppError::WgQuickFailed(format!("wg show failed: {}", e))
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "No such device" (or "Unable to access interface: …") means the
        // interface isn't up yet — not an error; we return None.
        if stderr.contains("No such device")
            || stderr.contains("Unable to access interface")
            || stderr.contains("does not exist")
        {
            return Ok(None);
        }
        return Err(AppError::WgShowParseFailed(format!(
            "wg show exited {:?}: {}",
            output.status.code(),
            stderr.trim(),
        )));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    if raw.trim().is_empty() {
        // Interface is up but wg reported nothing — treat as absent
        return Ok(None);
    }

    // When `iface` was None we used "all"; the dump may cover multiple
    // interfaces — take the first one's block.
    let effective_iface = iface.unwrap_or("wg0");
    let status = parse_wg_show_dump(effective_iface, raw.trim())?;
    Ok(Some(status))
}

// ---------------------------------------------------------------------------
// Unit tests (pure; no root, no network, no display)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- Golden strings for `wg show <iface> dump` --------------------------

    /// Minimal interface-only dump (no peers).
    const DUMP_NO_PEERS: &str =
        "WMhpHrGqhHmMBh4GJbLfP3c6BefX+YnhXFoobarPrivKey=\twg7c1D2K+Lx6Y2foobarPubKey=\t51820\t(none)";

    /// One peer with a known endpoint and handshake.
    const DUMP_ONE_PEER: &str = "\
WMhpHrGqhHmMBh4GJbLfP3c6BefX+YnhXFoobarPrivKey=\twg7c1D2K+Lx6Y2foobarPubKey=\t51820\t(none)
xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t203.0.113.1:51820\t10.0.0.2/32\t1710000000\t1024\t2048\toff";

    /// Two peers: one with preshared key + no endpoint, one normal.
    const DUMP_TWO_PEERS: &str = "\
WMhpHrGqhHmMBh4GJbLfP3c6BefX+YnhXFoobarPrivKey=\twg7c1D2K+Lx6Y2foobarPubKey=\t51820\t0x1
xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\tPresharedKeyFooBarBazQuxAAAAAAAAAAAAAAAAAAAA=\t(none)\t10.0.0.0/24\t0\t0\t0\toff
aB2jmZQR9YFooBarBazQuxPeer2PubKeyAAAAAAAAAAAA=\t(none)\t198.51.100.42:51820\t0.0.0.0/0,::/0\t1709999999\t123456789\t987654321\t25";

    #[test]
    fn parse_no_peers() {
        let s = parse_wg_show_dump("wg0", DUMP_NO_PEERS).expect("should parse");
        assert_eq!(s.interface, "wg0");
        assert_eq!(s.public_key, "wg7c1D2K+Lx6Y2foobarPubKey=");
        assert!(s.peers.is_empty());
    }

    #[test]
    fn parse_one_peer_fields() {
        let s = parse_wg_show_dump("wg0", DUMP_ONE_PEER).expect("should parse");
        assert_eq!(s.peers.len(), 1);
        let p = &s.peers[0];
        assert_eq!(p.public_key, "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
        assert_eq!(p.endpoint.as_deref(), Some("203.0.113.1:51820"));
        // handshake: unix 1710000000
        let hs = p.last_handshake.expect("should have handshake");
        let secs = hs.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_710_000_000);
        assert_eq!(p.rx_bytes, 1024);
        assert_eq!(p.tx_bytes, 2048);
    }

    #[test]
    fn parse_two_peers_first_never_seen() {
        let s = parse_wg_show_dump("wg0", DUMP_TWO_PEERS).expect("should parse");
        assert_eq!(s.peers.len(), 2);
        // Peer 0: never handshaked, no endpoint
        assert!(s.peers[0].last_handshake.is_none());
        assert!(s.peers[0].endpoint.is_none());
        assert_eq!(s.peers[0].rx_bytes, 0);
        // Peer 1: normal
        assert_eq!(
            s.peers[1].endpoint.as_deref(),
            Some("198.51.100.42:51820")
        );
        let hs = s.peers[1].last_handshake.expect("should have handshake");
        let secs = hs.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(secs, 1_709_999_999);
        assert_eq!(s.peers[1].rx_bytes, 123_456_789);
        assert_eq!(s.peers[1].tx_bytes, 987_654_321);
    }

    #[test]
    fn parse_empty_input_errors() {
        let err = parse_wg_show_dump("wg0", "").unwrap_err();
        assert!(err.to_string().contains("[E206]"));
    }

    #[test]
    fn parse_short_iface_line_errors() {
        let err = parse_wg_show_dump("wg0", "only-one-field").unwrap_err();
        assert!(err.to_string().contains("[E206]"));
    }

    #[test]
    fn parse_bad_peer_rx_bytes_errors() {
        let bad = format!(
            "{}\n{}\t(none)\t(none)\t(none)\t0\tNOT_A_NUMBER\t0\toff",
            DUMP_NO_PEERS,
            "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
        );
        let err = parse_wg_show_dump("wg0", &bad).unwrap_err();
        assert!(err.to_string().contains("[E206]"));
    }
}
