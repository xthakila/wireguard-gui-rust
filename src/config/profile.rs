//! In-memory representation of a WireGuard `.conf` profile and its parsing/serialization.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// A full WireGuard profile: one `[Interface]` and zero-or-more `[Peer]` sections.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WgProfile {
    pub name: String,
    pub interface: InterfaceSection,
    pub peers: Vec<PeerSection>,
    /// On-disk path this profile was loaded from / will be saved to. Not serialized.
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

/// The `[Interface]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceSection {
    pub private_key: String,
    pub address: Vec<String>,
    pub dns: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
}

/// A `[Peer]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerSection {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Return `true` when the string is valid standard base64 that decodes to exactly 32 bytes.
fn is_valid_wg_key(s: &str) -> bool {
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(s.trim()) {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

/// Validate a single CIDR string like `10.0.0.1/24` or `fd00::1/64`.
///
/// Accepted forms:
///   IPv4: four decimal octets (0-255) `/` prefix (0-32)
///   IPv6: any colon-separated address `/` prefix (0-128)
fn is_valid_cidr(s: &str) -> bool {
    let s = s.trim();
    let (addr, prefix_str) = match s.split_once('/') {
        Some(pair) => pair,
        None => return false,
    };

    // Parse the prefix length.
    let prefix: u8 = match prefix_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    if addr.contains(':') {
        // IPv6: use std parse.
        let ok: bool = addr.parse::<std::net::Ipv6Addr>().is_ok();
        ok && prefix <= 128
    } else {
        // IPv4.
        let ok: bool = addr.parse::<std::net::Ipv4Addr>().is_ok();
        ok && prefix <= 32
    }
}

// ── main impl ────────────────────────────────────────────────────────────────

impl WgProfile {
    /// Parse a profile from raw `.conf` text. `name` becomes the profile's name.
    ///
    /// The format is INI-like with repeatable `[Peer]` sections. Within each section
    /// multi-valued keys (`Address`, `DNS`, `AllowedIPs`) are split on `,` and
    /// accumulated across repeated appearances of the same key.
    pub fn from_conf_str(name: &str, content: &str) -> AppResult<Self> {
        let mut profile = WgProfile {
            name: name.to_owned(),
            ..Default::default()
        };

        // Track which section we are currently inside.
        enum Section {
            None,
            Interface,
            Peer(PeerSection),
        }

        let mut current = Section::None;

        let flush_peer = |current: Section, profile: &mut WgProfile| -> Section {
            if let Section::Peer(peer) = current {
                profile.peers.push(peer);
            }
            Section::None
        };

        for (lineno, raw) in content.lines().enumerate() {
            // Strip inline comments (# and ;) and whitespace.
            let line = raw.trim();
            let line = match line.find('#').or_else(|| line.find(';')) {
                Some(idx) => line[..idx].trim(),
                None => line,
            };

            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') {
                // Section header.
                let header = line.trim_matches(|c| c == '[' || c == ']').trim();
                match header.to_lowercase().as_str() {
                    "interface" => {
                        flush_peer(current, &mut profile);
                        current = Section::Interface;
                    }
                    "peer" => {
                        flush_peer(current, &mut profile);
                        current = Section::Peer(PeerSection::default());
                    }
                    other => {
                        return Err(AppError::ProfileParseError {
                            name: name.to_owned(),
                            detail: format!("unknown section '[{other}]' at line {}", lineno + 1),
                        });
                    }
                }
                continue;
            }

            // Key = value pair.
            let (key, value) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => {
                    return Err(AppError::ProfileParseError {
                        name: name.to_owned(),
                        detail: format!("malformed line {} (no '='): {:?}", lineno + 1, raw),
                    });
                }
            };

            match &mut current {
                Section::None => {
                    return Err(AppError::ProfileParseError {
                        name: name.to_owned(),
                        detail: format!(
                            "key '{}' at line {} appears before any section header",
                            key,
                            lineno + 1
                        ),
                    });
                }

                Section::Interface => {
                    match key.to_lowercase().as_str() {
                        "privatekey" => profile.interface.private_key = value.to_owned(),
                        "address" => {
                            for part in value.split(',') {
                                let s = part.trim().to_owned();
                                if !s.is_empty() {
                                    profile.interface.address.push(s);
                                }
                            }
                        }
                        "dns" => {
                            for part in value.split(',') {
                                let s = part.trim().to_owned();
                                if !s.is_empty() {
                                    profile.interface.dns.push(s);
                                }
                            }
                        }
                        "listenport" => {
                            let port: u16 =
                                value.parse().map_err(|_| AppError::ProfileParseError {
                                    name: name.to_owned(),
                                    detail: format!("invalid ListenPort '{value}' at line {}", lineno + 1),
                                })?;
                            profile.interface.listen_port = Some(port);
                        }
                        "mtu" => {
                            let mtu: u16 =
                                value.parse().map_err(|_| AppError::ProfileParseError {
                                    name: name.to_owned(),
                                    detail: format!("invalid MTU '{value}' at line {}", lineno + 1),
                                })?;
                            profile.interface.mtu = Some(mtu);
                        }
                        // wg-quick extras we accept silently (PostUp, PreDown, etc.)
                        _ => {}
                    }
                }

                Section::Peer(peer) => {
                    match key.to_lowercase().as_str() {
                        "publickey" => peer.public_key = value.to_owned(),
                        "presharedkey" => peer.preshared_key = Some(value.to_owned()),
                        "endpoint" => peer.endpoint = Some(value.to_owned()),
                        "allowedips" => {
                            for part in value.split(',') {
                                let s = part.trim().to_owned();
                                if !s.is_empty() {
                                    peer.allowed_ips.push(s);
                                }
                            }
                        }
                        "persistentkeepalive" => {
                            let ka: u16 =
                                value.parse().map_err(|_| AppError::ProfileParseError {
                                    name: name.to_owned(),
                                    detail: format!(
                                        "invalid PersistentKeepalive '{value}' at line {}",
                                        lineno + 1
                                    ),
                                })?;
                            peer.persistent_keepalive = Some(ka);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Flush a trailing [Peer] section.
        flush_peer(current, &mut profile);

        Ok(profile)
    }

    /// Render this profile back to canonical `.conf` text.
    ///
    /// Output format matches what `wg-quick` expects:
    ///   - `[Interface]` first
    ///   - One key per line; multi-valued fields (Address, DNS, AllowedIPs) are
    ///     emitted as comma-joined single lines.
    pub fn to_conf_string(&self) -> String {
        let mut out = String::new();

        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", self.interface.private_key));
        if !self.interface.address.is_empty() {
            out.push_str(&format!("Address = {}\n", self.interface.address.join(", ")));
        }
        if !self.interface.dns.is_empty() {
            out.push_str(&format!("DNS = {}\n", self.interface.dns.join(", ")));
        }
        if let Some(port) = self.interface.listen_port {
            out.push_str(&format!("ListenPort = {port}\n"));
        }
        if let Some(mtu) = self.interface.mtu {
            out.push_str(&format!("MTU = {mtu}\n"));
        }

        for peer in &self.peers {
            out.push('\n');
            out.push_str("[Peer]\n");
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));
            if let Some(psk) = &peer.preshared_key {
                out.push_str(&format!("PresharedKey = {psk}\n"));
            }
            if let Some(ep) = &peer.endpoint {
                out.push_str(&format!("Endpoint = {ep}\n"));
            }
            if !peer.allowed_ips.is_empty() {
                out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
            }
            if let Some(ka) = peer.persistent_keepalive {
                out.push_str(&format!("PersistentKeepalive = {ka}\n"));
            }
        }

        out
    }

    /// Validate the profile. Returns `(field, detail)` pairs for each problem found;
    /// an empty vec means the profile is valid.
    pub fn validate(&self) -> Vec<(String, String)> {
        let mut errors: Vec<(String, String)> = Vec::new();

        // Interface.PrivateKey
        if self.interface.private_key.is_empty() {
            errors.push((
                "Interface.PrivateKey".to_owned(),
                "must not be empty".to_owned(),
            ));
        } else if !is_valid_wg_key(&self.interface.private_key) {
            errors.push((
                "Interface.PrivateKey".to_owned(),
                "must be a valid base64-encoded 32-byte key".to_owned(),
            ));
        }

        // Interface.Address
        if self.interface.address.is_empty() {
            errors.push((
                "Interface.Address".to_owned(),
                "at least one address/CIDR is required".to_owned(),
            ));
        }
        for addr in &self.interface.address {
            if !is_valid_cidr(addr) {
                errors.push((
                    "Interface.Address".to_owned(),
                    format!("'{addr}' is not a valid CIDR"),
                ));
            }
        }

        // Interface.ListenPort (optional; 0 is unusual but permitted by wg)
        // No additional validation needed beyond u16 range (handled by the type).

        // Peers
        for (i, peer) in self.peers.iter().enumerate() {
            let ctx = |field: &str| format!("Peer[{i}].{field}");

            // PublicKey
            if peer.public_key.is_empty() {
                errors.push((ctx("PublicKey"), "must not be empty".to_owned()));
            } else if !is_valid_wg_key(&peer.public_key) {
                errors.push((
                    ctx("PublicKey"),
                    "must be a valid base64-encoded 32-byte key".to_owned(),
                ));
            }

            // PresharedKey (optional)
            if let Some(psk) = &peer.preshared_key
                && !is_valid_wg_key(psk)
            {
                errors.push((
                    ctx("PresharedKey"),
                    "must be a valid base64-encoded 32-byte key".to_owned(),
                ));
            }

            // AllowedIPs
            for cidr in &peer.allowed_ips {
                if !is_valid_cidr(cidr) {
                    errors.push((ctx("AllowedIPs"), format!("'{cidr}' is not a valid CIDR")));
                }
            }

            // Endpoint: basic "host:port" or "[ipv6]:port" sanity check.
            if let Some(ep) = &peer.endpoint {
                let valid = if ep.starts_with('[') {
                    // IPv6 literal: [addr]:port
                    ep.contains("]:") && ep.split("]:").nth(1).and_then(|p| p.parse::<u16>().ok()).is_some()
                } else {
                    let parts: Vec<&str> = ep.rsplitn(2, ':').collect();
                    parts.len() == 2 && parts[0].parse::<u16>().is_ok() && !parts[1].is_empty()
                };
                if !valid {
                    errors.push((ctx("Endpoint"), format!("'{ep}' is not a valid host:port")));
                }
            }
        }

        errors
    }

    /// The set of networks routed through the tunnel (union of all peers' AllowedIPs).
    pub fn routed_networks(&self) -> Vec<String> {
        let mut networks: Vec<String> = Vec::new();
        for peer in &self.peers {
            for cidr in &peer.allowed_ips {
                let s = cidr.trim().to_owned();
                if !networks.contains(&s) {
                    networks.push(s);
                }
            }
        }
        networks
    }

    /// True when this profile routes all traffic (any peer has `0.0.0.0/0` or `::/0`).
    pub fn is_full_tunnel(&self) -> bool {
        self.peers.iter().any(|peer| {
            peer.allowed_ips.iter().any(|cidr| {
                let s = cidr.trim();
                s == "0.0.0.0/0" || s == "::/0"
            })
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // A syntactically valid base64-encoded 32-byte key (32 zero bytes in base64).
    const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn minimal_conf(private_key: &str, allowed_ips: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {private_key}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = {allowed_ips}\n"
        )
    }

    // ── parse / round-trip ────────────────────────────────────────────────────

    #[test]
    fn parse_minimal_profile() {
        let conf = minimal_conf(ZERO_KEY, "0.0.0.0/0");
        let p = WgProfile::from_conf_str("test", &conf).unwrap();
        assert_eq!(p.name, "test");
        assert_eq!(p.interface.private_key, ZERO_KEY);
        assert_eq!(p.interface.address, vec!["10.0.0.1/24"]);
        assert_eq!(p.peers.len(), 1);
        assert_eq!(p.peers[0].public_key, ZERO_KEY);
        assert_eq!(p.peers[0].allowed_ips, vec!["0.0.0.0/0"]);
    }

    #[test]
    fn round_trip_preserves_data() {
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.2/24, fd00::2/128\n\
             DNS = 1.1.1.1, 8.8.8.8\nListenPort = 51820\nMTU = 1420\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nEndpoint = vpn.example.com:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
        );
        let p = WgProfile::from_conf_str("wg0", &conf).unwrap();
        let out = p.to_conf_string();
        let p2 = WgProfile::from_conf_str("wg0", &out).unwrap();

        assert_eq!(p2.interface.private_key, ZERO_KEY);
        assert_eq!(p2.interface.address, vec!["10.0.0.2/24", "fd00::2/128"]);
        assert_eq!(p2.interface.dns, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(p2.interface.listen_port, Some(51820));
        assert_eq!(p2.interface.mtu, Some(1420));
        assert_eq!(p2.peers.len(), 1);
        assert_eq!(p2.peers[0].endpoint.as_deref(), Some("vpn.example.com:51820"));
        assert_eq!(p2.peers[0].persistent_keepalive, Some(25));
        assert!(p2.peers[0].allowed_ips.contains(&"0.0.0.0/0".to_owned()));
        assert!(p2.peers[0].allowed_ips.contains(&"::/0".to_owned()));
    }

    #[test]
    fn multiple_peers_parsed() {
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = 10.1.0.0/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = 10.2.0.0/24\n"
        );
        let p = WgProfile::from_conf_str("multi", &conf).unwrap();
        assert_eq!(p.peers.len(), 2);
    }

    #[test]
    fn inline_comments_stripped() {
        let conf = format!(
            "[Interface] # my tunnel\nPrivateKey = {ZERO_KEY} # secret\n\
             Address = 10.0.0.1/24 ; this is a comment\n"
        );
        let p = WgProfile::from_conf_str("comments", &conf).unwrap();
        assert_eq!(p.interface.private_key, ZERO_KEY);
        assert_eq!(p.interface.address, vec!["10.0.0.1/24"]);
    }

    #[test]
    fn parse_error_on_unknown_section() {
        let conf = "[Unknown]\nFoo = bar\n";
        let err = WgProfile::from_conf_str("bad", conf).unwrap_err();
        assert!(matches!(err, crate::error::AppError::ProfileParseError { .. }));
    }

    #[test]
    fn parse_error_on_key_before_section() {
        let conf = "PrivateKey = foo\n";
        let err = WgProfile::from_conf_str("bad", conf).unwrap_err();
        assert!(matches!(err, crate::error::AppError::ProfileParseError { .. }));
    }

    #[test]
    fn allowedips_comma_split_within_line() {
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = 10.0.0.0/8, 192.168.0.0/16\n"
        );
        let p = WgProfile::from_conf_str("split", &conf).unwrap();
        assert_eq!(
            p.peers[0].allowed_ips,
            vec!["10.0.0.0/8", "192.168.0.0/16"]
        );
    }

    // ── validate ─────────────────────────────────────────────────────────────

    #[test]
    fn validate_empty_private_key() {
        let conf = "[Interface]\nPrivateKey = \nAddress = 10.0.0.1/24\n\n\
                    [Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\n";
        let p = WgProfile::from_conf_str("v", conf).unwrap();
        let errs = p.validate();
        assert!(errs.iter().any(|(f, _)| f == "Interface.PrivateKey"), "errs={errs:?}");
    }

    #[test]
    fn validate_bad_private_key() {
        let mut p = WgProfile::default();
        p.interface.private_key = "not-valid-base64!!!".to_owned();
        p.interface.address = vec!["10.0.0.1/24".to_owned()];
        let errs = p.validate();
        assert!(errs.iter().any(|(f, _)| f == "Interface.PrivateKey"), "errs={errs:?}");
    }

    #[test]
    fn validate_bad_cidr() {
        let mut p = WgProfile::default();
        p.interface.private_key = ZERO_KEY.to_owned();
        p.interface.address = vec!["not-a-cidr".to_owned()];
        let errs = p.validate();
        assert!(errs.iter().any(|(f, _)| f == "Interface.Address"), "errs={errs:?}");
    }

    #[test]
    fn validate_cidr_prefix_too_large() {
        let mut p = WgProfile::default();
        p.interface.private_key = ZERO_KEY.to_owned();
        p.interface.address = vec!["10.0.0.1/33".to_owned()]; // /33 invalid for IPv4
        let errs = p.validate();
        assert!(errs.iter().any(|(f, _)| f == "Interface.Address"), "errs={errs:?}");
    }

    #[test]
    fn validate_valid_profile_no_errors() {
        let conf = minimal_conf(ZERO_KEY, "0.0.0.0/0");
        let p = WgProfile::from_conf_str("ok", &conf).unwrap();
        let errs = p.validate();
        assert!(errs.is_empty(), "unexpected errors: {errs:?}");
    }

    #[test]
    fn validate_bad_peer_public_key() {
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = badkey\nAllowedIPs = 0.0.0.0/0\n"
        );
        let p = WgProfile::from_conf_str("bad", &conf).unwrap();
        let errs = p.validate();
        assert!(errs.iter().any(|(f, _)| f.contains("PublicKey")), "errs={errs:?}");
    }

    #[test]
    fn validate_bad_allowed_ips() {
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = oops\n"
        );
        let p = WgProfile::from_conf_str("bad", &conf).unwrap();
        let errs = p.validate();
        assert!(errs.iter().any(|(f, _)| f.contains("AllowedIPs")), "errs={errs:?}");
    }

    #[test]
    fn validate_bad_endpoint() {
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nEndpoint = notanendpoint\nAllowedIPs = 0.0.0.0/0\n"
        );
        let p = WgProfile::from_conf_str("bad", &conf).unwrap();
        let errs = p.validate();
        assert!(errs.iter().any(|(f, _)| f.contains("Endpoint")), "errs={errs:?}");
    }

    // ── routed_networks / is_full_tunnel ─────────────────────────────────────

    #[test]
    fn full_tunnel_via_v4() {
        let conf = minimal_conf(ZERO_KEY, "0.0.0.0/0");
        let p = WgProfile::from_conf_str("ft", &conf).unwrap();
        assert!(p.is_full_tunnel());
    }

    #[test]
    fn full_tunnel_via_v6() {
        let conf = minimal_conf(ZERO_KEY, "::/0");
        let p = WgProfile::from_conf_str("ft6", &conf).unwrap();
        assert!(p.is_full_tunnel());
    }

    #[test]
    fn split_tunnel_not_full() {
        let conf = minimal_conf(ZERO_KEY, "10.0.0.0/8");
        let p = WgProfile::from_conf_str("split", &conf).unwrap();
        assert!(!p.is_full_tunnel());
    }

    #[test]
    fn routed_networks_dedup() {
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = 10.0.0.0/8, 192.168.0.0/16\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = 10.0.0.0/8, 172.16.0.0/12\n"
        );
        let p = WgProfile::from_conf_str("nets", &conf).unwrap();
        let nets = p.routed_networks();
        // 10.0.0.0/8 appears in both peers but should appear only once.
        let count_10 = nets.iter().filter(|s| s.as_str() == "10.0.0.0/8").count();
        assert_eq!(count_10, 1, "nets={nets:?}");
        assert!(nets.contains(&"192.168.0.0/16".to_owned()));
        assert!(nets.contains(&"172.16.0.0/12".to_owned()));
    }
}
