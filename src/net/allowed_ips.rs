//! AllowedIPs presets — full tunnel, split-tunnel (exclude RFC1918), or a custom CIDR list.

use serde::{Deserialize, Serialize};

use crate::config::profile::WgProfile;
use crate::error::AppResult;

/// A reusable AllowedIPs policy applied to a profile's peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AllowedIpsPreset {
    /// Route everything (`0.0.0.0/0`, `::/0`).
    FullTunnel,
    /// Route everything except local RFC1918 ranges.
    SplitExcludeRFC1918,
    /// An explicit list of CIDRs.
    Custom(Vec<String>),
}

/// The standard IPv4 CIDR complement of the three RFC1918 private blocks
/// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) plus `::/0` for IPv6.
///
/// Computed as `0.0.0.0/0` minus the RFC1918 ranges using standard binary
/// CIDR subtraction.  The list is ordered from lowest to highest prefix.
const SPLIT_EXCLUDE_RFC1918: &[&str] = &[
    // IPv4 public space, RFC1918 holes removed.
    "0.0.0.0/5",
    "8.0.0.0/7",
    "11.0.0.0/8",
    "12.0.0.0/6",
    "16.0.0.0/4",
    "32.0.0.0/3",
    "64.0.0.0/2",
    "128.0.0.0/3",
    "160.0.0.0/5",
    "168.0.0.0/6",
    "172.0.0.0/12",
    "172.32.0.0/11",
    "172.64.0.0/10",
    "172.128.0.0/9",
    "173.0.0.0/8",
    "174.0.0.0/7",
    "176.0.0.0/4",
    "192.0.0.0/9",
    "192.128.0.0/11",
    "192.160.0.0/13",
    "192.169.0.0/16",
    "192.170.0.0/15",
    "192.172.0.0/14",
    "192.176.0.0/12",
    "192.192.0.0/10",
    "193.0.0.0/8",
    "194.0.0.0/7",
    "196.0.0.0/6",
    "200.0.0.0/5",
    "208.0.0.0/4",
    // IPv6 — all traffic.
    "::/0",
];

impl AllowedIpsPreset {
    /// Produce a copy of `profile` with this preset applied to its peers' AllowedIPs.
    ///
    /// - [`AllowedIpsPreset::FullTunnel`] sets every peer to `["0.0.0.0/0", "::/0"]`.
    /// - [`AllowedIpsPreset::SplitExcludeRFC1918`] sets every peer to the standard
    ///   non-RFC1918 CIDR list (public IPv4 + all IPv6).
    /// - [`AllowedIpsPreset::Custom`] replaces every peer's list with the supplied CIDRs.
    pub fn apply_to_profile(&self, profile: &WgProfile) -> AppResult<WgProfile> {
        let cidrs = self.cidrs();
        let mut out = profile.clone();
        for peer in &mut out.peers {
            peer.allowed_ips = cidrs.iter().map(|s| s.to_string()).collect();
        }
        Ok(out)
    }

    /// A short label for UI display.
    pub fn display_name(&self) -> &str {
        match self {
            AllowedIpsPreset::FullTunnel => "Full Tunnel",
            AllowedIpsPreset::SplitExcludeRFC1918 => "Split Tunnel (exclude RFC1918)",
            AllowedIpsPreset::Custom(_) => "Custom",
        }
    }

    /// The canonical CIDR list this preset resolves to.
    fn cidrs(&self) -> Vec<&str> {
        match self {
            AllowedIpsPreset::FullTunnel => vec!["0.0.0.0/0", "::/0"],
            AllowedIpsPreset::SplitExcludeRFC1918 => SPLIT_EXCLUDE_RFC1918.to_vec(),
            AllowedIpsPreset::Custom(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::profile::{InterfaceSection, PeerSection, WgProfile};

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn make_profile_with_peers(peers: usize) -> WgProfile {
        WgProfile {
            name: "test".to_string(),
            interface: InterfaceSection {
                private_key: "AAAA".to_string(),
                address: vec!["10.0.0.2/32".to_string()],
                dns: vec!["1.1.1.1".to_string()],
                listen_port: None,
                mtu: None,
            },
            peers: (0..peers)
                .map(|i| PeerSection {
                    public_key: format!("PEER{i}"),
                    preshared_key: None,
                    endpoint: Some(format!("192.0.2.{i}:51820")),
                    allowed_ips: vec!["10.0.0.0/8".to_string()],
                    persistent_keepalive: None,
                })
                .collect(),
            path: None,
        }
    }

    // ------------------------------------------------------------------
    // FullTunnel
    // ------------------------------------------------------------------

    #[test]
    fn full_tunnel_display_name() {
        assert_eq!(AllowedIpsPreset::FullTunnel.display_name(), "Full Tunnel");
    }

    #[test]
    fn full_tunnel_apply_no_peers() {
        let profile = make_profile_with_peers(0);
        let result = AllowedIpsPreset::FullTunnel
            .apply_to_profile(&profile)
            .unwrap();
        assert!(result.peers.is_empty());
    }

    #[test]
    fn full_tunnel_apply_single_peer() {
        let profile = make_profile_with_peers(1);
        let result = AllowedIpsPreset::FullTunnel
            .apply_to_profile(&profile)
            .unwrap();
        assert_eq!(result.peers.len(), 1);
        assert_eq!(
            result.peers[0].allowed_ips,
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
        );
    }

    #[test]
    fn full_tunnel_apply_multiple_peers() {
        let profile = make_profile_with_peers(3);
        let result = AllowedIpsPreset::FullTunnel
            .apply_to_profile(&profile)
            .unwrap();
        assert_eq!(result.peers.len(), 3);
        for peer in &result.peers {
            assert_eq!(
                peer.allowed_ips,
                vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
            );
        }
    }

    #[test]
    fn full_tunnel_does_not_mutate_original() {
        let profile = make_profile_with_peers(1);
        let original_ips = profile.peers[0].allowed_ips.clone();
        let _result = AllowedIpsPreset::FullTunnel
            .apply_to_profile(&profile)
            .unwrap();
        assert_eq!(profile.peers[0].allowed_ips, original_ips);
    }

    #[test]
    fn full_tunnel_preserves_other_fields() {
        let profile = make_profile_with_peers(1);
        let result = AllowedIpsPreset::FullTunnel
            .apply_to_profile(&profile)
            .unwrap();
        assert_eq!(result.name, profile.name);
        assert_eq!(result.interface.private_key, profile.interface.private_key);
        assert_eq!(result.peers[0].public_key, profile.peers[0].public_key);
        assert_eq!(result.peers[0].endpoint, profile.peers[0].endpoint);
    }

    // ------------------------------------------------------------------
    // SplitExcludeRFC1918
    // ------------------------------------------------------------------

    #[test]
    fn split_display_name() {
        assert_eq!(
            AllowedIpsPreset::SplitExcludeRFC1918.display_name(),
            "Split Tunnel (exclude RFC1918)"
        );
    }

    #[test]
    fn split_apply_single_peer() {
        let profile = make_profile_with_peers(1);
        let result = AllowedIpsPreset::SplitExcludeRFC1918
            .apply_to_profile(&profile)
            .unwrap();
        assert_eq!(result.peers.len(), 1);
        let ips = &result.peers[0].allowed_ips;
        // Must contain some public IPv4 and the IPv6 catch-all.
        assert!(ips.contains(&"0.0.0.0/5".to_string()), "missing 0.0.0.0/5");
        assert!(ips.contains(&"::/0".to_string()), "missing ::/0");
    }

    #[test]
    fn split_excludes_rfc1918_ranges() {
        let profile = make_profile_with_peers(1);
        let result = AllowedIpsPreset::SplitExcludeRFC1918
            .apply_to_profile(&profile)
            .unwrap();
        let ips = &result.peers[0].allowed_ips;
        // The three RFC1918 blocks must not appear literally.
        assert!(
            !ips.contains(&"10.0.0.0/8".to_string()),
            "10/8 must be excluded"
        );
        assert!(
            !ips.contains(&"172.16.0.0/12".to_string()),
            "172.16/12 must be excluded"
        );
        assert!(
            !ips.contains(&"192.168.0.0/16".to_string()),
            "192.168/16 must be excluded"
        );
    }

    #[test]
    fn split_apply_multiple_peers_all_equal() {
        let profile = make_profile_with_peers(4);
        let result = AllowedIpsPreset::SplitExcludeRFC1918
            .apply_to_profile(&profile)
            .unwrap();
        assert_eq!(result.peers.len(), 4);
        let first = &result.peers[0].allowed_ips;
        for peer in &result.peers {
            assert_eq!(&peer.allowed_ips, first);
        }
    }

    #[test]
    fn split_cidr_count_matches_constant() {
        let profile = make_profile_with_peers(1);
        let result = AllowedIpsPreset::SplitExcludeRFC1918
            .apply_to_profile(&profile)
            .unwrap();
        assert_eq!(
            result.peers[0].allowed_ips.len(),
            SPLIT_EXCLUDE_RFC1918.len()
        );
    }

    #[test]
    fn split_constant_entries_are_valid_cidr_strings() {
        for cidr in SPLIT_EXCLUDE_RFC1918 {
            // Must contain a '/' separator.
            assert!(cidr.contains('/'), "not a CIDR: {cidr}");
            let (_, prefix) = cidr.rsplit_once('/').unwrap();
            let prefix: u8 = prefix.parse().expect("prefix not a number");
            // IPv4 prefix ≤ 32, IPv6 prefix ≤ 128.
            assert!(prefix <= 128, "prefix out of range: {cidr}");
        }
    }

    // ------------------------------------------------------------------
    // Custom
    // ------------------------------------------------------------------

    #[test]
    fn custom_display_name() {
        let preset = AllowedIpsPreset::Custom(vec!["10.8.0.0/24".to_string()]);
        assert_eq!(preset.display_name(), "Custom");
    }

    #[test]
    fn custom_apply_empty_list() {
        let profile = make_profile_with_peers(2);
        let preset = AllowedIpsPreset::Custom(vec![]);
        let result = preset.apply_to_profile(&profile).unwrap();
        for peer in &result.peers {
            assert!(peer.allowed_ips.is_empty());
        }
    }

    #[test]
    fn custom_apply_single_cidr() {
        let profile = make_profile_with_peers(1);
        let cidr = "10.8.0.0/24".to_string();
        let preset = AllowedIpsPreset::Custom(vec![cidr.clone()]);
        let result = preset.apply_to_profile(&profile).unwrap();
        assert_eq!(result.peers[0].allowed_ips, vec![cidr]);
    }

    #[test]
    fn custom_apply_multiple_cidrs() {
        let profile = make_profile_with_peers(2);
        let cidrs = vec![
            "10.8.0.0/24".to_string(),
            "192.0.2.0/24".to_string(),
            "::/1".to_string(),
        ];
        let preset = AllowedIpsPreset::Custom(cidrs.clone());
        let result = preset.apply_to_profile(&profile).unwrap();
        for peer in &result.peers {
            assert_eq!(peer.allowed_ips, cidrs);
        }
    }

    #[test]
    fn custom_does_not_mutate_original() {
        let profile = make_profile_with_peers(1);
        let original_ips = profile.peers[0].allowed_ips.clone();
        let preset = AllowedIpsPreset::Custom(vec!["198.51.100.0/24".to_string()]);
        let _result = preset.apply_to_profile(&profile).unwrap();
        assert_eq!(profile.peers[0].allowed_ips, original_ips);
    }

    #[test]
    fn custom_vector_cloned_independently() {
        // Mutating the result must not affect the preset's internal vec.
        let cidrs = vec!["10.0.0.0/8".to_string()];
        let preset = AllowedIpsPreset::Custom(cidrs.clone());
        let profile = make_profile_with_peers(1);
        let mut result = preset.apply_to_profile(&profile).unwrap();
        result.peers[0].allowed_ips.push("172.16.0.0/12".to_string());
        // Applying again must still yield the original one-entry list.
        let result2 = preset.apply_to_profile(&profile).unwrap();
        assert_eq!(result2.peers[0].allowed_ips, cidrs);
    }

    // ------------------------------------------------------------------
    // Serialization round-trip (pure, no I/O)
    // ------------------------------------------------------------------

    #[test]
    fn presets_serialize_roundtrip() {
        let presets = vec![
            AllowedIpsPreset::FullTunnel,
            AllowedIpsPreset::SplitExcludeRFC1918,
            AllowedIpsPreset::Custom(vec!["10.0.0.0/8".to_string(), "::/0".to_string()]),
        ];
        for preset in &presets {
            let json = serde_json::to_string(preset).expect("serialize failed");
            let back: AllowedIpsPreset =
                serde_json::from_str(&json).expect("deserialize failed");
            assert_eq!(preset, &back);
        }
    }

    // ------------------------------------------------------------------
    // apply_to_profile returns Ok, never Err for well-formed inputs
    // ------------------------------------------------------------------

    #[test]
    fn apply_returns_ok_for_all_presets() {
        let profile = make_profile_with_peers(2);
        let presets = [
            AllowedIpsPreset::FullTunnel,
            AllowedIpsPreset::SplitExcludeRFC1918,
            AllowedIpsPreset::Custom(vec!["0.0.0.0/0".to_string()]),
        ];
        for preset in &presets {
            assert!(
                preset.apply_to_profile(&profile).is_ok(),
                "{} returned Err",
                preset.display_name()
            );
        }
    }
}
