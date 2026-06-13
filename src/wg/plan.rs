//! Dry-run planning: what *would* happen if a profile were brought up (for a preview pane).

use crate::config::profile::WgProfile;

/// A human-readable summary of the effect of connecting a profile.
#[derive(Debug, Clone)]
pub struct DryRunPlan {
    pub profile_name: String,
    pub addresses: Vec<String>,
    pub routed_networks: Vec<String>,
    pub dns_servers: Vec<String>,
    pub endpoint: Option<String>,
    pub is_full_tunnel: bool,
    pub peer_count: usize,
    pub estimated_mtu: Option<u16>,
    pub kill_switch: bool,
}

/// Compute the dry-run plan for `profile` (with the kill switch on/off).
///
/// This is a pure function: it derives every field directly from the profile
/// without touching the system.
pub fn compute_plan(profile: &WgProfile, kill_switch: bool) -> DryRunPlan {
    // Collect all networks routed through the tunnel (union of peer AllowedIPs).
    let routed_networks: Vec<String> = profile
        .peers
        .iter()
        .flat_map(|p| p.allowed_ips.iter().cloned())
        .collect();

    // Full tunnel if any peer routes the default route.
    let is_full_tunnel = routed_networks.iter().any(|n| {
        n == "0.0.0.0/0"
            || n == "::/0"
            || n.starts_with("0.0.0.0/0")
            || n.starts_with("::/0")
    });

    // Use the endpoint from the first peer that has one.
    let endpoint = profile
        .peers
        .iter()
        .find_map(|p| p.endpoint.clone());

    DryRunPlan {
        profile_name: profile.name.clone(),
        addresses: profile.interface.address.clone(),
        routed_networks,
        dns_servers: profile.interface.dns.clone(),
        endpoint,
        is_full_tunnel,
        peer_count: profile.peers.len(),
        estimated_mtu: profile.interface.mtu,
        kill_switch,
    }
}

// ---------------------------------------------------------------------------
// Unit tests (pure; no I/O, no root, no network)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::profile::{InterfaceSection, PeerSection, WgProfile};

    fn make_profile(
        name: &str,
        addresses: Vec<&str>,
        dns: Vec<&str>,
        mtu: Option<u16>,
        peers: Vec<PeerSection>,
    ) -> WgProfile {
        WgProfile {
            name: name.to_string(),
            interface: InterfaceSection {
                private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                address: addresses.iter().map(|s| s.to_string()).collect(),
                dns: dns.iter().map(|s| s.to_string()).collect(),
                listen_port: None,
                mtu,
            },
            peers,
            path: None,
        }
    }

    fn peer(
        pubkey: &str,
        endpoint: Option<&str>,
        allowed_ips: Vec<&str>,
    ) -> PeerSection {
        PeerSection {
            public_key: pubkey.to_string(),
            preshared_key: None,
            endpoint: endpoint.map(|s| s.to_string()),
            allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
            persistent_keepalive: None,
        }
    }

    // --- split-tunnel (no default-route peer) --------------------------------

    #[test]
    fn split_tunnel_plan() {
        let profile = make_profile(
            "work-vpn",
            vec!["10.8.0.2/24"],
            vec!["10.8.0.1"],
            Some(1420),
            vec![peer(
                "PeerPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                Some("vpn.example.com:51820"),
                vec!["10.8.0.0/24", "192.168.1.0/24"],
            )],
        );

        let plan = compute_plan(&profile, false);

        assert_eq!(plan.profile_name, "work-vpn");
        assert_eq!(plan.addresses, vec!["10.8.0.2/24"]);
        assert_eq!(plan.dns_servers, vec!["10.8.0.1"]);
        assert_eq!(plan.endpoint.as_deref(), Some("vpn.example.com:51820"));
        assert!(!plan.is_full_tunnel, "split tunnel should not be full");
        assert_eq!(plan.peer_count, 1);
        assert_eq!(plan.estimated_mtu, Some(1420));
        assert!(!plan.kill_switch);
        assert_eq!(
            plan.routed_networks,
            vec!["10.8.0.0/24", "192.168.1.0/24"]
        );
    }

    // --- full-tunnel (0.0.0.0/0 present) ------------------------------------

    #[test]
    fn full_tunnel_plan_ipv4() {
        let profile = make_profile(
            "full",
            vec!["10.0.0.2/32"],
            vec![],
            None,
            vec![peer(
                "PeerPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                Some("1.2.3.4:51820"),
                vec!["0.0.0.0/0"],
            )],
        );

        let plan = compute_plan(&profile, true);

        assert!(plan.is_full_tunnel, "0.0.0.0/0 should trigger full tunnel");
        assert!(plan.kill_switch);
        assert_eq!(plan.estimated_mtu, None);
    }

    #[test]
    fn full_tunnel_plan_dual_stack() {
        let profile = make_profile(
            "full-ds",
            vec!["10.0.0.2/32", "fd00::2/128"],
            vec!["1.1.1.1"],
            None,
            vec![peer(
                "PeerPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                Some("1.2.3.4:51820"),
                vec!["0.0.0.0/0", "::/0"],
            )],
        );

        let plan = compute_plan(&profile, true);

        assert!(plan.is_full_tunnel);
        assert_eq!(plan.routed_networks, vec!["0.0.0.0/0", "::/0"]);
    }

    // --- zero peers ----------------------------------------------------------

    #[test]
    fn no_peers_plan() {
        let profile = make_profile("empty", vec!["10.0.0.1/32"], vec![], None, vec![]);

        let plan = compute_plan(&profile, false);

        assert_eq!(plan.peer_count, 0);
        assert!(plan.routed_networks.is_empty());
        assert!(!plan.is_full_tunnel);
        assert!(plan.endpoint.is_none());
    }

    // --- multiple peers ------------------------------------------------------

    #[test]
    fn multiple_peers_first_endpoint_wins() {
        let profile = make_profile(
            "multi",
            vec!["10.0.0.2/32"],
            vec![],
            None,
            vec![
                peer(
                    "Peer1PubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    Some("a.example.com:51820"),
                    vec!["10.1.0.0/24"],
                ),
                peer(
                    "Peer2PubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    Some("b.example.com:51820"),
                    vec!["10.2.0.0/24"],
                ),
            ],
        );

        let plan = compute_plan(&profile, false);

        assert_eq!(plan.peer_count, 2);
        // First peer's endpoint is returned
        assert_eq!(plan.endpoint.as_deref(), Some("a.example.com:51820"));
        assert_eq!(
            plan.routed_networks,
            vec!["10.1.0.0/24", "10.2.0.0/24"]
        );
        assert!(!plan.is_full_tunnel);
    }

    #[test]
    fn kill_switch_flag_propagated() {
        let profile = make_profile("ks", vec![], vec![], None, vec![]);
        let plan_on = compute_plan(&profile, true);
        let plan_off = compute_plan(&profile, false);
        assert!(plan_on.kill_switch);
        assert!(!plan_off.kill_switch);
    }
}
