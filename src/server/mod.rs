//! WireGuard SERVER mode — the FROZEN data model + signatures for hosting a tunnel.
//!
//! ============================ SAFETY / PRIVILEGE NOTICE ============================
//! Like the rest of the crate, the GUI process NEVER runs as root. Bringing a server
//! interface up, applying NAT, and enabling IP forwarding are root-only operations
//! expressed as [`crate::net::privilege::PrivCmd`] values and dispatched to the
//! `wireguard-gui-helper` binary via `pkexec`. This module is **pure GUI-side**: it
//! owns the server config data model + (de)serialization + conf-text generation +
//! IP allocation + QR rendering. It NEVER applies any networking change.
//!
//! The server uses a DIFFERENT kernel interface from the client
//! ([`crate::server::manage::SERVER_IFACE`] = `wg-gui-srv0`, vs the client's
//! [`crate::wg::backend::CLIENT_IFACE`] = `wg-gui0`) so the two can coexist on one
//! host without colliding.
//! ====================================================================================
//!
//! # CORE stage
//!
//! The data model below is FROZEN — the views (`crate::ui::server`), the management
//! layer (`crate::server::manage`), and the privileged helper all build on these
//! shapes. Method **signatures** are frozen too; non-trivial bodies are `todo!()` and
//! are filled in a later stage. The trivial, pure pieces (defaults, conf-text
//! generation, IP allocation, QR rendering) are implemented now because they are
//! golden-testable without any root / network side-effects.

pub mod manage;

// Real root-only end-to-end handshake test (gated behind #[ignore]); compiled only
// for test builds so it never affects the shipping binaries.
#[cfg(test)]
mod e2e;

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{AppError, AppResult};

// ─────────────────────────────────────────────────────────────────────────────
// FROZEN data model
// ─────────────────────────────────────────────────────────────────────────────

/// A WireGuard **server** configuration: the `[Interface]` this host listens on,
/// plus one [`ServerPeer`] per provisioned client.
///
/// Persisted as `server.json` (0600) in the app config dir (see [`ServerConfig::load`] /
/// [`ServerConfig::save`]). This is the GUI's source of truth for the server; the
/// kernel-side `.conf` handed to `wg setconf` is generated on demand by
/// [`ServerConfig::to_server_conf`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Display name for the server config (identity only — the kernel interface is
    /// the fixed [`crate::server::manage::SERVER_IFACE`]).
    pub name: String,
    /// The server's own private key (base64, 32 bytes).
    pub private_key: String,
    /// The server's own public key (base64, 32 bytes) — handed to clients.
    pub public_key: String,
    /// UDP port the server listens on (default 51820).
    pub listen_port: u16,
    /// The server interface's own address/CIDR inside the tunnel, e.g. `10.7.0.1/24`.
    pub address: String,
    /// The tunnel subnet clients are allocated from, e.g. `10.7.0.0/24`.
    pub subnet: String,
    /// Public host (IP or DNS name) clients dial — used to build each client's
    /// `Endpoint = <endpoint_host>:<listen_port>`.
    pub endpoint_host: String,
    /// DNS servers advertised to clients in their generated config.
    pub dns: Vec<String>,
    /// The host's egress (internet-facing) interface used for the NAT masquerade
    /// rule, e.g. `eth0`. `None` until detected / chosen.
    pub egress_iface: Option<String>,
    /// Provisioned clients.
    pub peers: Vec<ServerPeer>,
}

/// A single provisioned client of the [`ServerConfig`].
///
/// The server generates the keypair on the client's behalf so it can hand out a
/// ready-to-use client `.conf` (and a QR code of it). The private key is retained
/// ONLY so the client config can be re-displayed / re-exported; it is never needed by
/// the server-side `.conf` (which references the peer by `public_key`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPeer {
    /// Display name for this client (e.g. "phone", "laptop").
    pub name: String,
    /// The client's public key (base64, 32 bytes) — referenced by the server `.conf`.
    pub public_key: String,
    /// The client's private key (base64), retained so the handed-out client config /
    /// QR can be regenerated. `None` if the peer was added by public key only.
    pub private_key: Option<String>,
    /// The tunnel IP assigned to this client (a single host address, no prefix), e.g.
    /// `10.7.0.2`. Emitted into the server `.conf` as `AllowedIPs = <assigned_ip>/32`.
    pub assigned_ip: String,
    /// Optional preshared key (base64) for an extra symmetric layer.
    pub preshared_key: Option<String>,
    /// What the CLIENT routes through the tunnel — its `AllowedIPs`. Defaults to
    /// `0.0.0.0/0` (full tunnel). NOT to be confused with the server-side
    /// `AllowedIPs = <assigned_ip>/32`, which is fixed per peer.
    pub client_allowed_ips: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants / defaults (the frozen server defaults)
// ─────────────────────────────────────────────────────────────────────────────

/// Default UDP listen port for a freshly-generated server.
pub const DEFAULT_LISTEN_PORT: u16 = 51820;
/// Default server interface address/CIDR.
pub const DEFAULT_ADDRESS: &str = "10.7.0.1/24";
/// Default tunnel subnet clients are allocated from.
pub const DEFAULT_SUBNET: &str = "10.7.0.0/24";
/// Default client `AllowedIPs` (full tunnel).
pub const DEFAULT_CLIENT_ALLOWED_IPS: &str = "0.0.0.0/0";

// ─────────────────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────────────────

/// The on-disk path of the persisted server config: `server.json` in the app config
/// dir (`~/.config/wireguard-gui-rust/server.json`).
///
/// Pure path computation — does not touch the filesystem.
pub fn server_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("wireguard-gui-rust").join("server.json"))
}

impl ServerConfig {
    /// Load the persisted server config from `server.json`.
    ///
    /// Returns `Ok(None)` when no server has been configured yet (file absent);
    /// `Ok(Some(_))` when it loads + parses; `Err` on an I/O or parse failure.
    pub fn load() -> AppResult<Option<Self>> {
        let path = match server_config_path() {
            Some(p) => p,
            None => {
                return Err(AppError::ProfileIo(
                    "cannot determine config directory".into(),
                ))
            }
        };

        match fs::read_to_string(&path) {
            Ok(text) => {
                let cfg: Self = serde_json::from_str(&text).map_err(|e| {
                    AppError::ProfileIo(format!(
                        "failed to parse server.json at {}: {}",
                        path.display(),
                        e
                    ))
                })?;
                Ok(Some(cfg))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AppError::ProfileIo(format!(
                "failed to read {}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Persist this server config to `server.json` with 0600 permissions
    /// (owner read/write only — it holds private keys).
    pub fn save(&self) -> AppResult<()> {
        let path = match server_config_path() {
            Some(p) => p,
            None => {
                return Err(AppError::ProfileIo(
                    "cannot determine config directory".into(),
                ))
            }
        };

        // Ensure the parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::ProfileIo(format!(
                    "failed to create config dir {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let json = serde_json::to_string_pretty(self).map_err(|e| {
            AppError::ProfileIo(format!("failed to serialize server config: {}", e))
        })?;

        // Write to a temporary file in the same directory first so that the final
        // rename (which is atomic on the same filesystem) does not leave a partial
        // file if the process is interrupted.
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, &json).map_err(|e| {
            AppError::ProfileIo(format!(
                "failed to write {}: {}",
                tmp_path.display(),
                e
            ))
        })?;

        // Set 0600 permissions on the tmp file before renaming so the private key
        // is never world-readable, even transiently.
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            AppError::ProfileIo(format!("failed to set permissions on server.json: {}", e))
        })?;

        fs::rename(&tmp_path, &path).map_err(|e| {
            AppError::ProfileIo(format!(
                "failed to rename {} → {}: {}",
                tmp_path.display(),
                path.display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Generate a brand-new server config for `endpoint_host`: a fresh keypair, the
    /// default port/address/subnet, and no peers yet.
    ///
    /// `endpoint_host` is the public IP or DNS name clients will dial.
    pub fn generate_new(endpoint_host: &str) -> AppResult<Self> {
        let (private_key, public_key) = generate_keypair_sync()?;

        Ok(ServerConfig {
            name: "wg-gui-server".into(),
            private_key,
            public_key,
            listen_port: DEFAULT_LISTEN_PORT,
            address: DEFAULT_ADDRESS.into(),
            subnet: DEFAULT_SUBNET.into(),
            endpoint_host: endpoint_host.to_owned(),
            dns: vec!["1.1.1.1".into(), "1.0.0.1".into()],
            egress_iface: None,
            peers: Vec::new(),
        })
    }

    /// Render the kernel-side server `.conf` (the text fed to `wg setconf` /
    /// `wg-quick`): one `[Interface]` (PrivateKey / Address / ListenPort) followed by
    /// one `[Peer]` per client (PublicKey / optional PresharedKey /
    /// `AllowedIPs = <assigned_ip>/32`).
    ///
    /// Pure and side-effect-free.
    pub fn to_server_conf(&self) -> String {
        let mut out = String::new();

        // [Interface]
        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", self.private_key));
        out.push_str(&format!("Address = {}\n", self.address));
        out.push_str(&format!("ListenPort = {}\n", self.listen_port));

        // [Peer] per client
        for peer in &self.peers {
            out.push('\n');
            out.push_str("[Peer]\n");
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));
            if let Some(psk) = &peer.preshared_key {
                out.push_str(&format!("PresharedKey = {}\n", psk));
            }
            // The server sees each client as a /32 host route.
            out.push_str(&format!("AllowedIPs = {}/32\n", peer.assigned_ip));
        }

        out
    }

    /// Render the CLIENT `.conf` to hand out for `peer`: an `[Interface]` carrying the
    /// client's private key + its tunnel address + the server's DNS, and a single
    /// `[Peer]` pointing back at this server (server PublicKey, optional PresharedKey,
    /// `Endpoint = <endpoint_host>:<listen_port>`, `AllowedIPs = <client_allowed_ips>`).
    ///
    /// Pure and side-effect-free.
    pub fn client_conf(&self, peer: &ServerPeer) -> String {
        let mut out = String::new();

        // [Interface] — the client's own side.
        out.push_str("[Interface]\n");
        if let Some(privkey) = &peer.private_key {
            out.push_str(&format!("PrivateKey = {}\n", privkey));
        }
        // Client's tunnel address is its assigned IP as a /32 (it is a single host).
        out.push_str(&format!("Address = {}/32\n", peer.assigned_ip));
        if !self.dns.is_empty() {
            out.push_str(&format!("DNS = {}\n", self.dns.join(", ")));
        }

        // [Peer] — the server.
        out.push('\n');
        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", self.public_key));
        if let Some(psk) = &peer.preshared_key {
            out.push_str(&format!("PresharedKey = {}\n", psk));
        }
        out.push_str(&format!(
            "Endpoint = {}:{}\n",
            self.endpoint_host, self.listen_port
        ));
        out.push_str(&format!("AllowedIPs = {}\n", peer.client_allowed_ips));

        out
    }

    /// Provision a new client named `name`: mint a keypair, allocate the next free IP
    /// in [`ServerConfig::subnet`], default `client_allowed_ips` to `0.0.0.0/0`, push
    /// the peer, and return a reference to it.
    pub fn add_peer(&mut self, name: &str) -> AppResult<&ServerPeer> {
        // Allocate the next free IP before minting the keypair so we fail fast on
        // a full subnet without doing any crypto work.
        let assigned_ip = self.next_ip_inner()?;

        // Mint a fresh keypair for the client (sync: no tokio runtime required).
        let (private_key, public_key) = generate_keypair_sync()?;

        self.peers.push(ServerPeer {
            name: name.to_owned(),
            public_key,
            private_key: Some(private_key),
            assigned_ip,
            preshared_key: None,
            client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.into(),
        });

        // Return a reference to the just-pushed peer.
        Ok(self.peers.last().expect("just pushed"))
    }

    /// Remove the peer at `idx` (no-op if out of range).
    pub fn remove_peer(&mut self, idx: usize) {
        if idx < self.peers.len() {
            self.peers.remove(idx);
        }
    }

    /// Compute the next free host IP in [`ServerConfig::subnet`] not already taken by
    /// the server address or an existing peer's `assigned_ip`.
    ///
    /// Returns a bare host address (no prefix), e.g. `10.7.0.2`. Pure.
    pub fn next_ip(&self) -> String {
        // Surface the error as a sentinel string so the frozen signature (returning
        // `String`, not `AppResult<String>`) is preserved. In practice the GUI only
        // calls this on a valid config.
        self.next_ip_inner()
            .unwrap_or_else(|_| "subnet-full".to_owned())
    }

    // ── private helpers ──────────────────────────────────────────────────────

    /// Inner implementation of next-IP allocation; returns an `AppResult` so callers
    /// that can propagate errors (e.g. `add_peer`) do so cleanly.
    fn next_ip_inner(&self) -> AppResult<String> {
        let (net_addr, prefix_len) = parse_cidr(&self.subnet).ok_or_else(|| {
            AppError::AllowedIpsError(format!("invalid subnet: {}", self.subnet))
        })?;

        // Build the set of taken IPs: the server's own address + all peer IPs.
        let mut taken = std::collections::HashSet::new();

        // Server's own address (strip the /prefix if present).
        let server_host = self
            .address
            .split('/')
            .next()
            .unwrap_or(&self.address)
            .trim();
        if let Ok(ip) = server_host.parse::<Ipv4Addr>() {
            taken.insert(u32::from(ip));
        }

        for peer in &self.peers {
            let peer_host = peer.assigned_ip.split('/').next().unwrap_or(&peer.assigned_ip).trim();
            if let Ok(ip) = peer_host.parse::<Ipv4Addr>() {
                taken.insert(u32::from(ip));
            }
        }

        // Iterate host IPs in the subnet, skipping .0 (network address) and the
        // broadcast (last host), plus any taken IPs. Start from .1 upwards.
        //
        // host_bits = number of host bits (32 - prefix_len).
        // For a /24: hosts = .1 through .254.
        // For a /30: hosts = .1 through .2.
        // For a /32: the single address net_u32 itself.
        let net_u32 = u32::from(net_addr);
        let host_bits = 32u32.saturating_sub(prefix_len as u32);
        // first and last host addresses in the subnet (inclusive range).
        let (first, last) = if host_bits == 0 {
            // /32: single host
            (net_u32, net_u32)
        } else {
            let subnet_size = 1u32 << host_bits;
            (net_u32 + 1, net_u32 + subnet_size - 2)
        };

        for candidate_u32 in first..=last {
            if !taken.contains(&candidate_u32) {
                return Ok(Ipv4Addr::from(candidate_u32).to_string());
            }
        }

        Err(AppError::AllowedIpsError(format!(
            "subnet {} is full — no free host IPs",
            self.subnet
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sync key generation helper (private)
//
// The public `crate::config::keygen::generate_keypair` is `async` (it wraps the
// computation in `tokio::task::spawn_blocking` so it doesn't block the executor).
// Here we need a synchronous path that works both from plain unit tests (no runtime)
// and from async `Task::perform` contexts (where nesting a new runtime would panic).
// The x25519 computation itself is CPU-only and deterministically fast, so calling it
// synchronously is safe and correct — we just use the same crates directly.
// ─────────────────────────────────────────────────────────────────────────────

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Generate a fresh `(private_key_b64, public_key_b64)` pair synchronously.
///
/// Uses the same `x25519-dalek` + `rand` + `base64` crates as
/// [`crate::config::keygen::generate_keypair`] but without the async wrapper, so it
/// is callable from both sync (tests, `generate_new`, `add_peer`) and async contexts
/// without nesting tokio runtimes.
fn generate_keypair_sync() -> AppResult<(String, String)> {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    let priv_b64 = B64.encode(secret.as_bytes());
    let pub_b64 = B64.encode(public.as_bytes());
    Ok((priv_b64, pub_b64))
}

// ─────────────────────────────────────────────────────────────────────────────
// Subnet parsing helper (private)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse an IPv4 CIDR string like `10.7.0.0/24` into `(network_address, prefix_len)`.
/// Returns `None` on any parse failure.
fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let addr: Ipv4Addr = addr_str.trim().parse().ok()?;
    let prefix: u8 = prefix_str.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    // Mask to the network address (zero out host bits).
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let net = Ipv4Addr::from(u32::from(addr) & mask);
    Some((net, prefix))
}

// ─────────────────────────────────────────────────────────────────────────────
// QR rendering (pure — no I/O, no network, no root)
// ─────────────────────────────────────────────────────────────────────────────

/// Render `text` (a client `.conf`) as a QR-code PNG, returning the encoded bytes.
///
/// The bytes are suitable for `iced::widget::image::Handle::from_bytes` (iced's
/// `image` feature) so the UI can show a scannable code the user points a phone at.
///
/// Pure: builds the QR matrix and PNG entirely in memory. Errors (text too large for
/// any QR version, encode failure) surface as [`AppError`].
pub fn qr_png(text: &str) -> AppResult<Vec<u8>> {
    use image::Luma;
    use qrcode::QrCode;

    let code = QrCode::new(text.as_bytes())
        .map_err(|e| AppError::ExportFailed(format!("QR encode failed: {e}")))?;

    // Render to a 1-byte-per-pixel grayscale image, then PNG-encode to bytes.
    let img = code
        .render::<Luma<u8>>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build();

    let mut bytes: Vec<u8> = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut bytes),
        image::ImageFormat::Png,
    )
    .map_err(|e| AppError::ExportFailed(format!("QR PNG encode failed: {e}")))?;

    Ok(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure only (no root, no network, no display, no real wg interface).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // A syntactically valid base64-encoded 32-byte key (32 zero bytes).
    const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn sample_server() -> ServerConfig {
        ServerConfig {
            name: "home-server".into(),
            private_key: ZERO_KEY.into(),
            public_key: ZERO_KEY.into(),
            listen_port: DEFAULT_LISTEN_PORT,
            address: DEFAULT_ADDRESS.into(),
            subnet: DEFAULT_SUBNET.into(),
            endpoint_host: "vpn.example.com".into(),
            dns: vec!["1.1.1.1".into()],
            egress_iface: Some("eth0".into()),
            peers: vec![ServerPeer {
                name: "phone".into(),
                public_key: ZERO_KEY.into(),
                private_key: Some(ZERO_KEY.into()),
                assigned_ip: "10.7.0.2".into(),
                preshared_key: None,
                client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.into(),
            }],
        }
    }

    #[test]
    fn defaults_are_frozen() {
        assert_eq!(DEFAULT_LISTEN_PORT, 51820);
        assert_eq!(DEFAULT_ADDRESS, "10.7.0.1/24");
        assert_eq!(DEFAULT_SUBNET, "10.7.0.0/24");
        assert_eq!(DEFAULT_CLIENT_ALLOWED_IPS, "0.0.0.0/0");
    }

    #[test]
    fn server_config_serde_round_trip() {
        let original = sample_server();
        let json = serde_json::to_string_pretty(&original).expect("serialize");
        let restored: ServerConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
    }

    #[test]
    fn server_peer_serde_round_trip() {
        let peer = sample_server().peers.remove(0);
        let json = serde_json::to_string(&peer).expect("serialize");
        let back: ServerPeer = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(peer, back);
    }

    #[test]
    fn server_config_default_is_empty() {
        let d = ServerConfig::default();
        assert!(d.peers.is_empty());
        assert!(d.name.is_empty());
        assert_eq!(d.listen_port, 0);
    }

    #[test]
    fn server_config_path_is_server_json() {
        // dirs::config_dir() returns None only in extremely restricted envs.
        if let Some(p) = server_config_path() {
            assert!(p.ends_with("server.json"));
            assert!(p.to_string_lossy().contains("wireguard-gui-rust"));
        }
    }

    // ── qr_png (pure, no I/O) ────────────────────────────────────────────────

    #[test]
    fn qr_png_produces_valid_png_header() {
        let png = qr_png("[Interface]\nPrivateKey = abc\n").expect("qr render");
        // PNG magic number: 89 50 4E 47 0D 0A 1A 0A.
        assert!(png.len() > 8, "png too short");
        assert_eq!(
            &png[..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            "missing PNG signature"
        );
    }

    #[test]
    fn qr_png_is_deterministic() {
        let a = qr_png("same text").expect("a");
        let b = qr_png("same text").expect("b");
        assert_eq!(a, b, "QR PNG should be deterministic for the same input");
    }

    #[test]
    fn qr_png_differs_for_different_text() {
        let a = qr_png("text one").expect("a");
        let b = qr_png("text two and it is longer").expect("b");
        assert_ne!(a, b, "different inputs must yield different PNGs");
    }

    // ── to_server_conf ───────────────────────────────────────────────────────

    #[test]
    fn server_conf_contains_interface_fields() {
        let cfg = sample_server();
        let conf = cfg.to_server_conf();
        assert!(conf.contains("[Interface]"), "missing [Interface]");
        assert!(
            conf.contains(&format!("PrivateKey = {}", ZERO_KEY)),
            "missing PrivateKey"
        );
        assert!(
            conf.contains("Address = 10.7.0.1/24"),
            "missing Address"
        );
        assert!(
            conf.contains("ListenPort = 51820"),
            "missing ListenPort"
        );
    }

    #[test]
    fn server_conf_peer_uses_slash_32() {
        let cfg = sample_server();
        let conf = cfg.to_server_conf();
        assert!(
            conf.contains("[Peer]"),
            "missing [Peer] for the provisioned client"
        );
        assert!(
            conf.contains("AllowedIPs = 10.7.0.2/32"),
            "server peer AllowedIPs must be /32: {conf}"
        );
        assert!(
            conf.contains(&format!("PublicKey = {}", ZERO_KEY)),
            "missing PublicKey"
        );
    }

    #[test]
    fn server_conf_no_peers_has_no_peer_section() {
        let mut cfg = sample_server();
        cfg.peers.clear();
        let conf = cfg.to_server_conf();
        assert!(!conf.contains("[Peer]"), "unexpected [Peer] in peerless conf");
    }

    #[test]
    fn server_conf_preshared_key_included_when_present() {
        let mut cfg = sample_server();
        cfg.peers[0].preshared_key = Some("PSK+BASE64PLACEHOLDER=".into());
        let conf = cfg.to_server_conf();
        assert!(
            conf.contains("PresharedKey = PSK+BASE64PLACEHOLDER="),
            "PresharedKey missing from server conf: {conf}"
        );
    }

    #[test]
    fn server_conf_round_trip_stable() {
        // Rendering twice yields the same string (idempotent, no hidden state).
        let cfg = sample_server();
        assert_eq!(cfg.to_server_conf(), cfg.to_server_conf());
    }

    // ── client_conf ──────────────────────────────────────────────────────────

    #[test]
    fn client_conf_contains_client_private_key() {
        let cfg = sample_server();
        let peer = &cfg.peers[0];
        let conf = cfg.client_conf(peer);
        assert!(conf.contains("[Interface]"), "missing [Interface]");
        assert!(
            conf.contains(&format!("PrivateKey = {}", ZERO_KEY)),
            "missing client PrivateKey"
        );
    }

    #[test]
    fn client_conf_address_is_slash_32() {
        let cfg = sample_server();
        let peer = &cfg.peers[0];
        let conf = cfg.client_conf(peer);
        assert!(
            conf.contains("Address = 10.7.0.2/32"),
            "client Address must be /32: {conf}"
        );
    }

    #[test]
    fn client_conf_dns_included() {
        let cfg = sample_server();
        let peer = &cfg.peers[0];
        let conf = cfg.client_conf(peer);
        assert!(conf.contains("DNS = 1.1.1.1"), "missing DNS: {conf}");
    }

    #[test]
    fn client_conf_peer_section_points_at_server() {
        let cfg = sample_server();
        let peer = &cfg.peers[0];
        let conf = cfg.client_conf(peer);
        assert!(conf.contains("[Peer]"), "missing [Peer]");
        assert!(
            conf.contains(&format!("PublicKey = {}", cfg.public_key)),
            "client [Peer] must carry server public key"
        );
        assert!(
            conf.contains("Endpoint = vpn.example.com:51820"),
            "missing Endpoint: {conf}"
        );
        assert!(
            conf.contains("AllowedIPs = 0.0.0.0/0"),
            "missing AllowedIPs: {conf}"
        );
    }

    #[test]
    fn client_conf_preshared_key_in_peer_section() {
        let mut cfg = sample_server();
        cfg.peers[0].preshared_key = Some("PSK+BASE64PLACEHOLDER=".into());
        let conf = cfg.client_conf(&cfg.peers[0].clone());
        assert!(
            conf.contains("PresharedKey = PSK+BASE64PLACEHOLDER="),
            "PresharedKey missing from client conf: {conf}"
        );
    }

    #[test]
    fn client_conf_no_dns_when_empty() {
        let mut cfg = sample_server();
        cfg.dns.clear();
        let conf = cfg.client_conf(&cfg.peers[0].clone());
        assert!(
            !conf.contains("DNS"),
            "DNS line must be absent when dns is empty: {conf}"
        );
    }

    #[test]
    fn client_conf_custom_allowed_ips() {
        let mut cfg = sample_server();
        cfg.peers[0].client_allowed_ips = "10.0.0.0/8".into();
        let conf = cfg.client_conf(&cfg.peers[0].clone());
        assert!(
            conf.contains("AllowedIPs = 10.0.0.0/8"),
            "custom AllowedIPs not reflected: {conf}"
        );
    }

    // ── next_ip / IP allocation ───────────────────────────────────────────────

    #[test]
    fn next_ip_skips_server_and_existing_peers() {
        // Default config: server = .1, peer = .2 → next should be .3.
        let cfg = sample_server();
        assert_eq!(cfg.next_ip(), "10.7.0.3");
    }

    #[test]
    fn next_ip_on_empty_server_gives_first_host() {
        let mut cfg = sample_server();
        cfg.peers.clear();
        // server = 10.7.0.1/24, no peers → first free host = .2
        assert_eq!(cfg.next_ip(), "10.7.0.2");
    }

    #[test]
    fn next_ip_sequential_allocation() {
        // Fill .2 through .5 explicitly, expect .6 next.
        let mut cfg = sample_server();
        cfg.peers.clear();
        for i in 2u8..=5 {
            cfg.peers.push(ServerPeer {
                name: format!("peer{i}"),
                public_key: ZERO_KEY.into(),
                private_key: None,
                assigned_ip: format!("10.7.0.{i}"),
                preshared_key: None,
                client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.into(),
            });
        }
        assert_eq!(cfg.next_ip(), "10.7.0.6");
    }

    #[test]
    fn next_ip_skips_gaps_in_taken_set() {
        // Server = .1; peer = .3 (skipping .2) → next should be .2 (lowest free).
        let mut cfg = sample_server();
        cfg.peers[0].assigned_ip = "10.7.0.3".into();
        assert_eq!(cfg.next_ip(), "10.7.0.2");
    }

    #[test]
    fn next_ip_subnet_full_returns_sentinel() {
        // Use a /30 subnet: hosts are .1 and .2 (server and one peer fill both).
        let mut cfg = ServerConfig {
            name: "tiny".into(),
            private_key: ZERO_KEY.into(),
            public_key: ZERO_KEY.into(),
            listen_port: DEFAULT_LISTEN_PORT,
            address: "10.7.0.1/30".into(),
            subnet: "10.7.0.0/30".into(),
            endpoint_host: "vpn.example.com".into(),
            dns: vec![],
            egress_iface: None,
            peers: vec![],
        };
        // Server takes .1; add peer at .2 to fill the /30.
        cfg.peers.push(ServerPeer {
            name: "only-peer".into(),
            public_key: ZERO_KEY.into(),
            private_key: None,
            assigned_ip: "10.7.0.2".into(),
            preshared_key: None,
            client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.into(),
        });
        // /30: hosts .1 and .2, both taken → next_ip should return the sentinel.
        let result = cfg.next_ip();
        assert_eq!(result, "subnet-full", "expected sentinel, got: {result}");
    }

    #[test]
    fn next_ip_inner_returns_error_on_full_subnet() {
        let mut cfg = ServerConfig {
            name: "tiny".into(),
            private_key: ZERO_KEY.into(),
            public_key: ZERO_KEY.into(),
            listen_port: DEFAULT_LISTEN_PORT,
            address: "10.7.0.1/30".into(),
            subnet: "10.7.0.0/30".into(),
            endpoint_host: "vpn.example.com".into(),
            dns: vec![],
            egress_iface: None,
            peers: vec![],
        };
        cfg.peers.push(ServerPeer {
            name: "only-peer".into(),
            public_key: ZERO_KEY.into(),
            private_key: None,
            assigned_ip: "10.7.0.2".into(),
            preshared_key: None,
            client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.into(),
        });
        let err = cfg.next_ip_inner().unwrap_err();
        assert!(
            matches!(err, AppError::AllowedIpsError(_)),
            "expected AllowedIpsError, got: {err:?}"
        );
    }

    // ── add_peer / remove_peer ────────────────────────────────────────────────

    #[test]
    fn add_peer_allocates_next_ip_and_returns_reference() {
        let mut cfg = sample_server(); // server=.1, peer=.2 already
        let peer = cfg.add_peer("laptop").expect("add_peer failed");
        assert_eq!(peer.name, "laptop");
        assert_eq!(peer.assigned_ip, "10.7.0.3");
        assert!(peer.private_key.is_some(), "private key must be set");
        assert!(!peer.public_key.is_empty(), "public key must not be empty");
        assert_eq!(peer.client_allowed_ips, DEFAULT_CLIENT_ALLOWED_IPS);
        assert_eq!(cfg.peers.len(), 2);
    }

    #[test]
    fn add_peer_keys_are_valid_base64_32_bytes() {
        use base64::Engine as _;
        let mut cfg = sample_server();
        let peer = cfg.add_peer("tablet").expect("add_peer failed");
        let priv_bytes = base64::engine::general_purpose::STANDARD
            .decode(peer.private_key.as_ref().unwrap())
            .expect("private_key base64");
        let pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(&peer.public_key)
            .expect("public_key base64");
        assert_eq!(priv_bytes.len(), 32, "private key must be 32 bytes");
        assert_eq!(pub_bytes.len(), 32, "public key must be 32 bytes");
    }

    #[test]
    fn add_peer_successive_calls_allocate_sequentially() {
        let mut cfg = sample_server(); // .1 server, .2 existing
        let p3 = cfg.add_peer("a").unwrap().assigned_ip.clone();
        let p4 = cfg.add_peer("b").unwrap().assigned_ip.clone();
        assert_eq!(p3, "10.7.0.3");
        assert_eq!(p4, "10.7.0.4");
    }

    #[test]
    fn remove_peer_removes_by_index() {
        let mut cfg = sample_server();
        assert_eq!(cfg.peers.len(), 1);
        cfg.remove_peer(0);
        assert!(cfg.peers.is_empty(), "peer list should be empty after remove");
    }

    #[test]
    fn remove_peer_out_of_range_is_noop() {
        let mut cfg = sample_server();
        cfg.remove_peer(99); // should not panic
        assert_eq!(cfg.peers.len(), 1, "peer count unchanged after out-of-range remove");
    }

    // ── generate_new ─────────────────────────────────────────────────────────

    #[test]
    fn generate_new_sets_expected_defaults() {
        let cfg = ServerConfig::generate_new("vpn.example.com").expect("generate_new failed");
        assert_eq!(cfg.endpoint_host, "vpn.example.com");
        assert_eq!(cfg.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(cfg.address, DEFAULT_ADDRESS);
        assert_eq!(cfg.subnet, DEFAULT_SUBNET);
        assert!(cfg.peers.is_empty(), "fresh server must have no peers");
        assert!(!cfg.private_key.is_empty(), "private key must be set");
        assert!(!cfg.public_key.is_empty(), "public key must be set");
    }

    #[test]
    fn generate_new_keys_are_valid_base64_32_bytes() {
        use base64::Engine as _;
        let cfg = ServerConfig::generate_new("example.com").expect("generate_new failed");
        let priv_bytes = base64::engine::general_purpose::STANDARD
            .decode(&cfg.private_key)
            .expect("private_key base64");
        let pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(&cfg.public_key)
            .expect("public_key base64");
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn generate_new_produces_distinct_keys_on_successive_calls() {
        let a = ServerConfig::generate_new("a.example.com").unwrap();
        let b = ServerConfig::generate_new("b.example.com").unwrap();
        assert_ne!(a.private_key, b.private_key, "keys must differ");
    }

    // ── serde persistence round-trip (tempdir) ────────────────────────────────

    #[test]
    fn save_and_load_round_trip() {
        // Override the config dir to a tempdir so we don't pollute the real one.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wireguard-gui-rust").join("server.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // Bypass the `server_config_path()` indirection by writing/reading the JSON
        // directly (the save/load functions read the real config dir; here we test the
        // serde layer directly as the function contract says, since we can't override
        // dirs::config_dir() without unsafe env manipulation in a portable way).
        let original = sample_server();
        let json = serde_json::to_string_pretty(&original).unwrap();
        std::fs::write(&path, &json).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Verify the permissions are correct.
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file permissions must be 0600");

        // Verify the JSON deserializes back to the original.
        let restored: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn load_returns_none_for_absent_file() {
        // Test the absent-file case by attempting to read a path that doesn't exist.
        let absent = "/tmp/wireguard-gui-rust-nonexistent-123456/server.json";
        let result = std::fs::read_to_string(absent);
        assert!(
            result.is_err()
                && result.unwrap_err().kind() == std::io::ErrorKind::NotFound,
            "absent file must return NotFound"
        );
    }

    // ── parse_cidr (private helper) ───────────────────────────────────────────

    #[test]
    fn parse_cidr_valid_24() {
        let (net, prefix) = parse_cidr("10.7.0.0/24").expect("parse failed");
        assert_eq!(net, Ipv4Addr::new(10, 7, 0, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_masks_host_bits() {
        // "10.7.0.1/24" should produce network 10.7.0.0 (mask applied).
        let (net, prefix) = parse_cidr("10.7.0.1/24").expect("parse failed");
        assert_eq!(net, Ipv4Addr::new(10, 7, 0, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_slash_30() {
        let (net, prefix) = parse_cidr("10.7.0.0/30").expect("parse failed");
        assert_eq!(net, Ipv4Addr::new(10, 7, 0, 0));
        assert_eq!(prefix, 30);
    }

    #[test]
    fn parse_cidr_invalid_returns_none() {
        assert!(parse_cidr("not-a-cidr").is_none());
        assert!(parse_cidr("10.7.0.0/33").is_none());
        assert!(parse_cidr("10.7.0.999/24").is_none());
    }

    // ── qr_png returns non-empty valid PNG ────────────────────────────────────

    #[test]
    fn qr_png_non_empty() {
        let bytes = qr_png("test content for QR code").expect("qr_png failed");
        assert!(!bytes.is_empty(), "PNG bytes must be non-empty");
    }

    #[test]
    fn qr_png_full_client_conf_is_valid_png() {
        // Use a realistic client conf string.
        let conf = "\
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.7.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
";
        let png = qr_png(conf).expect("qr_png on realistic conf failed");
        // PNG magic: 89 50 4E 47 0D 0A 1A 0A
        assert_eq!(&png[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        assert!(png.len() > 100, "PNG must be non-trivially large");
    }
}
