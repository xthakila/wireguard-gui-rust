//! REAL end-to-end handshake integration test for the app-generated configs.
//!
//! ============================ SAFETY / WHAT THIS PROVES ============================
//! This test takes the configs the application itself generates
//! ([`ServerConfig::generate_new`] + [`ServerConfig::add_peer`] →
//! [`ServerConfig::to_server_conf`] for the server side and
//! [`ServerConfig::client_conf`] for the client side) and stands up a real WireGuard
//! tunnel between TWO network namespaces joined by a veth pair, then proves traffic
//! flows: it pings the server's tunnel address from the client namespace and asserts a
//! recent handshake + non-zero transfer on BOTH sides.
//!
//! It is gated behind `#[ignore]` because it REQUIRES ROOT (it creates network
//! namespaces, veth links, and WireGuard interfaces) and the WireGuard kernel module +
//! `ip`/`wg`/`ping` tooling. The default `cargo test` run NEVER executes it. The parent
//! harness runs it as root in an isolated netns:
//!
//!   cargo test --bin wireguard-gui server::e2e -- --ignored --nocapture
//!
//! Everything is created with a per-run-unique suffix and torn down best-effort (both
//! namespaces deleted) even on panic, so repeated runs never collide and never leak
//! kernel state.
//! ==================================================================================

#![cfg(test)]

use std::process::Command;

use crate::server::ServerConfig;

// ─────────────────────────────────────────────────────────────────────────────
// Small process helpers (this test owns its own runner — it must not depend on the
// privileged helper, since the parent runs it directly as root in a netns).
// ─────────────────────────────────────────────────────────────────────────────

/// Run a command, returning `Ok(stdout)` on success or `Err(message)` on failure.
fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {program} {args:?}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{program} {args:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Run a command, ignoring its result (best-effort teardown steps).
fn run_ok(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).output();
}

/// Strip wg-quick-only keys (`Address`, `DNS`, `MTU`) from a generated `.conf` so the
/// remaining text is consumable by `wg setconf` (which understands ONLY the kernel-
/// level `[Interface]PrivateKey/ListenPort` and `[Peer]` keys). Optionally rewrite the
/// peer `Endpoint` and `AllowedIPs` lines (used on the client side to point the peer at
/// the server's veth IP and to route the tunnel subnet).
fn strip_for_setconf(
    conf: &str,
    override_endpoint: Option<&str>,
    override_allowed_ips: Option<&str>,
) -> String {
    let mut out = String::new();
    for line in conf.lines() {
        let key = line
            .split('=')
            .next()
            .map(|k| k.trim().to_ascii_lowercase())
            .unwrap_or_default();
        match key.as_str() {
            // wg-quick-only — not understood by `wg setconf`.
            "address" | "dns" | "mtu" => continue,
            "endpoint" => {
                if let Some(ep) = override_endpoint {
                    out.push_str(&format!("Endpoint = {ep}\n"));
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            "allowedips" => {
                if let Some(aips) = override_allowed_ips {
                    out.push_str(&format!("AllowedIPs = {aips}\n"));
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Write `text` to a conf path and return it (the caller deletes it on teardown).
///
/// Uses `/etc/wireguard` (not /tmp): `wg`/`wg-quick` are AppArmor-confined to that directory on
/// most distros, so `wg setconf` cannot read a conf from /tmp or /run ("fopen: Permission denied").
/// This mirrors how the real app's helper stages confs. The test runs as root, so it can write here.
fn write_tmp(name: &str, text: &str) -> std::io::Result<String> {
    std::fs::create_dir_all("/etc/wireguard")?;
    let path = format!("/etc/wireguard/{name}");
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Parse the seconds field of a `wg show <iface> latest-handshakes` line for `pubkey`.
/// Returns `0` when the peer never handshaked or is absent.
fn handshake_secs(dump: &str, pubkey: &str) -> u64 {
    for line in dump.lines() {
        let mut f = line.split('\t');
        if f.next() == Some(pubkey) {
            return f.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        }
    }
    0
}

/// Parse `(rx, tx)` byte counts from `wg show <iface> transfer` for `pubkey`.
fn transfer_bytes(dump: &str, pubkey: &str) -> (u64, u64) {
    for line in dump.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.first() == Some(&pubkey) && f.len() >= 3 {
            let rx = f[1].trim().parse().unwrap_or(0);
            let tx = f[2].trim().parse().unwrap_or(0);
            return (rx, tx);
        }
    }
    (0, 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Teardown guard — deletes both namespaces no matter how the test exits (pass,
// fail, or panic via unwind).
// ─────────────────────────────────────────────────────────────────────────────

struct NetnsGuard {
    srv_ns: String,
    cli_ns: String,
    tmp_files: Vec<String>,
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        // Deleting a namespace removes every interface inside it (incl. the veth
        // ends moved in), so this is sufficient to fully clean up.
        run_ok("ip", &["netns", "del", &self.srv_ns]);
        run_ok("ip", &["netns", "del", &self.cli_ns]);
        // The veth pair: if either end never made it into a namespace, drop it.
        run_ok("ip", &["link", "del", "veth-s"]);
        for f in &self.tmp_files {
            let _ = std::fs::remove_file(f);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The test.
// ─────────────────────────────────────────────────────────────────────────────

/// Stand up a real WireGuard tunnel between two namespaces using the APP-GENERATED
/// configs and prove traffic passes (ping + recent handshake + non-zero transfer).
///
/// REQUIRES ROOT. Gated behind `#[ignore]`; never runs under a plain `cargo test`.
#[test]
#[ignore = "requires root: creates network namespaces, veth, and WireGuard interfaces"]
fn server_client_handshake_e2e() {
    // Per-run-unique veth/netns names so concurrent or repeated runs never collide.
    let uniq = std::process::id();
    let srv_ns = format!("wgsrv-ns-{uniq}");
    let cli_ns = format!("wgcli-ns-{uniq}");
    let srv_if = "wg-e2e-srv";
    let cli_if = "wg-e2e-cli";
    // veth underlay addresses (the physical link the tunnel rides over).
    let srv_veth_ip = "172.31.250.1";
    let cli_veth_ip = "172.31.250.2";
    let veth_prefix = "30";
    // Tunnel addresses come from the app defaults (server = 10.7.0.1, peer = 10.7.0.2).
    let server_tunnel_ip = "10.7.0.1";
    let tunnel_subnet = "10.7.0.0/24";

    // Install the teardown guard up front so a panic anywhere below still cleans up.
    let mut guard = NetnsGuard {
        srv_ns: srv_ns.clone(),
        cli_ns: cli_ns.clone(),
        tmp_files: Vec::new(),
    };

    // ── 1. Generate the configs WITH THE APPLICATION'S OWN CODE. ──────────────
    let mut server = ServerConfig::generate_new("172.31.250.1").expect("generate_new");
    // The server listens on its default port; the client will dial the server's
    // veth IP at that port.
    let listen_port = server.listen_port;
    let peer = server.add_peer("e2e-client").expect("add_peer").clone();

    let server_conf_raw = server.to_server_conf();
    let client_conf_raw = server.client_conf(&peer);

    // Strip wg-quick-only keys for `wg setconf`. Point the client's peer Endpoint at
    // the SERVER's veth IP:port and route only the tunnel subnet client-side.
    let server_setconf = strip_for_setconf(&server_conf_raw, None, None);
    let client_endpoint = format!("{srv_veth_ip}:{listen_port}");
    let client_setconf =
        strip_for_setconf(&client_conf_raw, Some(&client_endpoint), Some(tunnel_subnet));

    let server_conf_path =
        write_tmp(&format!("wg-e2e-srv-{uniq}.conf"), &server_setconf).expect("write srv conf");
    let client_conf_path =
        write_tmp(&format!("wg-e2e-cli-{uniq}.conf"), &client_setconf).expect("write cli conf");
    guard.tmp_files.push(server_conf_path.clone());
    guard.tmp_files.push(client_conf_path.clone());

    // ── 2. Two namespaces joined by a veth pair. ──────────────────────────────
    run("ip", &["netns", "add", &srv_ns]).expect("netns add srv");
    run("ip", &["netns", "add", &cli_ns]).expect("netns add cli");

    run("ip", &["link", "add", "veth-s", "type", "veth", "peer", "name", "veth-c"])
        .expect("veth pair");
    run("ip", &["link", "set", "veth-s", "netns", &srv_ns]).expect("move veth-s");
    run("ip", &["link", "set", "veth-c", "netns", &cli_ns]).expect("move veth-c");

    // Address + bring up the underlay link in each namespace.
    run(
        "ip",
        &["-n", &srv_ns, "addr", "add", &format!("{srv_veth_ip}/{veth_prefix}"), "dev", "veth-s"],
    )
    .expect("addr veth-s");
    run(
        "ip",
        &["-n", &cli_ns, "addr", "add", &format!("{cli_veth_ip}/{veth_prefix}"), "dev", "veth-c"],
    )
    .expect("addr veth-c");
    run("ip", &["-n", &srv_ns, "link", "set", "veth-s", "up"]).expect("up veth-s");
    run("ip", &["-n", &cli_ns, "link", "set", "veth-c", "up"]).expect("up veth-c");
    run("ip", &["-n", &srv_ns, "link", "set", "lo", "up"]).expect("up srv lo");
    run("ip", &["-n", &cli_ns, "link", "set", "lo", "up"]).expect("up cli lo");

    // ── 3. A WireGuard interface in each namespace, configured from the app conf. ─
    // Create the wg interface inside each namespace and apply the generated conf.
    for (ns, ifname, conf_path) in [
        (&srv_ns, srv_if, &server_conf_path),
        (&cli_ns, cli_if, &client_conf_path),
    ] {
        run("ip", &["-n", ns, "link", "add", ifname, "type", "wireguard"])
            .unwrap_or_else(|e| panic!("create {ifname}: {e}"));
        run("ip", &["netns", "exec", ns, "wg", "setconf", ifname, conf_path])
            .unwrap_or_else(|e| panic!("wg setconf {ifname}: {e}"));
    }

    // Assign the TUNNEL addresses (from the app config: server .1, client .2).
    run(
        "ip",
        &["-n", &srv_ns, "addr", "add", &format!("{server_tunnel_ip}/24"), "dev", srv_if],
    )
    .expect("tunnel addr srv");
    run(
        "ip",
        &["-n", &cli_ns, "addr", "add", &format!("{}/24", peer.assigned_ip), "dev", cli_if],
    )
    .expect("tunnel addr cli");

    // Bring both wg interfaces up.
    run("ip", &["-n", &srv_ns, "link", "set", srv_if, "up"]).expect("up srv wg");
    run("ip", &["-n", &cli_ns, "link", "set", cli_if, "up"]).expect("up cli wg");

    // ── 4. From the client namespace, ping the server's TUNNEL address. ───────
    // -c 3 packets, -W 2s timeout; success proves the encrypted tunnel carries
    // traffic. -I binds the source to the client tunnel interface.
    let ping = run(
        "ip",
        &[
            "netns", "exec", &cli_ns, "ping", "-c", "3", "-W", "2", "-I", cli_if,
            server_tunnel_ip,
        ],
    );
    assert!(
        ping.is_ok(),
        "ping {server_tunnel_ip} through the app-generated tunnel failed: {:?}",
        ping.err()
    );

    // ── 5. Assert a recent handshake + non-zero transfer on BOTH sides. ───────
    // Client view: the peer is the SERVER's public key.
    let cli_hs_dump =
        run("ip", &["netns", "exec", &cli_ns, "wg", "show", cli_if, "latest-handshakes"])
            .expect("client latest-handshakes");
    let cli_xfer_dump =
        run("ip", &["netns", "exec", &cli_ns, "wg", "show", cli_if, "transfer"])
            .expect("client transfer");
    let cli_hs = handshake_secs(&cli_hs_dump, &server.public_key);
    let (cli_rx, cli_tx) = transfer_bytes(&cli_xfer_dump, &server.public_key);
    assert!(cli_hs > 0, "client has no handshake with the server:\n{cli_hs_dump}");
    assert!(
        cli_rx > 0 && cli_tx > 0,
        "client transfer must be non-zero both ways, got rx={cli_rx} tx={cli_tx}:\n{cli_xfer_dump}"
    );

    // Server view: the peer is the CLIENT's public key.
    let srv_hs_dump =
        run("ip", &["netns", "exec", &srv_ns, "wg", "show", srv_if, "latest-handshakes"])
            .expect("server latest-handshakes");
    let srv_xfer_dump =
        run("ip", &["netns", "exec", &srv_ns, "wg", "show", srv_if, "transfer"])
            .expect("server transfer");
    let srv_hs = handshake_secs(&srv_hs_dump, &peer.public_key);
    let (srv_rx, srv_tx) = transfer_bytes(&srv_xfer_dump, &peer.public_key);
    assert!(srv_hs > 0, "server has no handshake with the client:\n{srv_hs_dump}");
    assert!(
        srv_rx > 0 && srv_tx > 0,
        "server transfer must be non-zero both ways, got rx={srv_rx} tx={srv_tx}:\n{srv_xfer_dump}"
    );

    // `guard` drops here → both namespaces (and the veth + temp confs) are removed.
    drop(guard);
}
