//! Per-application network namespaces — route a specific executable through the tunnel.
//!
//! The public interface of this module is intentionally **pure**: every `*_cmds` function
//! returns a `Vec<Vec<String>>` — an ordered list of argv vectors that the privileged helper
//! must execute in sequence to implement the operation.  Nothing in this file ever calls
//! `Command::new` or touches the filesystem; that keeps the code golden-testable without root
//! and without any network side-effects on the dev machine.
//!
//! # Design sketch
//!
//! Kernel-isolated per-app tunnels use Linux **network namespaces**.  A WireGuard interface is
//! created in the *host* namespace and then moved into a freshly-created netns; the host routing
//! table is never touched.  DNS is provided via `/etc/netns/<ns>/resolv.conf`, which the kernel
//! presents as `/etc/resolv.conf` to processes running inside the namespace.
//!
//! The full setup sequence (executed inside the helper as root):
//! ```text
//! ip netns add <ns>
//! ip link add <wgif> type wireguard
//! ip link set <wgif> netns <ns>
//! ip netns exec <ns> wg setconf <wgif> <conf_path>
//! ip -n <ns> addr add <address> dev <wgif>
//! ip -n <ns> link set <wgif> up
//! ip -n <ns> link set lo up
//! ip -n <ns> route add default dev <wgif>
//! mkdir -p /etc/netns/<ns>
//! # (helper writes resolv.conf content from `dns` to /etc/netns/<ns>/resolv.conf)
//! ```
//!
//! Teardown:
//! ```text
//! ip netns del <ns>
//! rm -rf /etc/netns/<ns>
//! ```
//!
//! Launch (unprivileged user inside the namespace):
//! ```text
//! ip netns exec <ns> runuser -u <username> -- env KEY=VAL ... <exe> [args...]
//! ```
//!
//! Reconcile orphan namespaces on boot (list + selective teardown):
//! ```text
//! ip netns list
//! # for each wg-gui-* ns with no live tunnel → ip netns del <ns> + rm -rf /etc/netns/<ns>
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

// ── wg-quick key stripping ────────────────────────────────────────────────────

/// Keys that are valid in a `wg-quick(8)` conf but are **not** understood by
/// `wg(8)` / `wg setconf`.  Strip these from `[Interface]` before handing the
/// conf to `wg setconf` inside the netns.
///
/// Reference: wg-quick(8) § CONFIGURATION.
const WG_QUICK_ONLY_KEYS: &[&str] = &[
    "address",
    "dns",
    "mtu",
    "table",
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
];

/// Strip wg-quick-only keys from a WireGuard conf string so the result is safe
/// to pass to `wg setconf`.
///
/// The transformer:
/// * Removes any `[Interface]` key whose lowercase name matches
///   [`WG_QUICK_ONLY_KEYS`] (e.g. `Address`, `DNS`, `MTU`, `PostUp`, …).
/// * Preserves `PrivateKey` and `ListenPort` in `[Interface]`.
/// * Passes `[Peer]` sections through unchanged.
/// * Preserves blank lines and comments as-is (they are harmless to `wg`).
///
/// # Example (in a unit test context)
///
/// ```text
/// let conf = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n\
///             [Peer]\nPublicKey = xyz\nAllowedIPs = 0.0.0.0/0\n";
/// let stripped = strip_wg_quick_keys(conf);
/// // → keeps "PrivateKey", drops "Address" and "DNS", keeps [Peer] intact.
/// ```
pub fn strip_wg_quick_keys(conf: &str) -> String {
    #[derive(PartialEq)]
    enum Section {
        Other,
        Interface,
        Peer,
    }

    let mut out = String::with_capacity(conf.len());
    let mut section = Section::Other;

    for line in conf.lines() {
        let trimmed = line.trim();

        // Section header detection.
        if trimmed.starts_with('[') {
            let header = trimmed.trim_matches(|c| c == '[' || c == ']').trim();
            match header.to_lowercase().as_str() {
                "interface" => section = Section::Interface,
                "peer" => section = Section::Peer,
                _ => section = Section::Other,
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }

        // In [Interface]: drop wg-quick-only keys.
        if section == Section::Interface {
            // Extract the key (portion before '=', if present).
            if let Some((key, _)) = trimmed.split_once('=') {
                let key_lower = key.trim().to_lowercase();
                if WG_QUICK_ONLY_KEYS.contains(&key_lower.as_str()) {
                    // Skip this line entirely.
                    continue;
                }
            }
        }

        out.push_str(line);
        out.push('\n');
    }

    out
}

// ── resolv.conf content builder ───────────────────────────────────────────────

/// Build the content for `/etc/netns/<ns>/resolv.conf` given a slice of DNS
/// server addresses.
///
/// Pure string construction; no filesystem I/O.  The file is written by the
/// privileged helper, not by this function.
///
/// Each address is emitted as `nameserver <addr>`.  If `dns` is empty an empty
/// string is returned (the kernel will fall back to the host's resolver, which
/// is usually not what you want for a netns tunnel — callers should warn).
pub fn resolv_conf_content(dns: &[&str]) -> String {
    let mut out = String::new();
    for addr in dns {
        let addr = addr.trim();
        if !addr.is_empty() {
            out.push_str("nameserver ");
            out.push_str(addr);
            out.push('\n');
        }
    }
    out
}

// ── command-sequence builders ─────────────────────────────────────────────────

/// Return the ordered list of argv vectors that set up a kernel-isolated
/// WireGuard network namespace.
///
/// The helper executes them in sequence; **all** must succeed before the
/// namespace is considered live.
///
/// After these commands succeed the helper must also:
/// 1. `mkdir -p /etc/netns/<ns>`
/// 2. Write [`resolv_conf_content`]`(dns)` to `/etc/netns/<ns>/resolv.conf`.
///
/// Parameters:
/// * `ns`        — namespace name (e.g. `wg-gui-firefox`).
/// * `wgif`      — WireGuard interface name (e.g. `wg-gui-ns0`).
/// * `conf_path` — path to the **stripped** conf (wg-quick-only keys removed).
/// * `address`   — tunnel address with prefix (e.g. `10.2.0.2/32`).
pub fn setup_cmds(ns: &str, wgif: &str, conf_path: &str, address: &str) -> Vec<Vec<String>> {
    vec![
        // 1. Create the network namespace.
        vec![
            "ip".into(),
            "netns".into(),
            "add".into(),
            ns.into(),
        ],
        // 2. Create a WireGuard interface in the host namespace.
        vec![
            "ip".into(),
            "link".into(),
            "add".into(),
            wgif.into(),
            "type".into(),
            "wireguard".into(),
        ],
        // 3. Move the interface into the namespace.
        vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            wgif.into(),
            "netns".into(),
            ns.into(),
        ],
        // 4. Configure WireGuard (stripped conf: PrivateKey/ListenPort + [Peer]).
        vec![
            "ip".into(),
            "netns".into(),
            "exec".into(),
            ns.into(),
            "wg".into(),
            "setconf".into(),
            wgif.into(),
            conf_path.into(),
        ],
        // 5. Assign tunnel address inside the namespace.
        vec![
            "ip".into(),
            "-n".into(),
            ns.into(),
            "addr".into(),
            "add".into(),
            address.into(),
            "dev".into(),
            wgif.into(),
        ],
        // 6. Bring the WireGuard interface up.
        vec![
            "ip".into(),
            "-n".into(),
            ns.into(),
            "link".into(),
            "set".into(),
            wgif.into(),
            "up".into(),
        ],
        // 7. Bring loopback up.
        vec![
            "ip".into(),
            "-n".into(),
            ns.into(),
            "link".into(),
            "set".into(),
            "lo".into(),
            "up".into(),
        ],
        // 8. Add default route through the WireGuard interface.
        vec![
            "ip".into(),
            "-n".into(),
            ns.into(),
            "route".into(),
            "add".into(),
            "default".into(),
            "dev".into(),
            wgif.into(),
        ],
    ]
}

/// Return the ordered list of argv vectors that tear down a network namespace.
///
/// Parameters:
/// * `ns` — namespace name to remove.
///
/// After these commands the helper should also delete `/etc/netns/<ns>`.
pub fn teardown_cmds(ns: &str) -> Vec<Vec<String>> {
    vec![
        // 1. Delete the namespace (also destroys all interfaces inside it).
        vec!["ip".into(), "netns".into(), "del".into(), ns.into()],
        // 2. Remove per-namespace DNS config.
        vec![
            "rm".into(),
            "-rf".into(),
            format!("/etc/netns/{}", ns),
        ],
    ]
}

/// Return the path where the per-namespace DNS configuration is stored.
///
/// Pure helper; no I/O.
pub fn resolv_conf_path(ns: &str) -> PathBuf {
    PathBuf::from(format!("/etc/netns/{}/resolv.conf", ns))
}

/// Return the argv that launches `exe` (with `args`) inside namespace `ns` as
/// user `username`, forwarding the supplied environment variables.
///
/// Shape:
/// ```text
/// ip netns exec <ns>
///   runuser -u <username> --
///     env KEY=VAL ...
///       <exe> [args...]
/// ```
///
/// `env_vars` is a slice of `(key, value)` pairs; they are emitted as
/// `KEY=VALUE` tokens inside the `env` invocation.  The caller is responsible
/// for ensuring there are no shell metacharacters — the argv is passed directly
/// to `execvp`, never to a shell.
///
/// Note: the GUI resolves the calling user's uid to `username` (e.g. via
/// `/etc/passwd`). The helper dispatches using `PrivCmd::NetnsLaunch { uid, …
/// }` and resolves uid → name server-side; this builder takes the already-
/// resolved name so it remains pure and testable.
pub fn launch_argv(
    ns: &str,
    username: &str,
    exe: &str,
    args: &[String],
    env_vars: &[(String, String)],
) -> Vec<String> {
    // Fixed wrapper prefix: ip netns exec <ns> runuser -u <username> -- env
    let mut argv: Vec<String> = vec![
        "ip".into(),
        "netns".into(),
        "exec".into(),
        ns.into(),
        // Privilege drop: runuser -u <username> --
        "runuser".into(),
        "-u".into(),
        username.into(),
        "--".into(),
        // Env forwarding follows: env KEY=VAL ...
        "env".into(),
    ];

    // Env forwarding values.
    for (k, v) in env_vars {
        argv.push(format!("{}={}", k, v));
    }

    // Executable and its arguments.
    argv.push(exe.into());
    for arg in args {
        argv.push(arg.clone());
    }

    argv
}

/// Return the argv that lists all network namespaces on this host.
///
/// Pure; used by the boot reconciler to detect orphan `wg-gui-*` namespaces.
///
/// Output lines have the form `<name> (id: <N>)` or just `<name>`.
pub fn list_netns_argv() -> Vec<String> {
    vec!["ip".into(), "netns".into(), "list".into()]
}

/// Parse the output of `ip netns list` and return namespace names that match
/// the `wg-gui-` prefix (i.e. namespaces owned by this application).
///
/// Pure; testable with golden strings.
pub fn parse_our_namespaces(ip_netns_list_output: &str) -> Vec<String> {
    ip_netns_list_output
        .lines()
        .filter_map(|line| {
            // Each line is either just the name or "name (id: N)".
            // `split_whitespace` already skips leading whitespace, so no trim needed.
            let name = line.split_whitespace().next()?;
            if name.starts_with("wg-gui-") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

// ── NetnsRule / NetnsManager (public types kept for API compatibility) ────────

/// Bind a single executable to a named network namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetnsRule {
    pub executable_path: PathBuf,
    pub ns_name: String,
}

/// Builds command sequences and coordinates namespace lifecycle.
///
/// All heavy lifting is done by the pure `*_cmds` / `launch_argv` free
/// functions above; this struct is a grouping convenience and holds no state.
pub struct NetnsManager;

impl NetnsManager {
    /// Build the setup command sequence for `ns`.
    ///
    /// Returns an ordered list of argv vectors ready to be dispatched through
    /// [`crate::net::privilege::run_privileged`] via [`crate::net::privilege::PrivCmd::NetnsSetup`].
    ///
    /// `dns` is used to build the resolv.conf content via [`resolv_conf_content`];
    /// the helper writes that file after executing the returned commands.
    pub fn setup_cmds(
        &self,
        ns: &str,
        wgif: &str,
        conf_path: &str,
        address: &str,
    ) -> Vec<Vec<String>> {
        setup_cmds(ns, wgif, conf_path, address)
    }

    /// Build the teardown command sequence for `ns`.
    pub fn teardown_cmds(&self, ns: &str) -> Vec<Vec<String>> {
        teardown_cmds(ns)
    }

    /// Build the launch argv for running `exe` inside `ns` as `username`.
    pub fn launch_argv(
        &self,
        ns: &str,
        username: &str,
        exe: &str,
        args: &[String],
        env_vars: &[(String, String)],
    ) -> Vec<String> {
        launch_argv(ns, username, exe, args, env_vars)
    }

    /// Build the argv that lists all namespaces (for reconciliation on boot).
    pub fn list_netns_argv(&self) -> Vec<String> {
        list_netns_argv()
    }

    /// Parse `ip netns list` output and return our namespace names.
    pub fn parse_our_namespaces(&self, output: &str) -> Vec<String> {
        parse_our_namespaces(output)
    }

    /// Async wrapper: encode `ns_name` into a [`crate::net::privilege::PrivCmd::NetnsSetup`]
    /// and dispatch it via pkexec.
    ///
    /// The caller must supply the stripped conf path (wg-quick-only keys already
    /// removed), the tunnel address, and the DNS servers.
    pub async fn setup(
        &self,
        ns: &str,
        wgif: &str,
        conf_path: &str,
        address: &str,
        dns: Vec<String>,
    ) -> AppResult<()> {
        use crate::net::privilege::{run_privileged, PrivCmd};
        run_privileged(&PrivCmd::NetnsSetup {
            ns: ns.to_string(),
            wgif: wgif.to_string(),
            conf_path: conf_path.to_string(),
            address: address.to_string(),
            dns,
        })
        .await
    }

    /// Async wrapper: encode a [`crate::net::privilege::PrivCmd::NetnsTeardown`] and dispatch.
    pub async fn teardown(&self, ns: &str) -> AppResult<()> {
        use crate::net::privilege::{run_privileged, PrivCmd};
        run_privileged(&PrivCmd::NetnsTeardown { ns: ns.to_string() }).await
    }

    /// Async wrapper: encode a [`crate::net::privilege::PrivCmd::NetnsLaunch`] and dispatch.
    pub async fn launch(
        &self,
        ns: &str,
        uid: u32,
        exe: &str,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) -> AppResult<()> {
        use crate::net::privilege::{run_privileged, PrivCmd};
        run_privileged(&PrivCmd::NetnsLaunch {
            ns: ns.to_string(),
            uid,
            exe: exe.to_string(),
            args,
            env,
        })
        .await
    }

    /// Add a per-app rule (associates an executable with a namespace).
    ///
    /// In this phase the rule is advisory — the caller uses [`Self::launch`] to
    /// actually run the executable inside the namespace.  Persistence of rules
    /// across sessions is handled by the settings store.
    pub async fn add_rule(&self, rule: &NetnsRule) -> AppResult<()> {
        // Validate that the namespace name looks sane before we persist anything.
        if rule.ns_name.is_empty() {
            return Err(AppError::NetnsFailed(
                "namespace name must not be empty".into(),
            ));
        }
        if !rule.ns_name.starts_with("wg-gui-") {
            return Err(AppError::NetnsFailed(format!(
                "namespace name '{}' does not start with 'wg-gui-'",
                rule.ns_name
            )));
        }
        // Rule storage is delegated to the settings layer; nothing to do here.
        Ok(())
    }

    /// Remove a per-app rule (dissociates the executable from its namespace).
    ///
    /// Does NOT tear down the namespace — call [`Self::teardown`] separately if
    /// no more rules reference it.
    pub async fn remove_rule(&self, rule: &NetnsRule) -> AppResult<()> {
        let _ = rule;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests (pure — no I/O, no root, no network mutation)
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_wg_quick_keys ───────────────────────────────────────────────────

    #[test]
    fn strip_removes_address_and_dns() {
        let conf = "[Interface]\n\
                    PrivateKey = abc123\n\
                    Address = 10.0.0.2/32\n\
                    DNS = 1.1.1.1, 8.8.8.8\n\
                    ListenPort = 51820\n\n\
                    [Peer]\n\
                    PublicKey = XYZ\n\
                    AllowedIPs = 0.0.0.0/0\n";
        let out = strip_wg_quick_keys(conf);
        assert!(out.contains("PrivateKey = abc123"), "kept PrivateKey; out={out}");
        assert!(out.contains("ListenPort = 51820"), "kept ListenPort; out={out}");
        assert!(!out.contains("Address"), "dropped Address; out={out}");
        assert!(!out.contains("DNS"), "dropped DNS; out={out}");
        assert!(out.contains("[Peer]"), "kept [Peer] section; out={out}");
        assert!(out.contains("PublicKey = XYZ"), "kept PublicKey; out={out}");
        assert!(out.contains("AllowedIPs = 0.0.0.0/0"), "kept AllowedIPs; out={out}");
    }

    #[test]
    fn strip_removes_mtu_postup_predown() {
        let conf = "[Interface]\n\
                    PrivateKey = KEY\n\
                    Address = 10.0.0.1/24\n\
                    MTU = 1420\n\
                    PostUp = iptables -A FORWARD -i wg0 -j ACCEPT\n\
                    PreDown = iptables -D FORWARD -i wg0 -j ACCEPT\n";
        let out = strip_wg_quick_keys(conf);
        assert!(out.contains("PrivateKey"), "out={out}");
        assert!(!out.contains("MTU"), "dropped MTU; out={out}");
        assert!(!out.contains("PostUp"), "dropped PostUp; out={out}");
        assert!(!out.contains("PreDown"), "dropped PreDown; out={out}");
    }

    #[test]
    fn strip_is_case_insensitive_on_keys() {
        let conf = "[Interface]\n\
                    privatekey = K\n\
                    address = 10.0.0.1/32\n\
                    DNS = 1.1.1.1\n";
        let out = strip_wg_quick_keys(conf);
        assert!(out.contains("privatekey"), "kept privatekey; out={out}");
        assert!(!out.contains("address"), "dropped address; out={out}");
        assert!(!out.contains("DNS"), "dropped DNS; out={out}");
    }

    #[test]
    fn strip_leaves_peer_sections_intact() {
        let conf = "[Interface]\n\
                    PrivateKey = PRIV\n\
                    Address = 10.0.0.2/32\n\n\
                    [Peer]\n\
                    PublicKey = PUB\n\
                    PresharedKey = PSK\n\
                    Endpoint = 203.0.113.1:51820\n\
                    AllowedIPs = 0.0.0.0/0\n\
                    PersistentKeepalive = 25\n";
        let out = strip_wg_quick_keys(conf);
        assert!(out.contains("PublicKey = PUB"));
        assert!(out.contains("PresharedKey = PSK"));
        assert!(out.contains("Endpoint = 203.0.113.1:51820"));
        assert!(out.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(out.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn strip_empty_conf_returns_empty() {
        assert_eq!(strip_wg_quick_keys(""), "");
    }

    #[test]
    fn strip_conf_without_wg_quick_keys_is_unchanged() {
        let conf = "[Interface]\n\
                    PrivateKey = KEY\n\
                    ListenPort = 51820\n\n\
                    [Peer]\n\
                    PublicKey = PUB\n\
                    AllowedIPs = 10.0.0.0/24\n";
        let out = strip_wg_quick_keys(conf);
        // Every original line should still be present.
        for line in conf.lines() {
            assert!(out.contains(line), "missing line {:?}; out={out}", line);
        }
    }

    // ── resolv_conf_content ───────────────────────────────────────────────────

    #[test]
    fn resolv_conf_single_server() {
        let out = resolv_conf_content(&["1.1.1.1"]);
        assert_eq!(out, "nameserver 1.1.1.1\n");
    }

    #[test]
    fn resolv_conf_multiple_servers() {
        let out = resolv_conf_content(&["1.1.1.1", "8.8.8.8"]);
        assert_eq!(out, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    }

    #[test]
    fn resolv_conf_empty_slice() {
        assert_eq!(resolv_conf_content(&[]), "");
    }

    #[test]
    fn resolv_conf_trims_whitespace() {
        let out = resolv_conf_content(&["  1.1.1.1  ", "  8.8.8.8  "]);
        assert_eq!(out, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    }

    #[test]
    fn resolv_conf_skips_empty_entries() {
        let out = resolv_conf_content(&["1.1.1.1", "", "8.8.8.8"]);
        assert_eq!(out, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    }

    // ── resolv_conf_path ──────────────────────────────────────────────────────

    #[test]
    fn resolv_conf_path_correct() {
        let p = resolv_conf_path("wg-gui-firefox");
        assert_eq!(p, PathBuf::from("/etc/netns/wg-gui-firefox/resolv.conf"));
    }

    // ── setup_cmds (golden argv) ──────────────────────────────────────────────

    #[test]
    fn setup_cmds_golden_count() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        // Exactly 8 commands per the design.
        assert_eq!(cmds.len(), 8, "cmds={cmds:?}");
    }

    #[test]
    fn setup_cmds_golden_step1_netns_add() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(cmds[0], vec!["ip", "netns", "add", "wg-gui-app"]);
    }

    #[test]
    fn setup_cmds_golden_step2_link_add_wireguard() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(
            cmds[1],
            vec!["ip", "link", "add", "wg-gui-ns0", "type", "wireguard"]
        );
    }

    #[test]
    fn setup_cmds_golden_step3_link_set_netns() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(
            cmds[2],
            vec!["ip", "link", "set", "wg-gui-ns0", "netns", "wg-gui-app"]
        );
    }

    #[test]
    fn setup_cmds_golden_step4_wg_setconf() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(
            cmds[3],
            vec![
                "ip", "netns", "exec", "wg-gui-app",
                "wg", "setconf", "wg-gui-ns0", "/run/wg-gui/ns.conf"
            ]
        );
    }

    #[test]
    fn setup_cmds_golden_step5_addr_add() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(
            cmds[4],
            vec!["ip", "-n", "wg-gui-app", "addr", "add", "10.2.0.2/32", "dev", "wg-gui-ns0"]
        );
    }

    #[test]
    fn setup_cmds_golden_step6_wgif_up() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(
            cmds[5],
            vec!["ip", "-n", "wg-gui-app", "link", "set", "wg-gui-ns0", "up"]
        );
    }

    #[test]
    fn setup_cmds_golden_step7_lo_up() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(
            cmds[6],
            vec!["ip", "-n", "wg-gui-app", "link", "set", "lo", "up"]
        );
    }

    #[test]
    fn setup_cmds_golden_step8_default_route() {
        let cmds = setup_cmds("wg-gui-app", "wg-gui-ns0", "/run/wg-gui/ns.conf", "10.2.0.2/32");
        assert_eq!(
            cmds[7],
            vec!["ip", "-n", "wg-gui-app", "route", "add", "default", "dev", "wg-gui-ns0"]
        );
    }

    // ── teardown_cmds (golden argv) ───────────────────────────────────────────

    #[test]
    fn teardown_cmds_golden_count() {
        let cmds = teardown_cmds("wg-gui-app");
        assert_eq!(cmds.len(), 2, "cmds={cmds:?}");
    }

    #[test]
    fn teardown_cmds_golden_step1_netns_del() {
        let cmds = teardown_cmds("wg-gui-app");
        assert_eq!(cmds[0], vec!["ip", "netns", "del", "wg-gui-app"]);
    }

    #[test]
    fn teardown_cmds_golden_step2_rm_etc_netns() {
        let cmds = teardown_cmds("wg-gui-app");
        assert_eq!(cmds[1], vec!["rm", "-rf", "/etc/netns/wg-gui-app"]);
    }

    // ── launch_argv (golden argv) ─────────────────────────────────────────────

    #[test]
    fn launch_argv_golden_no_args_no_env() {
        let argv = launch_argv("wg-gui-app", "alice", "/usr/bin/firefox", &[], &[]);
        assert_eq!(
            argv,
            vec![
                "ip", "netns", "exec", "wg-gui-app",
                "runuser", "-u", "alice", "--",
                "env",
                "/usr/bin/firefox",
            ]
        );
    }

    #[test]
    fn launch_argv_golden_with_env_and_args() {
        let args: Vec<String> = vec!["--new-instance".into(), "--profile".into(), "p".into()];
        let env_vars: Vec<(String, String)> = vec![
            ("DISPLAY".into(), ":0".into()),
            ("WAYLAND_DISPLAY".into(), "wayland-0".into()),
            ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()),
        ];
        let argv = launch_argv("wg-gui-firefox", "alice", "/usr/bin/firefox", &args, &env_vars);

        // Preamble
        assert_eq!(&argv[0..4], &["ip", "netns", "exec", "wg-gui-firefox"]);
        // runuser
        assert_eq!(&argv[4..8], &["runuser", "-u", "alice", "--"]);
        // env
        assert_eq!(argv[8], "env");
        // env vars
        assert_eq!(argv[9], "DISPLAY=:0");
        assert_eq!(argv[10], "WAYLAND_DISPLAY=wayland-0");
        assert_eq!(argv[11], "XDG_RUNTIME_DIR=/run/user/1000");
        // exe + args
        assert_eq!(argv[12], "/usr/bin/firefox");
        assert_eq!(argv[13], "--new-instance");
        assert_eq!(argv[14], "--profile");
        assert_eq!(argv[15], "p");
        assert_eq!(argv.len(), 16);
    }

    #[test]
    fn launch_argv_env_key_equals_value_format() {
        let env_vars = vec![("MY_KEY".into(), "my value with spaces".into())];
        let argv = launch_argv("wg-gui-app", "bob", "/usr/bin/true", &[], &env_vars);
        // Find the env var token.
        let found = argv.iter().any(|t| t == "MY_KEY=my value with spaces");
        assert!(found, "expected 'MY_KEY=my value with spaces' in argv={argv:?}");
    }

    #[test]
    fn launch_argv_no_shell_quoting_needed() {
        // Paths with spaces must remain as single argv tokens, not shell-escaped.
        let exe = "/home/user/my apps/browser";
        let argv = launch_argv("wg-gui-app", "alice", exe, &[], &[]);
        let last = argv.last().expect("argv must be non-empty");
        assert_eq!(last, exe);
    }

    // ── list_netns_argv ───────────────────────────────────────────────────────

    #[test]
    fn list_netns_argv_golden() {
        assert_eq!(list_netns_argv(), vec!["ip", "netns", "list"]);
    }

    // ── parse_our_namespaces ──────────────────────────────────────────────────

    #[test]
    fn parse_our_namespaces_picks_wg_gui_prefix() {
        let output = "wg-gui-firefox (id: 3)\nwg-gui-chromium (id: 5)\nsome-other-ns\n";
        let ns = parse_our_namespaces(output);
        assert_eq!(ns, vec!["wg-gui-firefox", "wg-gui-chromium"]);
    }

    #[test]
    fn parse_our_namespaces_empty_output() {
        assert!(parse_our_namespaces("").is_empty());
    }

    #[test]
    fn parse_our_namespaces_no_match() {
        let output = "some-ns\nanother-ns\n";
        assert!(parse_our_namespaces(output).is_empty());
    }

    #[test]
    fn parse_our_namespaces_without_id_suffix() {
        // Some kernels / ip-versions omit the " (id: N)" part.
        let output = "wg-gui-app\n";
        let ns = parse_our_namespaces(output);
        assert_eq!(ns, vec!["wg-gui-app"]);
    }

    // ── NetnsManager delegation ───────────────────────────────────────────────

    #[test]
    fn manager_setup_cmds_delegates_to_free_fn() {
        let mgr = NetnsManager;
        let via_mgr = mgr.setup_cmds("wg-gui-x", "wg-gui-if0", "/tmp/x.conf", "10.0.0.1/32");
        let direct = setup_cmds("wg-gui-x", "wg-gui-if0", "/tmp/x.conf", "10.0.0.1/32");
        assert_eq!(via_mgr, direct);
    }

    #[test]
    fn manager_teardown_cmds_delegates_to_free_fn() {
        let mgr = NetnsManager;
        assert_eq!(mgr.teardown_cmds("wg-gui-x"), teardown_cmds("wg-gui-x"));
    }

    #[test]
    fn manager_launch_argv_delegates_to_free_fn() {
        let mgr = NetnsManager;
        let args: Vec<String> = vec![];
        let env: Vec<(String, String)> = vec![];
        assert_eq!(
            mgr.launch_argv("wg-gui-x", "alice", "/usr/bin/x", &args, &env),
            launch_argv("wg-gui-x", "alice", "/usr/bin/x", &args, &env),
        );
    }

    // ── add_rule / remove_rule validation ─────────────────────────────────────

    #[test]
    fn add_rule_rejects_empty_ns_name() {
        let mgr = NetnsManager;
        let rule = NetnsRule {
            executable_path: PathBuf::from("/usr/bin/x"),
            ns_name: "".into(),
        };
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(mgr.add_rule(&rule));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NetnsFailed(_)));
    }

    #[test]
    fn add_rule_rejects_non_wg_gui_prefix() {
        let mgr = NetnsManager;
        let rule = NetnsRule {
            executable_path: PathBuf::from("/usr/bin/x"),
            ns_name: "my-custom-ns".into(),
        };
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(mgr.add_rule(&rule));
        assert!(result.is_err());
    }

    #[test]
    fn add_rule_accepts_valid_ns_name() {
        let mgr = NetnsManager;
        let rule = NetnsRule {
            executable_path: PathBuf::from("/usr/bin/firefox"),
            ns_name: "wg-gui-firefox".into(),
        };
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(mgr.add_rule(&rule));
        assert!(result.is_ok());
    }

    // ── Integration test (root required — marked #[ignore]) ───────────────────
    //
    // This test creates a throwaway netns named `wg-gui-test-<pid>`, adds a
    // DUMMY (not wireguard, not real) interface inside it, then tears it down.
    // It never installs wg keys, never touches host routes, and is self-cleaning.
    //
    // Run manually with: sudo -E cargo test -- --ignored netns_throwaway_integration
    //
    // The test is excluded from the normal `cargo test` run so CI stays green
    // without root.

    #[test]
    #[ignore]
    fn netns_throwaway_integration() {
        use std::process::Command;

        // Give the namespace a unique name so concurrent runs don't collide.
        let ns = format!("wg-gui-test-{}", std::process::id());
        // Linux interface names are capped at 15 chars (IFNAMSIZ-1), so keep this short.
        let dummy_if = format!("wgd{}", std::process::id());

        // Helper: run a command and assert success.
        let run = |argv: &[&str]| {
            let status = Command::new(argv[0])
                .args(&argv[1..])
                .status()
                .expect("command spawn failed");
            assert!(status.success(), "command {:?} failed: {}", argv, status);
        };

        // Cleanup helper: best-effort, called even on panic.
        let cleanup = || {
            let _ = Command::new("ip")
                .args(["netns", "del", &ns])
                .status();
            let _ = Command::new("rm")
                .args(["-rf", &format!("/etc/netns/{}", ns)])
                .status();
        };

        // Guard: ensure we can create the ns (requires root).
        let probe = Command::new("ip")
            .args(["netns", "add", &ns])
            .status()
            .expect("ip netns add spawn failed");
        if !probe.success() {
            eprintln!("SKIP: ip netns add requires root — skipping integration test");
            return;
        }

        // Add a DUMMY (not wireguard) interface inside the ns — dummy type needs no
        // kernel module beyond 'dummy' which is always present; it never moves real
        // traffic and never touches host routing.
        let add_dummy = Command::new("ip")
            .args(["-n", &ns, "link", "add", &dummy_if, "type", "dummy"])
            .status()
            .expect("ip link add dummy spawn failed");
        if !add_dummy.success() {
            cleanup();
            panic!("ip link add dummy failed");
        }

        // Verify the interface exists inside the namespace.
        let show = Command::new("ip")
            .args(["-n", &ns, "link", "show", &dummy_if])
            .status()
            .expect("ip link show spawn failed");
        assert!(
            show.success(),
            "dummy interface {} not found in ns {}",
            dummy_if,
            ns
        );

        // Parse our namespaces output should include this ns.
        let list_out = Command::new("ip")
            .args(["netns", "list"])
            .output()
            .expect("ip netns list spawn failed");
        let list_str = String::from_utf8_lossy(&list_out.stdout);
        assert!(
            parse_our_namespaces(&list_str).contains(&ns),
            "parse_our_namespaces did not find {} in {:?}",
            ns,
            list_str
        );

        // Tear down: delete the namespace (also destroys the dummy interface inside).
        run(&["ip", "netns", "del", &ns]);

        // Clean up /etc/netns/<ns> if it was created (it wasn't here, but be tidy).
        let _ = Command::new("rm")
            .args(["-rf", &format!("/etc/netns/{}", ns)])
            .status();
    }
}
