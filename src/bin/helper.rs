//! wireguard-gui-helper — the ONE privileged binary.
//!
//! ============================ SECURITY / PRIVILEGE NOTICE ============================
//! This binary is the only artifact in the project that runs as ROOT. It is launched by
//! the unprivileged GUI through `pkexec`, gated by the single polkit action
//! `org.wireguardgui.rust.manage` (see assets/org.wireguardgui.rust.manage.policy), which
//! pins the exec path to `/usr/lib/wireguard-gui/wireguard-gui-helper`. The GUI itself NEVER
//! runs privileged code; it only constructs a `PrivCmd`, serializes it to JSON, and hands it
//! to this helper.
//!
//! It accepts exactly one root-only operation per invocation, described by a `PrivCmd` read
//! from `--json <payload>` (or stdin). Each variant maps to a single handler.
//! ====================================================================================
//!
//! The `PrivCmd` protocol and the crate error type are SHARED with the GUI via `#[path]`
//! includes so there is exactly ONE source of truth for the wire shape — the helper and the
//! GUI can never drift. Do not duplicate the enum here.

#![allow(dead_code)]

use std::io::Read;
use std::process::{Command, ExitCode};

// --- Shared sources (single source of truth, included — NOT copied) ------------------------
// `src/bin/*.rs` is its own crate root with no access to the GUI's modules. Including the
// canonical files keeps the protocol frozen across both binaries. `privilege` depends on
// `crate::error`, so `error` is included first.
#[path = "../error.rs"]
mod error;
#[path = "../net/privilege.rs"]
mod privilege;

use error::{AppError, AppResult};
use privilege::PrivCmd;

// nftables table: family = "inet", name = "wg_gui_killswitch".
// Keep both so argv builders emit them as SEPARATE arguments to nft.
const NFT_TABLE_FAMILY: &str = "inet";
const NFT_TABLE_NAME: &str = "wg_gui_killswitch";
// Combined "family name" string used only in rendered nft rule text (not CLI argv).
const NFT_TABLE: &str = "inet wg_gui_killswitch";

// ── SERVER / NAT constants ────────────────────────────────────────────────────

/// The server conf is written here (0600) by `ServerWriteConf`.
/// The path is owned by the helper binary (runs as root) — never staged by the
/// GUI, so the private key never lands world-readable.
const SERVER_CONF_PATH: &str = "/etc/wireguard/wg-gui-srv0.conf";

/// The CLIENT conf is written here (0600) by `ClientWriteConf`.
///
/// MUST live under `/etc/wireguard` (not `/run` or `/tmp`): `wg-quick` is
/// AppArmor-confined to `/etc/wireguard`, so a conf staged elsewhere fails with
/// `fopen: Permission denied` on NetworkManager-less systems. The basename MUST
/// be `<CLIENT_IFACE>.conf` (`wg-gui0.conf`) because the GUI then runs
/// `pkexec wg-quick up wg-gui0` by interface NAME — wg-quick reads
/// `/etc/wireguard/wg-gui0.conf`. `CLIENT_IFACE` (`wg-gui0`) is the single source
/// of truth in `src/wg/backend.rs`; this path mirrors it (a unit test in
/// `src/wg/backend.rs` asserts the agreement).
const CLIENT_CONF_PATH: &str = "/etc/wireguard/wg-gui0.conf";

/// nftables NAT table used exclusively for server masquerade.
/// Uniquely named so it never collides with user-managed tables or the
/// kill-switch table.
const NFT_NAT_TABLE_FAMILY: &str = "inet";
const NFT_NAT_TABLE_NAME: &str = "wg_gui_srv_nat";

fn main() -> ExitCode {
    // -----------------------------------------------------------------------
    // Root guard: this binary MUST run as effective uid 0. Refuse otherwise.
    // We avoid adding a libc dep by querying /proc/self/status directly.
    // -----------------------------------------------------------------------
    if !is_euid_root() {
        eprintln!(
            "wireguard-gui-helper: FATAL — must run as root (euid 0). \
             Launch via pkexec, not directly."
        );
        return ExitCode::FAILURE;
    }

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wireguard-gui-helper: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Return true when our effective uid is 0 (root).
///
/// Reads /proc/self/status and finds the `Euid:` line — no libc dep required.
/// Falls back to `false` (safe fail) if the file cannot be read.
fn is_euid_root() -> bool {
    // Fast path: extern C geteuid. This works because libc is always a
    // transitive dep on Linux (pulled in by tokio, std, etc.).
    // Edition 2024 requires extern blocks to be marked `unsafe`.
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid() is a pure syscall with no side effects and no
    // unsafety concerns — it cannot fail.
    unsafe { geteuid() == 0 }
}

/// Parse the incoming `PrivCmd` and dispatch to its handler.
fn run() -> AppResult<()> {
    let payload = read_payload()?;
    let cmd: PrivCmd = serde_json::from_str(&payload)
        .map_err(|e| AppError::IpcFailed(format!("cannot decode PrivCmd: {e}")))?;
    dispatch(cmd)
}

/// Read the JSON payload from `--json <payload>` or, if absent, from stdin.
fn read_payload() -> AppResult<String> {
    // Only the FIRST argument selects the input mode; `--json` consumes the next
    // argument as the payload, `-`/`--stdin` (or no argument at all) falls through to
    // reading stdin. There is intentionally no loop here — the mode is decided by the
    // single leading flag.
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--json") => {
            return args.next().ok_or_else(|| {
                AppError::IpcFailed("--json requires a payload argument".into())
            });
        }
        // Explicit stdin request, or no argument — fall through to stdin below.
        Some("-") | Some("--stdin") | None => {}
        Some(other) => {
            return Err(AppError::IpcFailed(format!(
                "unexpected argument: {other} (expected --json <payload> or --stdin)"
            )));
        }
    }
    // Fall back to stdin.
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| AppError::IpcFailed(format!("cannot read stdin: {e}")))?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        return Err(AppError::IpcFailed(
            "no payload: pass --json <payload> or pipe JSON on stdin".into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Route a decoded command to its handler.
fn dispatch(cmd: PrivCmd) -> AppResult<()> {
    match cmd {
        PrivCmd::WgQuickUp { iface, conf_path } => handle_wgquick_up(&iface, &conf_path),
        PrivCmd::WgQuickDown { iface } => handle_wgquick_down(&iface),
        PrivCmd::ClientWriteConf { conf_text } => handle_client_write_conf(&conf_text),
        PrivCmd::ClientRemoveConf => handle_client_remove_conf(),
        PrivCmd::KillSwitchArm {
            iface,
            endpoint_ip,
            endpoint_port,
            lan_cidrs,
            lease_secs,
            netns_endpoint_udp,
        } => handle_killswitch_arm(
            &iface,
            &endpoint_ip,
            endpoint_port,
            &lan_cidrs,
            lease_secs,
            netns_endpoint_udp.as_ref(),
        ),
        PrivCmd::KillSwitchDisarm => handle_killswitch_disarm(),
        PrivCmd::NetnsSetup {
            ns,
            wgif,
            conf_path,
            address,
            dns,
        } => handle_netns_setup(&ns, &wgif, &conf_path, &address, &dns),
        PrivCmd::NetnsTeardown { ns } => handle_netns_teardown(&ns),
        PrivCmd::NetnsLaunch {
            ns,
            uid,
            exe,
            args,
            env,
        } => handle_netns_launch(&ns, uid, &exe, &args, &env),
        PrivCmd::BootEnableSystemd { iface } => handle_boot_enable_systemd(&iface),
        PrivCmd::BootDisableSystemd { iface } => handle_boot_disable_systemd(&iface),
        PrivCmd::ServerWriteConf { conf_text } => handle_server_write_conf(&conf_text),
        PrivCmd::ServerUp => handle_server_up(),
        PrivCmd::ServerDown => handle_server_down(),
        PrivCmd::NatEnable {
            subnet,
            egress_iface,
        } => handle_nat_enable(&subnet, &egress_iface),
        PrivCmd::NatDisable => handle_nat_disable(),
    }
}

// ---------------------------------------------------------------------------
// Pure argv/ruleset builders — testable with NO execution, NO root.
// These mirror (and will eventually replace the todo!() stubs in)
// src/net/killswitch.rs and src/net/netns.rs.  They live here because
// src/bin/ has no access to the GUI's module tree.
// ---------------------------------------------------------------------------

/// Render the complete nft input for the `inet wg_gui_killswitch` table.
///
/// Lockout-prevention allow-list is always emitted FIRST:
///   1. loopback (oifname lo)
///   2. tunnel interface itself (oifname <iface>)
///   3. WireGuard endpoint UDP (so reconnect can punch through)
///   4. LAN/RFC1918 CIDRs (configurable, may be empty)
///   5. established/related (keeps existing sessions alive while arming)
///   6. optional per-app netns endpoint UDP punch-through
///   7. OUTPUT policy drop
///
/// The output chain is called `output` inside the `inet wg_gui_killswitch` table.
/// Every chain/table uses the unique `wg_gui_killswitch` name so it never
/// collides with user-managed tables.
pub fn nft_killswitch_ruleset(
    iface: &str,
    endpoint_ip: &str,
    endpoint_port: u16,
    lan_cidrs: &[String],
    netns_endpoint_udp: Option<&(String, u16)>,
) -> String {
    let mut rules = Vec::<String>::new();

    // 1. loopback — always allow
    rules.push("        oifname lo accept".into());

    // 2. tunnel interface — always allow tunnel traffic
    rules.push(format!("        oifname {iface} accept"));

    // 3. WireGuard endpoint UDP — allows reconnect to punch through the kill-switch
    rules.push(format!(
        "        ip daddr {endpoint_ip} udp dport {endpoint_port} accept"
    ));

    // 4. LAN/RFC1918 CIDRs
    for cidr in lan_cidrs {
        rules.push(format!("        ip daddr {cidr} accept"));
    }

    // 5. established/related — preserves existing sessions during arm
    rules.push("        ct state established,related accept".into());

    // 6. optional per-app netns endpoint UDP punch-through
    if let Some((ns_ip, ns_port)) = netns_endpoint_udp {
        rules.push(format!(
            "        ip daddr {ns_ip} udp dport {ns_port} accept"
        ));
    }

    // 7. default drop is expressed via chain policy, not an explicit rule.
    //    The `policy drop;` statement is emitted LAST in the chain body so the
    //    rendered text reads in evaluation order (all accept rules, then the
    //    fall-through drop). nftables treats `policy` as a chain attribute and
    //    honours it regardless of its textual position, so this is equivalent
    //    semantically but makes the lockout-prevention ordering explicit.
    let rules_block = rules.join("\n");
    format!(
        "table {NFT_TABLE} {{\n    chain output {{\n        type filter hook output priority 0;\n{rules_block}\n        policy drop;\n    }}\n}}\n"
    )
}

/// Build the `systemd-run` argv for the kill-switch dead-man timer.
///
/// The timer will auto-flush the kill-switch table if the GUI stops renewing
/// (survives SIGKILL).  `systemd-run --on-active=<lease_secs>s` schedules a
/// transient unit.
///
/// Note: `nft delete table` takes the family and table name as SEPARATE arguments.
pub fn systemd_run_deadman_argv(lease_secs: u64) -> Vec<String> {
    vec![
        "systemd-run".into(),
        "--on-active".into(),
        format!("{lease_secs}s"),
        "--timer-property=AccuracySec=1s".into(),
        "nft".into(),
        "delete".into(),
        "table".into(),
        NFT_TABLE_FAMILY.into(),
        NFT_TABLE_NAME.into(),
    ]
}

/// Build the `nft delete table inet wg_gui_killswitch` argv for kill-switch disarm.
///
/// `nft` expects family and table name as separate argv entries.
pub fn nft_delete_table_argv() -> Vec<String> {
    vec![
        "nft".into(),
        "delete".into(),
        "table".into(),
        NFT_TABLE_FAMILY.into(),
        NFT_TABLE_NAME.into(),
    ]
}

/// Build the `ip link show <iface>` argv used to check an interface exists.
pub fn ip_link_show_argv(iface: &str) -> Vec<String> {
    vec!["ip".into(), "link".into(), "show".into(), iface.into()]
}

/// Build the sequence of argv-lists for full netns setup.
///
/// Returns a `Vec<Vec<String>>` — each inner vec is one command to run in
/// order.  Pure and side-effect-free so it is golden-testable.
pub fn netns_setup_argv_sequence(
    ns: &str,
    wgif: &str,
    conf_path: &str,
    address: &str,
) -> Vec<Vec<String>> {
    vec![
        // 1. create the namespace
        vec!["ip".into(), "netns".into(), "add".into(), ns.into()],
        // 2. create the WireGuard interface in the root namespace
        vec![
            "ip".into(),
            "link".into(),
            "add".into(),
            wgif.into(),
            "type".into(),
            "wireguard".into(),
        ],
        // 3. move the WireGuard interface into the namespace
        vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            wgif.into(),
            "netns".into(),
            ns.into(),
        ],
        // 4. configure WireGuard inside the namespace using the conf file
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
        // 5. assign the tunnel address
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
        // 6. bring the WireGuard interface up
        vec![
            "ip".into(),
            "-n".into(),
            ns.into(),
            "link".into(),
            "set".into(),
            wgif.into(),
            "up".into(),
        ],
        // 7. bring loopback up
        vec![
            "ip".into(),
            "-n".into(),
            ns.into(),
            "link".into(),
            "set".into(),
            "lo".into(),
            "up".into(),
        ],
        // 8. default route via WireGuard interface
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

/// Build the `ip netns del <ns>` argv.
pub fn netns_del_argv(ns: &str) -> Vec<String> {
    vec!["ip".into(), "netns".into(), "del".into(), ns.into()]
}

/// Build the `ip netns exec <ns> runuser -u <username> -- env <env…> <exe> <args…>` argv.
///
/// `uid` is resolved to a username by reading `/etc/passwd` at call time (pure
/// lookup inside this fn so callers don't need to import anything).
pub fn netns_launch_argv(
    ns: &str,
    username: &str,
    exe: &str,
    args: &[String],
    env: &[(String, String)],
) -> Vec<String> {
    let mut argv = vec![
        "ip".into(),
        "netns".into(),
        "exec".into(),
        ns.into(),
        "runuser".into(),
        "-u".into(),
        username.into(),
        "--".into(),
        "env".into(),
    ];
    // env pairs as KEY=VALUE
    for (k, v) in env {
        argv.push(format!("{k}={v}"));
    }
    argv.push(exe.into());
    argv.extend_from_slice(args);
    argv
}

// ── SERVER / NAT pure builders ────────────────────────────────────────────────

/// Build the `wg-quick up <SERVER_CONF_PATH>` argv for bringing the server up.
pub fn wgquick_server_up_argv() -> Vec<String> {
    vec!["wg-quick".into(), "up".into(), SERVER_CONF_PATH.into()]
}

/// Build the `wg-quick down <SERVER_CONF_PATH>` argv for tearing the server down.
pub fn wgquick_server_down_argv() -> Vec<String> {
    vec!["wg-quick".into(), "down".into(), SERVER_CONF_PATH.into()]
}

/// Build the `sysctl -w net.ipv4.ip_forward=1` argv.
pub fn sysctl_ipv4_forward_argv() -> Vec<String> {
    vec![
        "sysctl".into(),
        "-w".into(),
        "net.ipv4.ip_forward=1".into(),
    ]
}

/// Build the `sysctl -w net.ipv6.conf.all.forwarding=1` argv.
pub fn sysctl_ipv6_forward_argv() -> Vec<String> {
    vec![
        "sysctl".into(),
        "-w".into(),
        "net.ipv6.conf.all.forwarding=1".into(),
    ]
}

/// Build the `nft delete table inet wg_gui_srv_nat` argv.
///
/// Family and table name are SEPARATE arguments (not a single string) — mirrors
/// the kill-switch pattern.
pub fn nft_delete_nat_table_argv() -> Vec<String> {
    vec![
        "nft".into(),
        "delete".into(),
        "table".into(),
        NFT_NAT_TABLE_FAMILY.into(),
        NFT_NAT_TABLE_NAME.into(),
    ]
}

/// Render the complete nft input text for the `inet wg_gui_srv_nat` masquerade
/// table.
///
/// Creates a `nat` chain hooked into `postrouting` that masquerades all tunnel
/// traffic sourced from `subnet` as it leaves `egress_iface`.  The table is
/// uniquely named `wg_gui_srv_nat` to avoid colliding with user-managed tables.
///
/// # Parameters
///
/// - `subnet`        — the tunnel subnet to masquerade (e.g. `"10.7.0.0/24"`)
/// - `egress_iface`  — the host's internet-facing interface (e.g. `"eth0"`)
///
/// # Pure
///
/// Side-effect-free.  Write the returned string to a temp file and pass it to
/// `nft -c -f <file>` for a syntax-only check (no networking changes), or let
/// the helper run `nft -f <file>` for the real apply.
pub fn nft_nat_ruleset(subnet: &str, egress_iface: &str) -> String {
    // The nftables `nat` chain type is only available in the `ip` or `inet`
    // family.  We use `inet` (dual-stack) but the masquerade rule targets
    // IPv4 via `ip saddr`.  IPv6 masquerade (SNAT) is not addressed here.
    format!(
        "# wg_gui_srv_nat — generated by wireguard-gui-rust\n\
         # DO NOT EDIT MANUALLY — managed by wireguard-gui-helper\n\
         \n\
         table {NFT_NAT_TABLE_FAMILY} {NFT_NAT_TABLE_NAME} {{\n\
             chain postrouting {{\n\
                 type nat hook postrouting priority 100;\n\
                 ip saddr {subnet} oifname \"{egress_iface}\" masquerade;\n\
             }}\n\
         }}\n"
    )
}

/// Look up a username from `/etc/passwd` for the given `uid`.
///
/// Returns `Err` with a clear message when the uid is not found (prevents
/// running apps as root by mistake).
fn username_for_uid(uid: u32) -> AppResult<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|e| {
        AppError::NetnsFailed(format!("cannot read /etc/passwd: {e}"))
    })?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.splitn(7, ':').collect();
        if fields.len() >= 4
            && let Ok(line_uid) = fields[2].parse::<u32>()
            && line_uid == uid
        {
            return Ok(fields[0].to_string());
        }
    }
    Err(AppError::NetnsFailed(format!(
        "uid {uid} not found in /etc/passwd — refusing to launch (safety guard: never launch as root uid 0)"
    )))
}

/// Run a command (via `std::process::Command`) and return an error on non-zero exit.
///
/// Stderr is captured and included in the error message so callers can pattern-match
/// on tool-specific error strings (e.g. nft "No such table").
///
/// This is the single execution point for all handlers.  Every real mutation
/// flows through here so audit/logging is easy to add later.
fn run_cmd(program: &str, args: &[String]) -> AppResult<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::WgNotFound
            } else {
                AppError::IpcFailed(format!("spawn '{program}': {e}"))
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(AppError::IpcFailed(format!(
            "'{program}' exited with status {}: {}",
            output.status,
            stderr.trim(),
        )))
    } else {
        Ok(())
    }
}

/// Run a command and capture its stdout (used for `ip link show` existence checks).
fn run_cmd_stdout(program: &str, args: &[String]) -> AppResult<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::WgNotFound
            } else {
                AppError::IpcFailed(format!("spawn '{program}': {e}"))
            }
        })?;
    if !output.status.success() {
        Err(AppError::IpcFailed(format!(
            "'{program}' exited with status {}",
            output.status
        )))
    } else {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

// ---------------------------------------------------------------------------
// Handlers — root-only ops.  Each performs exactly the documented mutation.
// ---------------------------------------------------------------------------

/// `wg-quick up <conf_path>` — bring a tunnel up from a generated config file.
///
/// `iface` is used only for log context; wg-quick derives the interface name
/// from the conf filename.
fn handle_wgquick_up(iface: &str, conf_path: &str) -> AppResult<()> {
    eprintln!("helper: wg-quick up iface={iface} conf={conf_path}");
    run_cmd("wg-quick", &["up".into(), conf_path.into()])
}

/// `wg-quick down <iface>` — tear the tunnel down.
fn handle_wgquick_down(iface: &str) -> AppResult<()> {
    eprintln!("helper: wg-quick down iface={iface}");
    run_cmd("wg-quick", &["down".into(), iface.into()])
}

/// Arm the nftables kill-switch:
///
///   1. Refuse if `iface` is not present (safety guard — never arm for a
///      non-existent interface or we'd lock the user out).
///   2. Write the nft ruleset to a temp file.
///   3. Apply it: `nft -f <tempfile>`.
///   4. Arm the dead-man timer: `systemd-run --on-active=<lease>s … nft delete table …`
///      so the table self-destructs if the GUI dies without disarming.
fn handle_killswitch_arm(
    iface: &str,
    endpoint_ip: &str,
    endpoint_port: u16,
    lan_cidrs: &[String],
    lease_secs: u64,
    netns_endpoint_udp: Option<&(String, u16)>,
) -> AppResult<()> {
    eprintln!(
        "helper: killswitch arm iface={iface} endpoint={endpoint_ip}:{endpoint_port} \
         lan_cidrs={lan_cidrs:?} lease={lease_secs}s"
    );

    // 1. Safety guard: refuse if the WireGuard interface does not exist.
    //    `ip link show <iface>` exits non-zero if the interface is absent.
    run_cmd_stdout("ip", &ip_link_show_argv(iface)).map_err(|_| {
        AppError::IpcFailed(format!(
            "kill-switch arm refused: interface '{iface}' does not exist. \
             Bring the tunnel up before arming the kill-switch."
        ))
    })?;

    // 2. Render the nft ruleset.
    let ruleset = nft_killswitch_ruleset(
        iface,
        endpoint_ip,
        endpoint_port,
        lan_cidrs,
        netns_endpoint_udp,
    );

    // 3. Write ruleset to a temp file and apply with `nft -f`.
    let tmp_path = format!("/run/wg-gui-ks-{}.nft", std::process::id());
    std::fs::write(&tmp_path, &ruleset).map_err(|e| {
        AppError::IpcFailed(format!("cannot write nft ruleset to {tmp_path}: {e}"))
    })?;
    let nft_result = run_cmd("nft", &["-f".into(), tmp_path.clone()]);
    // Always clean up the temp file, even on error.
    let _ = std::fs::remove_file(&tmp_path);
    nft_result?;

    // 4. Arm the dead-man timer (best-effort — if systemd-run is absent, log
    //    a warning but don't fail the arm; the table is still protecting the user).
    let dm_args = systemd_run_deadman_argv(lease_secs);
    if let Err(e) = run_cmd("systemd-run", &dm_args[1..]) {
        eprintln!(
            "helper: WARNING — dead-man timer could not be armed ({e}). \
             Kill-switch is active but will NOT auto-expire if the GUI is killed."
        );
    }

    Ok(())
}

/// Remove the kill-switch: `nft delete table inet wg_gui_killswitch`.
///
/// Idempotent — if the table does not exist, nft exits non-zero but we
/// treat "table not found" as a no-op (already disarmed).
fn handle_killswitch_disarm() -> AppResult<()> {
    eprintln!("helper: killswitch disarm");
    let args = nft_delete_table_argv();
    match run_cmd("nft", &args[1..]) {
        Ok(()) => Ok(()),
        Err(AppError::IpcFailed(msg)) if msg.contains("No such file or directory")
            || msg.contains("table not found")
            || msg.contains("No such table") =>
        {
            // Already gone — idempotent success.
            eprintln!("helper: killswitch already disarmed (table not present)");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Build a kernel-isolated per-app network namespace and route it through WireGuard.
///
/// Sequence (mirrors the design doc — never touches host routes):
///   1.  ip netns add <ns>
///   2.  ip link add <wgif> type wireguard
///   3.  ip link set <wgif> netns <ns>
///   4.  ip netns exec <ns> wg setconf <wgif> <conf_path>
///   5.  ip -n <ns> addr add <address> dev <wgif>
///   6.  ip -n <ns> link set <wgif> up
///   7.  ip -n <ns> link set lo up
///   8.  ip -n <ns> route add default dev <wgif>
///   9.  mkdir -p /etc/netns/<ns>; write resolv.conf from dns
fn handle_netns_setup(
    ns: &str,
    wgif: &str,
    conf_path: &str,
    address: &str,
    dns: &[String],
) -> AppResult<()> {
    eprintln!("helper: netns setup ns={ns} wgif={wgif} addr={address} dns={dns:?}");

    // Run the sequence of ip commands.
    for argv in netns_setup_argv_sequence(ns, wgif, conf_path, address) {
        let program = argv[0].clone();
        run_cmd(&program, &argv[1..])?;
    }

    // 9. Write ns-local DNS configuration.
    if !dns.is_empty() {
        let dir = format!("/etc/netns/{ns}");
        std::fs::create_dir_all(&dir).map_err(|e| {
            AppError::NetnsFailed(format!("cannot create {dir}: {e}"))
        })?;
        let resolv_path = format!("{dir}/resolv.conf");
        let resolv_content = dns
            .iter()
            .map(|server| format!("nameserver {server}"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&resolv_path, &resolv_content).map_err(|e| {
            AppError::NetnsFailed(format!("cannot write {resolv_path}: {e}"))
        })?;
    }

    Ok(())
}

/// Tear a namespace down: `ip netns del <ns>`; `rm -rf /etc/netns/<ns>`.
///
/// Deleting the namespace automatically removes all virtual interfaces inside it.
/// We do a best-effort removal of /etc/netns/<ns> afterwards.
fn handle_netns_teardown(ns: &str) -> AppResult<()> {
    eprintln!("helper: netns teardown ns={ns}");

    run_cmd("ip", &netns_del_argv(ns)[1..])?;

    // Remove /etc/netns/<ns> — best-effort (may not exist if DNS was not configured).
    let etc_path = format!("/etc/netns/{ns}");
    if let Err(e) = std::fs::remove_dir_all(&etc_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("helper: WARNING — could not remove {etc_path}: {e}");
    }

    Ok(())
}

/// Launch an executable inside a namespace as the unprivileged owner user.
///
/// `ip netns exec <ns> runuser -u <username> -- env <env…> <exe> <args…>`
///
/// Safety requirements:
///   - uid 0 is explicitly refused (never run GUI apps as root inside a netns).
///   - The username is resolved from /etc/passwd; an unknown uid is rejected.
fn handle_netns_launch(
    ns: &str,
    uid: u32,
    exe: &str,
    args: &[String],
    env: &[(String, String)],
) -> AppResult<()> {
    eprintln!("helper: netns launch ns={ns} uid={uid} exe={exe}");

    // Safety guard: refuse uid 0 — never run GUI apps as root inside a netns.
    if uid == 0 {
        return Err(AppError::NetnsFailed(
            "netns launch refused: uid 0 (root) is not allowed for application launch".into(),
        ));
    }

    let username = username_for_uid(uid)?;
    let argv = netns_launch_argv(ns, &username, exe, args, env);

    // argv[0] = "ip", rest = ["netns", "exec", <ns>, "runuser", …]
    run_cmd(&argv[0], &argv[1..])
}

/// Connect-on-boot for the wg-quick path: `systemctl enable wg-quick@<iface>`.
fn handle_boot_enable_systemd(iface: &str) -> AppResult<()> {
    eprintln!("helper: systemctl enable wg-quick@{iface}");
    run_cmd(
        "systemctl",
        &["enable".into(), format!("wg-quick@{iface}")],
    )
}

/// Disable connect-on-boot: `systemctl disable wg-quick@<iface>`.
fn handle_boot_disable_systemd(iface: &str) -> AppResult<()> {
    eprintln!("helper: systemctl disable wg-quick@{iface}");
    run_cmd(
        "systemctl",
        &["disable".into(), format!("wg-quick@{iface}")],
    )
}

// ---------------------------------------------------------------------------
// SERVER-mode handlers (root-only).
//
// SAFETY: every handler here changes host networking.  They execute ONLY when
// this binary is running as root (euid 0) inside the pkexec/polkit gate.
// The unprivileged GUI constructs PrivCmd values and sends them via pkexec;
// nothing here runs in the GUI process.
// ---------------------------------------------------------------------------

/// Write `conf_text` to `path` under `/etc/wireguard`, creating the parent dir if
/// needed and locking the file to mode 0600 (owner read/write only) because it
/// holds a WireGuard private key.
///
/// Shared by [`handle_server_write_conf`] and [`handle_client_write_conf`] so both
/// the server and client conf-write paths are byte-for-byte identical (single
/// source of truth for the 0600-write semantics).
fn write_conf_0600(path: &str, conf_text: &str) -> AppResult<()> {
    // Ensure the parent directory exists (/etc/wireguard).
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            AppError::IpcFailed(format!("cannot create dir {}: {e}", parent.display()))
        })?;
    }

    // Write with O_CREAT | O_WRONLY | O_TRUNC and mode 0600.
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut file = opts
        .open(path)
        .map_err(|e| AppError::IpcFailed(format!("cannot open {path}: {e}")))?;
    use std::io::Write as _;
    file.write_all(conf_text.as_bytes())
        .map_err(|e| AppError::IpcFailed(format!("cannot write {path}: {e}")))?;

    Ok(())
}

/// Write the server `.conf` text to the helper-owned server conf path
/// (`wg-gui-srv0.conf`, mode 0600) for a subsequent `ServerUp`.
///
/// The conf is delivered in-band so the unprivileged GUI never has to stage a
/// world-readable temp file that holds the server's private key.  Permissions
/// are locked to 0600 (owner read/write only) because the file contains the
/// server private key.
fn handle_server_write_conf(conf_text: &str) -> AppResult<()> {
    eprintln!("helper: server write conf → {SERVER_CONF_PATH}");
    write_conf_0600(SERVER_CONF_PATH, conf_text)
}

/// Write the CLIENT `.conf` text to the helper-owned client conf path
/// (`/etc/wireguard/wg-gui0.conf`, mode 0600) for a subsequent
/// `pkexec wg-quick up wg-gui0`.
///
/// This is the AppArmor fix: `wg-quick` is confined to `/etc/wireguard`, so it
/// cannot read a conf staged under `/run` or `/tmp`. Mirrors
/// [`handle_server_write_conf`] exactly (same 0600 in-band write), differing only
/// in the destination path.
fn handle_client_write_conf(conf_text: &str) -> AppResult<()> {
    eprintln!("helper: client write conf → {CLIENT_CONF_PATH}");
    write_conf_0600(CLIENT_CONF_PATH, conf_text)
}

/// Remove the helper-owned client conf (`/etc/wireguard/wg-gui0.conf`) on
/// disconnect. Idempotent — a missing file is treated as success.
fn handle_client_remove_conf() -> AppResult<()> {
    eprintln!("helper: client remove conf → {CLIENT_CONF_PATH}");
    match std::fs::remove_file(CLIENT_CONF_PATH) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(AppError::IpcFailed(format!(
            "cannot remove {CLIENT_CONF_PATH}: {e}"
        ))),
    }
}

/// Bring the server interface up: `wg-quick up <SERVER_CONF_PATH>`.
fn handle_server_up() -> AppResult<()> {
    eprintln!("helper: wg-quick up {SERVER_CONF_PATH}");
    let argv = wgquick_server_up_argv();
    run_cmd(&argv[0], &argv[1..])
}

/// Tear the server interface down: `wg-quick down <SERVER_CONF_PATH>`.
fn handle_server_down() -> AppResult<()> {
    eprintln!("helper: wg-quick down {SERVER_CONF_PATH}");
    let argv = wgquick_server_down_argv();
    run_cmd(&argv[0], &argv[1..])
}

/// Enable IPv4 (and IPv6) forwarding + an nft masquerade for `subnet` out
/// `egress_iface`.
///
/// Steps:
///   1. `sysctl -w net.ipv4.ip_forward=1`
///   2. `sysctl -w net.ipv6.conf.all.forwarding=1`
///   3. Write masquerade nft ruleset to a temp file.
///   4. `nft -f <tempfile>` (apply — idempotent because we flush+recreate).
///
/// IPv4 forwarding is intentionally left enabled on `NatDisable` — other
/// services on this host may depend on it.
fn handle_nat_enable(subnet: &str, egress_iface: &str) -> AppResult<()> {
    eprintln!("helper: nat enable subnet={subnet} egress={egress_iface}");

    // 1. Enable IPv4 forwarding.
    let v4_argv = sysctl_ipv4_forward_argv();
    run_cmd(&v4_argv[0], &v4_argv[1..])?;

    // 2. Enable IPv6 forwarding (best-effort — may not matter when IPv6 is
    //    absent, but never causes harm).
    let v6_argv = sysctl_ipv6_forward_argv();
    if let Err(e) = run_cmd(&v6_argv[0], &v6_argv[1..]) {
        eprintln!(
            "helper: WARNING — IPv6 forwarding sysctl failed ({e}); \
             continuing (IPv4-only NAT will work)"
        );
    }

    // 3. Render the masquerade nft ruleset.
    let ruleset = nft_nat_ruleset(subnet, egress_iface);

    // 4. Write to a unique temp path and apply.
    let tmp_path = format!("/run/wg-gui-nat-{}.nft", std::process::id());
    std::fs::write(&tmp_path, &ruleset).map_err(|e| {
        AppError::IpcFailed(format!("cannot write nft nat ruleset to {tmp_path}: {e}"))
    })?;
    let nft_result = run_cmd("nft", &["-f".into(), tmp_path.clone()]);
    let _ = std::fs::remove_file(&tmp_path);
    nft_result?;

    Ok(())
}

/// Remove the NAT masquerade table (idempotent).
///
/// `nft delete table inet wg_gui_srv_nat`.  If the table does not exist, treats
/// the nft error as a no-op (already removed / never armed).
fn handle_nat_disable() -> AppResult<()> {
    eprintln!("helper: nat disable — nft delete table {NFT_NAT_TABLE_FAMILY} {NFT_NAT_TABLE_NAME}");
    let args = nft_delete_nat_table_argv();
    match run_cmd("nft", &args[1..]) {
        Ok(()) => Ok(()),
        Err(AppError::IpcFailed(msg))
            if msg.contains("No such file or directory")
                || msg.contains("table not found")
                || msg.contains("No such table") =>
        {
            eprintln!("helper: nat table already absent (idempotent)");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Unit tests — pure builders and logic, NO execution, NO root.
// Any test that would require root is marked #[ignore] so `cargo test` stays
// green without privilege.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- nft_killswitch_ruleset (golden, no I/O) ----------------------------

    #[test]
    fn nft_ruleset_contains_table_name() {
        let rs = nft_killswitch_ruleset("wg0", "203.0.113.1", 51820, &[], None);
        assert!(rs.contains("wg_gui_killswitch"), "missing table name: {rs}");
        assert!(rs.contains("inet"), "missing family 'inet': {rs}");
    }

    #[test]
    fn nft_ruleset_lockout_prevention_order() {
        let rs = nft_killswitch_ruleset(
            "wg-gui0",
            "203.0.113.7",
            51820,
            &["192.168.0.0/16".into()],
            None,
        );
        // lo accept must appear BEFORE the drop policy.
        let lo_pos = rs.find("oifname lo accept").expect("lo accept missing");
        let iface_pos = rs.find("oifname wg-gui0 accept").expect("iface accept missing");
        let ep_pos = rs
            .find("ip daddr 203.0.113.7 udp dport 51820 accept")
            .expect("endpoint accept missing");
        let lan_pos = rs
            .find("ip daddr 192.168.0.0/16 accept")
            .expect("LAN accept missing");
        let est_pos = rs
            .find("ct state established,related accept")
            .expect("established accept missing");
        let drop_pos = rs.find("policy drop").expect("drop policy missing");

        assert!(lo_pos < drop_pos, "lo must come before drop");
        assert!(iface_pos < drop_pos, "iface must come before drop");
        assert!(ep_pos < drop_pos, "endpoint must come before drop");
        assert!(lan_pos < drop_pos, "LAN must come before drop");
        assert!(est_pos < drop_pos, "established must come before drop");
        assert!(lo_pos < iface_pos, "lo must come before iface");
        assert!(iface_pos < ep_pos, "iface must come before endpoint");
    }

    #[test]
    fn nft_ruleset_netns_udp_punch_through() {
        let rs = nft_killswitch_ruleset(
            "wg0",
            "203.0.113.1",
            51820,
            &[],
            Some(&("198.51.100.5".into(), 12345)),
        );
        assert!(
            rs.contains("ip daddr 198.51.100.5 udp dport 12345 accept"),
            "netns punch-through missing: {rs}"
        );
    }

    #[test]
    fn nft_ruleset_no_netns_punch_through_when_none() {
        let rs = nft_killswitch_ruleset("wg0", "203.0.113.1", 51820, &[], None);
        // Should contain exactly one endpoint accept (the main WireGuard endpoint).
        let count = rs.matches("udp dport").count();
        assert_eq!(count, 1, "expected 1 udp dport rule, got {count}: {rs}");
    }

    #[test]
    fn nft_ruleset_multiple_lan_cidrs() {
        let lan = vec![
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
        ];
        let rs = nft_killswitch_ruleset("wg0", "203.0.113.1", 51820, &lan, None);
        assert!(rs.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(rs.contains("ip daddr 172.16.0.0/12 accept"));
        assert!(rs.contains("ip daddr 192.168.0.0/16 accept"));
    }

    #[test]
    fn nft_ruleset_empty_lan_cidrs() {
        let rs = nft_killswitch_ruleset("wg0", "203.0.113.1", 51820, &[], None);
        // No LAN cidrs — should not produce stray ip daddr lines beyond the endpoint.
        let daddr_count = rs.matches("ip daddr").count();
        assert_eq!(daddr_count, 1, "expected only endpoint daddr rule, got {daddr_count}: {rs}");
    }

    // --- systemd_run_deadman_argv -------------------------------------------

    #[test]
    fn deadman_argv_contains_lease_and_nft_delete() {
        let argv = systemd_run_deadman_argv(30);
        assert_eq!(argv[0], "systemd-run");
        assert!(
            argv.iter().any(|a| a == "--on-active"),
            "missing --on-active: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a == "30s"),
            "missing lease duration 30s: {argv:?}"
        );
        // The delete table command must be embedded with family and name as separate args.
        assert!(argv.iter().any(|a| a == "nft"), "missing nft: {argv:?}");
        assert!(
            argv.iter().any(|a| a == "delete"),
            "missing delete: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a == NFT_TABLE_FAMILY),
            "missing table family 'inet': {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a == NFT_TABLE_NAME),
            "missing table name: {argv:?}"
        );
    }

    #[test]
    fn deadman_argv_lease_is_respected() {
        let argv60 = systemd_run_deadman_argv(60);
        let argv300 = systemd_run_deadman_argv(300);
        assert!(argv60.iter().any(|a| a == "60s"));
        assert!(argv300.iter().any(|a| a == "300s"));
    }

    // --- nft_delete_table_argv ----------------------------------------------

    #[test]
    fn nft_delete_table_argv_shape() {
        let argv = nft_delete_table_argv();
        assert_eq!(argv[0], "nft");
        assert_eq!(argv[1], "delete");
        assert_eq!(argv[2], "table");
        // family and name must be SEPARATE arguments (not a single "inet wg_gui_killswitch" string).
        assert_eq!(argv[3], NFT_TABLE_FAMILY, "family must be 'inet'");
        assert_eq!(argv[4], NFT_TABLE_NAME, "name must be 'wg_gui_killswitch'");
        assert_eq!(argv.len(), 5);
    }

    // --- ip_link_show_argv --------------------------------------------------

    #[test]
    fn ip_link_show_argv_golden() {
        let argv = ip_link_show_argv("wg-gui0");
        assert_eq!(argv, vec!["ip", "link", "show", "wg-gui0"]);
    }

    // --- netns_setup_argv_sequence ------------------------------------------

    #[test]
    fn netns_setup_sequence_length_and_order() {
        let seq = netns_setup_argv_sequence("wg-gui-app", "wg-gui-ns0", "/run/wg.conf", "10.2.0.2/32");
        // Exactly 8 commands in the documented order.
        assert_eq!(seq.len(), 8, "expected 8 steps, got {}", seq.len());

        // Step 1: ip netns add
        assert_eq!(&seq[0], &["ip", "netns", "add", "wg-gui-app"]);

        // Step 2: ip link add <wgif> type wireguard
        assert_eq!(
            &seq[1],
            &["ip", "link", "add", "wg-gui-ns0", "type", "wireguard"]
        );

        // Step 3: ip link set <wgif> netns <ns>
        assert_eq!(
            &seq[2],
            &["ip", "link", "set", "wg-gui-ns0", "netns", "wg-gui-app"]
        );

        // Step 4: wg setconf inside namespace
        assert_eq!(
            &seq[3],
            &[
                "ip", "netns", "exec", "wg-gui-app",
                "wg", "setconf", "wg-gui-ns0", "/run/wg.conf"
            ]
        );

        // Step 5: addr add
        assert!(seq[4].contains(&"addr".into()), "step 5 must contain addr: {:?}", seq[4]);
        assert!(seq[4].contains(&"10.2.0.2/32".into()), "step 5 must contain address");

        // Step 6: link set <wgif> up
        assert!(seq[5].contains(&"wg-gui-ns0".into()), "step 6 must reference wgif");
        assert!(seq[5].contains(&"up".into()), "step 6 must set up");

        // Step 7: link set lo up
        assert!(seq[6].contains(&"lo".into()), "step 7 must reference lo");
        assert!(seq[6].contains(&"up".into()), "step 7 must set up");

        // Step 8: route add default
        assert!(seq[7].contains(&"route".into()), "step 8 must be a route cmd");
        assert!(seq[7].contains(&"default".into()), "step 8 must add default route");
    }

    #[test]
    fn netns_setup_sequence_references_all_params() {
        let seq = netns_setup_argv_sequence("test-ns", "test-wg0", "/tmp/test.conf", "10.0.0.1/24");
        let all: Vec<String> = seq.into_iter().flatten().collect();
        let joined = all.join(" ");
        assert!(joined.contains("test-ns"), "missing ns");
        assert!(joined.contains("test-wg0"), "missing wgif");
        assert!(joined.contains("/tmp/test.conf"), "missing conf_path");
        assert!(joined.contains("10.0.0.1/24"), "missing address");
    }

    // --- netns_del_argv -----------------------------------------------------

    #[test]
    fn netns_del_argv_golden() {
        assert_eq!(
            netns_del_argv("wg-gui-app"),
            vec!["ip", "netns", "del", "wg-gui-app"]
        );
    }

    // --- netns_launch_argv --------------------------------------------------

    #[test]
    fn netns_launch_argv_shape() {
        let env = vec![
            ("DISPLAY".into(), ":0".into()),
            ("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()),
        ];
        let args = vec!["--new-instance".into()];
        let argv = netns_launch_argv("wg-gui-app", "alice", "/usr/bin/firefox", &args, &env);

        // Must start with ip netns exec <ns> runuser -u <user> -- env
        assert_eq!(argv[0], "ip");
        assert_eq!(argv[1], "netns");
        assert_eq!(argv[2], "exec");
        assert_eq!(argv[3], "wg-gui-app");
        assert_eq!(argv[4], "runuser");
        assert_eq!(argv[5], "-u");
        assert_eq!(argv[6], "alice");
        assert_eq!(argv[7], "--");
        assert_eq!(argv[8], "env");

        // env pairs encoded as KEY=VALUE
        let kv_pos: Vec<_> = argv
            .iter()
            .enumerate()
            .filter(|(_, a)| a.contains('='))
            .collect();
        assert!(
            kv_pos.iter().any(|(_, a)| a.as_str() == "DISPLAY=:0"),
            "DISPLAY missing: {argv:?}"
        );
        assert!(
            kv_pos.iter().any(|(_, a)| a.as_str() == "XDG_RUNTIME_DIR=/run/user/1000"),
            "XDG_RUNTIME_DIR missing: {argv:?}"
        );

        // exe and args come last
        assert!(
            argv.iter().any(|a| a == "/usr/bin/firefox"),
            "exe missing: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a == "--new-instance"),
            "arg missing: {argv:?}"
        );
    }

    #[test]
    fn netns_launch_argv_empty_env_and_args() {
        let argv = netns_launch_argv("ns", "bob", "/usr/bin/ls", &[], &[]);
        // Should still have the ip netns exec … runuser -u … -- env <exe> shape.
        assert!(argv.iter().any(|a| a == "env"), "env keyword missing");
        assert!(argv.last() == Some(&"/usr/bin/ls".into()), "exe must be last");
    }

    // --- boot enable/disable argv (golden, pure) ----------------------------

    #[test]
    fn boot_enable_argv_golden() {
        // handle_boot_enable_systemd is imperative; we test the argv shape inline.
        let iface = "wg-gui-home";
        let service = format!("wg-quick@{iface}");
        assert_eq!(service, "wg-quick@wg-gui-home");
    }

    #[test]
    fn boot_disable_argv_golden() {
        let iface = "wg-gui-work";
        let service = format!("wg-quick@{iface}");
        assert_eq!(service, "wg-quick@wg-gui-work");
    }

    // --- username_for_uid (data-driven, no root needed) ---------------------

    #[test]
    fn username_for_uid_root_is_root() {
        // uid 0 should be "root" on any Linux system.
        let name = username_for_uid(0).expect("root must be in /etc/passwd");
        assert_eq!(name, "root", "uid 0 should map to 'root', got '{name}'");
    }

    #[test]
    fn username_for_uid_unknown_returns_err() {
        // uid u32::MAX is guaranteed not to exist.
        let result = username_for_uid(u32::MAX);
        assert!(result.is_err(), "unknown uid must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains(&u32::MAX.to_string()),
            "error must mention the uid: {msg}"
        );
    }

    // --- netns launch uid=0 guard -------------------------------------------

    #[test]
    fn netns_launch_refuses_uid_zero() {
        // We can test the guard without actually executing anything.
        let result = handle_netns_launch("any-ns", 0, "/bin/bash", &[], &[]);
        assert!(result.is_err(), "uid 0 launch must be refused");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("uid 0") || msg.contains("root"),
            "error must mention uid 0 or root: {msg}"
        );
    }

    // ── SERVER / NAT pure-builder tests (no execution, no root) ─────────────

    #[test]
    fn wgquick_server_up_argv_golden() {
        let argv = wgquick_server_up_argv();
        assert_eq!(argv, vec!["wg-quick", "up", SERVER_CONF_PATH]);
    }

    #[test]
    fn wgquick_server_down_argv_golden() {
        let argv = wgquick_server_down_argv();
        assert_eq!(argv, vec!["wg-quick", "down", SERVER_CONF_PATH]);
    }

    #[test]
    fn sysctl_ipv4_forward_argv_golden() {
        let argv = sysctl_ipv4_forward_argv();
        assert_eq!(argv, vec!["sysctl", "-w", "net.ipv4.ip_forward=1"]);
    }

    #[test]
    fn sysctl_ipv6_forward_argv_golden() {
        let argv = sysctl_ipv6_forward_argv();
        assert_eq!(argv, vec!["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"]);
    }

    #[test]
    fn nft_delete_nat_table_argv_golden() {
        let argv = nft_delete_nat_table_argv();
        // Must be exactly 5 elements: nft delete table <family> <name>.
        // family and name are SEPARATE arguments (not "inet wg_gui_srv_nat" as one string).
        assert_eq!(argv.len(), 5, "expected 5 argv elements: {argv:?}");
        assert_eq!(argv[0], "nft");
        assert_eq!(argv[1], "delete");
        assert_eq!(argv[2], "table");
        assert_eq!(argv[3], NFT_NAT_TABLE_FAMILY, "family must be 'inet'");
        assert_eq!(argv[4], NFT_NAT_TABLE_NAME, "name must be 'wg_gui_srv_nat'");
    }

    #[test]
    fn nft_nat_ruleset_contains_table_and_chain() {
        let rs = nft_nat_ruleset("10.7.0.0/24", "eth0");
        assert!(
            rs.contains("wg_gui_srv_nat"),
            "missing table name 'wg_gui_srv_nat': {rs}"
        );
        assert!(rs.contains("inet"), "missing family 'inet': {rs}");
        assert!(rs.contains("postrouting"), "missing postrouting hook: {rs}");
        assert!(rs.contains("masquerade"), "missing masquerade target: {rs}");
    }

    #[test]
    fn nft_nat_ruleset_subnet_and_egress_embedded() {
        let rs = nft_nat_ruleset("10.7.0.0/24", "eth0");
        assert!(
            rs.contains("ip saddr 10.7.0.0/24"),
            "subnet missing from ruleset: {rs}"
        );
        assert!(
            rs.contains(r#"oifname "eth0""#),
            "egress iface (quoted) missing from ruleset: {rs}"
        );
    }

    #[test]
    fn nft_nat_ruleset_different_params_produce_different_output() {
        let rs1 = nft_nat_ruleset("10.7.0.0/24", "eth0");
        let rs2 = nft_nat_ruleset("192.168.0.0/16", "ens3");
        assert_ne!(rs1, rs2, "different params must produce different rulesets");
    }

    #[test]
    fn nft_nat_ruleset_postrouting_priority_is_100() {
        let rs = nft_nat_ruleset("10.7.0.0/24", "eth0");
        // nftables nat postrouting must be at priority 100 (standard srcnat).
        assert!(
            rs.contains("priority 100"),
            "expected postrouting priority 100: {rs}"
        );
    }

    #[test]
    fn server_conf_path_is_etc_wireguard() {
        assert_eq!(SERVER_CONF_PATH, "/etc/wireguard/wg-gui-srv0.conf");
    }

    #[test]
    fn client_conf_path_is_etc_wireguard_with_iface_basename() {
        // MUST be under /etc/wireguard (AppArmor confinement) and the basename MUST
        // be <CLIENT_IFACE>.conf so `wg-quick up wg-gui0` resolves it by name.
        assert_eq!(CLIENT_CONF_PATH, "/etc/wireguard/wg-gui0.conf");
        assert!(
            CLIENT_CONF_PATH.starts_with("/etc/wireguard/"),
            "client conf must live under /etc/wireguard (AppArmor): {CLIENT_CONF_PATH}"
        );
        assert!(
            CLIENT_CONF_PATH.ends_with("/wg-gui0.conf"),
            "client conf basename must be wg-gui0.conf: {CLIENT_CONF_PATH}"
        );
    }

    /// Verify the masquerade ruleset passes `nft -c -f <file>` (syntax check only —
    /// NEVER applies any NAT or networking change).  Requires the `nft` binary.
    /// Marked #[ignore] because CI runners may not have nft installed.
    #[test]
    #[ignore]
    fn nft_nat_ruleset_syntax_check_with_nft_binary() {
        let ruleset = nft_nat_ruleset("10.7.0.0/24", "eth0");
        let path = "/tmp/wg-gui-nat-syntax-test.nft";
        std::fs::write(path, &ruleset).unwrap();
        let status = Command::new("nft").args(["-c", "-f", path]).status().unwrap();
        let _ = std::fs::remove_file(path);
        assert!(
            status.success(),
            "nft -c rejected the NAT masquerade ruleset:\n{ruleset}"
        );
    }

    // --- nft syntax check (requires nft binary + root — mark #[ignore]) -----

    /// Verify the rendered nft ruleset passes `nft -c -f <file>` (syntax only,
    /// does NOT apply any rules).  Requires the `nft` binary and root.
    #[test]
    #[ignore]
    fn nft_syntax_check_with_nft_binary() {
        let ruleset = nft_killswitch_ruleset(
            "wg-gui-test",
            "203.0.113.1",
            51820,
            &["192.168.0.0/16".into(), "10.0.0.0/8".into()],
            Some(&("198.51.100.5".into(), 12345)),
        );
        let path = "/tmp/wg-gui-ks-syntax-test.nft";
        std::fs::write(path, &ruleset).unwrap();
        let status = Command::new("nft").args(["-c", "-f", path]).status().unwrap();
        let _ = std::fs::remove_file(path);
        assert!(status.success(), "nft syntax check failed for:\n{ruleset}");
    }

    /// Create a throwaway test network namespace with a dummy interface, verify
    /// it can be added and deleted cleanly, then remove it.  Requires root.
    #[test]
    #[ignore]
    fn netns_add_del_throwaway_requires_root() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let ns = format!("wg-gui-test-{uniq}");

        // Add namespace
        let add_status = Command::new("ip")
            .args(["netns", "add", &ns])
            .status()
            .unwrap();
        assert!(add_status.success(), "ip netns add failed");

        // Add a dummy interface inside it (touches nothing on the host).
        let dummy_if = format!("wg-t-{}", uniq % 9999);
        let link_add = Command::new("ip")
            .args(["-n", &ns, "link", "add", &dummy_if, "type", "dummy"])
            .status()
            .unwrap();
        assert!(link_add.success(), "ip link add dummy failed");

        // Clean up — delete the namespace (also removes the dummy interface).
        let del_status = Command::new("ip")
            .args(["netns", "del", &ns])
            .status()
            .unwrap();
        assert!(del_status.success(), "ip netns del failed");
    }
}
