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
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => {
                return args.next().ok_or_else(|| {
                    AppError::IpcFailed("--json requires a payload argument".into())
                });
            }
            "-" | "--stdin" => break,
            other => {
                return Err(AppError::IpcFailed(format!(
                    "unexpected argument: {other} (expected --json <payload> or --stdin)"
                )));
            }
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
        if fields.len() >= 4 {
            if let Ok(line_uid) = fields[2].parse::<u32>() {
                if line_uid == uid {
                    return Ok(fields[0].to_string());
                }
            }
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
    if let Err(e) = std::fs::remove_dir_all(&etc_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("helper: WARNING — could not remove {etc_path}: {e}");
        }
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
