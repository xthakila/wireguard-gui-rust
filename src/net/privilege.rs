//! Privilege escalation — run the few operations that genuinely need root (wg-quick,
//! nftables, netns) via a privileged helper / pkexec.
//!
//! Phase 3 feature. Stub only for now.

use std::path::PathBuf;

use crate::error::AppResult;

/// A discrete privileged operation the helper is allowed to perform.
#[derive(Debug, Clone)]
pub enum PrivCmd {
    /// `wg-quick up <conf_path>`.
    WgQuickUp(PathBuf),
    /// `wg-quick down <iface>`.
    WgQuickDown(String),
    /// Install the kill-switch nftables ruleset for an interface.
    ArmKillSwitch(String),
    /// Remove the kill-switch ruleset.
    DisarmKillSwitch,
}

/// Execute a privileged command, escalating as needed.
pub async fn run_privileged(cmd: PrivCmd) -> AppResult<()> {
    let _ = cmd;
    todo!()
}
