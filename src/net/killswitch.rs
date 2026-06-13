//! Kill switch — block all non-tunnel traffic via nftables while a tunnel is up.
//!
//! Phase 3 feature. Stub only for now.

use crate::error::AppResult;

/// Arms/disarms the nftables-based kill switch.
pub struct KillSwitch;

impl KillSwitch {
    /// Install the blocking ruleset for interface `iface`.
    pub async fn arm(&self, iface: &str) -> AppResult<()> {
        let _ = iface;
        todo!()
    }

    /// Remove the blocking ruleset.
    pub async fn disarm(&self) -> AppResult<()> {
        todo!()
    }

    /// Render the nftables ruleset for `iface` (allowing only WireGuard + the tunnel).
    fn nft_ruleset(iface: &str) -> String {
        let _ = iface;
        todo!()
    }
}
