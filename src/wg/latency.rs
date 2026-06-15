//! Tunnel health / latency (feature 5).
//!
//! WireGuard is connectionless, so the most reliable cheap health signal is the
//! age of the most recent handshake: a healthy tunnel re-keys roughly every two
//! minutes, so a recent handshake means traffic is flowing. [`health_from_handshake`]
//! turns that age into a coarse [`Health`] for display.
//!
//! The thresholds mirror WireGuard's own rekey/keepalive behaviour: handshakes
//! happen ~every 120s on active traffic, so under ~180s is `Good`, under ~300s is
//! `Stale` (the tunnel may be idle but not necessarily dead), and beyond that is
//! treated as `Down`. A `None` age (no peer has ever handshaked) is also `Down`.
//!
//! Everything load-bearing here is a pure function so it is fully unit-testable
//! with no root, network, or runtime. An optional async probe stub is provided
//! for a future active-latency refinement.

use crate::ui::theme::StatusKind;

/// Coarse tunnel-health classification for the dashboard / list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Recent handshake — traffic is flowing.
    Good,
    /// Handshake is aging — idle or borderline.
    Stale,
    /// No (recent) handshake — treat as down.
    Down,
}

/// Handshake age (seconds) under which the tunnel is considered [`Health::Good`].
pub const GOOD_THRESHOLD_SECS: u64 = 180;
/// Handshake age (seconds) under which the tunnel is considered [`Health::Stale`]
/// (between [`GOOD_THRESHOLD_SECS`] and this is `Stale`; beyond is `Down`).
pub const STALE_THRESHOLD_SECS: u64 = 300;

/// Classify tunnel health from the age (seconds) of the most recent handshake.
///
/// `None` (no handshake ever observed) → [`Health::Down`]. Otherwise:
///   - `< GOOD_THRESHOLD_SECS`  → [`Health::Good`]
///   - `< STALE_THRESHOLD_SECS` → [`Health::Stale`]
///   - else                     → [`Health::Down`]
///
/// Pure and side-effect-free.
pub fn health_from_handshake(last_handshake_age_secs: Option<u64>) -> Health {
    match last_handshake_age_secs {
        Some(age) if age < GOOD_THRESHOLD_SECS => Health::Good,
        Some(age) if age < STALE_THRESHOLD_SECS => Health::Stale,
        _ => Health::Down,
    }
}

impl Health {
    /// A short, human-readable label suitable for a status pill or tooltip.
    ///
    /// Callers MUST NOT key on the returned strings — use the [`Health`] variant
    /// directly for any logic.
    pub fn label(self) -> &'static str {
        match self {
            Health::Good => "Connected",
            Health::Stale => "Stale",
            Health::Down => "Down",
        }
    }

    /// Map this health value to the [`StatusKind`] that drives the theme's colour
    /// palette (green / amber / red).
    ///
    /// - [`Health::Good`]  → [`StatusKind::Connected`]  (green)
    /// - [`Health::Stale`] → [`StatusKind::Connecting`]  (amber)
    /// - [`Health::Down`]  → [`StatusKind::Error`]        (red)
    pub fn status_kind(self) -> StatusKind {
        match self {
            Health::Good => StatusKind::Connected,
            Health::Stale => StatusKind::Connecting,
            Health::Down => StatusKind::Error,
        }
    }
}

/// Optional active-latency probe (stub for a future refinement).
///
/// A real implementation would ICMP/UDP-ping the tunnel endpoint and return the
/// round-trip time in milliseconds. For now this is a non-privileged stub so the
/// signature is frozen; it never performs I/O.
pub async fn probe_latency_ms(_endpoint: &str) -> Option<u64> {
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (pure)
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── health_from_handshake threshold tests ─────────────────────────────────

    #[test]
    fn none_age_is_down() {
        assert_eq!(health_from_handshake(None), Health::Down);
    }

    #[test]
    fn age_zero_is_good() {
        assert_eq!(health_from_handshake(Some(0)), Health::Good);
    }

    #[test]
    fn mid_range_good_is_good() {
        assert_eq!(health_from_handshake(Some(30)), Health::Good);
        assert_eq!(health_from_handshake(Some(90)), Health::Good);
    }

    #[test]
    fn boundary_below_good_threshold_is_good() {
        // Last value strictly inside the Good range.
        assert_eq!(
            health_from_handshake(Some(GOOD_THRESHOLD_SECS - 1)),
            Health::Good,
        );
    }

    #[test]
    fn boundary_at_good_threshold_is_stale() {
        // GOOD_THRESHOLD_SECS itself is NOT Good (the range is [0, threshold)).
        assert_eq!(
            health_from_handshake(Some(GOOD_THRESHOLD_SECS)),
            Health::Stale,
        );
    }

    #[test]
    fn mid_range_stale_is_stale() {
        assert_eq!(health_from_handshake(Some(250)), Health::Stale);
    }

    #[test]
    fn boundary_below_stale_threshold_is_stale() {
        // Last value strictly inside the Stale range.
        assert_eq!(
            health_from_handshake(Some(STALE_THRESHOLD_SECS - 1)),
            Health::Stale,
        );
    }

    #[test]
    fn boundary_at_stale_threshold_is_down() {
        // STALE_THRESHOLD_SECS itself is NOT Stale (the range is [good, stale)).
        assert_eq!(
            health_from_handshake(Some(STALE_THRESHOLD_SECS)),
            Health::Down,
        );
    }

    #[test]
    fn large_age_is_down() {
        assert_eq!(health_from_handshake(Some(10_000)), Health::Down);
        assert_eq!(health_from_handshake(Some(u64::MAX)), Health::Down);
    }

    // ── threshold ordering is a compile-time invariant ─────────────────────────

    #[test]
    fn thresholds_are_ordered() {
        const {
            assert!(GOOD_THRESHOLD_SECS < STALE_THRESHOLD_SECS);
        }
    }

    // ── Health::label() ────────────────────────────────────────────────────────

    #[test]
    fn good_label_is_connected() {
        assert_eq!(Health::Good.label(), "Connected");
    }

    #[test]
    fn stale_label_is_stale() {
        assert_eq!(Health::Stale.label(), "Stale");
    }

    #[test]
    fn down_label_is_down() {
        assert_eq!(Health::Down.label(), "Down");
    }

    #[test]
    fn labels_are_non_empty() {
        for h in [Health::Good, Health::Stale, Health::Down] {
            assert!(!h.label().is_empty(), "{h:?} label must not be empty");
        }
    }

    // ── Health::status_kind() — StatusKind mapping ────────────────────────────

    #[test]
    fn good_maps_to_connected() {
        assert_eq!(Health::Good.status_kind(), StatusKind::Connected);
    }

    #[test]
    fn stale_maps_to_connecting() {
        assert_eq!(Health::Stale.status_kind(), StatusKind::Connecting);
    }

    #[test]
    fn down_maps_to_error() {
        assert_eq!(Health::Down.status_kind(), StatusKind::Error);
    }

    #[test]
    fn status_kind_never_idle_for_any_health_variant() {
        // None of the three health values should produce the "unknown/idle" grey —
        // that is reserved for the app-level "not connected to any tunnel" state,
        // not for handshake health.
        for h in [Health::Good, Health::Stale, Health::Down] {
            assert_ne!(
                h.status_kind(),
                StatusKind::Idle,
                "{h:?} must not map to Idle",
            );
        }
    }

    // ── round-trip consistency: health_from_handshake → label / status_kind ──

    #[test]
    fn none_gives_down_label_and_error_kind() {
        let h = health_from_handshake(None);
        assert_eq!(h.label(), "Down");
        assert_eq!(h.status_kind(), StatusKind::Error);
    }

    #[test]
    fn fresh_age_gives_connected_label_and_kind() {
        let h = health_from_handshake(Some(10));
        assert_eq!(h.label(), "Connected");
        assert_eq!(h.status_kind(), StatusKind::Connected);
    }

    #[test]
    fn stale_age_gives_stale_label_and_connecting_kind() {
        let h = health_from_handshake(Some(200));
        assert_eq!(h.label(), "Stale");
        assert_eq!(h.status_kind(), StatusKind::Connecting);
    }

    #[test]
    fn old_age_gives_down_label_and_error_kind() {
        let h = health_from_handshake(Some(9999));
        assert_eq!(h.label(), "Down");
        assert_eq!(h.status_kind(), StatusKind::Error);
    }
}
