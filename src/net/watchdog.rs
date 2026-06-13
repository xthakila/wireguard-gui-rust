//! Auto-reconnect watchdog — pure reconnect-decision logic.
//!
//! This module is **intentionally I/O-free**. It provides two pure functions that the caller
//! (a polling task) feeds with already-measured observations:
//!
//! - [`should_reconnect`] — decide whether a reconnect attempt is warranted.
//! - [`next_backoff`] — return the exponential back-off delay for a given retry attempt.
//!
//! ## Reconnect policy
//!
//! A tunnel is considered dropped when ANY of the following hold:
//! - The WireGuard interface no longer exists on the host (`iface_present == false`).
//! - The time since the most recent confirmed handshake exceeds `threshold_secs` (design
//!   default 150 s; callers may override for testing or user-tuning).
//! - There has been **no** handshake at all (`last_handshake_age_secs == None`) and the
//!   interface is present — the peer has never replied, which is also a failure.
//!
//! Reconnect is suppressed entirely when `intentional_down` is set; this flag is raised by
//! the GUI when the user explicitly requests a disconnect so the watchdog does not fight them.
//!
//! ## Back-off schedule
//!
//! Attempt 0 → 2 s, attempt 1 → 4 s, attempt 2 → 8 s, … doubling each time, hard-capped at
//! 60 s.  The sequence is: 2, 4, 8, 16, 32, 60, 60, 60, …
//!
//! ## Integration sketch (not part of this module)
//!
//! ```text
//! loop {
//!     sleep(poll_interval).await;
//!     if intentional_down { continue; }
//!     let age   = wg_show_latest_handshake(&iface).await.ok();
//!     let present = iface_exists(&iface).await;
//!     if should_reconnect(age, present, intentional_down, THRESHOLD_SECS) {
//!         sleep(next_backoff(attempt)).await;
//!         backend.connect(...).await?;
//!         attempt += 1;
//!     } else {
//!         attempt = 0; // fresh handshake observed — reset
//!     }
//! }
//! ```

use std::time::Duration;

/// The design-specified default handshake-age threshold above which a tunnel is considered
/// dropped.  Callers may pass a different value (e.g. in tests or if the user configures it).
pub const DEFAULT_THRESHOLD_SECS: u64 = 150;

/// The initial back-off delay (first retry).
const BACKOFF_BASE_SECS: u64 = 2;

/// The maximum back-off delay (subsequent retries after saturation).
const BACKOFF_CAP_SECS: u64 = 60;

/// Decide whether a reconnect attempt is warranted.
///
/// # Arguments
///
/// | Parameter               | Meaning                                                          |
/// |-------------------------|------------------------------------------------------------------|
/// | `last_handshake_age_secs` | Seconds since the last confirmed WireGuard handshake, or `None` if the interface is present but has never exchanged a handshake. |
/// | `iface_present`         | Whether the WireGuard interface currently exists on the host.    |
/// | `intentional_down`      | Set by the GUI when the user explicitly disconnected. Suppresses all reconnect attempts. |
/// | `threshold_secs`        | Age (in seconds) above which a handshake is considered stale.   |
///
/// # Returns
///
/// `true` when a reconnect should be initiated; `false` otherwise.
///
/// # Decision table
///
/// | `intentional_down` | `iface_present` | `last_handshake_age_secs` | result  |
/// |--------------------|-----------------|---------------------------|---------|
/// | `true`             | any             | any                       | `false` |
/// | `false`            | `false`         | any                       | `true`  |
/// | `false`            | `true`          | `None`                    | `true`  |
/// | `false`            | `true`          | `Some(age >= threshold)`  | `true`  |
/// | `false`            | `true`          | `Some(age < threshold)`   | `false` |
#[inline]
pub fn should_reconnect(
    last_handshake_age_secs: Option<u64>,
    iface_present: bool,
    intentional_down: bool,
    threshold_secs: u64,
) -> bool {
    // User initiated the disconnect — respect the intent unconditionally.
    if intentional_down {
        return false;
    }

    // Interface vanished from the kernel — definitely dropped.
    if !iface_present {
        return true;
    }

    // Interface exists but we have no handshake data at all, or the last confirmed handshake
    // was too long ago — reconnect.
    match last_handshake_age_secs {
        None => true,
        Some(age) => age >= threshold_secs,
    }
}

/// Return the back-off [`Duration`] to wait before the `attempt`-th reconnect try.
///
/// Uses binary exponential back-off starting at 2 s, doubling each attempt, hard-capped at
/// 60 s.  `attempt` is zero-indexed (0 = first retry).
///
/// | `attempt` | delay |
/// |-----------|-------|
/// | 0         | 2 s   |
/// | 1         | 4 s   |
/// | 2         | 8 s   |
/// | 3         | 16 s  |
/// | 4         | 32 s  |
/// | 5+        | 60 s  |
#[inline]
pub fn next_backoff(attempt: u32) -> Duration {
    // Clamp the shift count to avoid undefined behaviour for large attempts:
    // once the shift would exceed the cap anyway (attempt >= 6 gives 2<<6=128>60),
    // we cap immediately.  checked_shl returns None when attempt >= 64, so we
    // treat that as "already saturated" and return the cap directly.
    let secs = BACKOFF_BASE_SECS
        .checked_shl(attempt)
        .unwrap_or(u64::MAX)
        .min(BACKOFF_CAP_SECS);
    Duration::from_secs(secs)
}

// ---------------------------------------------------------------------------
// Unit tests — pure, no I/O, no root, no network. Always run in CI.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // should_reconnect — intentional_down suppression
    // -----------------------------------------------------------------------

    #[test]
    fn intentional_down_suppresses_even_when_iface_missing() {
        // User disconnected → never reconnect, regardless of interface state.
        assert!(!should_reconnect(None, false, true, DEFAULT_THRESHOLD_SECS));
    }

    #[test]
    fn intentional_down_suppresses_stale_handshake() {
        assert!(!should_reconnect(Some(9999), true, true, DEFAULT_THRESHOLD_SECS));
    }

    #[test]
    fn intentional_down_suppresses_fresh_handshake_too() {
        // Sanity: intentional_down + fresh handshake is still suppressed.
        assert!(!should_reconnect(Some(0), true, true, DEFAULT_THRESHOLD_SECS));
    }

    // -----------------------------------------------------------------------
    // should_reconnect — interface missing
    // -----------------------------------------------------------------------

    #[test]
    fn missing_iface_triggers_reconnect() {
        // No handshake data and interface gone.
        assert!(should_reconnect(None, false, false, DEFAULT_THRESHOLD_SECS));
    }

    #[test]
    fn missing_iface_with_stale_handshake_triggers_reconnect() {
        assert!(should_reconnect(Some(999), false, false, DEFAULT_THRESHOLD_SECS));
    }

    #[test]
    fn missing_iface_with_fresh_handshake_still_triggers_reconnect() {
        // The age carried over from the last observation doesn't matter — interface is gone.
        assert!(should_reconnect(Some(1), false, false, DEFAULT_THRESHOLD_SECS));
    }

    // -----------------------------------------------------------------------
    // should_reconnect — interface present, no handshake yet
    // -----------------------------------------------------------------------

    #[test]
    fn no_handshake_ever_triggers_reconnect() {
        // Interface up but peer has never replied.
        assert!(should_reconnect(None, true, false, DEFAULT_THRESHOLD_SECS));
    }

    // -----------------------------------------------------------------------
    // should_reconnect — stale handshake (age >= threshold)
    // -----------------------------------------------------------------------

    #[test]
    fn stale_handshake_exactly_at_threshold_triggers_reconnect() {
        // Boundary: age == threshold is considered stale (>=).
        assert!(should_reconnect(
            Some(DEFAULT_THRESHOLD_SECS),
            true,
            false,
            DEFAULT_THRESHOLD_SECS
        ));
    }

    #[test]
    fn stale_handshake_above_threshold_triggers_reconnect() {
        assert!(should_reconnect(
            Some(DEFAULT_THRESHOLD_SECS + 1),
            true,
            false,
            DEFAULT_THRESHOLD_SECS
        ));
    }

    #[test]
    fn very_old_handshake_triggers_reconnect() {
        assert!(should_reconnect(Some(86400), true, false, DEFAULT_THRESHOLD_SECS));
    }

    // -----------------------------------------------------------------------
    // should_reconnect — fresh handshake (age < threshold)
    // -----------------------------------------------------------------------

    #[test]
    fn fresh_handshake_does_not_trigger_reconnect() {
        assert!(!should_reconnect(
            Some(DEFAULT_THRESHOLD_SECS - 1),
            true,
            false,
            DEFAULT_THRESHOLD_SECS
        ));
    }

    #[test]
    fn very_fresh_handshake_does_not_trigger_reconnect() {
        assert!(!should_reconnect(Some(0), true, false, DEFAULT_THRESHOLD_SECS));
    }

    #[test]
    fn handshake_at_one_second_does_not_trigger_reconnect() {
        assert!(!should_reconnect(Some(1), true, false, DEFAULT_THRESHOLD_SECS));
    }

    // -----------------------------------------------------------------------
    // should_reconnect — custom threshold
    // -----------------------------------------------------------------------

    #[test]
    fn custom_threshold_respected_low() {
        // Threshold = 30 s; age 29 → no reconnect.
        assert!(!should_reconnect(Some(29), true, false, 30));
    }

    #[test]
    fn custom_threshold_respected_at_boundary() {
        // Threshold = 30 s; age 30 → reconnect.
        assert!(should_reconnect(Some(30), true, false, 30));
    }

    #[test]
    fn custom_threshold_zero_always_reconnects() {
        // Threshold = 0 → any observed age (including 0) triggers reconnect.
        assert!(should_reconnect(Some(0), true, false, 0));
        assert!(should_reconnect(Some(1), true, false, 0));
    }

    #[test]
    fn custom_threshold_very_large_never_triggers_on_fresh_handshake() {
        // Threshold = u64::MAX; a fresh handshake should never reconnect.
        assert!(!should_reconnect(Some(1_000_000), true, false, u64::MAX));
    }

    // -----------------------------------------------------------------------
    // next_backoff — full schedule
    // -----------------------------------------------------------------------

    #[test]
    fn backoff_attempt_0_is_2s() {
        assert_eq!(next_backoff(0), Duration::from_secs(2));
    }

    #[test]
    fn backoff_attempt_1_is_4s() {
        assert_eq!(next_backoff(1), Duration::from_secs(4));
    }

    #[test]
    fn backoff_attempt_2_is_8s() {
        assert_eq!(next_backoff(2), Duration::from_secs(8));
    }

    #[test]
    fn backoff_attempt_3_is_16s() {
        assert_eq!(next_backoff(3), Duration::from_secs(16));
    }

    #[test]
    fn backoff_attempt_4_is_32s() {
        assert_eq!(next_backoff(4), Duration::from_secs(32));
    }

    #[test]
    fn backoff_attempt_5_hits_cap_60s() {
        // 2 << 5 = 64, which exceeds the 60 s cap → should saturate at 60.
        assert_eq!(next_backoff(5), Duration::from_secs(60));
    }

    #[test]
    fn backoff_attempt_6_stays_at_cap() {
        assert_eq!(next_backoff(6), Duration::from_secs(60));
    }

    #[test]
    fn backoff_large_attempt_stays_at_cap() {
        assert_eq!(next_backoff(100), Duration::from_secs(60));
    }

    #[test]
    fn backoff_max_u32_does_not_overflow() {
        // saturating_shl handles this gracefully; result must be exactly the cap.
        assert_eq!(next_backoff(u32::MAX), Duration::from_secs(BACKOFF_CAP_SECS));
    }

    #[test]
    fn backoff_schedule_is_monotone_until_cap() {
        // The sequence 2,4,8,16,32,60 must be strictly increasing up to the cap, then flat.
        let schedule: Vec<u64> =
            (0u32..=8).map(|a| next_backoff(a).as_secs()).collect();
        for window in schedule.windows(2) {
            assert!(
                window[1] >= window[0],
                "back-off is not monotone: {:?}",
                schedule
            );
        }
    }

    #[test]
    fn backoff_schedule_caps_at_60s() {
        for attempt in 5..=20 {
            assert_eq!(
                next_backoff(attempt),
                Duration::from_secs(60),
                "attempt {attempt} exceeded cap"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Interaction: intentional_down overrides everything (property-style sweep)
    // -----------------------------------------------------------------------

    #[test]
    fn intentional_down_overrides_all_combinations() {
        let ages: &[Option<u64>] = &[None, Some(0), Some(1), Some(150), Some(u64::MAX)];
        let presents = [true, false];
        for &age in ages {
            for &present in &presents {
                assert!(
                    !should_reconnect(age, present, true, DEFAULT_THRESHOLD_SECS),
                    "intentional_down=true should always return false \
                     (age={age:?}, present={present})"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Interaction: missing iface always reconnects unless intentional_down
    // -----------------------------------------------------------------------

    #[test]
    fn missing_iface_always_reconnects_when_not_intentional() {
        let ages: &[Option<u64>] = &[None, Some(0), Some(1), Some(150), Some(u64::MAX)];
        for &age in ages {
            assert!(
                should_reconnect(age, false, false, DEFAULT_THRESHOLD_SECS),
                "missing iface should always reconnect (age={age:?})"
            );
        }
    }
}
