//! Data-usage tracking (feature 2).
//!
//! WireGuard reports *cumulative* rx/tx byte counters per interface (summed
//! across peers). Those counters reset to zero whenever the interface is torn
//! down and re-created, so to show meaningful "this session" and "all time"
//! figures we have to:
//!   - track the last cumulative reading we saw,
//!   - compute the per-tick delta, treating a *decrease* as a counter reset
//!     (the interface bounced) rather than negative traffic, and
//!   - accumulate those deltas into a persisted lifetime total.
//!
//! [`DataUsage`] is the per-profile record; [`UsageStore`] is the persisted map
//! of them, saved as `stats.json` in the config dir. Everything here is pure +
//! synchronous (the reducer drives it on each status tick); no privileged code,
//! no network.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

// ─────────────────────────────────────────────────────────────────────────────
// human_bytes helper
// ─────────────────────────────────────────────────────────────────────────────

/// Format a raw byte count as a compact human-readable string using
/// IEC binary prefixes (KiB, MiB, GiB, TiB).
///
/// # Examples
///
/// ```
/// # use wireguard_gui::stats::human_bytes;
/// assert_eq!(human_bytes(0),               "0 B");
/// assert_eq!(human_bytes(1023),            "1023 B");
/// assert_eq!(human_bytes(1024),            "1.00 KiB");
/// assert_eq!(human_bytes(1536),            "1.50 KiB");
/// assert_eq!(human_bytes(1_048_576),       "1.00 MiB");
/// assert_eq!(human_bytes(1_073_741_824),   "1.00 GiB");
/// ```
pub fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1_024;
    const MIB: u64 = 1_024 * KIB;
    const GIB: u64 = 1_024 * MIB;
    const TIB: u64 = 1_024 * GIB;

    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else if bytes < GIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes < TIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{:.2} TiB", bytes as f64 / TIB as f64)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DataUsage
// ─────────────────────────────────────────────────────────────────────────────

/// Per-profile data-usage accounting.
///
/// `session_*` reset to zero when a fresh session begins (see
/// [`UsageStore::record`] reset handling); `total_*` accumulate across the whole
/// lifetime of the profile and survive restarts via [`UsageStore`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataUsage {
    /// The profile these figures belong to.
    pub profile: String,
    /// Bytes received this session (since the current interface came up).
    pub session_rx: u64,
    /// Bytes sent this session.
    pub session_tx: u64,
    /// Lifetime bytes received across all sessions for this profile.
    pub total_rx: u64,
    /// Lifetime bytes sent across all sessions for this profile.
    pub total_tx: u64,
}

impl DataUsage {
    /// A zeroed record for `profile`.
    pub fn new(profile: impl Into<String>) -> Self {
        DataUsage {
            profile: profile.into(),
            ..Default::default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UsageStore
// ─────────────────────────────────────────────────────────────────────────────

/// The persisted set of per-profile [`DataUsage`] records, plus the last
/// cumulative counter reading per profile (used to compute deltas).
///
/// Serialized to `stats.json`. The `last_seen` map is persisted too so a delta
/// computed across a restart is still correct (a fresh process would otherwise
/// treat the first reading as a full session's traffic).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageStore {
    /// Per-profile usage records, keyed by profile name.
    pub usage: HashMap<String, DataUsage>,
    /// Last cumulative `(rx, tx)` reading seen per profile, keyed by profile
    /// name. Used to compute the per-tick delta and detect counter resets.
    pub last_seen: HashMap<String, (u64, u64)>,
}

/// Path to the usage file: `~/.config/wireguard-gui-rust/stats.json`.
fn stats_path() -> Option<PathBuf> {
    dirs::config_dir().map(|base| base.join("wireguard-gui-rust").join("stats.json"))
}

/// Atomically write `contents` to `path` (same-directory temp → rename) and set
/// file permissions to 0o600 (owner read/write only).
///
/// The write is atomic on Linux because rename(2) within the same filesystem is
/// guaranteed atomic by POSIX, so a concurrent reader never sees a partial file.
fn atomic_write_0600(path: &Path, contents: &str) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = path.parent().ok_or_else(|| {
        AppError::SettingsSaveFailed(format!(
            "no parent directory for {}",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(dir).map_err(|e| {
        AppError::SettingsSaveFailed(format!("create dir {}: {}", dir.display(), e))
    })?;

    // Write to a sibling temp file so the rename is on the same filesystem.
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, contents)
        .map_err(|e| AppError::SettingsSaveFailed(format!("{}: {}", tmp_path.display(), e)))?;

    // Set permissions before making the file visible at the final path.
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        AppError::SettingsSaveFailed(format!("chmod {}: {}", tmp_path.display(), e))
    })?;

    std::fs::rename(&tmp_path, path)
        .map_err(|e| AppError::SettingsSaveFailed(format!("rename to {}: {}", path.display(), e)))
}

impl UsageStore {
    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    /// Load the usage store from disk, falling back to an empty default if the
    /// file does not yet exist.
    ///
    /// Returns an error for any I/O problem other than "file not found", or if
    /// the JSON is malformed.
    pub fn load() -> AppResult<Self> {
        let path = stats_path().ok_or_else(|| {
            AppError::SettingsLoadFailed("cannot determine config directory".to_string())
        })?;
        Self::load_from(&path)
    }

    /// Load from an explicit path (used internally and in tests).
    pub(crate) fn load_from(path: &Path) -> AppResult<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).map_err(|e| {
                AppError::SettingsLoadFailed(format!("{}: {}", path.display(), e))
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(UsageStore::default()),
            Err(e) => Err(AppError::SettingsLoadFailed(format!(
                "{}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Persist the usage store to disk (pretty-printed JSON, atomic, 0600).
    pub fn save(&self) -> AppResult<()> {
        let path = stats_path().ok_or_else(|| {
            AppError::SettingsSaveFailed("cannot determine config directory".to_string())
        })?;
        self.save_to(&path)
    }

    /// Save to an explicit path (used internally and in tests).
    pub(crate) fn save_to(&self, path: &Path) -> AppResult<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| AppError::SettingsSaveFailed(format!("serialize: {e}")))?;
        atomic_write_0600(path, &json)
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    /// Read-only accessor for a profile's current usage record, if any.
    pub fn get(&self, profile: &str) -> Option<&DataUsage> {
        self.usage.get(profile)
    }

    // -------------------------------------------------------------------------
    // Core accounting
    // -------------------------------------------------------------------------

    /// Record a fresh cumulative `(rx, tx)` reading for `profile`, computing the
    /// session delta against the previous reading and accumulating the lifetime
    /// totals. Returns the updated [`DataUsage`] for `profile`.
    ///
    /// # First sample
    ///
    /// When this is the first reading ever seen for `profile` (no `last_seen`
    /// entry), the cumulative value IS the baseline; the session starts from zero
    /// and the delta added to the lifetime total is also zero. The next sample
    /// will compute a real delta against this baseline.
    ///
    /// # Normal sample
    ///
    /// `delta = max(0, cumulative - prev)` (the `max(0, …)` is handled by the
    /// counter-reset branch below). The delta is added to both `session_*` and
    /// `total_*`.
    ///
    /// # Counter reset
    ///
    /// WireGuard's counters reset to 0 when the interface bounces. If the new
    /// cumulative reading for **either** direction is strictly less than the last
    /// one we recorded, we treat it as a session boundary:
    ///   - the `session_*` counters restart from zero,
    ///   - the new cumulative value becomes the new baseline,
    ///   - the new cumulative value is **not** added to `total_*` (we cannot
    ///     reliably distinguish "the interface just came up and only transferred
    ///     these bytes" from "the counter wrapped"). The lifetime total only grows
    ///     from deltas between consecutive non-resetting readings.
    pub fn record(&mut self, profile: &str, cumulative_rx: u64, cumulative_tx: u64) -> DataUsage {
        let (delta_rx, delta_tx, reset) = match self.last_seen.get(profile).copied() {
            None => {
                // First sample: store as baseline, no traffic counted yet.
                (0u64, 0u64, true)
            }
            Some((last_rx, last_tx)) => {
                if cumulative_rx < last_rx || cumulative_tx < last_tx {
                    // Counter regression: interface bounced. Start a fresh session;
                    // don't add anything to the lifetime total for this tick.
                    (0u64, 0u64, true)
                } else {
                    (
                        cumulative_rx.saturating_sub(last_rx),
                        cumulative_tx.saturating_sub(last_tx),
                        false,
                    )
                }
            }
        };

        let entry = self
            .usage
            .entry(profile.to_string())
            .or_insert_with(|| DataUsage::new(profile));

        if reset {
            // A fresh session: session counters go back to zero.
            entry.session_rx = 0;
            entry.session_tx = 0;
        } else {
            entry.session_rx = entry.session_rx.saturating_add(delta_rx);
            entry.session_tx = entry.session_tx.saturating_add(delta_tx);
        }
        // Lifetime totals only grow by real (non-reset) deltas.
        entry.total_rx = entry.total_rx.saturating_add(delta_rx);
        entry.total_tx = entry.total_tx.saturating_add(delta_tx);

        // Always update the last-seen baseline.
        self.last_seen
            .insert(profile.to_string(), (cumulative_rx, cumulative_tx));
        entry.clone()
    }

    /// Reset only the *session* counters for `profile` (call this when a new
    /// connect begins so the session figures start from zero). Lifetime totals are
    /// untouched; the last-seen baseline is cleared so the next `record` call
    /// starts a clean session.
    pub fn reset_session(&mut self, profile: &str) {
        if let Some(entry) = self.usage.get_mut(profile) {
            entry.session_rx = 0;
            entry.session_tx = 0;
        }
        self.last_seen.remove(profile);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // human_bytes
    // -------------------------------------------------------------------------

    #[test]
    fn human_bytes_zero() {
        assert_eq!(human_bytes(0), "0 B");
    }

    #[test]
    fn human_bytes_just_below_kib() {
        assert_eq!(human_bytes(1023), "1023 B");
    }

    #[test]
    fn human_bytes_exactly_kib() {
        assert_eq!(human_bytes(1024), "1.00 KiB");
    }

    #[test]
    fn human_bytes_fractional_kib() {
        assert_eq!(human_bytes(1536), "1.50 KiB");
    }

    #[test]
    fn human_bytes_exactly_mib() {
        assert_eq!(human_bytes(1_048_576), "1.00 MiB");
    }

    #[test]
    fn human_bytes_exactly_gib() {
        assert_eq!(human_bytes(1_073_741_824), "1.00 GiB");
    }

    #[test]
    fn human_bytes_exactly_tib() {
        assert_eq!(human_bytes(1_099_511_627_776), "1.00 TiB");
    }

    #[test]
    fn human_bytes_large_value() {
        // 2.5 GiB
        assert_eq!(human_bytes(2_684_354_560), "2.50 GiB");
    }

    // -------------------------------------------------------------------------
    // record(): first sample seeds baseline with zero traffic
    // -------------------------------------------------------------------------

    #[test]
    fn first_reading_is_baseline_no_traffic_counted() {
        let mut store = UsageStore::default();
        // First sample: establishes the baseline.
        let u = store.record("home", 100, 200);
        // Session and total should be zero — we don't know how long the
        // interface has been up, so we treat the first sample as baseline only.
        assert_eq!(u.session_rx, 0);
        assert_eq!(u.session_tx, 0);
        assert_eq!(u.total_rx, 0);
        assert_eq!(u.total_tx, 0);
        // The baseline is stored.
        assert_eq!(store.last_seen["home"], (100, 200));
    }

    // -------------------------------------------------------------------------
    // record(): subsequent samples accumulate deltas
    // -------------------------------------------------------------------------

    #[test]
    fn second_reading_accumulates_delta() {
        let mut store = UsageStore::default();
        store.record("home", 100, 200); // baseline
        let u = store.record("home", 150, 260); // delta = 50 rx, 60 tx
        assert_eq!(u.session_rx, 50);
        assert_eq!(u.session_tx, 60);
        assert_eq!(u.total_rx, 50);
        assert_eq!(u.total_tx, 60);
    }

    #[test]
    fn three_monotonic_readings_accumulate_correctly() {
        let mut store = UsageStore::default();
        store.record("home", 1000, 2000);
        store.record("home", 1100, 2100); // delta 100/100
        let u = store.record("home", 1250, 2300); // delta 150/200
        assert_eq!(u.session_rx, 250);
        assert_eq!(u.session_tx, 300);
        assert_eq!(u.total_rx, 250);
        assert_eq!(u.total_tx, 300);
    }

    #[test]
    fn zero_delta_reading_leaves_totals_unchanged() {
        let mut store = UsageStore::default();
        store.record("home", 500, 1000);
        let u1 = store.record("home", 600, 1100);
        let u2 = store.record("home", 600, 1100); // same value again
        assert_eq!(u1.total_rx, u2.total_rx);
        assert_eq!(u1.total_tx, u2.total_tx);
    }

    // -------------------------------------------------------------------------
    // record(): counter reset (regression)
    // -------------------------------------------------------------------------

    #[test]
    fn counter_reset_on_rx_regression_resets_session_and_baseline() {
        let mut store = UsageStore::default();
        store.record("home", 100, 200); // baseline
        store.record("home", 150, 260); // delta 50/60 → total 50/60

        // rx drops — interface bounced.
        let u = store.record("home", 10, 400);
        // Session resets to zero (fresh session started).
        assert_eq!(u.session_rx, 0);
        assert_eq!(u.session_tx, 0);
        // Lifetime totals did NOT grow on the reset tick.
        assert_eq!(u.total_rx, 50);
        assert_eq!(u.total_tx, 60);
        // New baseline stored.
        assert_eq!(store.last_seen["home"], (10, 400));
    }

    #[test]
    fn counter_reset_on_tx_regression_resets_session_and_baseline() {
        let mut store = UsageStore::default();
        store.record("work", 0, 0);
        store.record("work", 200, 300); // delta 200/300

        // tx drops while rx is fine.
        let u = store.record("work", 250, 10);
        assert_eq!(u.session_rx, 0);
        assert_eq!(u.session_tx, 0);
        assert_eq!(u.total_rx, 200);
        assert_eq!(u.total_tx, 300);
    }

    #[test]
    fn traffic_after_counter_reset_accumulates_in_new_session() {
        let mut store = UsageStore::default();
        store.record("home", 500, 1000);
        store.record("home", 600, 1100); // delta 100/100 → total 100/100

        // Interface bounced.
        store.record("home", 0, 0); // reset; total stays 100/100

        // New session accumulates from the new baseline.
        let u = store.record("home", 50, 80);
        assert_eq!(u.session_rx, 50);
        assert_eq!(u.session_tx, 80);
        assert_eq!(u.total_rx, 150);
        assert_eq!(u.total_tx, 180);
    }

    // -------------------------------------------------------------------------
    // Per-profile isolation
    // -------------------------------------------------------------------------

    #[test]
    fn per_profile_isolation() {
        let mut store = UsageStore::default();
        store.record("home", 0, 0);
        store.record("home", 100, 100);
        store.record("work", 0, 0);
        store.record("work", 5, 5);
        assert_eq!(store.get("home").unwrap().total_rx, 100);
        assert_eq!(store.get("work").unwrap().total_rx, 5);
    }

    // -------------------------------------------------------------------------
    // reset_session
    // -------------------------------------------------------------------------

    #[test]
    fn reset_session_zeroes_session_keeps_total() {
        let mut store = UsageStore::default();
        store.record("home", 0, 0);
        store.record("home", 100, 200); // total 100/200, session 100/200
        store.reset_session("home");
        let u = store.get("home").unwrap().clone();
        assert_eq!(u.session_rx, 0);
        assert_eq!(u.session_tx, 0);
        assert_eq!(u.total_rx, 100);
        assert_eq!(u.total_tx, 200);
        // last_seen cleared → next record is a fresh baseline.
        assert!(!store.last_seen.contains_key("home"));
    }

    #[test]
    fn reset_session_followed_by_record_starts_clean_session() {
        let mut store = UsageStore::default();
        store.record("home", 0, 0);
        store.record("home", 150, 260);
        store.reset_session("home");

        // Next record: baseline, no traffic counted yet.
        let u1 = store.record("home", 200, 320);
        assert_eq!(u1.session_rx, 0);
        assert_eq!(u1.session_tx, 0);

        // Second record after reset: accumulates delta from new baseline.
        let u2 = store.record("home", 280, 400);
        assert_eq!(u2.session_rx, 80);
        assert_eq!(u2.session_tx, 80);
        // Lifetime total: previous (150/260) + new delta (80/80).
        assert_eq!(u2.total_rx, 230);
        assert_eq!(u2.total_tx, 340);
    }

    #[test]
    fn reset_session_on_unknown_profile_is_noop() {
        let mut store = UsageStore::default();
        store.reset_session("does-not-exist"); // must not panic
        assert!(store.usage.is_empty());
    }

    // -------------------------------------------------------------------------
    // In-memory serde round-trip
    // -------------------------------------------------------------------------

    #[test]
    fn round_trip_serde() {
        let mut store = UsageStore::default();
        store.record("home", 0, 0);
        store.record("home", 100, 200);
        let json = serde_json::to_string_pretty(&store).expect("serialize");
        let restored: UsageStore = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.get("home"), store.get("home"));
        assert_eq!(restored.last_seen.get("home").copied(), Some((100, 200)));
    }

    // -------------------------------------------------------------------------
    // Persistence round-trip in a tempdir (load_from / save_to)
    // -------------------------------------------------------------------------

    #[test]
    fn load_from_missing_file_returns_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stats.json");
        let store = UsageStore::load_from(&path).expect("load_from should succeed on missing file");
        assert!(store.usage.is_empty());
        assert!(store.last_seen.is_empty());
    }

    #[test]
    fn save_to_and_load_from_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stats.json");

        let mut store = UsageStore::default();
        store.record("home", 0, 0);
        store.record("home", 1024, 2048);
        store.record("work", 0, 0);
        store.record("work", 512, 256);

        store.save_to(&path).expect("save_to");

        let restored = UsageStore::load_from(&path).expect("load_from");
        assert_eq!(restored.get("home"), store.get("home"));
        assert_eq!(restored.get("work"), store.get("work"));
        assert_eq!(
            restored.last_seen.get("home").copied(),
            Some((1024, 2048))
        );
        assert_eq!(restored.last_seen.get("work").copied(), Some((512, 256)));
    }

    #[test]
    fn save_to_creates_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Nested subdir that doesn't exist yet.
        let path = dir.path().join("nested").join("subdir").join("stats.json");
        let store = UsageStore::default();
        store.save_to(&path).expect("save_to should create parent dirs");
        assert!(path.exists());
    }

    #[test]
    fn save_to_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stats.json");
        let store = UsageStore::default();
        store.save_to(&path).expect("save_to");

        let meta = std::fs::metadata(&path).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:04o}");
    }

    #[test]
    fn save_to_is_atomic_produces_valid_json() {
        // Save, then load — verifies the written content parses cleanly.
        // (True atomicity requires OS-level inspection; we verify the file
        // is never left in a partially-written state visible to load_from.)
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stats.json");

        let mut store = UsageStore::default();
        store.record("vpn", 0, 0);
        store.record("vpn", 999_999, 888_888);
        store.save_to(&path).expect("save_to");

        // No temp file should remain after a successful save.
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "temp file should have been renamed away");

        let restored = UsageStore::load_from(&path).expect("load_from");
        assert_eq!(
            restored.get("vpn").map(|u| u.total_rx),
            Some(999_999)
        );
    }

    #[test]
    fn save_to_overwrites_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stats.json");

        let mut store1 = UsageStore::default();
        store1.record("home", 0, 0);
        store1.record("home", 100, 200);
        store1.save_to(&path).expect("first save");

        let mut store2 = UsageStore::default();
        store2.record("home", 0, 0);
        store2.record("home", 9999, 8888);
        store2.save_to(&path).expect("second save");

        let restored = UsageStore::load_from(&path).expect("load_from");
        assert_eq!(restored.get("home").map(|u| u.total_rx), Some(9999));
    }

    #[test]
    fn load_from_invalid_json_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stats.json");
        std::fs::write(&path, b"{ not valid json }").expect("write");
        let result = UsageStore::load_from(&path);
        assert!(result.is_err());
    }
}
