//! Crate-wide error type. FULLY implemented (no stubs).
//!
//! Every variant carries a stable `Exxx` code in its `Display` string so logs/UI can be grepped
//! and matched against the original app's error codes.

/// All errors surfaced by the app, with stable codes.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AppError {
    // --- Profiles / config (E1xx) ---
    #[error("[E101] invalid profile name: {0}")]
    InvalidProfileName(String),

    #[error("[E102] profile not found: {0}")]
    ProfileNotFound(String),

    #[error("[E103] profile already exists: {0}")]
    ProfileExists(String),

    #[error("[E104] failed to parse profile '{name}': {detail}")]
    ProfileParseError { name: String, detail: String },

    #[error("[E105] validation error on field '{field}': {detail}")]
    ValidationError { field: String, detail: String },

    #[error("[E106] profile I/O error: {0}")]
    ProfileIo(String),

    // --- Tunnel / wg-quick (E2xx) ---
    #[error("[E201] wg-quick failed: {0}")]
    WgQuickFailed(String),

    #[error("[E202] wireguard tooling not found on PATH")]
    WgNotFound,

    #[error("[E203] permission denied (root/privilege required)")]
    PermissionDenied,

    #[error("[E204] tunnel already active: {0}")]
    TunnelAlreadyActive(String),

    #[error("[E205] no active tunnel")]
    NoActiveTunnel,

    #[error("[E206] failed to parse `wg show` output: {0}")]
    WgShowParseFailed(String),

    #[error("[E207] tunnel operation timed out")]
    TunnelTimeout,

    // --- Key generation (E3xx) ---
    #[error("[E301] key generation failed: {0}")]
    KeygenFailed(String),

    // --- Autostart (E4xx) ---
    #[error("[E401] failed to write autostart entry: {0}")]
    AutostartWriteFailed(String),

    // --- Single instance / IPC (E5xx) ---
    #[error("[E501] another instance is already running")]
    AlreadyRunning,

    #[error("[E502] IPC failed: {0}")]
    IpcFailed(String),

    // --- Settings (E6xx) ---
    #[error("[E601] failed to load settings: {0}")]
    SettingsLoadFailed(String),

    #[error("[E602] failed to save settings: {0}")]
    SettingsSaveFailed(String),

    // --- Public IP (E7xx) ---
    #[error("[E701] failed to fetch public IP: {0}")]
    PublicIpFetchFailed(String),

    // --- Import / export (E8xx) ---
    #[error("[E801] import failed: {0}")]
    ImportFailed(String),

    #[error("[E802] export failed: {0}")]
    ExportFailed(String),

    // --- Networking (E9xx) ---
    #[error("[E901] AllowedIPs error: {0}")]
    AllowedIpsError(String),

    #[error("[E902] network namespace operation failed: {0}")]
    NetnsFailed(String),
}

/// Convenience result alias used throughout the crate.
pub type AppResult<T> = Result<T, AppError>;
