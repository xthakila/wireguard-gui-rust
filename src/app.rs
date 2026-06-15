//! The real Iced application: frozen `State` + `Message` contract, the `update` reducer
//! wiring every message variant, and `view`/`subscription`/`theme` glue.
//!
//! The views themselves live in `crate::ui::*` (placeholder stubs in this CORE stage); this
//! module owns all state transitions and effect dispatch (`Task<Message>`).

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use iced::futures::SinkExt as _;
use iced::{window, Element, Subscription, Task, Theme};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::autostart::AutostartManager;
use crate::config::keygen;
use crate::config::profile::WgProfile;
use crate::config::store::ProfileStore;
use crate::error::AppError;
use crate::net::boot::{self, BootAction};
use crate::net::killswitch::KillSwitch;
use crate::net::privilege::run_privileged;
use crate::net::watchdog;
use crate::settings::{AppSettings, ThemePreference};
use crate::single_instance::{accept_raises, InstanceGuard};
use crate::stats::UsageStore;
use crate::tray::{AppTray, TrayCmd, TrayEvent};
use crate::wg::backend::detect_backend;
use crate::wg::latency::{health_from_handshake, Health};
use crate::wg::plan::{compute_plan, DryRunPlan};
use crate::wg::status::{fetch_status, LiveStatus};

// ─────────────────────────────────────────────────────────────────────────────
// Globals shared between `main` (which constructs the runtime resources) and the
// iced callbacks (`boot`/`subscription`/`update`), which take no extra arguments.
//
// The single-instance guard must outlive the process, so it is stashed here and
// never dropped. The tray handle is used from `update` to swap the icon at runtime.
// The two receivers are taken (once) by the subscription streams.
// ─────────────────────────────────────────────────────────────────────────────

/// Live tray handle (runtime icon updates).
pub static TRAY_HANDLE: OnceLock<ksni::blocking::Handle<AppTray>> = OnceLock::new();
/// Tray menu/activate event receiver (drained by the tray-event subscription).
pub static TRAY_EVENTS: OnceLock<Mutex<Option<UnboundedReceiver<TrayEvent>>>> = OnceLock::new();
/// The single-instance guard — held for the whole process lifetime so the socket stays bound.
pub static INSTANCE_GUARD: OnceLock<InstanceGuard> = OnceLock::new();
/// Channel the single-instance listener uses to forward "raise" requests into the subscription.
pub static RAISE_EVENTS: OnceLock<Mutex<Option<UnboundedReceiver<()>>>> = OnceLock::new();
/// The raw single-instance listener, parked here until `boot` spawns `accept_raises` on the
/// tokio runtime that iced sets up (we can't `tokio::spawn` from `main` before `.run()`).
pub static RAISE_LISTENER: OnceLock<Mutex<Option<std::os::unix::net::UnixListener>>> =
    OnceLock::new();

/// Stash the runtime resources created in `main` for the iced callbacks to reach later.
///
/// Called exactly once, BEFORE the iced builder runs (no tokio runtime required yet — the
/// listener is only *parked* here; the accepting task is spawned later from [`boot_runtime`]).
pub fn install_runtime(
    tray_handle: ksni::blocking::Handle<AppTray>,
    tray_events: UnboundedReceiver<TrayEvent>,
    instance_guard: InstanceGuard,
    raise_listener: std::os::unix::net::UnixListener,
) {
    let _ = TRAY_HANDLE.set(tray_handle);
    let _ = TRAY_EVENTS.set(Mutex::new(Some(tray_events)));
    let _ = INSTANCE_GUARD.set(instance_guard);
    let _ = RAISE_LISTENER.set(Mutex::new(Some(raise_listener)));
}

/// Spawn the single-instance accept loop on the live tokio runtime.
///
/// Idempotent: only the first call (with the parked listener present) does anything. Invoked
/// from `boot` (`State::new_with`), which runs inside iced's tokio runtime.
fn boot_runtime() {
    let listener = RAISE_LISTENER
        .get()
        .and_then(|m| m.lock().unwrap().take());
    if let Some(listener) = listener {
        let (tx, rx): (UnboundedSender<()>, UnboundedReceiver<()>) =
            tokio::sync::mpsc::unbounded_channel();
        let _ = RAISE_EVENTS.set(Mutex::new(Some(rx)));
        tokio::spawn(accept_raises(listener, tx));
    }
}

/// Swap the tray icon to reflect the connected/disconnected state.
fn update_tray_icon(connected: bool) {
    if let Some(handle) = TRAY_HANDLE.get() {
        handle.update(move |t: &mut AppTray| t.connected = connected);
    }
}

/// Push a [`TrayCmd`] into the live tray (profile list / connected-profile sync
/// for the quick-connect submenu). No-op when no tray handle is installed.
fn push_tray_cmd(cmd: TrayCmd) {
    if let Some(handle) = TRAY_HANDLE.get() {
        handle.update(move |t: &mut AppTray| t.apply(cmd.clone()));
    }
}

/// Dead-man lease (seconds) for the kill-switch arm. The root-side `systemd-run`
/// timer flushes the nftables table if the GUI dies without disarming. We arm with
/// a generous lease; renewal-on-tick is an owner-enabled refinement (each renewal
/// would re-trigger pkexec), so a single connect-time arm is the default behaviour.
const KILL_SWITCH_LEASE_SECS: u64 = 3600;

/// How many `(rx, tx)` throughput samples the dashboard sparkline retains. One
/// sample per status tick; sized to cover a useful recent window without
/// growing unbounded.
pub(crate) const THROUGHPUT_HISTORY_LEN: usize = 60;

// ─────────────────────────────────────────────────────────────────────────────
// Domain enums / structs (FROZEN — views depend on these shapes)
// ─────────────────────────────────────────────────────────────────────────────

/// The high-level tunnel connection status, shown in the status bar and tray.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelStatus {
    Disconnected,
    Connecting(String),
    Connected(String),
    Disconnecting,
    Error(String),
}

/// Which screen the main window is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    ProfileList,
    Editor,
    RawEditor,
    PlanPreview,
    Settings,
    Server,
}

/// Sort order for the profile list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    NameAsc,
    NameDesc,
}

/// Editing state for the structured / raw profile editor.
#[derive(Debug, Clone)]
pub struct EditorState {
    /// The name the profile is filed under (the original name when editing).
    pub profile_name: String,
    /// The profile being edited.
    pub draft: WgProfile,
    /// The raw `.conf` text mirror (kept in sync with `draft`).
    pub raw_text: String,
    /// Field/detail validation errors from `draft.validate()`.
    pub validation_errors: Vec<(String, String)>,
    /// True when this is a brand-new profile (vs editing an existing one).
    pub is_new: bool,
}

/// Severity of a transient banner notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerKind {
    Info,
    Success,
    Warning,
    Error,
}

/// A transient banner notification shown at the top of the window.
#[derive(Debug, Clone)]
pub struct Banner {
    pub kind: BannerKind,
    pub message: String,
}

/// A single field edit emitted by the editor view.
#[derive(Debug, Clone)]
pub enum EditorField {
    ProfileName(String),
    PrivateKey(String),
    Address(String),
    Dns(String),
    ListenPort(String),
    Mtu(String),
    PeerPublicKey(usize, String),
    PeerPresharedKey(usize, String),
    PeerEndpoint(usize, String),
    PeerAllowedIps(usize, String),
    PeerKeepalive(usize, String),
    AddPeer,
    RemovePeer(usize),
}

// ─────────────────────────────────────────────────────────────────────────────
// Application state (FROZEN)
// ─────────────────────────────────────────────────────────────────────────────

/// The whole application state.
///
/// Fields are `pub(crate)` so the per-screen view functions in `crate::ui::*`
/// can read them directly (the view layer is read-only over `State`; all
/// mutation goes through [`State::update`]).
pub struct State {
    /// The id of the main window (learned on `WindowOpened`).
    pub(crate) main_window: Option<window::Id>,
    /// On-disk profile store.
    pub(crate) profile_store: ProfileStore,
    /// All loaded profiles.
    pub(crate) profiles: Vec<WgProfile>,
    /// The profile currently active (connected / connecting), if any.
    pub(crate) active_profile: Option<String>,
    /// The high-level tunnel status.
    pub(crate) tunnel_status: TunnelStatus,
    /// Which screen is showing.
    pub(crate) screen: Screen,
    /// Profile-list search query.
    pub(crate) search_query: String,
    /// Profile-list sort order.
    pub(crate) sort_order: SortOrder,
    /// Editor state (Some while editing in the Editor / RawEditor screens).
    pub(crate) editor: Option<EditorState>,
    /// Latest live status snapshot.
    pub(crate) live_status: Option<LiveStatus>,
    /// Last-known public IP.
    pub(crate) public_ip: Option<String>,
    /// True while a public-IP fetch is in flight.
    pub(crate) public_ip_loading: bool,
    /// Persistent settings.
    pub(crate) settings: AppSettings,
    /// Transient banner notification.
    pub(crate) banner: Option<Banner>,
    /// Auto-reconnect toggle (mirrors `settings.auto_reconnect`, fast-path for the reducer).
    pub(crate) auto_reconnect: bool,
    /// The currently-previewed dry-run plan (Some on the PlanPreview screen).
    pub(crate) dry_run_plan: Option<DryRunPlan>,
    /// True when launched with `--hidden` (start to tray).
    pub(crate) start_hidden: bool,
    /// Set when the user explicitly disconnects so the auto-reconnect watchdog does
    /// not fight them. Cleared on a fresh (user-initiated) connect.
    pub(crate) intentional_down: bool,
    /// Zero-indexed auto-reconnect attempt counter, fed to [`watchdog::next_backoff`].
    /// Reset to 0 on a confirmed-fresh handshake or a user-initiated connect.
    pub(crate) reconnect_attempt: u32,
    /// Live `Content` for the raw `.conf` text editor.
    ///
    /// Held on the (non-`Clone`) top-level `State` — NOT on the `Clone`able
    /// `EditorState` — because `text_editor::Content` is neither `Clone` nor
    /// `Debug`. Mutated in place via `perform(action)` so the cursor/selection
    /// persist across frames (a fresh `Content::with_text` every frame would
    /// reset the cursor to 0 and break Backspace/Delete). Re-seeded from
    /// `editor.raw_text` whenever the raw editor becomes visible.
    pub(crate) raw_editor_content: iced::widget::text_editor::Content,

    // ── SERVER mode (FROZEN — the server view reads these) ────────────────────
    /// The loaded server config, if one has been created. `None` until the user
    /// creates a server (or a persisted `server.json` is loaded).
    pub(crate) server: Option<crate::server::ServerConfig>,
    /// True while the server interface (`wg-gui-srv0`) is up.
    pub(crate) server_running: bool,
    /// Latest per-peer status snapshot for the running server.
    pub(crate) server_peer_status: Vec<crate::wg::status::PeerStatus>,
    /// The in-progress "new client name" the server screen's text input holds.
    pub(crate) server_peer_name_input: String,
    /// The most recently generated client config to hand out, as
    /// `(peer_name, conf_text)`. Drives the QR / copy panel. `None` when nothing is
    /// pending display.
    pub(crate) last_client_conf: Option<(String, String)>,

    // ── DASHBOARD presentation state (read by the status screen) ──────────────
    /// When the current tunnel last became Connected. Set when a connect
    /// succeeds, cleared on disconnect / error. Drives the "connected for …"
    /// uptime readout. The `update()` reducer owns set/clear (wired in the
    /// integrate stage); construction leaves it `None`.
    pub(crate) connected_since: Option<std::time::Instant>,
    /// Rolling history of cumulative `(rx_bytes, tx_bytes)` samples (most recent
    /// last), capped at [`THROUGHPUT_HISTORY_LEN`]. Feeds the throughput
    /// sparkline. Push new samples with [`State::push_throughput_sample`]; the
    /// reducer calls it on each status tick (wired in the integrate stage).
    pub(crate) throughput_history: std::collections::VecDeque<(u64, u64)>,

    // ── Feature state (data usage + health) ───────────────────────────────────
    /// Persisted per-profile data-usage accounting (feature 2). Loaded at boot,
    /// updated on each status tick from the live cumulative byte counters, and
    /// saved back to `stats.json`. The list / dashboard views read it to show
    /// session + lifetime usage for the active profile.
    pub(crate) usage_store: UsageStore,
    /// Coarse health of the active tunnel (feature 5), recomputed on each status
    /// tick from the most-recent handshake age. `None` when no tunnel is up.
    pub(crate) active_health: Option<Health>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Messages (FROZEN — every variant is wired in `update`)
// ─────────────────────────────────────────────────────────────────────────────

/// Every event the application reacts to.
#[derive(Debug, Clone)]
pub enum Message {
    // ── boot / async loads ──────────────────────────────────────────────────
    ProfilesLoaded(Result<Vec<WgProfile>, AppError>),
    SettingsLoaded(Result<AppSettings, AppError>),

    // ── window / tray ─────────────────────────────────────────────────────────
    RaiseWindowRequested,
    TrayOpen,
    TrayQuit,
    WindowCloseRequested(window::Id),
    WindowOpened(window::Id),

    // ── profile list ──────────────────────────────────────────────────────────
    SearchChanged(String),
    SortChanged(SortOrder),
    SelectProfile(String),

    // ── connect / disconnect ────────────────────────────────────────────────
    ConnectProfile(String),
    DisconnectCurrent,
    ConnectResult(Result<(), AppError>),
    DisconnectResult(Result<(), AppError>),

    // ── kill switch (Phase 3) ─────────────────────────────────────────────────
    /// Result of an arm/disarm dispatch to the privileged helper. The bool records
    /// whether the op was an arm (`true`) or a disarm (`false`) for banner wording.
    KillSwitchResult { armed: bool, result: Result<(), AppError> },

    // ── auto-reconnect (Phase 3) ──────────────────────────────────────────────
    /// Fired (after a back-off delay) by the watchdog to retry a dropped tunnel.
    ReconnectTick(String),

    // ── delete ──────────────────────────────────────────────────────────────
    DeleteProfile(String),
    DeleteResult(Result<(), AppError>),

    // ── editor ──────────────────────────────────────────────────────────────
    OpenNewProfile,
    EditProfile(String),
    EditorFieldChanged(EditorField),
    EditorToggleRaw,
    /// A text-editor action (insert/delete/move/select/…) on the raw `.conf`
    /// editor. Applied to the persisted [`State::raw_editor_content`] so the
    /// cursor survives across frames, then the resulting text is mirrored back
    /// into `editor.raw_text` and re-parsed.
    RawEditorAction(iced::widget::text_editor::Action),
    EditorSave,
    EditorSaveResult(Result<WgProfile, AppError>),
    EditorCancel,
    GenerateKeypair,
    KeypairGenerated(Result<(String, String), AppError>),

    // ── import / export ───────────────────────────────────────────────────────
    ImportProfile,
    ImportFileChosen(Option<PathBuf>),
    ImportResult(Result<WgProfile, AppError>),
    ExportProfile(String),
    ExportFileChosen(Option<PathBuf>),
    ExportResult(Result<(), AppError>),

    // ── status polling ────────────────────────────────────────────────────────
    StatusTick,
    StatusFetched(Result<Option<LiveStatus>, AppError>),
    PublicIpFetched(Result<String, AppError>),

    // ── navigation ────────────────────────────────────────────────────────────
    OpenPlanPreview(String),
    OpenSettings,
    GoHome,

    // ── settings ──────────────────────────────────────────────────────────────
    SettingAutoReconnectToggled(bool),
    SettingAutoStartToggled(bool),
    SettingKillSwitchToggled(bool),
    /// Connect-on-boot toggled in Settings. The payload carries the profile to bind
    /// the boot unit to (or `None` to clear it). OFF by default; the privileged /
    /// nmcli boot command only runs in response to this explicit user action.
    SettingConnectOnBootChanged(Option<String>),
    /// Result of applying a connect-on-boot change (systemd-enable or nmcli autoconnect).
    BootConfigResult(Result<(), AppError>),
    SettingThemeChanged(ThemePreference),
    SettingsSaved(Result<(), AppError>),

    // ── server mode ─────────────────────────────────────────────────────────
    /// Navigate to the server screen.
    OpenServer,
    /// Result of lazily loading the persisted server config when the Server screen
    /// is first opened. `Ok(None)` means no server has been configured yet.
    ServerLoadResult(Result<Option<crate::server::ServerConfig>, AppError>),
    /// Create a brand-new server config for the given endpoint host (IP/DNS name).
    ServerCreate(String),
    /// Result of creating (or loading) a server config.
    ServerCreateResult(Result<crate::server::ServerConfig, AppError>),
    /// Toggle the server interface up/down.
    ServerStartToggle,
    /// Result of a server start/stop operation.
    ServerOpResult(Result<(), AppError>),
    /// Toggle NAT (masquerade + IP forwarding) for the server subnet on/off.
    ServerNatToggle(bool),
    /// Result of a NAT enable/disable dispatch. `enabled` records the requested
    /// direction for banner wording; this never alters `server_running`.
    ServerNatResult { enabled: bool, result: Result<(), AppError> },
    /// The "new client name" text input changed.
    ServerPeerNameChanged(String),
    /// Provision a new client peer (using `server_peer_name_input`).
    ServerAddPeer,
    /// Result of adding a peer: the updated config + the new peer's client conf text.
    ServerAddPeerResult(Result<crate::server::ServerConfig, AppError>),
    /// Remove the peer at the given index.
    ServerRemovePeer(usize),
    /// Result of removing a peer: the updated (and re-saved) config.
    ServerRemovePeerResult(Result<crate::server::ServerConfig, AppError>),
    /// Periodic tick to refresh the server's live peer status.
    ServerStatusTick,
    /// Result of a server peer-status refresh.
    ServerStatusResult(Result<Vec<crate::wg::status::PeerStatus>, AppError>),

    // ── misc ──────────────────────────────────────────────────────────────────
    DismissBanner,

    // ── new features ──────────────────────────────────────────────────────────
    /// Result of loading the persisted data-usage store at boot (feature 2).
    UsageLoaded(Result<UsageStore, AppError>),
    /// Toggle desktop notifications on/off in Settings (feature 1).
    SettingNotificationsToggled(bool),
    /// Tray quick-connect: connect to the named profile (feature 3, forwarded
    /// from the tray bridge). Connect logic is the same as [`Message::ConnectProfile`];
    /// kept as a distinct variant so the bridge can map `TrayEvent::ConnectProfile`.
    TrayConnectProfile(String),
    /// Tray quick-connect: disconnect the current tunnel (feature 3, forwarded
    /// from the tray bridge).
    TrayDisconnect,
    /// Import a profile from a QR-code image (feature 4): triggers an rfd image pick.
    ImportFromQr,
    /// The QR image the user picked (or `None` if the dialog was cancelled).
    ImportFromQrChosen(Option<PathBuf>),
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

impl State {
    /// Build the initial state and the boot task (load profiles + settings).
    pub fn new() -> (State, Task<Message>) {
        Self::new_with(false)
    }

    /// Build the initial state, honouring the `--hidden` flag.
    pub fn new_with(start_hidden: bool) -> (State, Task<Message>) {
        // We're now inside iced's tokio runtime — spawn the single-instance accept loop.
        boot_runtime();

        // Opening the store is sync + cheap; fall back to a directory-less placeholder on error
        // so the app can still surface the error via the banner (the boot load will report it).
        let profile_store = ProfileStore::new()
            .unwrap_or_else(|_| ProfileStore { dir: PathBuf::from(".") });

        let state = State {
            main_window: None,
            profile_store: profile_store.clone(),
            profiles: Vec::new(),
            active_profile: None,
            tunnel_status: TunnelStatus::Disconnected,
            screen: Screen::ProfileList,
            search_query: String::new(),
            sort_order: SortOrder::NameAsc,
            editor: None,
            live_status: None,
            public_ip: None,
            public_ip_loading: false,
            settings: AppSettings::default(),
            banner: None,
            auto_reconnect: true,
            dry_run_plan: None,
            start_hidden,
            intentional_down: false,
            reconnect_attempt: 0,
            raw_editor_content: iced::widget::text_editor::Content::new(),
            server: None,
            server_running: false,
            server_peer_status: Vec::new(),
            server_peer_name_input: String::new(),
            last_client_conf: None,
            connected_since: None,
            throughput_history: std::collections::VecDeque::with_capacity(
                THROUGHPUT_HISTORY_LEN,
            ),
            usage_store: UsageStore::default(),
            active_health: None,
        };

        // Load all profiles (list names → read each), settings, and the usage
        // store concurrently.
        let load_profiles = Task::perform(load_all_profiles(profile_store), Message::ProfilesLoaded);
        let load_settings = Task::perform(load_settings_async(), Message::SettingsLoaded);
        let load_usage = Task::perform(load_usage_async(), Message::UsageLoaded);

        (state, Task::batch([load_profiles, load_settings, load_usage]))
    }

    /// Read-only accessor for the start-hidden flag (used by `main` window setup).
    pub fn start_hidden(&self) -> bool {
        self.start_hidden
    }

    /// Record a cumulative `(rx_bytes, tx_bytes)` throughput sample for the
    /// dashboard sparkline, evicting the oldest once the history exceeds
    /// [`THROUGHPUT_HISTORY_LEN`].
    ///
    /// Pure state mutation — no side effects. The reducer calls this from the
    /// status-tick handler (wired in the integrate stage); it is exercised
    /// directly by unit tests here.
    pub(crate) fn push_throughput_sample(&mut self, rx: u64, tx: u64) {
        self.throughput_history.push_back((rx, tx));
        while self.throughput_history.len() > THROUGHPUT_HISTORY_LEN {
            self.throughput_history.pop_front();
        }
    }
}

/// Load every profile from the store (list + read), returning them sorted by name.
async fn load_all_profiles(store: ProfileStore) -> Result<Vec<WgProfile>, AppError> {
    let names = store.list_profiles().await?;
    let mut profiles = Vec::with_capacity(names.len());
    for name in names {
        // A single bad file shouldn't sink the whole list; skip unreadable profiles.
        if let Ok(p) = store.read_profile(&name).await {
            profiles.push(p);
        }
    }
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(profiles)
}

/// Load settings off the iced thread (the load itself is sync fs, so just wrap it).
async fn load_settings_async() -> Result<AppSettings, AppError> {
    AppSettings::load()
}

/// Load the persisted data-usage store off the iced thread (sync fs, wrapped).
async fn load_usage_async() -> Result<UsageStore, AppError> {
    UsageStore::load()
}

// ─────────────────────────────────────────────────────────────────────────────
// Update
// ─────────────────────────────────────────────────────────────────────────────

impl State {
    /// Reduce one message into a state mutation + follow-up task.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // ── boot loads ──────────────────────────────────────────────────
            Message::ProfilesLoaded(result) => {
                match result {
                    Ok(profiles) => {
                        self.profiles = profiles;
                        self.apply_sort();
                        // Feature 3: keep the tray quick-connect submenu in sync
                        // with the loaded profile list.
                        push_tray_cmd(TrayCmd::SetProfiles(
                            self.profiles.iter().map(|p| p.name.clone()).collect(),
                        ));
                    }
                    Err(e) => self.set_banner(BannerKind::Error, format!("Failed to load profiles: {e}")),
                }
                Task::none()
            }
            Message::SettingsLoaded(result) => {
                match result {
                    Ok(settings) => {
                        self.auto_reconnect = settings.auto_reconnect;
                        self.settings = settings;
                    }
                    Err(e) => self.set_banner(BannerKind::Warning, format!("Failed to load settings: {e}")),
                }
                Task::none()
            }

            // ── window / tray ─────────────────────────────────────────────────
            Message::WindowOpened(id) => {
                self.main_window = Some(id);
                // Honour --hidden: as soon as the window exists, send it to the tray.
                if self.start_hidden {
                    self.start_hidden = false;
                    return window::set_mode(id, window::Mode::Hidden);
                }
                Task::none()
            }
            Message::WindowCloseRequested(id) => {
                // Close-to-tray: remember the window and hide instead of quitting.
                self.main_window = Some(id);
                window::set_mode(id, window::Mode::Hidden)
            }
            Message::TrayOpen | Message::RaiseWindowRequested => self.show_window(),
            Message::TrayQuit => iced::exit(),

            // ── profile list ──────────────────────────────────────────────────
            Message::SearchChanged(q) => {
                self.search_query = q;
                Task::none()
            }
            Message::SortChanged(order) => {
                self.sort_order = order;
                self.apply_sort();
                Task::none()
            }
            Message::SelectProfile(name) => {
                self.active_profile = Some(name);
                Task::none()
            }

            // ── connect / disconnect ────────────────────────────────────────
            Message::ConnectProfile(name) => {
                let profile = match self.find_profile(&name) {
                    Some(p) => p.clone(),
                    None => {
                        self.set_banner(BannerKind::Error, format!("Profile '{name}' not found"));
                        return Task::none();
                    }
                };
                self.active_profile = Some(name.clone());
                self.tunnel_status = TunnelStatus::Connecting(name);
                // A user-initiated connect clears the "user disconnected" flag and
                // resets the back-off so the watchdog starts fresh.
                self.intentional_down = false;
                self.reconnect_attempt = 0;
                Task::perform(
                    async move {
                        let backend = detect_backend().await;
                        backend.connect(&profile).await
                    },
                    Message::ConnectResult,
                )
            }
            Message::DisconnectCurrent => {
                // User asked to disconnect — suppress auto-reconnect until they reconnect.
                self.intentional_down = true;
                self.reconnect_attempt = 0;
                // Tear down the actual kernel interface: the live status interface
                // if we have one, else the fixed client interface (`wg-gui0`).
                // NEVER the profile name (identity/display only).
                let iface = self
                    .live_status
                    .as_ref()
                    .map(|s| s.interface.clone())
                    .unwrap_or_else(|| crate::wg::backend::CLIENT_IFACE.to_string());
                self.tunnel_status = TunnelStatus::Disconnecting;
                Task::perform(
                    async move {
                        let backend = detect_backend().await;
                        backend.disconnect(&iface).await
                    },
                    Message::DisconnectResult,
                )
            }
            Message::ConnectResult(result) => {
                match result {
                    Ok(()) => {
                        let name = self
                            .active_profile
                            .clone()
                            .unwrap_or_else(|| "tunnel".to_owned());
                        self.tunnel_status = TunnelStatus::Connected(name.clone());
                        update_tray_icon(true);
                        self.reconnect_attempt = 0;
                        // Mark when the tunnel came up so the dashboard can show the
                        // "connected for …" uptime, and clear any stale throughput
                        // history so the sparkline starts fresh for this session.
                        self.connected_since = Some(std::time::Instant::now());
                        self.throughput_history.clear();
                        // Feature 2: a fresh connect starts a new usage session.
                        self.usage_store.reset_session(&name);
                        // Feature 3: tell the tray which profile is now connected.
                        push_tray_cmd(TrayCmd::SetConnected(Some(name.clone())));
                        // Feature 1: desktop notification (gated on the setting).
                        if self.settings.notifications_enabled {
                            crate::notify::notify_connected(&name);
                        }
                        self.set_banner(BannerKind::Success, format!("Connected to {name}"));

                        // Kill-switch: when enabled, arm it now that the tunnel is up.
                        if self.settings.kill_switch {
                            if let Some(arm_task) = self.arm_kill_switch_task(&name) {
                                return Task::batch([arm_task, self.status_refresh_task()]);
                            } else {
                                self.set_banner(
                                    BannerKind::Warning,
                                    "Kill switch enabled but the profile has no peer endpoint to \
                                     allow through — not armed (would lock you out).".to_owned(),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        self.tunnel_status = TunnelStatus::Error(e.to_string());
                        update_tray_icon(false);
                        // Connect failed — there is no live tunnel, so clear the
                        // uptime origin (it was never set, but stay defensive).
                        self.connected_since = None;
                        self.set_banner(BannerKind::Error, format!("Connect failed: {e}"));
                    }
                }
                // Refresh live status + public IP after the state change.
                self.status_refresh_task()
            }
            Message::DisconnectResult(result) => {
                match result {
                    Ok(()) => {
                        self.tunnel_status = TunnelStatus::Disconnected;
                        self.live_status = None;
                        update_tray_icon(false);
                        // Tunnel is down: clear the uptime origin and throughput
                        // history so the dashboard stops showing a live session.
                        self.connected_since = None;
                        self.throughput_history.clear();
                        // Feature 5: no live tunnel → no health.
                        self.active_health = None;
                        // Feature 3: clear the connected profile in the tray.
                        push_tray_cmd(TrayCmd::SetConnected(None));
                        // Feature 1: desktop notification (gated on the setting).
                        if self.settings.notifications_enabled {
                            let name = self
                                .active_profile
                                .clone()
                                .unwrap_or_else(|| "tunnel".to_owned());
                            crate::notify::notify_disconnected(&name);
                        }
                        self.set_banner(BannerKind::Info, "Disconnected".to_owned());

                        // Kill-switch: tear it down so traffic is restored after a
                        // deliberate disconnect (no point blocking with no tunnel).
                        if self.settings.kill_switch {
                            return Task::batch([
                                Self::disarm_kill_switch_task(),
                                self.status_refresh_task(),
                            ]);
                        }
                    }
                    Err(e) => {
                        self.tunnel_status = TunnelStatus::Error(e.to_string());
                        self.set_banner(BannerKind::Error, format!("Disconnect failed: {e}"));
                    }
                }
                self.status_refresh_task()
            }

            // ── kill switch ──────────────────────────────────────────────────
            Message::KillSwitchResult { armed, result } => {
                match (armed, result) {
                    (true, Ok(())) => {
                        self.set_banner(BannerKind::Success, "Kill switch armed".to_owned());
                    }
                    (false, Ok(())) => {
                        self.set_banner(BannerKind::Info, "Kill switch disarmed".to_owned());
                    }
                    (true, Err(e)) => {
                        self.set_banner(BannerKind::Error, format!("Kill switch arm failed: {e}"));
                    }
                    (false, Err(e)) => {
                        self.set_banner(
                            BannerKind::Error,
                            format!("Kill switch disarm failed: {e}"),
                        );
                    }
                }
                Task::none()
            }

            // ── auto-reconnect ───────────────────────────────────────────────
            Message::ReconnectTick(name) => {
                // The watchdog scheduled this retry; honour a user disconnect that may
                // have landed during the back-off wait.
                if self.intentional_down {
                    return Task::none();
                }
                let profile = match self.find_profile(&name) {
                    Some(p) => p.clone(),
                    None => return Task::none(),
                };
                self.tunnel_status = TunnelStatus::Connecting(name);
                Task::perform(
                    async move {
                        let backend = detect_backend().await;
                        backend.connect(&profile).await
                    },
                    Message::ConnectResult,
                )
            }

            // ── delete ──────────────────────────────────────────────────────
            Message::DeleteProfile(name) => {
                let store = self.profile_store.clone();
                Task::perform(
                    async move { store.delete_profile(&name).await },
                    Message::DeleteResult,
                )
            }
            Message::DeleteResult(result) => match result {
                Ok(()) => {
                    self.set_banner(BannerKind::Info, "Profile deleted".to_owned());
                    self.reload_profiles_task()
                }
                Err(e) => {
                    self.set_banner(BannerKind::Error, format!("Delete failed: {e}"));
                    Task::none()
                }
            },

            // ── editor ──────────────────────────────────────────────────────
            Message::OpenNewProfile => {
                let draft = WgProfile::default();
                let raw_text = draft.to_conf_string();
                self.editor = Some(EditorState {
                    profile_name: String::new(),
                    draft,
                    raw_text,
                    validation_errors: Vec::new(),
                    is_new: true,
                });
                // Ready the raw-editor Content so a toggle-to-raw shows the conf
                // immediately with a working cursor.
                self.seed_raw_editor_content();
                self.screen = Screen::Editor;
                Task::none()
            }
            Message::EditProfile(name) => {
                match self.find_profile(&name) {
                    Some(p) => {
                        let draft = p.clone();
                        let raw_text = draft.to_conf_string();
                        let validation_errors = draft.validate();
                        self.editor = Some(EditorState {
                            profile_name: name,
                            draft,
                            raw_text,
                            validation_errors,
                            is_new: false,
                        });
                        // Ready the raw-editor Content so a toggle-to-raw shows the
                        // conf immediately with a working cursor.
                        self.seed_raw_editor_content();
                        self.screen = Screen::Editor;
                    }
                    None => self.set_banner(BannerKind::Error, format!("Profile '{name}' not found")),
                }
                Task::none()
            }
            Message::EditorFieldChanged(field) => {
                if let Some(editor) = self.editor.as_mut() {
                    apply_editor_field(editor, field);
                    editor.validation_errors = editor.draft.validate();
                    editor.raw_text = editor.draft.to_conf_string();
                }
                Task::none()
            }
            Message::EditorToggleRaw => {
                // Flip between the structured Editor and the RawEditor.
                self.screen = match self.screen {
                    Screen::RawEditor => Screen::Editor,
                    _ => {
                        // Entering raw mode: re-seed the live Content from the
                        // current `.conf` text so the box shows it with a fresh,
                        // working cursor (the structured side keeps `raw_text`
                        // current via `EditorFieldChanged`).
                        self.seed_raw_editor_content();
                        Screen::RawEditor
                    }
                };
                Task::none()
            }
            Message::RawEditorAction(action) => {
                // Mutate the persisted Content in place so the cursor/selection
                // survive across frames (the bug fix: a fresh Content every frame
                // reset the cursor to 0, so Backspace/Delete did nothing).
                self.raw_editor_content.perform(action);
                let text = self.raw_editor_content.text();
                self.sync_raw_text(text);
                Task::none()
            }
            Message::EditorSave => {
                let Some(editor) = self.editor.as_mut() else {
                    return Task::none();
                };
                // The profile's name comes from the dedicated name field for new profiles.
                if !editor.profile_name.is_empty() {
                    editor.draft.name = editor.profile_name.clone();
                }
                let errors = editor.draft.validate();
                if !errors.is_empty() {
                    editor.validation_errors = errors;
                    self.set_banner(
                        BannerKind::Error,
                        "Cannot save: fix the validation errors first".to_owned(),
                    );
                    return Task::none();
                }
                if editor.draft.name.trim().is_empty() {
                    self.set_banner(BannerKind::Error, "Profile name must not be empty".to_owned());
                    return Task::none();
                }
                let store = self.profile_store.clone();
                let profile = editor.draft.clone();
                let is_new = editor.is_new;
                Task::perform(
                    async move {
                        if is_new {
                            store.create_profile(&profile).await?;
                        } else {
                            store.save_profile(&profile).await?;
                        }
                        Ok(profile)
                    },
                    Message::EditorSaveResult,
                )
            }
            Message::EditorSaveResult(result) => match result {
                Ok(profile) => {
                    self.editor = None;
                    self.screen = Screen::ProfileList;
                    self.set_banner(BannerKind::Success, format!("Saved '{}'", profile.name));
                    self.reload_profiles_task()
                }
                Err(e) => {
                    self.set_banner(BannerKind::Error, format!("Save failed: {e}"));
                    Task::none()
                }
            },
            Message::EditorCancel => {
                self.editor = None;
                self.screen = Screen::ProfileList;
                self.banner = None;
                Task::none()
            }
            Message::GenerateKeypair => {
                Task::perform(keygen::generate_keypair(), Message::KeypairGenerated)
            }
            Message::KeypairGenerated(result) => {
                match result {
                    Ok((private_key, public_key)) => {
                        if let Some(editor) = self.editor.as_mut() {
                            editor.draft.interface.private_key = private_key;
                            editor.validation_errors = editor.draft.validate();
                            editor.raw_text = editor.draft.to_conf_string();
                        }
                        self.set_banner(
                            BannerKind::Info,
                            format!("Generated keypair (public key: {public_key})"),
                        );
                    }
                    Err(e) => self.set_banner(BannerKind::Error, format!("Keygen failed: {e}")),
                }
                Task::none()
            }

            // ── import / export ───────────────────────────────────────────────
            Message::ImportProfile => Task::perform(pick_import_file(), Message::ImportFileChosen),
            Message::ImportFileChosen(maybe_path) => match maybe_path {
                Some(path) => {
                    let store = self.profile_store.clone();
                    Task::perform(
                        async move { store.import_from_path(&path).await },
                        Message::ImportResult,
                    )
                }
                None => Task::none(), // dialog cancelled
            },
            Message::ImportResult(result) => match result {
                Ok(profile) => {
                    self.set_banner(BannerKind::Success, format!("Imported '{}'", profile.name));
                    self.reload_profiles_task()
                }
                Err(e) => {
                    self.set_banner(BannerKind::Error, format!("Import failed: {e}"));
                    Task::none()
                }
            },
            Message::ExportProfile(name) => {
                Task::perform(pick_export_file(name), Message::ExportFileChosen)
            }
            Message::ExportFileChosen(maybe_path) => match maybe_path {
                Some(path) => {
                    // The export destination's file stem identifies which profile to export:
                    // we kept the source name in the suggested file name during pick_export_file.
                    let store = self.profile_store.clone();
                    let name = self
                        .active_profile
                        .clone()
                        .or_else(|| {
                            path.file_stem()
                                .and_then(|s| s.to_str())
                                .map(|s| s.to_owned())
                        })
                        .unwrap_or_default();
                    Task::perform(
                        async move { store.export_to_path(&name, &path).await },
                        Message::ExportResult,
                    )
                }
                None => Task::none(),
            },
            Message::ExportResult(result) => {
                match result {
                    Ok(()) => self.set_banner(BannerKind::Success, "Exported profile".to_owned()),
                    Err(e) => self.set_banner(BannerKind::Error, format!("Export failed: {e}")),
                }
                Task::none()
            }

            // ── status polling ────────────────────────────────────────────────
            Message::StatusTick => {
                // Auto-reconnect watchdog: decide from the most recent observation
                // (last fetched `live_status`) whether the tunnel has dropped, then
                // always kick off a fresh status refresh for the next tick.
                let refresh = self.status_refresh_task();
                if let Some(reconnect) = self.auto_reconnect_task() {
                    return Task::batch([reconnect, refresh]);
                }
                refresh
            }
            Message::StatusFetched(result) => {
                match result {
                    Ok(status) => {
                        // Feed the dashboard sparkline: push one cumulative
                        // (rx, tx) sample per tick, summed across the interface's
                        // peers. Only while a live status exists (a down tunnel
                        // returns None and contributes no sample).
                        if let Some(s) = status.as_ref() {
                            let (rx, tx) = s.peers.iter().fold((0u64, 0u64), |(rx, tx), p| {
                                (rx.saturating_add(p.rx_bytes), tx.saturating_add(p.tx_bytes))
                            });
                            self.push_throughput_sample(rx, tx);

                            // Feature 2: record cumulative usage for the active
                            // profile and persist it. Feature 5: recompute health
                            // from the freshest handshake age.
                            if let Some(name) = self.active_profile.clone() {
                                self.usage_store.record(&name, rx, tx);
                            }
                            self.active_health = Some(health_from_handshake(
                                latest_handshake_age_secs(s),
                            ));
                            self.live_status = status;
                            return self.save_usage_task();
                        }
                        // Tunnel down: no health to report.
                        self.active_health = None;
                        self.live_status = status;
                    }
                    Err(e) => {
                        // Status errors are noisy on a down tunnel; surface only via the banner
                        // when nothing is connected wouldn't be useful, so only warn on hard errors.
                        if !matches!(e, AppError::WgNotFound) {
                            self.set_banner(BannerKind::Warning, format!("Status: {e}"));
                        }
                    }
                }
                Task::none()
            }
            Message::PublicIpFetched(result) => {
                self.public_ip_loading = false;
                match result {
                    Ok(ip) => self.public_ip = Some(ip),
                    Err(_e) => self.public_ip = None,
                }
                Task::none()
            }

            // ── navigation ────────────────────────────────────────────────────
            Message::OpenPlanPreview(name) => {
                match self.find_profile(&name) {
                    Some(profile) => {
                        let plan = compute_plan(profile, self.settings.kill_switch);
                        self.dry_run_plan = Some(plan);
                        self.active_profile = Some(name);
                        self.screen = Screen::PlanPreview;
                    }
                    None => self.set_banner(BannerKind::Error, format!("Profile '{name}' not found")),
                }
                Task::none()
            }
            Message::OpenSettings => {
                self.screen = Screen::Settings;
                Task::none()
            }
            Message::GoHome => {
                self.screen = Screen::ProfileList;
                self.dry_run_plan = None;
                Task::none()
            }

            // ── settings ──────────────────────────────────────────────────────
            Message::SettingAutoReconnectToggled(on) => {
                self.settings.auto_reconnect = on;
                self.auto_reconnect = on;
                self.save_settings_task()
            }
            Message::SettingAutoStartToggled(on) => {
                self.settings.autostart = on;
                // Apply the OS-level autostart entry immediately (best-effort; report failures).
                match AutostartManager::new() {
                    Ok(mgr) => {
                        let res = if on { mgr.enable() } else { mgr.disable() };
                        if let Err(e) = res {
                            self.set_banner(BannerKind::Error, format!("Autostart: {e}"));
                        }
                    }
                    Err(e) => self.set_banner(BannerKind::Error, format!("Autostart: {e}")),
                }
                self.save_settings_task()
            }
            Message::SettingKillSwitchToggled(on) => {
                self.settings.kill_switch = on;
                let save = self.save_settings_task();
                // If a tunnel is already up, reflect the new preference immediately:
                // arm when turning on, disarm when turning off.
                let is_connected = matches!(self.tunnel_status, TunnelStatus::Connected(_));
                if on && is_connected {
                    let name = self
                        .active_profile
                        .clone()
                        .unwrap_or_else(|| "tunnel".to_owned());
                    if let Some(arm_task) = self.arm_kill_switch_task(&name) {
                        return Task::batch([arm_task, save]);
                    }
                } else if !on {
                    return Task::batch([Self::disarm_kill_switch_task(), save]);
                }
                save
            }
            Message::SettingConnectOnBootChanged(maybe_profile) => {
                self.settings.connect_on_boot = maybe_profile.clone();
                let save = self.save_settings_task();
                // Apply the boot configuration via the appropriate backend path.
                // This only runs in response to this explicit user action — never at
                // startup, build, or test time.
                if let Some(boot_task) = self.apply_connect_on_boot_task(maybe_profile) {
                    return Task::batch([boot_task, save]);
                }
                save
            }
            Message::BootConfigResult(result) => {
                match result {
                    Ok(()) => self.set_banner(
                        BannerKind::Success,
                        "Connect-on-boot updated".to_owned(),
                    ),
                    Err(e) => self.set_banner(
                        BannerKind::Error,
                        format!("Connect-on-boot update failed: {e}"),
                    ),
                }
                Task::none()
            }
            Message::SettingThemeChanged(pref) => {
                self.settings.theme = pref;
                self.save_settings_task()
            }
            Message::SettingsSaved(result) => {
                if let Err(e) = result {
                    self.set_banner(BannerKind::Error, format!("Save settings failed: {e}"));
                }
                Task::none()
            }

            // ── server mode ───────────────────────────────────────────────────
            Message::OpenServer => {
                self.screen = Screen::Server;
                // Lazily load the persisted server config the first time the screen
                // is opened. We only load when nothing is in memory yet so an
                // in-session config (just created / freshly mutated) is never
                // clobbered by an older on-disk copy. `load()` returns Ok(None) when
                // no server has been configured — surfaced via ServerCreateResult,
                // which treats Ok as "set/keep `self.server`".
                if self.server.is_none() {
                    return Task::perform(
                        async { crate::server::ServerConfig::load() },
                        Message::ServerLoadResult,
                    );
                }
                Task::none()
            }
            Message::ServerLoadResult(result) => {
                match result {
                    // A persisted config exists — adopt it.
                    Ok(Some(config)) => self.server = Some(config),
                    // No server configured yet: stay on the (empty) Server screen so
                    // the user can create one. Not an error.
                    Ok(None) => {}
                    Err(e) => {
                        self.set_banner(BannerKind::Warning, format!("Load server failed: {e}"))
                    }
                }
                Task::none()
            }
            Message::ServerCreate(endpoint_host) => Task::perform(
                async move {
                    // Generate the fresh config, then persist it immediately so the
                    // private key survives a restart. Detect the egress interface
                    // (read-only `ip route`) so NAT can be enabled later without a
                    // second probe; this is side-effect-free and never brings NAT up.
                    let mut config = crate::server::ServerConfig::generate_new(&endpoint_host)?;
                    config.egress_iface = crate::server::manage::detect_egress_iface();
                    config.save()?;
                    Ok(config)
                },
                Message::ServerCreateResult,
            ),
            Message::ServerCreateResult(result) => {
                match result {
                    Ok(config) => {
                        self.server = Some(config);
                        self.set_banner(BannerKind::Success, "Server created".to_owned());
                    }
                    Err(e) => self.set_banner(BannerKind::Error, format!("Create server failed: {e}")),
                }
                Task::none()
            }
            Message::ServerStartToggle => {
                let Some(config) = self.server.clone() else {
                    self.set_banner(BannerKind::Warning, "No server to start".to_owned());
                    return Task::none();
                };
                let was_running = self.server_running;
                Task::perform(
                    async move {
                        if was_running {
                            crate::server::manage::stop().await
                        } else {
                            crate::server::manage::start(&config).await
                        }
                    },
                    Message::ServerOpResult,
                )
            }
            Message::ServerOpResult(result) => {
                match result {
                    Ok(()) => {
                        self.server_running = !self.server_running;
                        let verb = if self.server_running { "started" } else { "stopped" };
                        self.set_banner(BannerKind::Success, format!("Server {verb}"));
                    }
                    Err(e) => self.set_banner(BannerKind::Error, format!("Server op failed: {e}")),
                }
                Task::none()
            }
            Message::ServerNatToggle(on) => {
                if let Some(config) = self.server.as_ref() {
                    let (subnet, egress) = (config.subnet.clone(), config.egress_iface.clone());
                    let cmd = if on {
                        match egress {
                            Some(egress_iface) => crate::net::privilege::PrivCmd::NatEnable {
                                subnet,
                                egress_iface,
                            },
                            None => {
                                self.set_banner(
                                    BannerKind::Warning,
                                    "No egress interface detected — cannot enable NAT".to_owned(),
                                );
                                return Task::none();
                            }
                        }
                    } else {
                        crate::net::privilege::PrivCmd::NatDisable
                    };
                    Task::perform(
                        async move { run_privileged(&cmd).await },
                        move |result| Message::ServerNatResult { enabled: on, result },
                    )
                } else {
                    Task::none()
                }
            }
            Message::ServerNatResult { enabled, result } => {
                // NAT is independent of the interface being up: never touch
                // `server_running` here (routing through `ServerOpResult` would have
                // wrongly toggled it).
                match result {
                    Ok(()) => {
                        let verb = if enabled { "enabled" } else { "disabled" };
                        self.set_banner(BannerKind::Success, format!("NAT {verb}"));
                    }
                    Err(e) => {
                        let verb = if enabled { "enable" } else { "disable" };
                        self.set_banner(BannerKind::Error, format!("NAT {verb} failed: {e}"));
                    }
                }
                Task::none()
            }
            Message::ServerPeerNameChanged(name) => {
                self.server_peer_name_input = name;
                Task::none()
            }
            Message::ServerAddPeer => {
                let Some(mut config) = self.server.clone() else {
                    return Task::none();
                };
                let name = std::mem::take(&mut self.server_peer_name_input);
                if name.trim().is_empty() {
                    self.set_banner(BannerKind::Warning, "Enter a client name first".to_owned());
                    return Task::none();
                }
                let running = self.server_running;
                Task::perform(
                    async move {
                        config.add_peer(&name)?;
                        // Persist so the new peer survives a restart.
                        config.save()?;
                        // If the server is up, rewrite + re-apply the running conf so
                        // the new peer is admitted live (idempotent ServerWriteConf +
                        // ServerUp). Best-effort: a failure here is reported, but the
                        // config is already saved.
                        if running {
                            crate::server::manage::start(&config).await?;
                        }
                        Ok(config)
                    },
                    Message::ServerAddPeerResult,
                )
            }
            Message::ServerAddPeerResult(result) => {
                match result {
                    Ok(config) => {
                        // Surface the newly-added peer's client conf for QR/copy.
                        if let Some(peer) = config.peers.last() {
                            let conf = config.client_conf(peer);
                            self.last_client_conf = Some((peer.name.clone(), conf));
                        }
                        self.server = Some(config);
                        self.set_banner(BannerKind::Success, "Client added".to_owned());
                    }
                    Err(e) => self.set_banner(BannerKind::Error, format!("Add client failed: {e}")),
                }
                Task::none()
            }
            Message::ServerRemovePeer(idx) => {
                let Some(mut config) = self.server.clone() else {
                    return Task::none();
                };
                // Clear any pending hand-out conf for the peer being revoked — the QR
                // panel must not keep showing a config we just removed.
                self.last_client_conf = None;
                let running = self.server_running;
                Task::perform(
                    async move {
                        config.remove_peer(idx);
                        // Persist the removal.
                        config.save()?;
                        // If the server is up, rewrite + re-apply so the removed peer
                        // is dropped from the live interface (idempotent re-apply).
                        if running {
                            crate::server::manage::start(&config).await?;
                        }
                        Ok(config)
                    },
                    Message::ServerRemovePeerResult,
                )
            }
            Message::ServerRemovePeerResult(result) => {
                match result {
                    Ok(config) => {
                        self.server = Some(config);
                        self.set_banner(BannerKind::Info, "Client removed".to_owned());
                    }
                    Err(e) => {
                        self.set_banner(BannerKind::Error, format!("Remove client failed: {e}"))
                    }
                }
                Task::none()
            }
            Message::ServerStatusTick => {
                let Some(config) = self.server.clone() else {
                    return Task::none();
                };
                if !self.server_running {
                    return Task::none();
                }
                Task::perform(
                    async move { crate::server::manage::status(&config).await },
                    Message::ServerStatusResult,
                )
            }
            Message::ServerStatusResult(result) => {
                match result {
                    Ok(peers) => self.server_peer_status = peers,
                    Err(e) => self.set_banner(BannerKind::Warning, format!("Server status: {e}")),
                }
                Task::none()
            }

            // ── misc ──────────────────────────────────────────────────────────
            Message::DismissBanner => {
                self.banner = None;
                Task::none()
            }

            // ── new features ────────────────────────────────────────────────
            Message::UsageLoaded(result) => {
                match result {
                    Ok(store) => self.usage_store = store,
                    Err(e) => {
                        self.set_banner(BannerKind::Warning, format!("Failed to load usage: {e}"))
                    }
                }
                Task::none()
            }
            Message::SettingNotificationsToggled(on) => {
                self.settings.notifications_enabled = on;
                self.save_settings_task()
            }
            // Tray quick-connect forwards into the existing connect/disconnect
            // reducers so there is one source of truth for the connect path.
            Message::TrayConnectProfile(name) => self.update(Message::ConnectProfile(name)),
            Message::TrayDisconnect => self.update(Message::DisconnectCurrent),
            Message::ImportFromQr => {
                Task::perform(pick_qr_image_file(), Message::ImportFromQrChosen)
            }
            Message::ImportFromQrChosen(maybe_path) => match maybe_path {
                Some(path) => {
                    let store = self.profile_store.clone();
                    Task::perform(
                        async move { import_from_qr(&store, &path).await },
                        Message::ImportResult,
                    )
                }
                None => Task::none(), // dialog cancelled
            },
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn set_banner(&mut self, kind: BannerKind, message: String) {
        self.banner = Some(Banner { kind, message });
    }

    /// Mirror raw `.conf` text into the open editor and re-parse it.
    ///
    /// Sets `editor.raw_text`, re-parses via [`WgProfile::from_conf_str`] (keeping
    /// the original on-disk path so saves overwrite in place), refreshes
    /// `validation_errors`, and surfaces a parse error via the banner — exactly the
    /// behaviour the former `RawTextChanged` handler had. A no-op when no editor is
    /// open. Does NOT touch `self.raw_editor_content` (the caller owns the cursor).
    fn sync_raw_text(&mut self, text: String) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        editor.raw_text = text.clone();
        let name = if editor.profile_name.is_empty() {
            editor.draft.name.clone()
        } else {
            editor.profile_name.clone()
        };
        match WgProfile::from_conf_str(&name, &text) {
            Ok(mut parsed) => {
                // Preserve the original on-disk path so saves overwrite in place.
                parsed.path = editor.draft.path.clone();
                editor.draft = parsed;
                editor.validation_errors = editor.draft.validate();
                self.banner = None;
            }
            Err(e) => {
                self.set_banner(BannerKind::Warning, format!("Parse error: {e}"));
            }
        }
    }

    /// Re-seed [`State::raw_editor_content`] from the open editor's `raw_text`.
    ///
    /// Called whenever the raw editor becomes visible (opening an editor screen or
    /// toggling structured → raw) so the box shows the current `.conf` with a fresh,
    /// working cursor. A no-op when no editor is open.
    fn seed_raw_editor_content(&mut self) {
        if let Some(editor) = self.editor.as_ref() {
            self.raw_editor_content =
                iced::widget::text_editor::Content::with_text(&editor.raw_text);
        }
    }

    fn find_profile(&self, name: &str) -> Option<&WgProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    fn apply_sort(&mut self) {
        match self.sort_order {
            SortOrder::NameAsc => self.profiles.sort_by(|a, b| a.name.cmp(&b.name)),
            SortOrder::NameDesc => self.profiles.sort_by(|a, b| b.name.cmp(&a.name)),
        }
    }

    /// Build a task that reloads all profiles from disk (used after create/delete/import).
    fn reload_profiles_task(&self) -> Task<Message> {
        let store = self.profile_store.clone();
        Task::perform(load_all_profiles(store), Message::ProfilesLoaded)
    }

    /// Build the persist-settings task.
    fn save_settings_task(&self) -> Task<Message> {
        let settings = self.settings.clone();
        Task::perform(async move { settings.save() }, Message::SettingsSaved)
    }

    /// Build a fire-and-forget persist-usage task (feature 2). The save result is
    /// discarded (`.discard()` → no follow-up message) — a failed usage write is
    /// best-effort and must not interrupt the status-tick flow or clobber the
    /// current banner.
    fn save_usage_task(&self) -> Task<Message> {
        let store = self.usage_store.clone();
        Task::future(async move {
            let _ = store.save();
        })
        .discard()
    }

    /// Refresh live status (for the active interface) and the public IP.
    fn status_refresh_task(&mut self) -> Task<Message> {
        self.public_ip_loading = true;
        // The kernel interface is the fixed client interface (`wg-gui0`), NOT the
        // profile name — the profile name is identity/display only. Query our
        // live status against the live interface if known, else CLIENT_IFACE.
        let iface = self
            .live_status
            .as_ref()
            .map(|s| s.interface.clone())
            .or_else(|| match &self.tunnel_status {
                TunnelStatus::Connected(_) | TunnelStatus::Connecting(_) => {
                    Some(crate::wg::backend::CLIENT_IFACE.to_string())
                }
                _ => None,
            });
        let status_task = Task::perform(
            async move { fetch_status(iface.as_deref()).await },
            Message::StatusFetched,
        );
        let ip_task = Task::perform(
            crate::public_ip::fetch_public_ip(),
            Message::PublicIpFetched,
        );
        Task::batch([status_task, ip_task])
    }

    // ── Phase-3: kill switch / auto-reconnect / connect-on-boot ───────────────

    /// Build the task that arms the kill-switch for the active tunnel, or `None`
    /// when the profile has no peer endpoint to punch through (arming without an
    /// allow-rule for the endpoint would lock the user out of reconnecting).
    ///
    /// The interface name is derived from the live status if known, otherwise it is
    /// the fixed client interface (`wg-gui0`, see [`crate::wg::backend::CLIENT_IFACE`]).
    /// `lan_cidrs` default to the user's configured `destination_split` (the local
    /// networks to keep reachable), or empty.
    fn arm_kill_switch_task(&self, profile_name: &str) -> Option<Task<Message>> {
        let profile = self.find_profile(profile_name)?;
        // Endpoint of the first peer that has one — this is the punch-through hole.
        let endpoint = profile.peers.iter().find_map(|p| p.endpoint.clone())?;
        let (endpoint_ip, endpoint_port) = split_endpoint(&endpoint)?;

        // Interface as the kernel sees it: prefer the live status, else the fixed
        // client interface (`wg-gui0`).
        let iface = self
            .live_status
            .as_ref()
            .map(|s| s.interface.clone())
            .unwrap_or_else(|| crate::wg::backend::CLIENT_IFACE.to_string());

        let lan_cidrs = self.settings.destination_split.clone();

        Some(Task::perform(
            async move {
                KillSwitch
                    .arm(
                        &iface,
                        &endpoint_ip,
                        endpoint_port,
                        lan_cidrs,
                        KILL_SWITCH_LEASE_SECS,
                        None,
                    )
                    .await
            },
            |result| Message::KillSwitchResult { armed: true, result },
        ))
    }

    /// Build the task that disarms (removes) the kill-switch table.
    fn disarm_kill_switch_task() -> Task<Message> {
        Task::perform(
            async move { KillSwitch.disarm().await },
            |result| Message::KillSwitchResult { armed: false, result },
        )
    }

    /// Auto-reconnect: if enabled and the user did not deliberately disconnect,
    /// consult [`watchdog::should_reconnect`] against the most recent observation
    /// and, when a reconnect is warranted, return a back-off-delayed reconnect task.
    /// Returns `None` when no reconnect should be attempted.
    fn auto_reconnect_task(&mut self) -> Option<Task<Message>> {
        if !self.settings.auto_reconnect || self.intentional_down {
            return None;
        }
        // Only attempt to reconnect a profile we believe should be up: a tunnel that
        // was Connected/Connecting or errored out, and for which we still know the
        // active profile to reconnect. A Disconnected status means nothing to do.
        let watch = matches!(
            self.tunnel_status,
            TunnelStatus::Connected(_) | TunnelStatus::Connecting(_) | TunnelStatus::Error(_)
        );
        if !watch {
            return None;
        }
        let name = self.active_profile.clone()?;

        // Observation from the last status fetch.
        let iface_present = self.live_status.is_some();
        let handshake_age = self
            .live_status
            .as_ref()
            .and_then(latest_handshake_age_secs);

        if watchdog::should_reconnect(
            handshake_age,
            iface_present,
            self.intentional_down,
            watchdog::DEFAULT_THRESHOLD_SECS,
        ) {
            // A reconnect is already in flight while we are Connecting — don't pile on.
            if matches!(self.tunnel_status, TunnelStatus::Connecting(_)) {
                return None;
            }
            let delay = watchdog::next_backoff(self.reconnect_attempt);
            self.reconnect_attempt = self.reconnect_attempt.saturating_add(1);
            // Feature 1: desktop notification on an unexpected drop (gated on the
            // setting). Only fire on the first detection of this drop — i.e. while we
            // are not yet mid-reconnect — so repeated ticks during back-off don't spam
            // the daemon. `reconnect_attempt` was 0 here on the first drop (it has just
            // been incremented above), so guard on the pre-increment value.
            if self.settings.notifications_enabled && self.reconnect_attempt == 1 {
                crate::notify::notify_dropped(&name);
            }
            self.set_banner(
                BannerKind::Warning,
                format!("Tunnel dropped — reconnecting to {name} in {}s…", delay.as_secs()),
            );
            // Wait out the back-off, then fire ReconnectTick on the iced runtime.
            Some(Task::perform(
                async move {
                    tokio::time::sleep(delay).await;
                    name
                },
                Message::ReconnectTick,
            ))
        } else {
            // Healthy handshake observed — reset the back-off counter.
            self.reconnect_attempt = 0;
            None
        }
    }

    /// Build the task that applies a connect-on-boot change for the given profile.
    ///
    /// Uses the NetworkManager client-side path when an NM backend is in use (no
    /// root: `nmcli connection modify … connection.autoconnect yes`); otherwise the
    /// privileged wg-quick/systemd path (`systemctl enable wg-quick@wg-gui-<n>` via
    /// the root helper). `None` clears the previously-bound boot unit (disable).
    ///
    /// This is only invoked from [`Message::SettingConnectOnBootChanged`] — an
    /// explicit user action — and never at startup, so connect-on-boot stays OFF by
    /// default and nothing privileged runs during build/test.
    fn apply_connect_on_boot_task(&self, maybe_profile: Option<String>) -> Option<Task<Message>> {
        // Determine which profile's boot unit to (re)configure and whether to
        // enable or disable it. When a profile is being set we enable it; when
        // cleared we disable whatever was previously bound.
        let (profile_name, action) = match maybe_profile {
            Some(name) => (name, BootAction::Enable),
            None => (self.settings.connect_on_boot.clone()?, BootAction::Disable),
        };

        // Prefer the non-root NM autoconnect path when NM is available; fall back to
        // the privileged systemd unit. Detection is async, so it lives inside the task.
        let iface = crate::wg::backend::nm_connection_name(&profile_name);
        Some(Task::perform(
            async move {
                if crate::wg::backend::detect_is_nm().await {
                    let argv = boot::nm_autoconnect_argv(&profile_name, action);
                    run_nmcli_argv(&argv).await
                } else {
                    let cmd = boot::systemd_boot_cmd(&iface, action);
                    // `cmd` is always a Boot{Enable,Disable}Systemd PrivCmd here.
                    run_privileged(&cmd).await
                }
            },
            Message::BootConfigResult,
        ))
    }

    /// Un-hide + focus the main window (tray "Open" / single-instance raise).
    fn show_window(&mut self) -> Task<Message> {
        match self.main_window {
            Some(id) => Task::batch([
                window::set_mode(id, window::Mode::Windowed),
                window::gain_focus(id),
            ]),
            // No window known yet (e.g. daemon mode before first open): open one.
            None => {
                let (id, task) = window::open(window::Settings::default());
                self.main_window = Some(id);
                task.map(Message::WindowOpened)
            }
        }
    }
}

/// Apply a single editor field edit to the draft profile.
fn apply_editor_field(editor: &mut EditorState, field: EditorField) {
    let draft = &mut editor.draft;
    match field {
        EditorField::ProfileName(v) => {
            editor.profile_name = v.clone();
            draft.name = v;
        }
        EditorField::PrivateKey(v) => draft.interface.private_key = v,
        EditorField::Address(v) => draft.interface.address = split_csv(&v),
        EditorField::Dns(v) => draft.interface.dns = split_csv(&v),
        EditorField::ListenPort(v) => draft.interface.listen_port = parse_opt_u16(&v),
        EditorField::Mtu(v) => draft.interface.mtu = parse_opt_u16(&v),
        EditorField::PeerPublicKey(i, v) => {
            if let Some(peer) = draft.peers.get_mut(i) {
                peer.public_key = v;
            }
        }
        EditorField::PeerPresharedKey(i, v) => {
            if let Some(peer) = draft.peers.get_mut(i) {
                peer.preshared_key = if v.trim().is_empty() { None } else { Some(v) };
            }
        }
        EditorField::PeerEndpoint(i, v) => {
            if let Some(peer) = draft.peers.get_mut(i) {
                peer.endpoint = if v.trim().is_empty() { None } else { Some(v) };
            }
        }
        EditorField::PeerAllowedIps(i, v) => {
            if let Some(peer) = draft.peers.get_mut(i) {
                peer.allowed_ips = split_csv(&v);
            }
        }
        EditorField::PeerKeepalive(i, v) => {
            if let Some(peer) = draft.peers.get_mut(i) {
                peer.persistent_keepalive = parse_opt_u16(&v);
            }
        }
        EditorField::AddPeer => draft.peers.push(Default::default()),
        EditorField::RemovePeer(i) => {
            if i < draft.peers.len() {
                draft.peers.remove(i);
            }
        }
    }
}

/// Split a comma-separated text field into trimmed, non-empty entries.
fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Parse an optional u16 from a text field (empty / invalid → None).
fn parse_opt_u16(s: &str) -> Option<u16> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        t.parse::<u16>().ok()
    }
}

/// Split a WireGuard peer `Endpoint` (`host:port` or `[v6]:port`) into its host and
/// port for the kill-switch endpoint punch-through rule. Returns `None` if the port
/// is missing or non-numeric. The host is returned verbatim (an IP literal or a
/// hostname) — DNS resolution is intentionally NOT performed here (no network I/O).
///
/// Pure and side-effect-free so it is unit-testable without any network access.
fn split_endpoint(endpoint: &str) -> Option<(String, u16)> {
    let ep = endpoint.trim();
    if let Some(rest) = ep.strip_prefix('[') {
        // IPv6 literal: [addr]:port
        let (addr, port_part) = rest.split_once("]:")?;
        let port: u16 = port_part.trim().parse().ok()?;
        if addr.is_empty() {
            return None;
        }
        Some((addr.to_string(), port))
    } else {
        // host:port — split on the LAST colon so bare hostnames/IPv4 work.
        let (host, port_part) = ep.rsplit_once(':')?;
        if host.is_empty() {
            return None;
        }
        let port: u16 = port_part.trim().parse().ok()?;
        Some((host.to_string(), port))
    }
}

/// Seconds since a [`LiveStatus`]'s most-recent peer handshake, or `None` when no
/// peer has ever handshaked. Used to feed [`watchdog::should_reconnect`].
fn latest_handshake_age_secs(status: &LiveStatus) -> Option<u64> {
    let now = std::time::SystemTime::now();
    status
        .peers
        .iter()
        .filter_map(|p| p.last_handshake)
        .filter_map(|hs| now.duration_since(hs).ok())
        .map(|d| d.as_secs())
        .min()
}

/// Run `nmcli` with the supplied argv (argv[0] is `"nmcli"`; the rest are args) and
/// map a non-zero exit / spawn failure into an [`AppError`]. Used by the
/// connect-on-boot NM autoconnect path (non-root, NM's own polkit agent).
async fn run_nmcli_argv(argv: &[String]) -> Result<(), AppError> {
    let output = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::WgNotFound
            } else {
                AppError::WgQuickFailed(format!("nmcli spawn error: {e}"))
            }
        })?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(AppError::WgQuickFailed(format!(
            "nmcli autoconnect failed ({}): {}",
            output.status,
            stderr.trim(),
        )))
    }
}

/// Open a native file picker for a `.conf` to import.
async fn pick_import_file() -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .add_filter("WireGuard config", &["conf"])
        .set_title("Import WireGuard profile")
        .pick_file()
        .await
        .map(|handle| handle.path().to_owned())
}

/// Open a native file picker for a QR-code image to import (feature 4).
async fn pick_qr_image_file() -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .add_filter("QR image", &["png", "jpg", "jpeg", "bmp", "gif", "webp"])
        .set_title("Import WireGuard profile from QR image")
        .pick_file()
        .await
        .map(|handle| handle.path().to_owned())
}

/// Decode a QR image into `.conf` text, parse it into a [`WgProfile`], and persist
/// it to the store — the QR analogue of [`ProfileStore::import_from_path`]
/// (feature 4). The profile name is taken from the image file stem.
async fn import_from_qr(store: &ProfileStore, path: &std::path::Path) -> Result<WgProfile, AppError> {
    let conf = crate::config::qr_import::decode_qr_image(path)?;
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("qr-import")
        .to_owned();
    let mut profile = WgProfile::from_conf_str(&name, &conf)
        .map_err(|e| AppError::ImportFailed(e.to_string()))?;
    store.create_profile(&profile).await?;
    profile.path = Some(store.dir.join(format!("{name}.conf")));
    Ok(profile)
}

/// Open a native save dialog for exporting profile `name` as a `.conf`.
async fn pick_export_file(name: String) -> Option<PathBuf> {
    rfd::AsyncFileDialog::new()
        .add_filter("WireGuard config", &["conf"])
        .set_file_name(format!("{name}.conf"))
        .set_title("Export WireGuard profile")
        .save_file()
        .await
        .map(|handle| handle.path().to_owned())
}

// ─────────────────────────────────────────────────────────────────────────────
// View / subscription / theme
// ─────────────────────────────────────────────────────────────────────────────

impl State {
    /// Dispatch to the per-screen view function.
    pub fn view(&self) -> Element<'_, Message> {
        match self.screen {
            Screen::ProfileList => crate::ui::profile_list::profile_list(self),
            Screen::Editor => crate::ui::editor::editor(self),
            Screen::RawEditor => crate::ui::editor::raw_editor(self),
            Screen::PlanPreview => crate::ui::plan::plan_preview(self),
            Screen::Settings => crate::ui::settings::settings(self),
            Screen::Server => crate::ui::server::server(self),
        }
    }

    /// The window title (used by both `application` and `daemon`).
    pub fn title(&self) -> String {
        match &self.tunnel_status {
            TunnelStatus::Connected(name) => format!("WireGuard — {name} (connected)"),
            TunnelStatus::Connecting(name) => format!("WireGuard — connecting {name}…"),
            TunnelStatus::Disconnecting => "WireGuard — disconnecting…".to_owned(),
            TunnelStatus::Error(_) => "WireGuard — error".to_owned(),
            TunnelStatus::Disconnected => "WireGuard".to_owned(),
        }
    }

    /// Subscriptions: tray events, single-instance raises, periodic status, window close.
    pub fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![
            Subscription::run(tray_event_stream),
            Subscription::run(raise_event_stream),
            iced::time::every(std::time::Duration::from_secs(5)).map(|_| Message::StatusTick),
            window::close_requests().map(Message::WindowCloseRequested),
            window::open_events().map(Message::WindowOpened),
        ];
        // Poll the server's live peer status while the server interface is up. The
        // `ServerStatusTick` handler is itself a no-op when the server is down or the
        // config is gone, so this is doubly guarded. The `wg show … dump` it triggers
        // is read-only and needs no root (degrades to empty on failure).
        if self.server_running {
            subs.push(
                iced::time::every(std::time::Duration::from_secs(5))
                    .map(|_| Message::ServerStatusTick),
            );
        }
        Subscription::batch(subs)
    }

    /// Resolve the active iced [`Theme`] from the user's preference.
    ///
    /// Delegates to [`crate::ui::theme::app_theme`] — the single decision point
    /// for the app's theme — so the shared screen helpers (cards, pills, button
    /// styles) and the active theme always agree. The custom dark/light variants
    /// carry the blue shield accent; `Named(..)` passes through to a built-in
    /// iced theme.
    pub fn theme(&self) -> Theme {
        crate::ui::theme::app_theme(&self.settings)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscription streams (reuse the proven Phase-0 tray bridge pattern)
// ─────────────────────────────────────────────────────────────────────────────

/// Bridge tray menu/activate events into the iced message pipeline.
fn tray_event_stream() -> impl iced::futures::Stream<Item = Message> {
    iced::stream::channel(16, |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
        let rx = TRAY_EVENTS.get().and_then(|m| m.lock().unwrap().take());
        if let Some(mut rx) = rx {
            while let Some(event) = rx.recv().await {
                let msg = match event {
                    TrayEvent::Open => Message::TrayOpen,
                    TrayEvent::Quit => Message::TrayQuit,
                    TrayEvent::ConnectProfile(name) => Message::TrayConnectProfile(name),
                    TrayEvent::Disconnect => Message::TrayDisconnect,
                };
                if output.send(msg).await.is_err() {
                    break;
                }
            }
        }
    })
}

/// Bridge single-instance "raise" requests into the iced message pipeline.
fn raise_event_stream() -> impl iced::futures::Stream<Item = Message> {
    iced::stream::channel(4, |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
        let rx = RAISE_EVENTS.get().and_then(|m| m.lock().unwrap().take());
        if let Some(mut rx) = rx {
            while rx.recv().await.is_some() {
                if output.send(Message::RaiseWindowRequested).await.is_err() {
                    break;
                }
            }
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure helpers only (no iced runtime, no I/O, no root, no network).
// These cover the Phase-3 wiring helpers used to build the kill-switch arm command
// and to feed the auto-reconnect watchdog.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::status::{LiveStatus, PeerStatus};
    use std::time::{Duration, SystemTime};

    // ── split_endpoint ────────────────────────────────────────────────────────

    #[test]
    fn split_endpoint_ipv4_host_port() {
        assert_eq!(
            split_endpoint("203.0.113.7:51820"),
            Some(("203.0.113.7".to_string(), 51820))
        );
    }

    #[test]
    fn split_endpoint_hostname_host_port() {
        assert_eq!(
            split_endpoint("vpn.example.com:51820"),
            Some(("vpn.example.com".to_string(), 51820))
        );
    }

    #[test]
    fn split_endpoint_ipv6_bracketed() {
        assert_eq!(
            split_endpoint("[2001:db8::1]:51820"),
            Some(("2001:db8::1".to_string(), 51820))
        );
    }

    #[test]
    fn split_endpoint_trims_whitespace() {
        assert_eq!(
            split_endpoint("  198.51.100.1:13231  "),
            Some(("198.51.100.1".to_string(), 13231))
        );
    }

    #[test]
    fn split_endpoint_missing_port_is_none() {
        assert_eq!(split_endpoint("203.0.113.7"), None);
    }

    #[test]
    fn split_endpoint_non_numeric_port_is_none() {
        assert_eq!(split_endpoint("203.0.113.7:notaport"), None);
        assert_eq!(split_endpoint("[2001:db8::1]:nope"), None);
    }

    #[test]
    fn split_endpoint_empty_host_is_none() {
        assert_eq!(split_endpoint(":51820"), None);
        assert_eq!(split_endpoint("[]:51820"), None);
    }

    #[test]
    fn split_endpoint_port_out_of_u16_range_is_none() {
        // 70000 > u16::MAX → reject.
        assert_eq!(split_endpoint("203.0.113.7:70000"), None);
    }

    // ── latest_handshake_age_secs ─────────────────────────────────────────────

    fn peer_with_handshake(hs: Option<SystemTime>) -> PeerStatus {
        PeerStatus {
            public_key: "k".into(),
            endpoint: None,
            last_handshake: hs,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    fn status_with(peers: Vec<PeerStatus>) -> LiveStatus {
        LiveStatus {
            interface: "wg-gui0".into(),
            public_key: "pk".into(),
            peers,
            fetched_at: SystemTime::now(),
        }
    }

    #[test]
    fn handshake_age_none_when_no_handshakes() {
        let st = status_with(vec![peer_with_handshake(None), peer_with_handshake(None)]);
        assert_eq!(latest_handshake_age_secs(&st), None);
    }

    #[test]
    fn handshake_age_no_peers_is_none() {
        let st = status_with(vec![]);
        assert_eq!(latest_handshake_age_secs(&st), None);
    }

    #[test]
    fn handshake_age_picks_most_recent() {
        let now = SystemTime::now();
        let old = now - Duration::from_secs(300);
        let recent = now - Duration::from_secs(5);
        let st = status_with(vec![
            peer_with_handshake(Some(old)),
            peer_with_handshake(Some(recent)),
            peer_with_handshake(None),
        ]);
        let age = latest_handshake_age_secs(&st).expect("should have an age");
        // The freshest handshake was ~5s ago; allow a small slop for test runtime.
        assert!((4..=30).contains(&age), "expected ~5s, got {age}");
    }

    // ── KILL_SWITCH_LEASE_SECS sanity ─────────────────────────────────────────

    #[test]
    fn kill_switch_lease_is_positive_and_reasonable() {
        // Must be long enough to outlast a polkit prompt + connect, but bounded so a
        // dead GUI's kill-switch self-heals within an hour. These bounds are on a
        // compile-time const, so assert them at compile time.
        const {
            assert!(KILL_SWITCH_LEASE_SECS >= 60);
            assert!(KILL_SWITCH_LEASE_SECS <= 86_400);
        }
    }

    // ── dashboard state additions ─────────────────────────────────────────────

    #[test]
    fn new_state_inits_dashboard_fields_empty() {
        let (state, _task) = State::new();
        assert!(state.connected_since.is_none());
        assert!(state.throughput_history.is_empty());
    }

    #[test]
    fn push_throughput_sample_appends_in_order() {
        let (mut state, _task) = State::new();
        state.push_throughput_sample(10, 20);
        state.push_throughput_sample(30, 40);
        let samples: Vec<_> = state.throughput_history.iter().copied().collect();
        assert_eq!(samples, vec![(10, 20), (30, 40)]);
    }

    #[test]
    fn push_throughput_sample_caps_history_evicting_oldest() {
        let (mut state, _task) = State::new();
        // Push one more than the cap; the oldest must be evicted.
        for i in 0..(THROUGHPUT_HISTORY_LEN as u64 + 5) {
            state.push_throughput_sample(i, i * 2);
        }
        assert_eq!(state.throughput_history.len(), THROUGHPUT_HISTORY_LEN);
        // Front is the (5)th sample (0..=4 evicted); back is the last pushed.
        assert_eq!(state.throughput_history.front().copied(), Some((5, 10)));
        let last = THROUGHPUT_HISTORY_LEN as u64 + 4;
        assert_eq!(state.throughput_history.back().copied(), Some((last, last * 2)));
    }
}
