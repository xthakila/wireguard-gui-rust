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
use crate::tray::{AppTray, TrayEvent};
use crate::wg::backend::detect_backend;
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

/// Dead-man lease (seconds) for the kill-switch arm. The root-side `systemd-run`
/// timer flushes the nftables table if the GUI dies without disarming. We arm with
/// a generous lease; renewal-on-tick is an owner-enabled refinement (each renewal
/// would re-trigger pkexec), so a single connect-time arm is the default behaviour.
const KILL_SWITCH_LEASE_SECS: u64 = 3600;

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
    RawTextChanged(String),
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

    // ── misc ──────────────────────────────────────────────────────────────────
    DismissBanner,
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
        };

        // Load all profiles (list names → read each) and settings concurrently.
        let load_profiles = Task::perform(load_all_profiles(profile_store), Message::ProfilesLoaded);
        let load_settings = Task::perform(load_settings_async(), Message::SettingsLoaded);

        (state, Task::batch([load_profiles, load_settings]))
    }

    /// Read-only accessor for the start-hidden flag (used by `main` window setup).
    pub fn start_hidden(&self) -> bool {
        self.start_hidden
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
                let iface = self
                    .live_status
                    .as_ref()
                    .map(|s| s.interface.clone())
                    .or_else(|| self.active_profile.clone());
                self.tunnel_status = TunnelStatus::Disconnecting;
                let Some(iface) = iface else {
                    self.set_banner(BannerKind::Warning, "No active tunnel to disconnect".to_owned());
                    self.tunnel_status = TunnelStatus::Disconnected;
                    return Task::none();
                };
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
                    _ => Screen::RawEditor,
                };
                Task::none()
            }
            Message::RawTextChanged(text) => {
                if let Some(editor) = self.editor.as_mut() {
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
                    Ok(status) => self.live_status = status,
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

            // ── misc ──────────────────────────────────────────────────────────
            Message::DismissBanner => {
                self.banner = None;
                Task::none()
            }
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn set_banner(&mut self, kind: BannerKind, message: String) {
        self.banner = Some(Banner { kind, message });
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

    /// Refresh live status (for the active interface) and the public IP.
    fn status_refresh_task(&mut self) -> Task<Message> {
        self.public_ip_loading = true;
        let iface = self
            .live_status
            .as_ref()
            .map(|s| s.interface.clone())
            .or_else(|| match &self.tunnel_status {
                TunnelStatus::Connected(name) | TunnelStatus::Connecting(name) => Some(name.clone()),
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
    /// The interface name is derived from the live status if known, otherwise from
    /// the NetworkManager connection-name convention (`wg-gui-<profile>`).
    /// `lan_cidrs` default to the user's configured `destination_split` (the local
    /// networks to keep reachable), or empty.
    fn arm_kill_switch_task(&self, profile_name: &str) -> Option<Task<Message>> {
        let profile = self.find_profile(profile_name)?;
        // Endpoint of the first peer that has one — this is the punch-through hole.
        let endpoint = profile.peers.iter().find_map(|p| p.endpoint.clone())?;
        let (endpoint_ip, endpoint_port) = split_endpoint(&endpoint)?;

        // Interface as the kernel sees it: prefer the live status, else the NM name.
        let iface = self
            .live_status
            .as_ref()
            .map(|s| s.interface.clone())
            .unwrap_or_else(|| crate::wg::backend::nm_connection_name(profile_name));

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
        Subscription::batch([
            Subscription::run(tray_event_stream),
            Subscription::run(raise_event_stream),
            iced::time::every(std::time::Duration::from_secs(5)).map(|_| Message::StatusTick),
            window::close_requests().map(Message::WindowCloseRequested),
            window::open_events().map(Message::WindowOpened),
        ])
    }

    /// Resolve the active iced [`Theme`] from the user's preference.
    ///
    /// `FollowSystem` maps to `Dark` for now (no system-theme detector is wired yet — iced
    /// 0.14 exposes no stable light/dark query, so we do NOT invent one).
    pub fn theme(&self) -> Theme {
        match &self.settings.theme {
            ThemePreference::Light => Theme::Light,
            ThemePreference::Dark => Theme::Dark,
            ThemePreference::FollowSystem => Theme::Dark,
            ThemePreference::Named(name) => named_theme(name),
        }
    }
}

/// Map a named-theme string to an iced built-in theme, defaulting to `Dark`.
fn named_theme(name: &str) -> Theme {
    match name {
        "Light" => Theme::Light,
        "Dark" => Theme::Dark,
        "Dracula" => Theme::Dracula,
        "Nord" => Theme::Nord,
        "SolarizedLight" => Theme::SolarizedLight,
        "SolarizedDark" => Theme::SolarizedDark,
        "GruvboxLight" => Theme::GruvboxLight,
        "GruvboxDark" => Theme::GruvboxDark,
        "CatppuccinLatte" => Theme::CatppuccinLatte,
        "CatppuccinFrappe" => Theme::CatppuccinFrappe,
        "CatppuccinMacchiato" => Theme::CatppuccinMacchiato,
        "CatppuccinMocha" => Theme::CatppuccinMocha,
        "TokyoNight" => Theme::TokyoNight,
        "TokyoNightStorm" => Theme::TokyoNightStorm,
        "TokyoNightLight" => Theme::TokyoNightLight,
        "KanagawaWave" => Theme::KanagawaWave,
        "KanagawaDragon" => Theme::KanagawaDragon,
        "KanagawaLotus" => Theme::KanagawaLotus,
        "Moonfly" => Theme::Moonfly,
        "Nightfly" => Theme::Nightfly,
        "Oxocarbon" => Theme::Oxocarbon,
        "Ferra" => Theme::Ferra,
        _ => Theme::Dark,
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
        // dead GUI's kill-switch self-heals within an hour.
        assert!(KILL_SWITCH_LEASE_SECS >= 60);
        assert!(KILL_SWITCH_LEASE_SECS <= 86_400);
    }
}
