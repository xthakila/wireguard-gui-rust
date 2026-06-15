//! ksni system tray (pure-Rust StatusNotifierItem, no libappindicator C dep).
//!
//! Proves: a tray icon appears against the live `org.kde.StatusNotifierWatcher`, menu clicks
//! reach the app via a channel, and the icon can be swapped at runtime via `handle.update()`.
//!
//! Feature 3 (tray quick-connect) extends the tray with a live profile list: the
//! menu renders a "Connect" submenu of every profile and a "Disconnect" item, and
//! the app pushes the current profile list / connected profile into the tray at
//! runtime via [`TrayCmd`] (applied through `handle.update()`).

use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, Tray};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Events produced by the tray, forwarded into the iced message pipeline.
#[derive(Debug, Clone)]
pub enum TrayEvent {
    Open,
    Quit,
    /// Quick-connect to the named profile (from the "Connect" submenu).
    ConnectProfile(String),
    /// Disconnect the current tunnel (from the "Disconnect" item).
    Disconnect,
}

/// Runtime commands the app pushes into the tray via `handle.update()`.
///
/// These let the reducer keep the tray's menu in sync with app state without the
/// tray reaching back into `State`: the app sends the current profile names and
/// which one (if any) is connected.
#[derive(Debug, Clone)]
pub enum TrayCmd {
    /// Replace the profile list shown in the "Connect" submenu.
    SetProfiles(Vec<String>),
    /// Set (or clear) which profile is currently connected.
    SetConnected(Option<String>),
}

/// The ksni tray model. `connected` drives the icon/title; `tx` ships menu events out.
///
/// `profiles` / `connected_profile` back the quick-connect submenu and are updated
/// at runtime via [`AppTray::apply`] (called from the app's `handle.update()`).
pub struct AppTray {
    /// Whether a tunnel is up (drives the icon/title).
    pub connected: bool,
    /// All known profile names, rendered in the "Connect" submenu.
    pub profiles: Vec<String>,
    /// The currently-connected profile, if any (rendered as a checkmark / disables
    /// its own Connect entry).
    pub connected_profile: Option<String>,
    tx: UnboundedSender<TrayEvent>,
}

impl AppTray {
    /// Apply a runtime [`TrayCmd`] to this tray model. Invoked from the app's
    /// `handle.update(|t| t.apply(cmd))`.
    pub fn apply(&mut self, cmd: TrayCmd) {
        match cmd {
            TrayCmd::SetProfiles(profiles) => self.profiles = profiles,
            TrayCmd::SetConnected(connected) => {
                self.connected = connected.is_some();
                self.connected_profile = connected;
            }
        }
    }
}

impl Tray for AppTray {
    fn id(&self) -> String {
        "wireguard-gui-rust-spike".into()
    }

    fn icon_name(&self) -> String {
        // Full-color themed icons (NOT a monochrome template — that was the old bug).
        if self.connected {
            "network-vpn".into()
        } else {
            "network-vpn-disconnected".into()
        }
    }

    fn title(&self) -> String {
        if self.connected {
            "WireGuard — connected".into()
        } else {
            "WireGuard — disconnected".into()
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let tx_open = self.tx.clone();
        let tx_quit = self.tx.clone();
        let tx_disconnect = self.tx.clone();

        // "Connect" submenu: one StandardItem per profile. Clicking sends a
        // ConnectProfile event. The currently-connected profile's entry is
        // disabled so it can't be re-triggered.
        let connect_items: Vec<MenuItem<Self>> = self
            .profiles
            .iter()
            .map(|name| {
                let tx = self.tx.clone();
                let profile = name.clone();
                let is_connected = self.connected_profile.as_deref() == Some(name.as_str());
                // Connected profile: disabled so it cannot be re-triggered, and its
                // label carries a "(connected)" suffix so the user can see which
                // profile is active at a glance without enabling the item.
                let label = if is_connected {
                    format!("{name} (connected)")
                } else {
                    name.clone()
                };
                StandardItem {
                    label,
                    enabled: !is_connected,
                    activate: Box::new(move |_: &mut Self| {
                        let _ = tx.send(TrayEvent::ConnectProfile(profile.clone()));
                    }),
                    ..Default::default()
                }
                .into()
            })
            .collect();

        vec![
            StandardItem {
                label: "Open".into(),
                activate: Box::new(move |_: &mut Self| {
                    let _ = tx_open.send(TrayEvent::Open);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            SubMenu {
                label: "Connect".into(),
                enabled: !connect_items.is_empty(),
                submenu: connect_items,
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Disconnect".into(),
                enabled: self.connected,
                activate: Box::new(move |_: &mut Self| {
                    let _ = tx_disconnect.send(TrayEvent::Disconnect);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(move |_: &mut Self| {
                    let _ = tx_quit.send(TrayEvent::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        // Left-click on the tray icon → raise the window.
        let _ = self.tx.send(TrayEvent::Open);
    }
}

/// Spawn the tray on its own thread (ksni `blocking` feature). Returns a handle for
/// runtime updates and a receiver of tray menu/activate events.
pub fn spawn_tray() -> (ksni::blocking::Handle<AppTray>, UnboundedReceiver<TrayEvent>) {
    use ksni::blocking::TrayMethods;
    let (tx, rx) = unbounded_channel();
    let tray = AppTray {
        connected: false,
        profiles: Vec::new(),
        connected_profile: None,
        tx,
    };
    let handle = tray.spawn().expect("failed to register system tray");
    (handle, rx)
}
