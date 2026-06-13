//! Phase-0 spike: ksni system tray (pure-Rust StatusNotifierItem, no libappindicator C dep).
//!
//! Proves: a tray icon appears against the live `org.kde.StatusNotifierWatcher`, menu clicks
//! reach the app via a channel, and the icon can be swapped at runtime via `handle.update()`.

use ksni::menu::StandardItem;
use ksni::{MenuItem, Tray};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Events produced by the tray, forwarded into the iced message pipeline.
#[derive(Debug, Clone)]
pub enum TrayEvent {
    Open,
    Quit,
}

/// The ksni tray model. `connected` drives the icon/title; `tx` ships menu events out.
pub struct AppTray {
    pub connected: bool,
    tx: UnboundedSender<TrayEvent>,
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
        tx,
    };
    let handle = tray.spawn().expect("failed to register system tray");
    (handle, rx)
}
