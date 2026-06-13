//! Phase-0 spike for wireguard-gui-rust.
//!
//! Purpose: PROVE the load-bearing Iced 0.14 + ksni 0.3.5 patterns compile and run on this
//! box before building the real app:
//!   - functional `iced::application` builder + Task/Subscription
//!   - a ksni tray bridged into iced messages via `iced::stream::channel`
//!   - close-to-tray (intercept the window close, hide instead of quit)
//!   - runtime tray icon swap via `handle.update()`
//!
//! This file is throwaway scaffolding; it gets replaced by the real `app.rs`/`main.rs` in Phase 2.

use std::sync::{Mutex, OnceLock};

use iced::futures::SinkExt;
use iced::widget::{button, column, container, text};
use iced::window;
use iced::{Element, Length, Subscription, Task, Theme};
use tokio::sync::mpsc::UnboundedReceiver;

mod tray;
use tray::{spawn_tray, AppTray, TrayEvent};

// The tray handle (for runtime icon updates) and the event receiver are created once in
// `main` and stashed in globals so the iced `boot`/`subscription` (which take no args) can reach them.
static TRAY_HANDLE: OnceLock<ksni::blocking::Handle<AppTray>> = OnceLock::new();
static TRAY_EVENTS: OnceLock<Mutex<Option<UnboundedReceiver<TrayEvent>>>> = OnceLock::new();

pub fn main() -> iced::Result {
    let (handle, rx) = spawn_tray();
    let _ = TRAY_HANDLE.set(handle);
    let _ = TRAY_EVENTS.set(Mutex::new(Some(rx)));

    iced::application(State::new, State::update, State::view)
        .title("wireguard-gui-rust — spike")
        .subscription(State::subscription)
        .theme(|_state: &State| Theme::Dark)
        .exit_on_close_request(false) // we intercept the close button for close-to-tray
        .run()
}

#[derive(Default)]
struct State {
    connected: bool,
    window_id: Option<window::Id>,
    log: Vec<String>,
}

#[derive(Debug, Clone)]
enum Message {
    ToggleConnected,
    TrayOpen,
    TrayQuit,
    WindowCloseRequested(window::Id),
}

impl State {
    fn new() -> (Self, Task<Message>) {
        (State::default(), Task::none())
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ToggleConnected => {
                self.connected = !self.connected;
                let connected = self.connected;
                self.log.push(format!("toggle → connected={connected}"));
                if let Some(handle) = TRAY_HANDLE.get() {
                    // Swap the tray icon/title at runtime.
                    handle.update(move |t: &mut AppTray| t.connected = connected);
                }
                Task::none()
            }
            Message::TrayOpen => {
                self.log.push("tray: Open".into());
                if let Some(id) = self.window_id {
                    Task::batch([
                        window::set_mode(id, window::Mode::Windowed),
                        window::gain_focus(id),
                    ])
                } else {
                    Task::none()
                }
            }
            Message::TrayQuit => {
                self.log.push("tray: Quit".into());
                iced::exit()
            }
            Message::WindowCloseRequested(id) => {
                // Close-to-tray: remember the window and hide it instead of quitting.
                self.window_id = Some(id);
                self.log.push("close → hide to tray".into());
                window::set_mode(id, window::Mode::Hidden)
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let status = if self.connected {
            "CONNECTED"
        } else {
            "disconnected"
        };
        let log_lines: String = self
            .log
            .iter()
            .rev()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        container(
            column![
                text(format!("WireGuard status: {status}")).size(22),
                button(text(if self.connected {
                    "Disconnect (toggle)"
                } else {
                    "Connect (toggle)"
                }))
                .on_press(Message::ToggleConnected),
                text("Close the window → it hides to the tray. Tray menu → Open / Quit.").size(13),
                text(log_lines).size(12),
            ]
            .spacing(16)
            .padding(24),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            Subscription::run(tray_event_stream),
            window::close_requests().map(Message::WindowCloseRequested),
        ])
    }
}

/// Bridge the tray's event receiver into an iced subscription stream.
fn tray_event_stream() -> impl iced::futures::Stream<Item = Message> {
    iced::stream::channel(16, |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
        // Take the receiver out of the global (runs once for the lifetime of the app).
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
