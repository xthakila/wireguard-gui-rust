//! wireguard-gui-rust — a pure-Rust WireGuard GUI (Iced 0.14 + ksni system tray).
//!
//! `main` wires the load-bearing runtime pieces proven in the Phase-0 spike:
//!   - single-instance enforcement (abstract-namespace Unix socket); a second launch signals
//!     the primary to raise its window, then exits.
//!   - a ksni system tray, bridged into iced messages, with runtime icon swap + close-to-tray.
//!   - the real `iced::application` (or `iced::daemon` when started `--hidden`).
//!
//! The application state, reducer, and views live in `app` + `ui::*`.

// Phase-2 CORE: the `ui::*` views are placeholder stubs and several Phase-1/3 items remain
// unwired (netns, killswitch, privilege), so silence the resulting dead-code warnings for now.
#![allow(dead_code)]

mod app;
mod autostart;
mod config;
mod error;
mod net;
mod public_ip;
mod settings;
mod single_instance;
mod tray;
mod ui;
mod wg;

use app::State;
use single_instance::{try_become_primary, InstanceResult};
use tray::spawn_tray;

// Free `fn` items (NOT closures) for the daemon callbacks. Using `fn`s sidesteps the
// higher-ranked-lifetime inference failure that bites closures whose body returns a borrow
// of the `&State` argument (`ViewFn ... is not general enough`).
fn daemon_view(state: &State, _window: iced::window::Id) -> iced::Element<'_, app::Message> {
    state.view()
}
fn daemon_title(state: &State, _window: iced::window::Id) -> String {
    state.title()
}
fn daemon_theme(state: &State, _window: iced::window::Id) -> iced::Theme {
    state.theme()
}

pub fn main() -> iced::Result {
    // --- Single-instance: a second launch raises the primary's window then exits. ---
    match try_become_primary() {
        Ok(InstanceResult::Secondary) => {
            // We already signalled the primary inside try_become_primary(); nothing more to do.
            std::process::exit(0);
        }
        Ok(InstanceResult::Primary(guard, listener)) => {
            // --- We are the primary. Parse flags, spawn the tray, stash runtime globals. ---
            let start_hidden = std::env::args().any(|a| a == "--hidden");

            let (tray_handle, tray_events) = spawn_tray();
            app::install_runtime(tray_handle, tray_events, guard, listener);

            run_gui(start_hidden)
        }
        Err(e) => {
            eprintln!("fatal: single-instance check failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Launch the iced GUI. `start_hidden` selects the daemon (window-less) path so the app can
/// boot straight to the tray; otherwise we run a normal windowed application.
fn run_gui(start_hidden: bool) -> iced::Result {
    if start_hidden {
        // Daemon mode: no window is created on boot. The tray "Open" action (or a single-instance
        // raise) opens one on demand via `window::open` in the reducer.
        iced::daemon(|| State::new_with(true), State::update, daemon_view)
            .title(daemon_title)
            .subscription(State::subscription)
            .theme(daemon_theme)
            .run()
    } else {
        // Normal windowed application; we intercept the close button for close-to-tray.
        // Pass method references (not closures) so the view/title/theme lifetimes stay generic.
        iced::application(State::new, State::update, State::view)
            .title(State::title)
            .subscription(State::subscription)
            .theme(State::theme)
            .exit_on_close_request(false)
            .run()
    }
}
