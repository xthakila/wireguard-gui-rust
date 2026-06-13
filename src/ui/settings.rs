//! Settings screen — behaviour toggles, theme picker, and Phase-3 placeholder rows.

use iced::widget::{button, checkbox, column, container, pick_list, row, rule, scrollable, text};
use iced::{Alignment, Element, Length, Padding};

use crate::app::{Message, State};
use crate::settings::ThemePreference;

// ─────────────────────────────────────────────────────────────────────────────
// Local theme-option enum used by the pick_list.
//
// `ThemePreference::Named(String)` is intentionally excluded from the picker;
// those values come from external config/override, not from user-facing clicks.
// ─────────────────────────────────────────────────────────────────────────────

/// The three user-facing theme choices exposed in the pick_list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThemeOption {
    FollowSystem,
    Light,
    Dark,
}

impl ThemeOption {
    const ALL: &'static [ThemeOption] = &[
        ThemeOption::FollowSystem,
        ThemeOption::Light,
        ThemeOption::Dark,
    ];

    fn into_preference(self) -> ThemePreference {
        match self {
            ThemeOption::FollowSystem => ThemePreference::FollowSystem,
            ThemeOption::Light => ThemePreference::Light,
            ThemeOption::Dark => ThemePreference::Dark,
        }
    }

    fn from_preference(pref: &ThemePreference) -> Option<Self> {
        match pref {
            ThemePreference::FollowSystem => Some(ThemeOption::FollowSystem),
            ThemePreference::Light => Some(ThemeOption::Light),
            ThemePreference::Dark => Some(ThemeOption::Dark),
            ThemePreference::Named(_) => None,
        }
    }
}

impl std::fmt::Display for ThemeOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThemeOption::FollowSystem => f.write_str("Follow System"),
            ThemeOption::Light => f.write_str("Light"),
            ThemeOption::Dark => f.write_str("Dark"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// View entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Render the settings screen.
pub fn settings(state: &State) -> Element<'_, Message> {
    let s = &state.settings;

    // ── header ─────────────────────────────────────────────────────────────────
    let header = row![
        button(text("← Back"))
            .on_press(Message::GoHome)
            .padding(Padding::from([6u16, 14u16])),
        text("Settings").size(22),
    ]
    .spacing(16)
    .align_y(Alignment::Center);

    // ── Behaviour section ──────────────────────────────────────────────────────
    let auto_reconnect_row = toggle_row(
        "Auto-reconnect",
        "Automatically reconnect when the tunnel drops unexpectedly.",
        checkbox(s.auto_reconnect)
            .on_toggle(Message::SettingAutoReconnectToggled)
            .into(),
    );

    let autostart_row = toggle_row(
        "Start on login",
        "Launch WireGuard GUI automatically when you log in.",
        checkbox(s.autostart)
            .on_toggle(Message::SettingAutoStartToggled)
            .into(),
    );

    // ── Appearance section ─────────────────────────────────────────────────────
    let selected_theme = ThemeOption::from_preference(&s.theme);

    // When a Named theme is active (set outside the picker), surface it as a note.
    let named_note: Element<'_, Message> = if let ThemePreference::Named(name) = &s.theme {
        text(format!("Active named theme: {name}")).size(12).into()
    } else {
        text("").size(1).into()
    };

    let theme_row = row![
        column![
            text("Theme").size(14),
            text("Choose between light, dark, or follow the system preference.").size(12),
        ]
        .spacing(2)
        .width(Length::Fill),
        column![
            pick_list(ThemeOption::ALL, selected_theme, |opt: ThemeOption| {
                Message::SettingThemeChanged(opt.into_preference())
            })
            .width(Length::Fixed(160.0)),
            named_note,
        ]
        .spacing(4)
        .align_x(Alignment::End),
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .padding(Padding::from([10u16, 0u16]));

    // ── Advanced section (Phase 3 placeholders) ────────────────────────────────
    let kill_switch_label = if s.kill_switch { "Enabled" } else { "Disabled" };
    let kill_switch_row = info_row(
        "Kill switch",
        "Block all traffic if the VPN tunnel drops. (Wired in Phase 3.)",
        format!("{kill_switch_label} — Phase 3"),
    );

    let boot_profile = s.connect_on_boot.as_deref().unwrap_or("(none)");
    let connect_on_boot_row = info_row(
        "Connect on boot",
        format!("Profile to connect at startup. Currently: {boot_profile}"),
        "Phase 3",
    );

    // ── assemble ───────────────────────────────────────────────────────────────
    let content = column![
        header,
        rule::horizontal(1u32),
        section_heading("Behaviour"),
        auto_reconnect_row,
        autostart_row,
        rule::horizontal(1u32),
        section_heading("Appearance"),
        theme_row,
        rule::horizontal(1u32),
        section_heading("Advanced"),
        kill_switch_row,
        connect_on_boot_row,
    ]
    .spacing(4)
    .padding(Padding::from([16u16, 20u16]));

    container(scrollable(content).height(Length::Fill))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Layout helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A bold section heading with a small top spacer.
fn section_heading(label: &str) -> Element<'_, Message> {
    column![text("").size(4), text(label).size(16)]
        .spacing(0)
        .into()
}

/// A settings row: label + description on the left, an interactive widget on the right.
fn toggle_row<'a>(
    label: &'a str,
    description: &'a str,
    widget: Element<'a, Message>,
) -> Element<'a, Message> {
    row![
        column![text(label).size(14), text(description).size(12),]
            .spacing(2)
            .width(Length::Fill),
        widget,
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .padding(Padding::from([10u16, 0u16]))
    .into()
}

/// A read-only informational row for Phase-3 placeholders.
///
/// Takes owned strings so the returned element borrows nothing from the caller's
/// locals (the fragments are moved into the `text` widgets).
fn info_row(
    label: impl Into<String>,
    description: impl Into<String>,
    status: impl Into<String>,
) -> Element<'static, Message> {
    row![
        column![text(label.into()).size(14), text(description.into()).size(12),]
            .spacing(2)
            .width(Length::Fill),
        text(status.into()).size(12),
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .padding(Padding::from([10u16, 0u16]))
    .into()
}
