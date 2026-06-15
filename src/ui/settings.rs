//! Settings screen — behaviour toggles, theme picker, and advanced controls.
//!
//! Renders grouped card surfaces using [`crate::ui::theme`] helpers exclusively.
//! All colours, spacing, radii, and text sizes come from the shared palette so
//! the screen is cohesive with every other view. No inline colours or raw pixel
//! literals appear here.

use iced::widget::{
    button, checkbox, column, container, pick_list, row, scrollable, text, Space,
};
use iced::{Alignment, Background, Border, Element, Length, Padding, Theme};

use crate::app::{Message, State};
use crate::settings::ThemePreference;
use crate::ui::theme::{
    self, body, card_style, icons, muted, section_title, title,
    CARD_PADDING, SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XL, SPACE_XS,
    TEXT_BODY, TEXT_CAPTION,
};

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

/// Render the settings screen using theme:: card surfaces and helpers.
pub fn settings(state: &State) -> Element<'_, Message> {
    let s = &state.settings;

    // ── Header bar ────────────────────────────────────────────────────────────
    let back_btn = button(
        row![
            text(icons::BACK).size(TEXT_BODY),
            text("Back").size(TEXT_BODY),
        ]
        .spacing(SPACE_XS)
        .align_y(Alignment::Center),
    )
    .on_press(Message::GoHome)
    .padding(Padding::from([SPACE_SM as u16, SPACE_MD as u16]))
    .style(theme::ghost());

    let header = container(
        row![
            back_btn,
            Space::new().width(SPACE_MD),
            row![
                text(icons::GEAR).size(TEXT_BODY),
                title("Settings"),
            ]
            .spacing(SPACE_SM)
            .align_y(Alignment::Center),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([SPACE_MD as u16, SPACE_LG as u16]))
    .width(Length::Fill)
    .style(|theme: &Theme| {
        let p = theme::palette(theme);
        container::Style {
            background: Some(Background::Color(p.surface)),
            border: Border {
                color: p.border,
                width: 0.0,
                radius: 0.0.into(),
            },
            ..container::Style::default()
        }
    });

    // ── Behaviour card ────────────────────────────────────────────────────────
    let auto_reconnect_row = toggle_row(
        "\u{21BB}  Auto-reconnect",
        "Automatically reconnect when the tunnel drops unexpectedly.",
        checkbox(s.auto_reconnect)
            .on_toggle(Message::SettingAutoReconnectToggled)
            .into(),
    );

    let autostart_row = toggle_row(
        "\u{23FB}  Start on login",
        "Launch WireGuard GUI automatically when you log in.",
        checkbox(s.autostart)
            .on_toggle(Message::SettingAutoStartToggled)
            .into(),
    );

    let behaviour_card = card_section(
        "Behaviour",
        column![
            auto_reconnect_row,
            row_divider(),
            autostart_row,
        ]
        .spacing(0),
    );

    // ── Appearance card ───────────────────────────────────────────────────────
    let selected_theme = ThemeOption::from_preference(&s.theme);

    // When a Named theme is active (set outside the picker), show a caption.
    let named_note: Element<'_, Message> = if let ThemePreference::Named(name) = &s.theme {
        muted(format!("Active named theme: {name}")).into()
    } else {
        text("").size(1).into()
    };

    let theme_row = row![
        column![
            body("\u{2609}  Theme"),
            muted("Choose light, dark, or follow the system preference."),
        ]
        .spacing(SPACE_XS)
        .width(Length::Fill),
        column![
            pick_list(ThemeOption::ALL, selected_theme, |opt: ThemeOption| {
                Message::SettingThemeChanged(opt.into_preference())
            })
            .width(Length::Fixed(160.0)),
            named_note,
        ]
        .spacing(SPACE_XS)
        .align_x(Alignment::End),
    ]
    .spacing(SPACE_MD)
    .align_y(Alignment::Center)
    .padding(Padding::from([SPACE_SM as u16, 0u16]));

    let appearance_card = card_section("Appearance", column![theme_row].spacing(0));

    // ── Advanced card ─────────────────────────────────────────────────────────
    let kill_switch_row = toggle_row(
        "\u{1F512}  Kill switch",
        "Block all non-tunnel traffic while the VPN is up; armed on connect, \
         removed on disconnect.",
        checkbox(s.kill_switch)
            .on_toggle(Message::SettingKillSwitchToggled)
            .into(),
    );

    // Connect-on-boot binds the currently-selected profile to a boot unit.
    // The checkbox is enabled only when a profile is active to bind to.
    let active = state.active_profile.clone();
    let boot_on = s.connect_on_boot.is_some();
    let boot_profile = s.connect_on_boot.as_deref().unwrap_or("none");
    let connect_on_boot_checkbox = {
        let cb = checkbox(boot_on);
        match (boot_on, active) {
            (true, _) => cb.on_toggle(|_| Message::SettingConnectOnBootChanged(None)),
            (false, Some(name)) => {
                cb.on_toggle(move |_| Message::SettingConnectOnBootChanged(Some(name.clone())))
            }
            (false, None) => cb,
        }
    };
    let connect_on_boot_row = toggle_row_owned(
        "\u{23FB}  Connect on boot".to_string(),
        format!("Auto-connect a profile at startup.  Bound: {boot_profile}"),
        connect_on_boot_checkbox.into(),
    );

    let advanced_card = card_section(
        "Advanced",
        column![
            kill_switch_row,
            row_divider(),
            connect_on_boot_row,
        ]
        .spacing(0),
    );

    // ── Scroll body ───────────────────────────────────────────────────────────
    let body_col = column![
        behaviour_card,
        appearance_card,
        advanced_card,
    ]
    .spacing(SPACE_MD)
    .padding(Padding::from([SPACE_LG as u16, SPACE_XL as u16]));

    let scrolled = scrollable(body_col).height(Length::Fill);

    container(
        column![header, scrolled].spacing(0),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(|theme: &Theme| {
        let p = theme::palette(theme);
        container::Style {
            background: Some(Background::Color(p.bg)),
            ..container::Style::default()
        }
    })
    .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Layout helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A card with a section title label above the content rows.
fn card_section<'a>(
    label: &'a str,
    content: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    column![
        section_title(label),
        container(content)
            .padding(0)
            .width(Length::Fill)
            .style(card_style),
    ]
    .spacing(SPACE_SM)
    .width(Length::Fill)
    .into()
}

/// A thin horizontal divider inside a card (not a `rule` — a styled container
/// so it respects the card's surface colour without hard-coding a colour here).
fn row_divider<'a>() -> Element<'a, Message> {
    container(text("").size(1))
        .width(Length::Fill)
        .height(1u32)
        .style(|theme: &Theme| {
            let p = theme::palette(theme);
            container::Style {
                background: Some(Background::Color(p.border)),
                ..container::Style::default()
            }
        })
        .into()
}

/// A settings row: label + description on the left, an interactive widget on the right.
/// Uses `surface_style` for the hover-area container and `theme::body` / `theme::muted`
/// for text — no inline colours.
fn toggle_row<'a>(
    label: &'a str,
    description: &'a str,
    widget: Element<'a, Message>,
) -> Element<'a, Message> {
    container(
        row![
            column![
                text(label).size(TEXT_BODY).style(|theme: &Theme| {
                    iced::widget::text::Style {
                        color: Some(theme::palette(theme).text),
                    }
                }),
                text(description).size(TEXT_CAPTION).style(|theme: &Theme| {
                    iced::widget::text::Style {
                        color: Some(theme::palette(theme).muted),
                    }
                }),
            ]
            .spacing(SPACE_XS)
            .width(Length::Fill),
            widget,
        ]
        .spacing(SPACE_MD)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([SPACE_MD as u16, CARD_PADDING as u16]))
    .width(Length::Fill)
    .into()
}

/// Like [`toggle_row`] but takes owned label/description strings so the row can
/// carry text built at call time (e.g. interpolated profile names) without
/// borrowing the caller's locals.
fn toggle_row_owned<'a>(
    label: String,
    description: String,
    widget: Element<'a, Message>,
) -> Element<'a, Message> {
    container(
        row![
            column![
                text(label).size(TEXT_BODY).style(|theme: &Theme| {
                    iced::widget::text::Style {
                        color: Some(theme::palette(theme).text),
                    }
                }),
                text(description).size(TEXT_CAPTION).style(|theme: &Theme| {
                    iced::widget::text::Style {
                        color: Some(theme::palette(theme).muted),
                    }
                }),
            ]
            .spacing(SPACE_XS)
            .width(Length::Fill),
            widget,
        ]
        .spacing(SPACE_MD)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([SPACE_MD as u16, CARD_PADDING as u16]))
    .width(Length::Fill)
    .into()
}

// `info_row` is kept for potential future use as a read-only informational row.
//
// Takes owned strings so the returned element borrows nothing from the caller's
// locals (the fragments are moved into the `text` widgets).
#[allow(dead_code)]
fn info_row(
    label: impl Into<String>,
    description: impl Into<String>,
    status: impl Into<String>,
) -> Element<'static, Message> {
    container(
        row![
            column![
                text(label.into()).size(TEXT_BODY),
                text(description.into()).size(TEXT_CAPTION).style(
                    |theme: &Theme| iced::widget::text::Style {
                        color: Some(theme::palette(theme).muted),
                    }
                ),
            ]
            .spacing(SPACE_XS)
            .width(Length::Fill),
            text(status.into()).size(TEXT_CAPTION).style(|theme: &Theme| {
                iced::widget::text::Style {
                    color: Some(theme::palette(theme).muted),
                }
            }),
        ]
        .spacing(SPACE_MD)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([SPACE_MD as u16, CARD_PADDING as u16]))
    .width(Length::Fill)
    .into()
}
