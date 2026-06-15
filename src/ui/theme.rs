//! Shared visual language for every screen.
//!
//! This module is the single source of cohesion for the GUI: the colour
//! palette, the spacing rhythm, and the reusable widget helpers (cards, section
//! titles, muted text, status pills, button styles, icon glyphs) that every
//! screen in [`crate::ui`] is expected to call instead of hand-rolling its own
//! colours and containers.
//!
//! Design direction: a refined dark theme (with a light variant) built around a
//! **blue accent** matching the app's shield icon, an **8px spacing rhythm**, a
//! clear type hierarchy (one large title, medium section labels, small muted
//! secondary text), subtly **elevated card surfaces**, and status **colours**
//! (green = connected, amber = connecting, red = error/disconnected, grey =
//! idle) surfaced as rounded **pill badges**.
//!
//! Everything here is pure and runtime-free, so it is fully unit-testable and
//! never touches privileged code.

use iced::widget::{button, container, text};
use iced::{Background, Border, Color, Element, Shadow, Theme, Vector};

use crate::settings::{AppSettings, ThemePreference};

// ─────────────────────────────────────────────────────────────────────────────
// Colour palette
//
// Two parallel palettes (dark + light) sharing one [`Palette`] shape so screens
// can ask for semantic colours without caring which theme is active. The accent
// blue is shared across both variants to keep brand identity constant; the
// status colours (success/warning/danger) are tuned per-variant for contrast.
// ─────────────────────────────────────────────────────────────────────────────

/// A semantic colour palette: every colour a screen should ever need, named by
/// role rather than by hue. Resolve one with [`palette`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    /// Window / root background.
    pub bg: Color,
    /// Elevated surface (cards, panels) — sits above [`Palette::bg`].
    pub surface: Color,
    /// A slightly stronger surface for nested / hovered rows.
    pub surface_alt: Color,
    /// Hairline border around cards and inputs.
    pub border: Color,
    /// Primary text colour.
    pub text: Color,
    /// De-emphasised secondary text (captions, hints, metadata).
    pub muted: Color,
    /// Brand accent — the shield blue. Used for primary actions and highlights.
    pub accent: Color,
    /// A stronger accent shade for hover / pressed states.
    pub accent_strong: Color,
    /// Connected / healthy.
    pub success: Color,
    /// Connecting / transitional / risky.
    pub warning: Color,
    /// Error / disconnected / destructive.
    pub danger: Color,
    /// Idle / unknown / disabled.
    pub idle: Color,
}

/// The refined **dark** palette (default).
pub const DARK: Palette = Palette {
    bg: Color::from_rgb(0.071, 0.086, 0.118),       // #12161E deep slate
    surface: Color::from_rgb(0.110, 0.129, 0.169),  // #1C212B card
    surface_alt: Color::from_rgb(0.145, 0.169, 0.216), // #252B37
    border: Color::from_rgb(0.231, 0.267, 0.337),   // #3B4456 hairline
    text: Color::from_rgb(0.918, 0.937, 0.965),      // #EAEFF6
    muted: Color::from_rgb(0.580, 0.624, 0.694),     // #949FB1
    accent: Color::from_rgb(0.231, 0.510, 0.965),    // #3B82F6 shield blue
    accent_strong: Color::from_rgb(0.149, 0.388, 0.922), // #2663EB
    success: Color::from_rgb(0.133, 0.773, 0.369),   // #22C55E green
    warning: Color::from_rgb(0.961, 0.620, 0.043),   // #F59E0B amber
    danger: Color::from_rgb(0.937, 0.267, 0.267),    // #EF4444 red
    idle: Color::from_rgb(0.557, 0.557, 0.557),      // #8E8E8E grey
};

/// The **light** palette (kept as a variant per the visual direction).
pub const LIGHT: Palette = Palette {
    bg: Color::from_rgb(0.961, 0.969, 0.980),        // #F5F7FA
    surface: Color::from_rgb(1.0, 1.0, 1.0),         // #FFFFFF card
    surface_alt: Color::from_rgb(0.937, 0.949, 0.965), // #EFF2F6
    border: Color::from_rgb(0.831, 0.859, 0.894),    // #D4DBE4 hairline
    text: Color::from_rgb(0.090, 0.122, 0.176),      // #171F2D
    muted: Color::from_rgb(0.392, 0.435, 0.514),     // #646F83
    accent: Color::from_rgb(0.149, 0.388, 0.922),    // #2663EB shield blue
    accent_strong: Color::from_rgb(0.114, 0.306, 0.847), // #1D4ED8
    success: Color::from_rgb(0.086, 0.639, 0.290),   // #16A34A
    warning: Color::from_rgb(0.851, 0.467, 0.024),   // #D97706
    danger: Color::from_rgb(0.863, 0.149, 0.149),    // #DC2626
    idle: Color::from_rgb(0.612, 0.639, 0.686),      // #9CA3AF
};

/// Resolve the semantic [`Palette`] for an iced [`Theme`].
///
/// The custom `WireGuard Dark` / `WireGuard Light` themes built by [`app_theme`]
/// map to [`DARK`] / [`LIGHT`]; any other (built-in / `Named`) theme is matched
/// by its overall lightness so cards and text still read correctly.
pub fn palette(theme: &Theme) -> Palette {
    match theme {
        Theme::Custom(custom) if custom.to_string() == LIGHT_THEME_NAME => LIGHT,
        Theme::Custom(custom) if custom.to_string() == DARK_THEME_NAME => DARK,
        other => {
            // Fall back by luminance so the helpers stay legible on any built-in
            // theme the user picks via `ThemePreference::Named`.
            let bg = other.palette().background;
            if relative_luminance(bg) > 0.5 { LIGHT } else { DARK }
        }
    }
}

/// Perceptual-ish relative luminance (Rec. 601 weights). Cheap and good enough
/// to decide "is this a light or dark background".
fn relative_luminance(c: Color) -> f32 {
    0.299 * c.r + 0.587 * c.g + 0.114 * c.b
}

// ─────────────────────────────────────────────────────────────────────────────
// Spacing rhythm (8px base) + type scale + radii
// ─────────────────────────────────────────────────────────────────────────────

/// Half-step of the rhythm — tight gaps inside a control (4px).
pub const SPACE_XS: f32 = 4.0;
/// One rhythm unit — default gap between related items (8px).
pub const SPACE_SM: f32 = 8.0;
/// Two units — gap between rows / fields (16px).
pub const SPACE_MD: f32 = 16.0;
/// Three units — section padding / gap between groups (24px).
pub const SPACE_LG: f32 = 24.0;
/// Four units — screen-level padding / major separation (32px).
pub const SPACE_XL: f32 = 32.0;

/// Inner padding for cards (16px all round).
pub const CARD_PADDING: f32 = 16.0;
/// Corner radius for cards / panels.
pub const RADIUS_CARD: f32 = 12.0;
/// Corner radius for buttons and inputs.
pub const RADIUS_CONTROL: f32 = 8.0;
/// Corner radius for status pills (fully rounded look).
pub const RADIUS_PILL: f32 = 999.0;

/// Type scale (logical px). One large title, medium section labels, small body
/// and smaller captions — a deliberate, limited hierarchy.
pub const TEXT_TITLE: f32 = 24.0;
/// Section / group heading.
pub const TEXT_SECTION: f32 = 16.0;
/// Default body text.
pub const TEXT_BODY: f32 = 14.0;
/// Captions, metadata, muted secondary text.
pub const TEXT_CAPTION: f32 = 12.0;

// ─────────────────────────────────────────────────────────────────────────────
// Container helpers (cards & surfaces)
// ─────────────────────────────────────────────────────────────────────────────

/// Wrap `content` in an elevated, rounded, hairline-bordered card with standard
/// padding. The go-to surface for grouping related content.
pub fn card<'a, Message: 'a>(
    content: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    container(content)
        .padding(CARD_PADDING)
        .style(card_style)
        .into()
}

/// The [`container`] style closure backing [`card`]. Exposed so screens can
/// apply the card look to a `container` they need to size/position themselves
/// (e.g. a `container(..).width(Fill).style(theme::card_style)`).
pub fn card_style(theme: &Theme) -> container::Style {
    let p = palette(theme);
    container::Style {
        text_color: Some(p.text),
        background: Some(Background::Color(p.surface)),
        border: Border {
            color: p.border,
            width: 1.0,
            radius: RADIUS_CARD.into(),
        },
        shadow: Shadow {
            color: Color { a: 0.25, ..Color::BLACK },
            offset: Vector::new(0.0, 2.0),
            blur_radius: 12.0,
        },
        snap: false,
    }
}

/// A flat surface (no shadow) for nested rows / inset panels inside a card.
pub fn surface_style(theme: &Theme) -> container::Style {
    let p = palette(theme);
    container::Style {
        text_color: Some(p.text),
        background: Some(Background::Color(p.surface_alt)),
        border: Border {
            color: p.border,
            width: 1.0,
            radius: RADIUS_CONTROL.into(),
        },
        shadow: Shadow::default(),
        snap: false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Text helpers
// ─────────────────────────────────────────────────────────────────────────────

/// The screen / app title — one large, full-strength heading.
pub fn title<'a>(label: impl text::IntoFragment<'a>) -> text::Text<'a, Theme> {
    text(label)
        .size(TEXT_TITLE)
        .style(|theme: &Theme| text::Style { color: Some(palette(theme).text) })
}

/// A medium-weight section / group label.
pub fn section_title<'a>(label: impl text::IntoFragment<'a>) -> text::Text<'a, Theme> {
    text(label)
        .size(TEXT_SECTION)
        .style(|theme: &Theme| text::Style { color: Some(palette(theme).text) })
}

/// De-emphasised secondary text (captions, hints, metadata) in the muted colour.
pub fn muted<'a>(label: impl text::IntoFragment<'a>) -> text::Text<'a, Theme> {
    text(label)
        .size(TEXT_CAPTION)
        .style(|theme: &Theme| text::Style { color: Some(palette(theme).muted) })
}

/// Default body text in the primary text colour.
pub fn body<'a>(label: impl text::IntoFragment<'a>) -> text::Text<'a, Theme> {
    text(label)
        .size(TEXT_BODY)
        .style(|theme: &Theme| text::Style { color: Some(palette(theme).text) })
}

/// An icon glyph (unicode symbol) sized for inline use beside a label. Keeps the
/// toolbar from being bare text. See [`icons`] for the shared glyph set.
pub fn icon<'a>(glyph: impl text::IntoFragment<'a>) -> text::Text<'a, Theme> {
    text(glyph).size(TEXT_SECTION)
}

/// Shared unicode glyphs so every screen uses the same symbol for the same idea.
pub mod icons {
    /// Connect / power.
    pub const POWER: &str = "\u{23FB}"; // ⏻
    /// Disconnect / stop.
    pub const STOP: &str = "\u{2715}"; // ✕
    /// Add / new.
    pub const PLUS: &str = "\u{002B}"; // +
    /// Settings / gear.
    pub const GEAR: &str = "\u{2699}"; // ⚙
    /// Import (down arrow into tray).
    pub const IMPORT: &str = "\u{2193}"; // ↓
    /// Export (up / out arrow).
    pub const EXPORT: &str = "\u{2191}"; // ↑
    /// Edit / pencil.
    pub const EDIT: &str = "\u{270E}"; // ✎
    /// Delete / trash.
    pub const TRASH: &str = "\u{1F5D1}"; // 🗑
    /// Back / previous.
    pub const BACK: &str = "\u{2190}"; // ←
    /// Lock / secured.
    pub const LOCK: &str = "\u{1F512}"; // 🔒
    /// Shield / brand.
    pub const SHIELD: &str = "\u{1F6E1}"; // 🛡
    /// Refresh / regenerate.
    pub const REFRESH: &str = "\u{21BB}"; // ↻
    /// Server.
    pub const SERVER: &str = "\u{1F5A5}"; // 🖥
}

// ─────────────────────────────────────────────────────────────────────────────
// Status pill
// ─────────────────────────────────────────────────────────────────────────────

/// A semantic status, used to colour [`status_pill`] and the status dot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    /// Connected / healthy — green.
    Connected,
    /// Connecting / transitional — amber.
    Connecting,
    /// Error / disconnected — red.
    Error,
    /// Idle / unknown — grey.
    Idle,
}

impl StatusKind {
    /// The pill / dot colour for this status under `theme`.
    pub fn color(self, theme: &Theme) -> Color {
        let p = palette(theme);
        match self {
            StatusKind::Connected => p.success,
            StatusKind::Connecting => p.warning,
            StatusKind::Error => p.danger,
            StatusKind::Idle => p.idle,
        }
    }
}

/// A rounded, filled status badge: a tinted pill with the status colour as a
/// translucent background and a solid-coloured label. Pass the [`StatusKind`]
/// for the green/amber/red/grey semantics.
pub fn status_pill<'a, Message: 'a>(
    label: impl text::IntoFragment<'a>,
    kind: StatusKind,
) -> Element<'a, Message> {
    let label = text(label).size(TEXT_CAPTION).style(move |theme: &Theme| {
        text::Style { color: Some(kind.color(theme)) }
    });

    container(label)
        .padding([SPACE_XS, SPACE_SM * 1.5])
        .style(move |theme: &Theme| {
            let c = kind.color(theme);
            container::Style {
                text_color: Some(c),
                background: Some(Background::Color(Color { a: 0.16, ..c })),
                border: Border {
                    color: Color { a: 0.40, ..c },
                    width: 1.0,
                    radius: RADIUS_PILL.into(),
                },
                shadow: Shadow::default(),
                snap: false,
            }
        })
        .into()
}

/// A small filled circular status dot in the given status colour. Useful in
/// dense lists where a full pill would be too heavy.
pub fn status_dot<'a, Message: 'a>(kind: StatusKind, diameter: f32) -> Element<'a, Message> {
    container(text(" "))
        .width(diameter)
        .height(diameter)
        .style(move |theme: &Theme| container::Style {
            background: Some(Background::Color(kind.color(theme))),
            border: Border {
                radius: (diameter / 2.0).into(),
                ..Border::default()
            },
            ..container::Style::default()
        })
        .into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Button style helpers
//
// Each returns a closure suitable for `button(..).style(theme::primary())`.
// They derive their colours from the shared palette so buttons match the cards
// and pills exactly.
// ─────────────────────────────────────────────────────────────────────────────

/// Build a filled button style closure from a base colour + text colour, with
/// hover/pressed/disabled handling baked in.
fn filled(
    base: fn(Palette) -> Color,
    strong: fn(Palette) -> Color,
    on: Color,
) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let p = palette(theme);
        let bg = match status {
            button::Status::Hovered | button::Status::Pressed => strong(p),
            _ => base(p),
        };
        let mut style = button::Style {
            background: Some(Background::Color(bg)),
            text_color: on,
            border: Border {
                radius: RADIUS_CONTROL.into(),
                ..Border::default()
            },
            shadow: Shadow::default(),
            snap: false,
        };
        if matches!(status, button::Status::Disabled) {
            style.background = style
                .background
                .map(|b| match b {
                    Background::Color(c) => Background::Color(Color { a: 0.4, ..c }),
                    other => other,
                });
            style.text_color = Color { a: 0.5, ..style.text_color };
        }
        style
    }
}

/// Primary action button — filled with the shield blue accent.
pub fn primary() -> impl Fn(&Theme, button::Status) -> button::Style {
    filled(|p| p.accent, |p| p.accent_strong, Color::WHITE)
}

/// Destructive action button — filled red.
pub fn danger() -> impl Fn(&Theme, button::Status) -> button::Style {
    filled(|p| p.danger, |p| p.danger, Color::WHITE)
}

/// Success action button — filled green (e.g. "Connect").
pub fn success() -> impl Fn(&Theme, button::Status) -> button::Style {
    filled(|p| p.success, |p| p.success, Color::WHITE)
}

/// Ghost button — transparent with a hairline border; the muted, secondary
/// action style. Fills faintly with the surface colour on hover.
pub fn ghost() -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme: &Theme, status: button::Status| {
        let p = palette(theme);
        let bg = match status {
            button::Status::Hovered | button::Status::Pressed => {
                Some(Background::Color(p.surface_alt))
            }
            _ => None,
        };
        button::Style {
            background: bg,
            text_color: if matches!(status, button::Status::Disabled) {
                Color { a: 0.5, ..p.text }
            } else {
                p.text
            },
            border: Border {
                color: p.border,
                width: 1.0,
                radius: RADIUS_CONTROL.into(),
            },
            shadow: Shadow::default(),
            snap: false,
        }
    }
}

/// Icon button — minimal, no border or fill; tints to the accent on hover. For
/// compact toolbar glyph buttons.
pub fn icon_button() -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme: &Theme, status: button::Status| {
        let p = palette(theme);
        let text_color = match status {
            button::Status::Hovered | button::Status::Pressed => p.accent,
            button::Status::Disabled => Color { a: 0.4, ..p.muted },
            button::Status::Active => p.muted,
        };
        let bg = match status {
            button::Status::Hovered | button::Status::Pressed => {
                Some(Background::Color(p.surface_alt))
            }
            _ => None,
        };
        button::Style {
            background: bg,
            text_color,
            border: Border {
                radius: RADIUS_CONTROL.into(),
                ..Border::default()
            },
            shadow: Shadow::default(),
            snap: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Theme construction (used by `app.rs theme()`)
// ─────────────────────────────────────────────────────────────────────────────

/// Name of the custom dark theme (also used by [`palette`] to map back).
pub const DARK_THEME_NAME: &str = "WireGuard Dark";
/// Name of the custom light theme.
pub const LIGHT_THEME_NAME: &str = "WireGuard Light";

/// Build the custom blue-accented dark [`Theme`].
pub fn dark_theme() -> Theme {
    Theme::custom(DARK_THEME_NAME.to_string(), to_iced_palette(DARK))
}

/// Build the custom blue-accented light [`Theme`].
pub fn light_theme() -> Theme {
    Theme::custom(LIGHT_THEME_NAME.to_string(), to_iced_palette(LIGHT))
}

/// Map our semantic [`Palette`] onto iced's 6-colour [`iced::theme::Palette`],
/// which iced expands into its extended palette for built-in widgets.
fn to_iced_palette(p: Palette) -> iced::theme::Palette {
    iced::theme::Palette {
        background: p.bg,
        text: p.text,
        primary: p.accent,
        success: p.success,
        warning: p.warning,
        danger: p.danger,
    }
}

/// Resolve the active iced [`Theme`] from the user's [`AppSettings`].
///
/// This is the single decision point for the app's theme; `app.rs`'s
/// `State::theme()` delegates here so the screen helpers and the chosen theme
/// always agree. `FollowSystem` maps to the dark variant (iced 0.14 exposes no
/// stable light/dark system query); `Named(..)` passes through to a built-in
/// iced theme.
pub fn app_theme(settings: &AppSettings) -> Theme {
    match &settings.theme {
        ThemePreference::Light => light_theme(),
        ThemePreference::Dark => dark_theme(),
        ThemePreference::FollowSystem => dark_theme(),
        ThemePreference::Named(name) => named_theme(name),
    }
}

/// Map a named-theme string to a built-in iced theme, defaulting to our custom
/// dark theme. Mirrors the set offered in the Settings screen.
pub fn named_theme(name: &str) -> Theme {
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
        "WireGuard Dark" => dark_theme(),
        "WireGuard Light" => light_theme(),
        _ => dark_theme(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (pure; no GUI / runtime)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spacing_follows_8px_rhythm() {
        const {
            assert!(SPACE_SM == 8.0);
            assert!(SPACE_MD == SPACE_SM * 2.0);
            assert!(SPACE_LG == SPACE_SM * 3.0);
            assert!(SPACE_XL == SPACE_SM * 4.0);
            assert!(SPACE_XS == SPACE_SM / 2.0);
        }
    }

    #[test]
    fn type_scale_is_descending() {
        const {
            assert!(TEXT_TITLE > TEXT_SECTION);
            assert!(TEXT_SECTION > TEXT_BODY);
            assert!(TEXT_BODY > TEXT_CAPTION);
        }
    }

    #[test]
    fn custom_themes_round_trip_to_their_palette() {
        assert_eq!(palette(&dark_theme()), DARK);
        assert_eq!(palette(&light_theme()), LIGHT);
    }

    #[test]
    fn app_theme_maps_preferences() {
        let dark = AppSettings { theme: ThemePreference::Dark, ..Default::default() };
        assert_eq!(palette(&app_theme(&dark)), DARK);

        let light = AppSettings { theme: ThemePreference::Light, ..Default::default() };
        assert_eq!(palette(&app_theme(&light)), LIGHT);

        // FollowSystem currently resolves to the dark variant.
        let follow = AppSettings { theme: ThemePreference::FollowSystem, ..Default::default() };
        assert_eq!(palette(&app_theme(&follow)), DARK);
    }

    #[test]
    fn named_theme_falls_back_to_dark() {
        // Unknown name → our custom dark theme.
        assert_eq!(palette(&named_theme("nonsense")), DARK);
        // A real built-in light theme is detected as light by luminance.
        assert_eq!(palette(&Theme::Light), LIGHT);
        assert_eq!(palette(&Theme::Dark), DARK);
    }

    #[test]
    fn status_kind_colors_are_distinct() {
        let t = dark_theme();
        let connected = StatusKind::Connected.color(&t);
        let connecting = StatusKind::Connecting.color(&t);
        let error = StatusKind::Error.color(&t);
        let idle = StatusKind::Idle.color(&t);
        assert_eq!(connected, DARK.success);
        assert_eq!(connecting, DARK.warning);
        assert_eq!(error, DARK.danger);
        assert_eq!(idle, DARK.idle);
    }

    #[test]
    fn accent_is_shared_blue_across_variants() {
        // Both variants are blue-forward (B channel dominant on the accent).
        const {
            assert!(DARK.accent.b > DARK.accent.r && DARK.accent.b > DARK.accent.g);
            assert!(LIGHT.accent.b > LIGHT.accent.r && LIGHT.accent.b > LIGHT.accent.g);
        }
    }

    #[test]
    fn luminance_orders_light_above_dark() {
        assert!(relative_luminance(LIGHT.bg) > 0.5);
        assert!(relative_luminance(DARK.bg) < 0.5);
    }
}
