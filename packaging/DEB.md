# Debian Packaging (cargo-deb)

This document describes the `[package.metadata.deb]` block to add to
`Cargo.toml` when you are ready to produce a `.deb` package.

**Do not add this block to `Cargo.toml` yet.**  It is recorded here for
reference and should be added only once the binary is stable and the full
icon + helper install paths have been confirmed on a target machine.

---

## Deferred Cargo.toml addition

```toml
[package.metadata.deb]
name            = "wireguard-gui"
maintainer      = "xthakila <https://github.com/xthakila/wireguard-gui-rust>"
copyright       = "The wireguard-gui-rust contributors"
license-file    = ["LICENSE-MIT", "4"]
extended-description = """\
WireGuard GUI is an unofficial graphical front-end for managing WireGuard
VPN tunnels on Linux.  It lets you create, edit, and toggle tunnels without
touching the command line.

WireGuard is a registered trademark of Jason A. Donenfeld.  This application
is not endorsed by or affiliated with Jason A. Donenfeld or the WireGuard
project.
"""
section         = "net"
priority        = "optional"
depends         = "$auto, wireguard-tools"
recommends      = "network-manager | openresolv | resolvconf"

# ── installed assets ────────────────────────────────────────────────────────
# Format: ["<source>", "<destination>", "<octal-mode>"]
# cargo-deb resolves the source path relative to the crate root.
assets = [
  # Main binary (built by cargo)
  ["target/release/wireguard-gui", "usr/bin/wireguard-gui", "755"],

  # .desktop entry (applications menu)
  ["assets/wireguard-gui-rust.desktop",
   "usr/share/applications/wireguard-gui-rust.desktop", "644"],

  # Polkit policy
  ["assets/org.wireguardgui.rust.manage.policy",
   "usr/share/polkit-1/actions/org.wireguardgui.rust.manage.policy", "644"],

  # hicolor icons — one entry per size
  ["assets/icons/hicolor/16x16/apps/wireguard-gui-rust.png",
   "usr/share/icons/hicolor/16x16/apps/wireguard-gui-rust.png", "644"],
  ["assets/icons/hicolor/32x32/apps/wireguard-gui-rust.png",
   "usr/share/icons/hicolor/32x32/apps/wireguard-gui-rust.png", "644"],
  ["assets/icons/hicolor/48x48/apps/wireguard-gui-rust.png",
   "usr/share/icons/hicolor/48x48/apps/wireguard-gui-rust.png", "644"],
  ["assets/icons/hicolor/64x64/apps/wireguard-gui-rust.png",
   "usr/share/icons/hicolor/64x64/apps/wireguard-gui-rust.png", "644"],
  ["assets/icons/hicolor/128x128/apps/wireguard-gui-rust.png",
   "usr/share/icons/hicolor/128x128/apps/wireguard-gui-rust.png", "644"],
  ["assets/icons/hicolor/256x256/apps/wireguard-gui-rust.png",
   "usr/share/icons/hicolor/256x256/apps/wireguard-gui-rust.png", "644"],
]
```

---

## Notes

### depends vs recommends

| Package | Reason |
|---|---|
| `wireguard-tools` | Hard dependency — `wg` and `wg-quick` must be present at runtime. |
| `network-manager` | Preferred resolver integration (optional). |
| `openresolv` | Alternative DNS resolver integration (optional). |
| `resolvconf` | Legacy resolver shim (optional). |

`$auto` is the cargo-deb placeholder that expands to the automatically-detected
shared-library dependencies for the compiled binary.

### .desktop and autostart

The file installed to `usr/share/applications/wireguard-gui-rust.desktop` is
for the applications menu.  If you also want the app to start at login, install
a **copy** of the file under `usr/etc/xdg/autostart/wireguard-gui-rust.desktop`
and change the `Exec` line to:

```ini
Exec=wireguard-gui --hidden
```

The `--hidden` flag tells the app to start minimised to the system tray instead
of opening the main window immediately.

### Polkit helper path

The policy file declares
`/usr/lib/wireguard-gui/wireguard-gui-helper` as the authorised executable.
You must build and install that helper binary to that exact path for polkit
privilege escalation to work.  Add a corresponding asset entry once the helper
crate exists:

```toml
["target/release/wireguard-gui-helper",
 "usr/lib/wireguard-gui/wireguard-gui-helper", "755"],
```

### Icon naming

The icon name used in the `.desktop` file (`wireguard-gui-rust`) must match the
installed filenames under `usr/share/icons/hicolor/…/apps/`.  Do **not** use or
redistribute the official WireGuard dragon logo — design and use an original
icon.

### Building the .deb

```sh
cargo install cargo-deb          # one-time
cargo deb                        # produces target/debian/*.deb
```

Requires that `[package.metadata.deb]` is present in `Cargo.toml` (see above)
and that `target/release/wireguard-gui` has already been built (`cargo build
--release`).
