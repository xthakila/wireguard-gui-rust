# AUR Packages for wireguard-gui-rust

This directory contains [Arch User Repository (AUR)](https://aur.archlinux.org/) package
definitions for **WireGuard GUI** — an unofficial, native Iced/Rust front-end for managing
WireGuard tunnels.

> **Trademark notice:** "WireGuard" is a registered trademark of Jason A. Donenfeld.
> This project is unofficial and is not affiliated with or endorsed by WireGuard® or
> Jason A. Donenfeld. Do **not** use the official WireGuard dragon logo as the application
> icon; use the custom icon shipped in `assets/icons/`.

---

## Packages

| Directory | AUR package | What it does |
|---|---|---|
| `wireguard-gui-rust/` | `wireguard-gui-rust` | Builds from source via `cargo build --frozen --release` |
| `wireguard-gui-rust-bin/` | `wireguard-gui-rust-bin` | Installs the pre-built binary from the GitHub release tarball |

Both packages install the same files: binary (`/usr/bin/wireguard-gui`), `.desktop` entry,
hicolor icons, polkit policy (`org.wireguardgui.rust.manage`), and both licences.

---

## Before pushing to AUR

### 1. Replace `sha256sums=('SKIP')` with real checksums

Each PKGBUILD currently contains `sha256sums=('SKIP')` as a placeholder with a comment
explaining why. AUR policy requires real checksums before submission.

For the **binary package** (`wireguard-gui-rust-bin`), after uploading the release tarball
to GitHub Releases:

```bash
cd aur/wireguard-gui-rust-bin
curl -LO https://github.com/xthakila/wireguard-gui-rust/releases/download/v0.1.0/wireguard-gui-rust-0.1.0-x86_64.tar.gz
sha256sum wireguard-gui-rust-0.1.0-x86_64.tar.gz
# Paste the result into sha256sums=('…')
```

For the **source package** (`wireguard-gui-rust`), after tagging the release:

```bash
cd aur/wireguard-gui-rust
curl -LO https://github.com/xthakila/wireguard-gui-rust/archive/refs/tags/v0.1.0.tar.gz
sha256sum v0.1.0.tar.gz
# Paste the result into sha256sums=('…')
```

### 2. Generate `.SRCINFO`

AUR requires a `.SRCINFO` file alongside every `PKGBUILD`. Generate it with `makepkg`:

```bash
# For the source package:
cd aur/wireguard-gui-rust
makepkg --printsrcinfo > .SRCINFO

# For the binary package:
cd aur/wireguard-gui-rust-bin
makepkg --printsrcinfo > .SRCINFO
```

Commit both `PKGBUILD` and `.SRCINFO` to your AUR git repository. The AUR git remote is
separate from this GitHub repo — see the
[AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines).

### 3. Verify with `namcap`

```bash
namcap aur/wireguard-gui-rust/PKGBUILD
namcap aur/wireguard-gui-rust-bin/PKGBUILD
```

Fix any warnings before submitting.

---

## Local test build

```bash
# Source package (requires Rust/cargo):
cd aur/wireguard-gui-rust
makepkg -si

# Binary package (requires the release tarball to exist on GitHub):
cd aur/wireguard-gui-rust-bin
makepkg -si
```

---

## Runtime dependencies

| Package | Why |
|---|---|
| `wireguard-tools` | `wg` and `wg-quick` — used to bring tunnels up/down |
| `dbus` | System/session bus for the system-tray integration (ksni) |
| `polkit` | Privilege escalation so `wg-quick` can run as root without a full sudo prompt |

Optional:

| Package | Why |
|---|---|
| `networkmanager` | Preferred DNS/routing backend; handles `DNS =` lines in tunnel configs |
| `openresolv` | Alternative resolver integration for `wg-quick` on systems without NetworkManager |
