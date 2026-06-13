# Packaging — WireGuard GUI (wireguard-gui-rust)

This document describes how WireGuard GUI is packaged for end-user distribution
and, critically, how each packaging format ensures that WireGuard itself (the
`wg` and `wg-quick` userspace tools) is present alongside the application so
that installing one package is all the user ever needs to do.

> **Trademark notice:** "WireGuard" is a registered trademark of Jason A. Donenfeld.
> This project is unofficial and is not affiliated with or endorsed by
> Jason A. Donenfeld or the WireGuard project.

---

## The one-step-install model

Every distribution format pulls in WireGuard tools automatically:

| Format | How WireGuard arrives |
|---|---|
| `.deb` | `Depends: wireguard-tools` — apt/dpkg resolves it before the package is configured |
| AUR (`wireguard-gui-rust` / `wireguard-gui-rust-bin`) | `depends=(wireguard-tools …)` — pacman/yay installs it in the same transaction |
| Snap | `stage-packages: [wireguard-tools, iproute2, iptables, …]` — snapcraft bundles the tools inside the snap's squashfs at build time |
| AppImage | `wg` and `wg-quick` are copied from the build host into `AppDir/usr/bin/` at build time; the AppImage ships them directly |

**The kernel module is not a concern for modern systems.** WireGuard was merged
into the Linux kernel mainline at version 5.6 (released March 2020). On any
kernel >= 5.6 the `wireguard` module is part of the tree and loads automatically
when a `wg` interface is first created — nothing to install. On older kernels
(4.19–5.5) a DKMS backport exists, but it is explicitly out of scope for this
project's packaging recipes.

---

## Where each recipe lives

```
wireguard-gui-rust/
  packaging/
    DEB.md                          # cargo-deb how-to + deferred Cargo.toml block
    appimage/
      build-appimage.sh             # AppDir assembly + linuxdeploy invocation
      AppRun                        # AppImage entry-point (sets PATH, GTK env, execs binary)
  snap/
    snapcraft.yaml                  # Snap recipe (core24, strict confinement, rust plugin)
  aur/
    README.md                       # AUR submission checklist + sha256/SRCINFO/namcap steps
    wireguard-gui-rust/
      PKGBUILD                      # Builds from source (cargo build --frozen --release)
    wireguard-gui-rust-bin/
      PKGBUILD                      # Installs pre-built binary from GitHub release tarball
  assets/
    org.wireguardgui.rust.manage.policy   # Polkit action definition
    wireguard-gui-rust.desktop            # .desktop entry (applications menu)
    icons/hicolor/*/apps/wireguard-gui-rust.png   # PNG icons (16–256 px)
    icons/wireguard-gui-rust.svg          # Scalable source icon
    tray/*/wireguard-gui-rust-{connected,disconnected}.png   # System-tray icons
  .github/workflows/
    ci.yml                          # PR / push CI (build + test)
    release.yml                     # Tag-triggered .deb + AppImage build and GitHub Release
```

---

## Debian/Ubuntu (.deb) — cargo-deb

The `.deb` is produced by `cargo-deb`. The recipe is driven entirely by a
`[package.metadata.deb]` block in `Cargo.toml`.

Key dependency declaration:

```toml
depends = "$auto, wireguard-tools"
```

`$auto` expands to the shared-library deps auto-detected by cargo-deb from the
compiled binary. `wireguard-tools` is the Debian/Ubuntu package that ships
`wg(8)` and `wg-quick(8)`.

Assets installed by the `.deb`:

| Source path | Installed path | Mode |
|---|---|---|
| `target/release/wireguard-gui` | `/usr/bin/wireguard-gui` | 755 |
| `assets/wireguard-gui-rust.desktop` | `/usr/share/applications/wireguard-gui-rust.desktop` | 644 |
| `assets/org.wireguardgui.rust.manage.policy` | `/usr/share/polkit-1/actions/org.wireguardgui.rust.manage.policy` | 644 |
| `assets/icons/hicolor/<size>/apps/wireguard-gui-rust.png` | `/usr/share/icons/hicolor/<size>/apps/wireguard-gui-rust.png` | 644 |

Full recipe details, autostart notes, and build commands are in
[`packaging/DEB.md`](../packaging/DEB.md).

---

## Arch Linux (AUR)

Two AUR packages are provided under `aur/`:

- **`wireguard-gui-rust`** (`aur/wireguard-gui-rust/PKGBUILD`) — builds from
  the tagged source tarball using `cargo build --frozen --release`. Suitable for
  users who want to build on their own machine and have a Rust toolchain.

- **`wireguard-gui-rust-bin`** (`aur/wireguard-gui-rust-bin/PKGBUILD`) —
  downloads and installs the pre-built binary from the GitHub release tarball.
  No Rust toolchain required.

Both declare:

```bash
depends=(
    'wireguard-tools'   # wg + wg-quick
    'dbus'              # session bus (ksni system-tray)
    'polkit'            # privilege escalation for wg-quick
)
```

Both install the same file set: binary, `.desktop` entry, hicolor PNG icons,
scalable SVG icon, polkit policy, and both licence files.

See [`aur/README.md`](../aur/README.md) for the pre-submission checklist
(real sha256sums, `.SRCINFO` generation, `namcap` verification).

---

## Snap

Recipe: `snap/snapcraft.yaml`  
Base: `core24`, confinement: `strict`, extension: `gnome` (pulls in the GNOME
platform snap, Wayland/X11 environment).

WireGuard tools are bundled via `stage-packages`:

```yaml
stage-packages:
  - wireguard-tools   # wg(8) and wg-quick(8)
  - iproute2          # ip(8) — required by wg-quick for route/address setup
  - iptables          # PostUp/PostDown firewall rules
  - libdbus-1-3       # D-Bus shared library
```

Two plugs are **not auto-connected** by the Snap Store because they carry
elevated privilege. The user must connect them once after installation:

```sh
sudo snap connect wireguard-gui:network-manager
sudo snap connect wireguard-gui:network-control
```

- `network-manager` — D-Bus access to NetworkManager for profile CRUD.
- `network-control` — `CAP_NET_ADMIN`, required by `wg(8)` and `wg-quick(8)`
  to bring tunnel interfaces up and down.

The snap also declares `unity7` to support the AppIndicator/KStatusNotifierItem
tray on Ubuntu.

---

## AppImage

Recipe: `packaging/appimage/build-appimage.sh`  
Entry-point: `packaging/appimage/AppRun`

The build script assembles an AppDir, bundles `wg` and `wg-quick` from the
build host, then calls `linuxdeploy` (with the GTK plugin) to copy shared
libraries and produce a self-contained type-2 AppImage.

How `wg`/`wg-quick` are bundled:

```bash
for tool in wg wg-quick; do
    cp "$(command -v "${tool}")" "${APPDIR}/usr/bin/${tool}"
done
```

`AppRun` prepends `$APPDIR/usr/bin` to `PATH` so the bundled tools are found
before any system copies. It also sets GTK/GLib environment pointers so that
GTK file-dialogs work on non-GTK desktops (KDE, etc.).

The end-user system still requires:

- Linux kernel >= 5.6 (WireGuard in-tree module).
- FUSE 2 or FUSE 3 to mount the AppImage at runtime.
- polkit for privilege escalation (see below).

---

## Polkit action and root helper

**Action ID:** `org.wireguardgui.rust.manage`  
**Policy file:** `assets/org.wireguardgui.rust.manage.policy`  
**Installed to:** `/usr/share/polkit-1/actions/org.wireguardgui.rust.manage.policy`

The policy authorises the root helper binary at:

```
/usr/lib/wireguard-gui/wireguard-gui-helper
```

Defaults:

| Session type | Behaviour |
|---|---|
| Active local session | `auth_admin_keep` — prompts once, keeps authorisation for the session |
| Inactive session (remote/lock-screen) | `auth_admin` — requires admin credentials each time |
| No session | `auth_admin` — requires admin credentials each time |

The helper binary is not yet built. Its asset entry must be added to
`Cargo.toml` once the helper crate exists:

```toml
["target/release/wireguard-gui-helper",
 "usr/lib/wireguard-gui/wireguard-gui-helper", "755"],
```

Until the helper is built and installed to `/usr/lib/wireguard-gui/`, polkit
privilege escalation will not work. The GUI will still launch; tunnel operations
that require root will fail with a permission error.

---

## System-tray on stock GNOME (Ubuntu)

GNOME Shell does not display system-tray icons natively. Applications that use
the `AppIndicator` / `KStatusNotifierItem` D-Bus protocol (which this app
does via the `ksni` crate) need the following GNOME Shell extension to be active:

**"AppIndicator and KStatusNotifierItem Support"**  
(also called "Ubuntu AppIndicators" or "KStatusNotifierItem/AppIndicator Support")

Ubuntu ships this extension and enables it by default, so on a standard Ubuntu
desktop the tray icon works without any user action.

On other stock GNOME distributions (Fedora, Arch + GNOME, etc.) the extension
must be installed manually:

- GNOME Extensions website: https://extensions.gnome.org/extension/615/
- Or via the distro package manager, e.g. on Fedora:
  `sudo dnf install gnome-shell-extension-appindicator`

On KDE Plasma, Xfce, and other desktop environments that implement the
StatusNotifierItem spec natively, the tray icon works without any extension.

The snap declares the `unity7` plug specifically to support the AppIndicator
path on Ubuntu snaps.

---

## DEFERRED: Cargo.toml edits

The `[package.metadata.deb]` block that drives `cargo-deb` **must not be added
to `Cargo.toml` until the build is stable and install paths are confirmed.**

The full block to add is documented in [`packaging/DEB.md`](../packaging/DEB.md).
Key points:

- `name = "wireguard-gui"` (package name in apt, distinct from the binary name)
- `depends = "$auto, wireguard-tools"` — hard runtime dependency
- `recommends = "network-manager | openresolv | resolvconf"` — optional resolver
  integration
- Asset entries for binary, `.desktop`, polkit policy, and all six hicolor PNG
  sizes (16, 32, 48, 64, 128, 256 px)
- A separate asset entry for the helper binary must be added once the helper
  crate is built (see polkit section above)

**Do not add this block until:**
1. The binary name and install path are finalised.
2. The polkit helper path (`/usr/lib/wireguard-gui/wireguard-gui-helper`) is
   confirmed on a real Debian/Ubuntu target.
3. The icon filenames match what is installed under
   `/usr/share/icons/hicolor/…/apps/`.

---

## CI / release pipeline

| Workflow | File | Trigger | What it does |
|---|---|---|---|
| CI | `.github/workflows/ci.yml` | Push / PR to any branch | Build + test (no packaging) |
| Release | `.github/workflows/release.yml` | Push of a `v*.*.*` tag | Builds `.deb` (cargo-deb) + AppImage (build-appimage.sh), creates GitHub Release with both as attachments |

Snap Store publish and AUR publish jobs exist in `release.yml` but are
commented out. To activate them, add the relevant secrets
(`SNAP_STORE_TOKEN`, `AUR_SSH_KEY`, `AUR_USERNAME`) to the repository and
uncomment the jobs.
