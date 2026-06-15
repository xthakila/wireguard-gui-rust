//! On-disk profile store. Profiles live as `.conf` files under a config directory.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt as _;

use crate::config::profile::WgProfile;
use crate::error::{AppError, AppResult};

/// Default config directory: `~/.config/wireguard-gui-rust/profiles/`
fn default_store_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("wireguard-gui-rust").join("profiles"))
}

/// Manages reading/writing WireGuard profiles in `dir`.
#[derive(Debug, Clone)]
pub struct ProfileStore {
    pub dir: PathBuf,
}

impl ProfileStore {
    /// Open (creating if needed) the default profile store directory.
    pub fn new() -> AppResult<Self> {
        let dir = default_store_dir().ok_or_else(|| {
            AppError::ProfileIo("cannot locate user config directory".to_owned())
        })?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::ProfileIo(format!("create_dir_all {dir:?}: {e}")))?;
        Ok(ProfileStore { dir })
    }

    /// Open (or create) a profile store rooted at an arbitrary directory.
    ///
    /// Useful in tests where you pass a `tempdir`.
    pub fn at(dir: impl Into<PathBuf>) -> AppResult<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::ProfileIo(format!("create_dir_all {dir:?}: {e}")))?;
        Ok(ProfileStore { dir })
    }

    fn conf_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.conf"))
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// List the names of all stored profiles (file stems of `*.conf` files, sorted).
    pub async fn list_profiles(&self) -> AppResult<Vec<String>> {
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || {
            let mut names: Vec<String> = Vec::new();
            let rd = std::fs::read_dir(&dir)
                .map_err(|e| AppError::ProfileIo(format!("read_dir {dir:?}: {e}")))?;
            for entry in rd {
                let entry =
                    entry.map_err(|e| AppError::ProfileIo(format!("dir entry: {e}")))?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf")
                    && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                {
                    names.push(stem.to_owned());
                }
            }
            names.sort();
            Ok(names)
        })
        .await
        .map_err(|e| AppError::ProfileIo(e.to_string()))?
    }

    /// Read a single profile by name.
    pub async fn read_profile(&self, name: &str) -> AppResult<WgProfile> {
        let path = self.conf_path(name);
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            if !path.exists() {
                return Err(AppError::ProfileNotFound(name.clone()));
            }
            let content = std::fs::read_to_string(&path)
                .map_err(|e| AppError::ProfileIo(format!("read {path:?}: {e}")))?;
            let mut profile = WgProfile::from_conf_str(&name, &content)?;
            profile.path = Some(path);
            Ok(profile)
        })
        .await
        .map_err(|e| AppError::ProfileIo(e.to_string()))?
    }

    /// Create a new profile (fails if one with the same name already exists).
    pub async fn create_profile(&self, profile: &WgProfile) -> AppResult<()> {
        let path = self.conf_path(&profile.name);
        if path.exists() {
            return Err(AppError::ProfileExists(profile.name.clone()));
        }
        self.write_profile_to_path(profile, &path).await
    }

    /// Save a profile, overwriting any existing file of the same name.
    pub async fn save_profile(&self, profile: &WgProfile) -> AppResult<()> {
        let path = self.conf_path(&profile.name);
        self.write_profile_to_path(profile, &path).await
    }

    /// Delete a profile by name.
    pub async fn delete_profile(&self, name: &str) -> AppResult<()> {
        let path = self.conf_path(name);
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            if !path.exists() {
                return Err(AppError::ProfileNotFound(name));
            }
            std::fs::remove_file(&path)
                .map_err(|e| AppError::ProfileIo(format!("remove {path:?}: {e}")))
        })
        .await
        .map_err(|e| AppError::ProfileIo(e.to_string()))?
    }

    /// Import a `.conf` from an arbitrary path into the store, returning the parsed profile.
    pub async fn import_from_path(&self, path: &Path) -> AppResult<WgProfile> {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| AppError::ImportFailed("path has no file stem".to_owned()))?
            .to_owned();

        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| AppError::ImportFailed(format!("read {path:?}: {e}")))?;

        let mut profile = WgProfile::from_conf_str(&stem, &content)
            .map_err(|e| AppError::ImportFailed(e.to_string()))?;

        self.create_profile(&profile).await?;

        let dest = self.conf_path(&profile.name);
        profile.path = Some(dest);
        Ok(profile)
    }

    /// Export a stored profile to an arbitrary path.
    pub async fn export_to_path(&self, name: &str, path: &Path) -> AppResult<()> {
        let profile = self.read_profile(name).await?;
        let conf = profile.to_conf_string();
        let path = path.to_owned();
        write_0600(&path, conf.as_bytes())
            .await
            .map_err(|e| AppError::ExportFailed(e.to_string()))
    }

    // ── private helpers ───────────────────────────────────────────────────────

    async fn write_profile_to_path(&self, profile: &WgProfile, path: &Path) -> AppResult<()> {
        let conf = profile.to_conf_string();
        write_0600(path, conf.as_bytes())
            .await
            .map_err(|e| AppError::ProfileIo(e.to_string()))
    }
}

/// Write `data` to `path` with 0600 permissions (owner read/write only).
///
/// The write is atomic-ish: data is first written to a temporary sibling file and then
/// renamed into place so a crash mid-write never leaves a truncated profile on disk.
async fn write_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // Build a sibling temp path.
    let tmp_path = path.with_extension("conf.tmp");

    // Write to the temp file.
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .await?;
    file.write_all(data).await?;
    file.flush().await?;
    drop(file); // close before chmod/rename

    // Set 0600.
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(&tmp_path, perms)?;

    // Atomic rename.
    tokio::fs::rename(&tmp_path, path).await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::profile::{InterfaceSection, PeerSection};

    // A syntactically valid base64-encoded 32-byte key.
    const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn make_profile(name: &str) -> WgProfile {
        WgProfile {
            name: name.to_owned(),
            interface: InterfaceSection {
                private_key: ZERO_KEY.to_owned(),
                address: vec!["10.0.0.1/24".to_owned()],
                ..Default::default()
            },
            peers: vec![PeerSection {
                public_key: ZERO_KEY.to_owned(),
                allowed_ips: vec!["0.0.0.0/0".to_owned()],
                ..Default::default()
            }],
            path: None,
        }
    }

    fn store_in_tempdir() -> (tempfile::TempDir, ProfileStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = ProfileStore::at(tmp.path()).unwrap();
        (tmp, store)
    }

    // ── create / list / delete ────────────────────────────────────────────────

    #[tokio::test]
    async fn create_and_list_profile() {
        let (_tmp, store) = store_in_tempdir();
        let profile = make_profile("wg0");
        store.create_profile(&profile).await.unwrap();

        let names = store.list_profiles().await.unwrap();
        assert_eq!(names, vec!["wg0"]);
    }

    #[tokio::test]
    async fn list_empty_store() {
        let (_tmp, store) = store_in_tempdir();
        let names = store.list_profiles().await.unwrap();
        assert!(names.is_empty());
    }

    #[tokio::test]
    async fn create_duplicate_returns_exists_error() {
        let (_tmp, store) = store_in_tempdir();
        let profile = make_profile("wg0");
        store.create_profile(&profile).await.unwrap();
        let err = store.create_profile(&profile).await.unwrap_err();
        assert!(
            matches!(err, AppError::ProfileExists(_)),
            "expected ProfileExists, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_profile_removes_file() {
        let (_tmp, store) = store_in_tempdir();
        let profile = make_profile("wg0");
        store.create_profile(&profile).await.unwrap();
        store.delete_profile("wg0").await.unwrap();

        let names = store.list_profiles().await.unwrap();
        assert!(names.is_empty());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_not_found() {
        let (_tmp, store) = store_in_tempdir();
        let err = store.delete_profile("ghost").await.unwrap_err();
        assert!(
            matches!(err, AppError::ProfileNotFound(_)),
            "expected ProfileNotFound, got {err:?}"
        );
    }

    #[tokio::test]
    async fn list_sorted_alphabetically() {
        let (_tmp, store) = store_in_tempdir();
        store.create_profile(&make_profile("zebra")).await.unwrap();
        store.create_profile(&make_profile("alpha")).await.unwrap();
        store.create_profile(&make_profile("mango")).await.unwrap();

        let names = store.list_profiles().await.unwrap();
        assert_eq!(names, vec!["alpha", "mango", "zebra"]);
    }

    // ── read ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn read_profile_round_trips_data() {
        let (_tmp, store) = store_in_tempdir();
        let profile = make_profile("wg0");
        store.create_profile(&profile).await.unwrap();

        let loaded = store.read_profile("wg0").await.unwrap();
        assert_eq!(loaded.name, "wg0");
        assert_eq!(loaded.interface.private_key, ZERO_KEY);
        assert_eq!(loaded.interface.address, vec!["10.0.0.1/24"]);
        assert_eq!(loaded.peers[0].public_key, ZERO_KEY);
    }

    #[tokio::test]
    async fn read_nonexistent_returns_not_found() {
        let (_tmp, store) = store_in_tempdir();
        let err = store.read_profile("ghost").await.unwrap_err();
        assert!(
            matches!(err, AppError::ProfileNotFound(_)),
            "expected ProfileNotFound, got {err:?}"
        );
    }

    // ── save (overwrite) ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn save_overwrites_existing() {
        let (_tmp, store) = store_in_tempdir();
        let profile = make_profile("wg0");
        store.create_profile(&profile).await.unwrap();

        let mut updated = profile.clone();
        updated.interface.address = vec!["10.99.99.1/24".to_owned()];
        store.save_profile(&updated).await.unwrap();

        let loaded = store.read_profile("wg0").await.unwrap();
        assert_eq!(loaded.interface.address, vec!["10.99.99.1/24"]);
    }

    // ── file permissions ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn created_file_has_0600_permissions() {
        let (tmp, store) = store_in_tempdir();
        store.create_profile(&make_profile("wg0")).await.unwrap();

        let path = tmp.path().join("wg0.conf");
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {:o}", mode);
    }

    // ── import / export ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn import_from_path_adds_profile() {
        let (_tmp, store) = store_in_tempdir();

        // Write the raw .conf to import into a SEPARATE directory, not the store dir.
        // (If the source lived inside the store dir its path would equal the import
        // destination — `<store>/myprofile.conf` — and create_profile would correctly
        // reject it as already-existing. Importing from elsewhere is the real-world case,
        // e.g. ~/Downloads/myprofile.conf → ~/.config/.../profiles/.)
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("myprofile.conf");
        let conf = format!(
            "[Interface]\nPrivateKey = {ZERO_KEY}\nAddress = 10.0.0.1/24\n\n\
             [Peer]\nPublicKey = {ZERO_KEY}\nAllowedIPs = 0.0.0.0/0\n"
        );
        tokio::fs::write(&src, &conf).await.unwrap();

        let imported = store.import_from_path(&src).await.unwrap();
        assert_eq!(imported.name, "myprofile");

        let names = store.list_profiles().await.unwrap();
        assert!(names.contains(&"myprofile".to_owned()));
    }

    #[tokio::test]
    async fn export_to_path_writes_conf() {
        let (tmp, store) = store_in_tempdir();
        store.create_profile(&make_profile("wg0")).await.unwrap();

        let dest = tmp.path().join("exported.conf");
        store.export_to_path("wg0", &dest).await.unwrap();

        assert!(dest.exists(), "exported file should exist");
        let content = tokio::fs::read_to_string(&dest).await.unwrap();
        assert!(content.contains("PrivateKey"), "exported file should contain key");
    }

    #[tokio::test]
    async fn exported_file_has_0600_permissions() {
        let (tmp, store) = store_in_tempdir();
        store.create_profile(&make_profile("wg0")).await.unwrap();

        let dest = tmp.path().join("out.conf");
        store.export_to_path("wg0", &dest).await.unwrap();

        let meta = std::fs::metadata(&dest).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exported file must be 0600, got {:o}", mode);
    }
}
