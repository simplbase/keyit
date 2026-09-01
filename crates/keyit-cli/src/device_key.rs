//! Local device private-key storage.
//!
//! Keyit prefers OS-native secure storage where it is available. This
//! module supports macOS Keychain through the system `security` tool and
//! a restrictive local-file backend for development, tests, and
//! platforms without a native implementation yet.
//!
//! Private device keys must never be written inside a project
//! repository. This module's storage directory is always resolved
//! independently of any project directory — see
//! [`default_keyit_data_dir`].

use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;

use data_encoding::HEXLOWER;
use keyit_protocol::encryption::KeyAgreementKeyPair;
use keyit_protocol::signing::SigningKeyPair;
use zeroize::Zeroize;

use crate::error::CliError;

/// Filename of the local device signing key, inside the directory
/// resolved by [`default_keyit_data_dir`].
pub const DEVICE_SIGNING_KEY_FILENAME: &str = "device-signing.key";
/// Filename of the local device X25519 key-agreement key, inside the
/// directory resolved by [`default_keyit_data_dir`].
pub const DEVICE_ENCRYPTION_KEY_FILENAME: &str = "device-encryption.key";
const KEY_STORE_ENV: &str = "KEYIT_KEY_STORE";
const MACOS_KEYCHAIN_SERVICE: &str = "dev.keyit.device-key";

/// Resolves the directory `keyit-cli` stores its local device signing
/// key in.
///
/// Checked in order:
///
/// 1. `KEYIT_DATA_DIR` — an explicit override. Not part of the
///    protocol; exists so tests (and users who want to relocate the
///    store) do not need to touch the real home directory.
/// 2. `XDG_DATA_HOME` — the XDG Base Directory spec's data home, if set.
/// 3. `HOME`/`.local/share/keyit` — the default for macOS/Linux.
///
/// Windows is not handled here because there is no general `HOME`
/// fallback; this returns [`CliError::HomeDirectoryNotFound`] rather
/// than guessing.
pub fn default_keyit_data_dir() -> Result<PathBuf, CliError> {
    if let Ok(dir) = std::env::var("KEYIT_DATA_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("keyit"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| CliError::HomeDirectoryNotFound)?;
    if home.is_empty() {
        return Err(CliError::HomeDirectoryNotFound);
    }
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("keyit"))
}

/// Loads this device's Ed25519 signing key from `dir`, generating and
/// persisting a new one if none exists yet.
///
/// Returns the keypair and the path it was loaded from/written to.
///
/// - If `dir/device-signing.key` exists, its contents are parsed as a
///   lowercase-hex-encoded 32-byte seed and reloaded via
///   [`SigningKeyPair::from_bytes`] — the same device identity is reused
///   across every `keyit init` run on this machine.
/// - Otherwise, a new keypair is generated via
///   [`SigningKeyPair::generate`], and its seed
///   ([`SigningKeyPair::to_bytes`]) is written to that path, hex-encoded,
///   with `0600` permissions on Unix (see this module's private
///   `write_new_file_with_restricted_permissions` helper).
///
/// Every buffer that transiently holds the raw seed (as bytes or as its
/// hex string form) is zeroed before this function returns.
pub fn load_or_create_device_signing_key(
    dir: &Path,
) -> Result<(SigningKeyPair, PathBuf), CliError> {
    let key_ref = DeviceKeyRef::new(DeviceKeyKind::Signing, dir);
    let mut seed =
        load_or_create_raw_device_key(&key_ref, || SigningKeyPair::generate().to_bytes())?;
    let keypair = SigningKeyPair::from_bytes(&seed);
    seed.zeroize();
    Ok((keypair, key_ref.display_path()))
}

/// Loads this device's X25519 key-agreement key from `dir`, generating
/// and persisting a new one if none exists yet.
///
/// The storage format and permission behavior match
/// [`load_or_create_device_signing_key`], but the key material is
/// independent and used only for DEK wrapping/unwrapping.
pub fn load_or_create_device_encryption_key(
    dir: &Path,
) -> Result<(KeyAgreementKeyPair, PathBuf), CliError> {
    let key_ref = DeviceKeyRef::new(DeviceKeyKind::Encryption, dir);
    let mut secret =
        load_or_create_raw_device_key(&key_ref, || KeyAgreementKeyPair::generate().to_bytes())?;
    let keypair = KeyAgreementKeyPair::from_bytes(&secret);
    secret.zeroize();
    Ok((keypair, key_ref.display_path()))
}

fn load_or_create_raw_device_key(
    key_ref: &DeviceKeyRef,
    generate: impl FnOnce() -> [u8; 32],
) -> Result<[u8; 32], CliError> {
    if key_ref.should_use_native()? {
        return load_or_create_native_device_key(key_ref, generate);
    }

    load_or_create_raw_device_key_file(&key_ref.file_path(), generate)
}

fn load_or_create_raw_device_key_file(
    key_path: &Path,
    generate: impl FnOnce() -> [u8; 32],
) -> Result<[u8; 32], CliError> {
    if key_path.exists() {
        return read_raw_device_key(key_path);
    }

    let dir = key_path
        .parent()
        .expect("device key path should always have a parent");
    fs::create_dir_all(dir).map_err(|e| CliError::io(dir, e))?;

    let seed = generate();
    let mut hex = HEXLOWER.encode(&seed);
    write_new_file_with_restricted_permissions(key_path, hex.as_bytes())?;
    hex.zeroize();

    Ok(seed)
}

fn load_or_create_native_device_key(
    key_ref: &DeviceKeyRef,
    generate: impl FnOnce() -> [u8; 32],
) -> Result<[u8; 32], CliError> {
    #[cfg(target_os = "macos")]
    {
        load_or_create_macos_keychain_key(key_ref, generate)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = key_ref;
        let _ = generate;
        Err(CliError::KeyStoreUnavailable {
            reason: "native key storage is implemented only for macOS in this build".to_string(),
        })
    }
}

#[cfg(target_os = "macos")]
fn load_or_create_macos_keychain_key(
    key_ref: &DeviceKeyRef,
    generate: impl FnOnce() -> [u8; 32],
) -> Result<[u8; 32], CliError> {
    if let Ok(hex) = read_macos_keychain_password(key_ref, MACOS_KEYCHAIN_SERVICE) {
        return decode_raw_device_key_hex(&key_ref.display_path(), &hex);
    }

    let seed = generate();
    write_macos_keychain_password(key_ref, MACOS_KEYCHAIN_SERVICE, &seed)?;
    Ok(seed)
}

#[cfg(target_os = "macos")]
fn write_macos_keychain_password(
    key_ref: &DeviceKeyRef,
    service: &str,
    seed: &[u8; 32],
) -> Result<(), CliError> {
    let mut hex = HEXLOWER.encode(seed);
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-s",
            service,
            "-a",
            key_ref.account(),
            "-w",
            &hex,
            "-U",
        ])
        .output()
        .map_err(|e| CliError::KeyStoreUnavailable {
            reason: format!("could not execute macOS security tool: {e}"),
        });
    hex.zeroize();

    let output = output?;
    if !output.status.success() {
        return Err(CliError::KeyStoreUnavailable {
            reason: format!(
                "macOS Keychain write failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_macos_keychain_password(key_ref: &DeviceKeyRef, service: &str) -> Result<String, CliError> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            service,
            "-a",
            key_ref.account(),
            "-w",
        ])
        .output()
        .map_err(|e| CliError::KeyStoreUnavailable {
            reason: format!("could not execute macOS security tool: {e}"),
        })?;
    if !output.status.success() {
        return Err(CliError::KeyStoreUnavailable {
            reason: format!(
                "macOS Keychain read failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    String::from_utf8(output.stdout).map_err(|e| CliError::KeyStoreUnavailable {
        reason: format!("macOS Keychain returned non-UTF-8 key material: {e}"),
    })
}

fn read_raw_device_key(key_path: &Path) -> Result<[u8; 32], CliError> {
    let mut hex_contents = fs::read_to_string(key_path).map_err(|e| CliError::io(key_path, e))?;
    let seed = decode_raw_device_key_hex(key_path, &hex_contents);
    hex_contents.zeroize();
    seed
}

fn decode_raw_device_key_hex(path: &Path, hex_contents: &str) -> Result<[u8; 32], CliError> {
    let mut seed_vec = HEXLOWER
        .decode(hex_contents.trim().as_bytes())
        .map_err(|_| CliError::MalformedDeviceKey {
            path: path.to_path_buf(),
        })?;

    if seed_vec.len() != 32 {
        seed_vec.zeroize();
        return Err(CliError::MalformedDeviceKey {
            path: path.to_path_buf(),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_vec);
    seed_vec.zeroize();
    Ok(seed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKeyKind {
    Signing,
    Encryption,
}

impl DeviceKeyKind {
    fn filename(self) -> &'static str {
        match self {
            Self::Signing => DEVICE_SIGNING_KEY_FILENAME,
            Self::Encryption => DEVICE_ENCRYPTION_KEY_FILENAME,
        }
    }

    fn account(self) -> &'static str {
        match self {
            Self::Signing => "device-signing",
            Self::Encryption => "device-encryption",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceKeyRef {
    kind: DeviceKeyKind,
    dir: PathBuf,
}

impl DeviceKeyRef {
    fn new(kind: DeviceKeyKind, dir: &Path) -> Self {
        Self {
            kind,
            dir: dir.to_path_buf(),
        }
    }

    fn file_path(&self) -> PathBuf {
        self.dir.join(self.kind.filename())
    }

    fn display_path(&self) -> PathBuf {
        if self.should_use_native().unwrap_or(false) {
            PathBuf::from(format!(
                "macos-keychain://{}/{}",
                MACOS_KEYCHAIN_SERVICE,
                self.account()
            ))
        } else {
            self.file_path()
        }
    }

    fn account(&self) -> &'static str {
        self.kind.account()
    }

    fn should_use_native(&self) -> Result<bool, CliError> {
        match std::env::var(KEY_STORE_ENV)
            .ok()
            .filter(|v| !v.is_empty())
            .as_deref()
        {
            Some("file") => return Ok(false),
            Some("native") => return Ok(true),
            Some("auto") | None => {}
            Some(other) => {
                return Err(CliError::KeyStoreUnavailable {
                    reason: format!(
                        "{KEY_STORE_ENV} must be one of auto, native, or file; got {other}"
                    ),
                });
            }
        }

        #[cfg(target_os = "macos")]
        {
            if std::env::var_os("KEYIT_DATA_DIR").is_some() {
                return Ok(false);
            }
            if let Ok(default_dir) = default_keyit_data_dir() {
                return Ok(self.dir == default_dir);
            }
        }
        Ok(false)
    }
}

/// Writes `contents` to a brand-new file at `path`, restricted to
/// owner-read/write (`0600`) on Unix from the moment it is created —
/// never briefly world-readable.
///
/// On non-Unix platforms this falls back to a plain [`fs::write`]
/// because Unix mode bits are unavailable.
#[cfg(unix)]
fn write_new_file_with_restricted_permissions(
    path: &Path,
    contents: &[u8],
) -> Result<(), CliError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::io(path, e))?;
    file.write_all(contents).map_err(|e| CliError::io(path, e))
}

#[cfg(not(unix))]
fn write_new_file_with_restricted_permissions(
    path: &Path,
    contents: &[u8],
) -> Result<(), CliError> {
    fs::write(path, contents).map_err(|e| CliError::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_new_key_when_none_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_, path) =
            load_or_create_device_signing_key(dir.path()).expect("should generate a key");
        assert!(path.exists());
        assert_eq!(path, dir.path().join(DEVICE_SIGNING_KEY_FILENAME));
    }

    #[test]
    fn reuses_an_existing_key_across_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (first, _) =
            load_or_create_device_signing_key(dir.path()).expect("first load should generate");
        let (second, _) =
            load_or_create_device_signing_key(dir.path()).expect("second load should reuse");

        assert_eq!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes()
        );
    }

    #[test]
    fn generates_and_reuses_an_encryption_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (first, path) =
            load_or_create_device_encryption_key(dir.path()).expect("first load should generate");
        let (second, second_path) =
            load_or_create_device_encryption_key(dir.path()).expect("second load should reuse");

        assert_eq!(path, dir.path().join(DEVICE_ENCRYPTION_KEY_FILENAME));
        assert_eq!(path, second_path);
        assert_eq!(
            first.public_key().as_bytes(),
            second.public_key().as_bytes()
        );
    }

    #[test]
    fn rejects_a_malformed_key_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(DEVICE_SIGNING_KEY_FILENAME), "not hex!!").expect("write");

        let err = load_or_create_device_signing_key(dir.path()).unwrap_err();
        assert!(matches!(err, CliError::MalformedDeviceKey { .. }));
    }

    #[test]
    fn rejects_a_key_file_of_the_wrong_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(DEVICE_SIGNING_KEY_FILENAME), "abcd").expect("write");

        let err = load_or_create_device_signing_key(dir.path()).unwrap_err();
        assert!(matches!(err, CliError::MalformedDeviceKey { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_restrictive_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let (_, path) =
            load_or_create_device_signing_key(dir.path()).expect("should generate a key");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn encryption_key_file_has_restrictive_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let (_, path) =
            load_or_create_device_encryption_key(dir.path()).expect("should generate a key");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn default_keyit_data_dir_respects_keyit_data_dir_override() {
        // SAFETY (not `unsafe` — just a note): this mutates process-wide
        // environment state, so this test does not run concurrently with
        // itself; Rust's test harness runs each `#[test]` in its own
        // thread but shares the process environment, so we scope the
        // override to this single check and restore it immediately.
        let previous = std::env::var("KEYIT_DATA_DIR").ok();
        std::env::set_var("KEYIT_DATA_DIR", "/tmp/keyit-data-dir-override-test");

        let resolved = default_keyit_data_dir().expect("should resolve");

        match previous {
            Some(value) => std::env::set_var("KEYIT_DATA_DIR", value),
            None => std::env::remove_var("KEYIT_DATA_DIR"),
        }

        assert_eq!(resolved, PathBuf::from("/tmp/keyit-data-dir-override-test"));
    }
}
