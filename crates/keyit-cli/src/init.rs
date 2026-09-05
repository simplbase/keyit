//! `keyit init` — local Keyit project initialization.
//!
//! Builds a real signed
//! [`DeviceIdentity`](keyit_protocol::records::DeviceIdentity)/[`ProjectGenesis`]/
//! [`MembershipGenesis`] using only `keyit-protocol`'s existing ID
//! derivation, canonicalization, and signing APIs, verifies every
//! signature it just produced, and only then writes `keyit.toml` plus
//! local runtime state under the Keyit data directory.
//!
//! This module does not read `.env`, does not perform any network I/O,
//! and does not encrypt any environment payload during init.

use std::path::PathBuf;

use keyit_protocol::ids::ProjectId;
use keyit_protocol::primitives::{NonceBytes, SignatureBytes, Timestamp};
use keyit_protocol::records::{ApprovalSource, MembershipGenesis, ProjectGenesis, Role};
use keyit_protocol::signing::SignedRecord;
use keyit_protocol::version::ProtocolVersion;

use crate::error::CliError;
use crate::keyit_dir::{self, KeyitDirLayout};
use crate::{device_identity, device_key};

/// Default relay URL recorded when `--relay-url` is not passed.
///
/// `relay.keyit.sh` is the canonical hosted relay and the default for
/// every new project. Every caller reads the relay URL through this
/// constant, or a project's own recorded `default_relay_url`, which is
/// seeded from it.
pub const DEFAULT_RELAY_URL: &str = "https://relay.keyit.sh";
/// Fallback project label used only when the project root has no usable
/// directory name (e.g. it is a filesystem root) — an edge case, not the
/// expected common path.
pub const FALLBACK_PROJECT_LABEL: &str = "keyit-project";

/// Inputs to [`run_init`].
///
/// Every path and the notion of "now" are explicit fields rather than
/// resolved internally, so library callers (tests, and `main.rs`) fully
/// control where this function touches the filesystem — nothing in
/// [`run_init`] resolves `$HOME` or calls `SystemTime::now()` itself.
#[derive(Debug, Clone)]
pub struct InitOptions {
    /// The directory to initialize as a Keyit project (where
    /// `keyit.toml` is created). Corresponds to running `keyit init`
    /// from this directory.
    pub project_root: PathBuf,
    /// Directory the local device signing key is stored in/loaded from
    /// — see [`device_key::default_keyit_data_dir`] for the real CLI's
    /// default, and note it is never inside `project_root`.
    pub keyit_data_dir: PathBuf,
    /// `--project-label`. Defaults to `project_root`'s directory name
    /// when `None`.
    pub project_label: Option<String>,
    /// `--relay-url`. Defaults to [`DEFAULT_RELAY_URL`] when `None`.
    pub relay_url: Option<String>,
    /// `--force`.
    pub force: bool,
    /// The creation timestamp recorded on every record this run
    /// produces.
    pub now: Timestamp,
}

/// What [`run_init`] created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitOutcome {
    /// The newly-derived project identifier.
    pub project_id: ProjectId,
    /// This device's identifier (also the project's first/owner member).
    pub creator_device_id: keyit_protocol::ids::DeviceId,
    /// Effective project label (after applying the directory-name
    /// default).
    pub project_label: String,
    /// Effective relay URL (after applying [`DEFAULT_RELAY_URL`]).
    pub default_relay_url: String,
    /// Runtime state layout written under the Keyit data directory.
    pub layout: KeyitDirLayout,
    /// Where the local device signing key was loaded from/written to.
    pub device_signing_key_path: PathBuf,
    /// Where the local device X25519 key-agreement key was loaded
    /// from/written to.
    pub device_encryption_key_path: PathBuf,
}

/// Runs `keyit init`'s core logic.
///
/// Order of operations:
///
/// 1. If Keyit locator/state already exists and `force` is `false`,
///    fail immediately with
///    [`CliError::AlreadyInitialized`] — before touching the device key
///    store or generating anything, so a plain re-run is a cheap,
///    side-effect-free failure.
/// 2. Resolve the effective project label and relay URL (applying
///    defaults).
/// 3. Load this machine's device signing and encryption keys from
///    `keyit_data_dir` (generating either if it doesn't exist yet),
///    and build this machine's
///    [`DeviceIdentity`](keyit_protocol::records::DeviceIdentity).
/// 4. Generate a fresh high-entropy genesis nonce, derive the project's
///    [`ProjectId`], build and sign a [`ProjectGenesis`], and **verify
///    that signature** before doing anything else with it.
/// 5. Build and sign a [`MembershipGenesis`] granting the creator device
///    the owner role, and verify that signature too.
/// 6. Only now write the repository locator and local runtime state.
pub fn run_init(options: InitOptions) -> Result<InitOutcome, CliError> {
    let InitOptions {
        project_root,
        keyit_data_dir,
        project_label,
        relay_url,
        force,
        now,
    } = options;

    let legacy_layout = KeyitDirLayout::under(&project_root);
    let locator_path = keyit_dir::project_locator_file(&project_root);
    if (legacy_layout.project_toml.exists() || locator_path.exists()) && !force {
        return Err(CliError::AlreadyInitialized { path: locator_path });
    }

    let project_label = project_label.unwrap_or_else(|| default_project_label(&project_root));
    let default_relay_url = relay_url.unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());

    let (device_keypair, device_signing_key_path) =
        device_key::load_or_create_device_signing_key(&keyit_data_dir)?;
    let (device_encryption_keypair, device_encryption_key_path) =
        device_key::load_or_create_device_encryption_key(&keyit_data_dir)?;
    let device_identity =
        device_identity::build_device_identity(&device_keypair, &device_encryption_keypair, now);

    let mut nonce_bytes = [0u8; 16];
    getrandom::fill(&mut nonce_bytes).expect("OS CSPRNG should be available");
    let genesis_nonce = NonceBytes::from_bytes(nonce_bytes.to_vec());

    let project_id = ProjectId::derive(
        ProtocolVersion::CURRENT,
        &genesis_nonce,
        &device_identity.device_id,
        now,
        &project_label,
        &default_relay_url,
    );

    let mut project_genesis = ProjectGenesis {
        protocol_version: ProtocolVersion::CURRENT,
        project_id: project_id.clone(),
        genesis_nonce,
        created_at: now,
        creator_device_id: device_identity.device_id.clone(),
        creator_device_public_identity: device_keypair.public_key(),
        project_label: project_label.clone(),
        default_relay_url: default_relay_url.clone(),
        canonicalization_version: 0,
        signature: zero_signature_field(),
    };
    project_genesis.signature = device_keypair.sign(ProjectGenesis::SIGN_LABEL, &project_genesis);
    project_genesis.verify_signature()?;

    let mut membership_genesis = MembershipGenesis {
        project_id: project_id.clone(),
        member_device_id: device_identity.device_id.clone(),
        role: Role::Owner,
        approved_by: ApprovalSource::Genesis,
        created_at: now,
        signature: zero_signature_field(),
    };
    membership_genesis.signature =
        device_keypair.sign(MembershipGenesis::SIGN_LABEL, &membership_genesis);
    membership_genesis.verify_signature(&device_keypair.public_key())?;

    let state_root = keyit_dir::project_state_root(&keyit_data_dir, &project_id);
    let layout = keyit_dir::write_keyit_dir(&state_root, &project_genesis, &membership_genesis)?;
    keyit_dir::write_project_locator(&project_root, &project_genesis)?;

    Ok(InitOutcome {
        project_id,
        creator_device_id: device_identity.device_id,
        project_label,
        default_relay_url,
        layout,
        device_signing_key_path,
        device_encryption_key_path,
    })
}

/// A structurally-valid zero signature, used only to give the record
/// struct a `SignatureBytes` value to hold between
/// construction and the real [`SigningKeyPair::sign`](keyit_protocol::signing::SigningKeyPair::sign)
/// call a few lines later (signing does not read the `signature` field
/// so this value never affects what gets signed). Always
/// overwritten before the record is used or written anywhere.
fn zero_signature_field() -> SignatureBytes {
    SignatureBytes::from_bytes(&[0u8; 64]).expect("64 zero bytes is a validly-shaped signature")
}

/// Default `--project-label`: `project_root`'s final path component.
///
/// Falls back to [`FALLBACK_PROJECT_LABEL`] for the unusual case where
/// `project_root` has no file-name component (e.g. it is `/` or `.`
/// resolves to something without one) — `keyit init` should still
/// produce a usable label rather than failing.
fn default_project_label(project_root: &std::path::Path) -> String {
    project_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| FALLBACK_PROJECT_LABEL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn options(project_root: PathBuf, keyit_data_dir: PathBuf) -> InitOptions {
        InitOptions {
            project_root,
            keyit_data_dir,
            project_label: None,
            relay_url: None,
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_400),
        }
    }

    struct Fixture {
        _project_dir: tempfile::TempDir,
        _data_dir: tempfile::TempDir,
        project_root: PathBuf,
        keyit_data_dir: PathBuf,
    }

    fn fixture() -> Fixture {
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let data_dir = tempfile::tempdir().expect("data tempdir");
        Fixture {
            project_root: project_dir.path().to_path_buf(),
            keyit_data_dir: data_dir.path().to_path_buf(),
            _project_dir: project_dir,
            _data_dir: data_dir,
        }
    }

    #[test]
    fn creates_keyit_dir() {
        let fx = fixture();
        let outcome = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed");
        assert!(outcome.layout.keyit_dir.exists());
        assert!(outcome.layout.keyit_dir.is_dir());
    }

    #[test]
    fn project_metadata_contains_a_kvp_project_id() {
        let fx = fixture();
        let outcome = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed");

        assert!(outcome.project_id.as_str().starts_with("kvp_"));

        let metadata =
            keyit_dir::read_project_metadata(&outcome.layout).expect("should read project.toml");
        assert_eq!(metadata.project_id, outcome.project_id.as_str());
    }

    #[test]
    fn genesis_and_membership_files_are_created() {
        let fx = fixture();
        let outcome = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed");

        assert!(outcome.layout.genesis_file.exists());
        assert!(outcome.layout.membership_genesis_file.exists());
    }

    #[test]
    fn private_key_is_not_written_under_keyit_dir() {
        let fx = fixture();
        let outcome = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed");

        // The device keys live outside the local project runtime cache.
        assert!(!outcome
            .device_signing_key_path
            .starts_with(&outcome.layout.keyit_dir));
        assert!(!outcome
            .device_encryption_key_path
            .starts_with(&outcome.layout.keyit_dir));

        // And no runtime cache file contains the raw device key material
        // (loaded independently here, from the same data dir, to get the
        // exact private bytes without relying on internal state).
        let (signing_keypair, _) =
            device_key::load_or_create_device_signing_key(&fx.keyit_data_dir)
                .expect("should reload the same key");
        let (encryption_keypair, _) =
            device_key::load_or_create_device_encryption_key(&fx.keyit_data_dir)
                .expect("should reload the same encryption key");
        let signing_seed_hex = data_encoding::HEXLOWER.encode(&signing_keypair.to_bytes());
        let encryption_secret_hex = data_encoding::HEXLOWER.encode(&encryption_keypair.to_bytes());

        for entry in walk_files(&outcome.layout.keyit_dir) {
            let content = fs::read_to_string(&entry).unwrap_or_default();
            assert!(
                !content.contains(&signing_seed_hex),
                "{entry:?} unexpectedly contains the device signing key"
            );
            assert!(
                !content.contains(&encryption_secret_hex),
                "{entry:?} unexpectedly contains the device encryption key"
            );
        }
    }

    #[test]
    fn existing_keyit_dir_fails_without_force() {
        let fx = fixture();
        run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("first init should succeed");

        let err =
            run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone())).unwrap_err();
        assert!(matches!(err, CliError::AlreadyInitialized { .. }));
    }

    #[test]
    fn force_overwrites_existing_metadata() {
        let fx = fixture();
        run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("first init should succeed");

        let mut second = options(fx.project_root.clone(), fx.keyit_data_dir.clone());
        second.force = true;
        second.project_label = Some("relabeled".to_string());

        let outcome = run_init(second).expect("forced re-init should succeed");
        assert_eq!(outcome.project_label, "relabeled");

        let metadata =
            keyit_dir::read_project_metadata(&outcome.layout).expect("should read project.toml");
        assert_eq!(metadata.project_label, "relabeled");
    }

    #[test]
    fn default_project_label_uses_directory_name() {
        let fx = fixture();
        let expected_label = fx
            .project_root
            .file_name()
            .expect("tempdir has a name")
            .to_string_lossy()
            .into_owned();

        let outcome = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed");
        assert_eq!(outcome.project_label, expected_label);
    }

    #[test]
    fn custom_project_label_is_respected() {
        let fx = fixture();
        let mut opts = options(fx.project_root.clone(), fx.keyit_data_dir.clone());
        opts.project_label = Some("my-custom-label".to_string());

        let outcome = run_init(opts).expect("init should succeed");
        assert_eq!(outcome.project_label, "my-custom-label");
    }

    #[test]
    fn default_relay_url_is_recorded() {
        let fx = fixture();
        let outcome = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed");
        assert_eq!(outcome.default_relay_url, DEFAULT_RELAY_URL);
    }

    #[test]
    fn custom_relay_url_is_respected() {
        let fx = fixture();
        let mut opts = options(fx.project_root.clone(), fx.keyit_data_dir.clone());
        opts.relay_url = Some("https://relay.example.com".to_string());

        let outcome = run_init(opts).expect("init should succeed");
        assert_eq!(outcome.default_relay_url, "https://relay.example.com");
    }

    #[test]
    fn generated_records_verify_after_being_written() {
        let fx = fixture();
        let outcome = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed");

        let project_genesis =
            keyit_dir::read_project_genesis(&outcome.layout).expect("should read genesis.keyit");
        project_genesis
            .verify_signature()
            .expect("persisted project genesis should verify");

        let membership_genesis = keyit_dir::read_membership_genesis(&outcome.layout)
            .expect("should read membership/genesis.keyit");
        membership_genesis
            .verify_signature(&project_genesis.creator_device_public_identity)
            .expect("persisted membership genesis should verify");
    }

    #[test]
    fn does_not_require_or_touch_an_env_file() {
        let fx = fixture();
        let env_path = fx.project_root.join(".env");
        let env_contents = "SECRET_KEY=do-not-touch-me\n";
        fs::write(&env_path, env_contents).expect("write .env");

        run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("init should succeed with a .env present");

        let after = fs::read_to_string(&env_path).expect("read .env back");
        assert_eq!(
            after, env_contents,
            ".env must be left completely untouched"
        );
    }

    #[test]
    fn succeeds_without_any_env_file_present() {
        let fx = fixture();
        assert!(!fx.project_root.join(".env").exists());
        run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect(".env must not be required");
    }

    #[test]
    fn reuses_the_same_device_key_across_different_projects() {
        let fx = fixture();
        let other_project_dir = tempfile::tempdir().expect("other project tempdir");

        let first = run_init(options(fx.project_root.clone(), fx.keyit_data_dir.clone()))
            .expect("first init should succeed");
        let second = run_init(options(
            other_project_dir.path().to_path_buf(),
            fx.keyit_data_dir.clone(),
        ))
        .expect("second init should succeed");

        assert_eq!(first.creator_device_id, second.creator_device_id);
        assert_eq!(
            first.device_signing_key_path,
            second.device_signing_key_path
        );
        assert_eq!(
            first.device_encryption_key_path,
            second.device_encryption_key_path
        );
    }

    fn walk_files(dir: &std::path::Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            for entry in fs::read_dir(&current).expect("read_dir") {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        files
    }
}
