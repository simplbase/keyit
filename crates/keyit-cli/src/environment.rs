//! `keyit env add` — local environment genesis creation.
//!
//! This module creates a signed [`EnvironmentGenesis`] inside an already
//! initialized Keyit project. It does not read the mapped dotenv file,
//! does not publish encrypted payloads, and does not contact a relay.

use std::path::PathBuf;

use keyit_protocol::canonical::{self, labels};
use keyit_protocol::ids::{DeviceId, EnvironmentId, ProjectId};
use keyit_protocol::primitives::{HashBytes, SignatureBytes, Timestamp};
use keyit_protocol::records::{
    ApprovalSource, DocumentType, EnvironmentGenesis, MembershipGenesis, ProjectGenesis, Role,
};
use keyit_protocol::signing::SignedRecord;
use keyit_protocol::version::ProtocolVersion;

use crate::error::CliError;
use crate::keyit_dir::{self, EnvironmentDirLayout};
use crate::{device_identity, device_key};

/// Inputs to [`run_env_add`].
#[derive(Debug, Clone)]
pub struct EnvAddOptions {
    /// The Keyit project root.
    pub project_root: PathBuf,
    /// Directory the local device keys are stored in/loaded from.
    pub keyit_data_dir: PathBuf,
    /// Human-readable environment label, e.g. `development`.
    pub environment_label: String,
    /// Machine-local dotenv path hint, e.g. `.env.local`.
    pub local_path: PathBuf,
    /// Creation timestamp.
    pub now: Timestamp,
}

/// What [`run_env_add`] created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvAddOutcome {
    /// Project this environment belongs to.
    pub project_id: ProjectId,
    /// Newly-derived environment identifier.
    pub environment_id: EnvironmentId,
    /// Effective environment label.
    pub environment_label: String,
    /// Local materialization path recorded in `local.toml`.
    pub local_path: PathBuf,
    /// Device that created the environment.
    pub created_by_device_id: DeviceId,
    /// Runtime state paths written under the Keyit data directory.
    pub layout: EnvironmentDirLayout,
}

/// Runs `keyit env add`'s core logic.
pub fn run_env_add(options: EnvAddOptions) -> Result<EnvAddOutcome, CliError> {
    let EnvAddOptions {
        project_root,
        keyit_data_dir,
        environment_label,
        local_path,
        now,
    } = options;

    validate_environment_label(&environment_label)?;

    let layout = crate::project_state::require_project_layout(&project_root, &keyit_data_dir)?;

    let project = keyit_dir::read_project_genesis(&layout)?;
    project.verify_signature()?;
    if !keyit_dir::project_locator_file(&project_root).exists() {
        keyit_dir::write_project_locator(&project_root, &project)?;
    }

    let membership = keyit_dir::read_membership_genesis(&layout)?;
    membership.verify_signature(&project.creator_device_public_identity)?;
    ensure_genesis_owner(&project, &membership)?;

    let (device_keypair, _) = device_key::load_or_create_device_signing_key(&keyit_data_dir)?;
    let (device_encryption_keypair, _) =
        device_key::load_or_create_device_encryption_key(&keyit_data_dir)?;
    let device_identity =
        device_identity::build_device_identity(&device_keypair, &device_encryption_keypair, now);
    if device_identity.device_id != project.creator_device_id {
        return Err(CliError::NotProjectOwner {
            reason: format!(
                "local device {} is not the project creator {}",
                device_identity.device_id, project.creator_device_id
            ),
        });
    }

    let existing = keyit_dir::read_environment_genesis_records(&layout)?;
    if existing
        .iter()
        .any(|(_, record)| record.environment_label == environment_label)
    {
        return Err(CliError::EnvironmentAlreadyExists {
            label: environment_label,
        });
    }

    let document_type = DocumentType::DotenvV1;
    let environment_id = EnvironmentId::derive(
        ProtocolVersion::CURRENT,
        &project.project_id,
        &environment_label,
        document_type.as_str(),
        now,
        &device_identity.device_id,
    );
    let parent_project_genesis_hash = project_genesis_hash(&project);

    let mut environment = EnvironmentGenesis {
        protocol_version: ProtocolVersion::CURRENT,
        project_id: project.project_id.clone(),
        environment_id: environment_id.clone(),
        environment_label: environment_label.clone(),
        document_type,
        local_path_hint: local_path.clone(),
        created_at: now,
        created_by_device_id: device_identity.device_id.clone(),
        parent_project_genesis_hash,
        signature: zero_signature_field(),
    };
    environment.signature = device_keypair.sign(EnvironmentGenesis::SIGN_LABEL, &environment);
    environment.verify_signature(&device_keypair.public_key())?;

    let env_layout = keyit_dir::write_environment_dir(&layout, &environment)?;
    let _locator_path =
        keyit_dir::upsert_locator_environment(&project_root, &environment, &local_path)?;

    Ok(EnvAddOutcome {
        project_id: project.project_id,
        environment_id,
        environment_label,
        local_path,
        created_by_device_id: device_identity.device_id,
        layout: env_layout,
    })
}

fn validate_environment_label(label: &str) -> Result<(), CliError> {
    if label.trim().is_empty() {
        return Err(CliError::MalformedRecordFile {
            path: PathBuf::from(".keyit/environments"),
            reason: "environment label must not be empty".to_string(),
        });
    }
    if label.contains('/') || label.contains('\\') {
        return Err(CliError::MalformedRecordFile {
            path: PathBuf::from(".keyit/environments"),
            reason: "environment label must not contain path separators".to_string(),
        });
    }
    Ok(())
}

fn ensure_genesis_owner(
    project: &ProjectGenesis,
    membership: &MembershipGenesis,
) -> Result<(), CliError> {
    if membership.project_id != project.project_id {
        return Err(CliError::NotProjectOwner {
            reason: "membership genesis belongs to a different project".to_string(),
        });
    }
    if membership.member_device_id != project.creator_device_id {
        return Err(CliError::NotProjectOwner {
            reason: "membership genesis does not grant the project creator".to_string(),
        });
    }
    if membership.role != Role::Owner || membership.approved_by != ApprovalSource::Genesis {
        return Err(CliError::NotProjectOwner {
            reason: "only the genesis owner can create environments".to_string(),
        });
    }
    Ok(())
}

fn project_genesis_hash(project: &ProjectGenesis) -> HashBytes {
    canonical::canonical_hash(labels::SIGN_PROJECT_GENESIS, project)
}

fn zero_signature_field() -> SignatureBytes {
    SignatureBytes::from_bytes(&[0u8; 64]).expect("64 zero bytes is a validly-shaped signature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{run_init, InitOptions};

    fn init_options(project_root: PathBuf, keyit_data_dir: PathBuf) -> InitOptions {
        InitOptions {
            project_root,
            keyit_data_dir,
            project_label: None,
            relay_url: None,
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_400),
        }
    }

    fn env_options(project_root: PathBuf, keyit_data_dir: PathBuf) -> EnvAddOptions {
        EnvAddOptions {
            project_root,
            keyit_data_dir,
            environment_label: "development".to_string(),
            local_path: PathBuf::from(".env.local"),
            now: Timestamp::from_unix_seconds(1_755_878_500),
        }
    }

    struct Fixture {
        _project_dir: tempfile::TempDir,
        _data_dir: tempfile::TempDir,
        project_root: PathBuf,
        keyit_data_dir: PathBuf,
    }

    fn initialized_fixture() -> Fixture {
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let data_dir = tempfile::tempdir().expect("data tempdir");
        let project_root = project_dir.path().to_path_buf();
        let keyit_data_dir = data_dir.path().to_path_buf();
        run_init(init_options(project_root.clone(), keyit_data_dir.clone())).expect("init");
        Fixture {
            _project_dir: project_dir,
            _data_dir: data_dir,
            project_root,
            keyit_data_dir,
        }
    }

    #[test]
    fn creates_environment_metadata_files() {
        let fx = initialized_fixture();
        let outcome = run_env_add(env_options(
            fx.project_root.clone(),
            fx.keyit_data_dir.clone(),
        ))
        .expect("env add");

        assert!(outcome.layout.environment_dir.exists());
        assert!(outcome.layout.environment_file.exists());
        assert!(outcome.layout.local_toml.exists());
        assert!(outcome.environment_id.as_str().starts_with("kve_"));
    }

    #[test]
    fn fails_before_init() {
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let data_dir = tempfile::tempdir().expect("data tempdir");
        let err = run_env_add(env_options(
            project_dir.path().to_path_buf(),
            data_dir.path().to_path_buf(),
        ))
        .unwrap_err();

        assert!(matches!(err, CliError::NotInitialized { .. }));
    }

    #[test]
    fn rejects_duplicate_environment_label() {
        let fx = initialized_fixture();
        run_env_add(env_options(
            fx.project_root.clone(),
            fx.keyit_data_dir.clone(),
        ))
        .expect("first env add");

        let err = run_env_add(env_options(
            fx.project_root.clone(),
            fx.keyit_data_dir.clone(),
        ))
        .unwrap_err();

        assert!(matches!(err, CliError::EnvironmentAlreadyExists { .. }));
    }

    #[test]
    fn does_not_read_local_dotenv_file() {
        let fx = initialized_fixture();
        let mut options = env_options(fx.project_root.clone(), fx.keyit_data_dir.clone());
        options.local_path = PathBuf::from("missing.env");

        run_env_add(options).expect("env add should not require local file to exist");
    }

    #[test]
    fn generated_environment_record_round_trips_and_verifies() {
        let fx = initialized_fixture();
        let outcome = run_env_add(env_options(
            fx.project_root.clone(),
            fx.keyit_data_dir.clone(),
        ))
        .expect("env add");

        let record =
            keyit_dir::read_environment_genesis(&outcome.layout).expect("read environment");
        let (keypair, _) = device_key::load_or_create_device_signing_key(&fx.keyit_data_dir)
            .expect("load device key");
        record
            .verify_signature(&keypair.public_key())
            .expect("environment signature should verify");
        assert_eq!(record.environment_label, "development");
        assert_eq!(record.local_path_hint, PathBuf::from(".env.local"));
    }
}
