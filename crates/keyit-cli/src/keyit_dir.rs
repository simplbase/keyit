//! Keyit project metadata layout and local file formats.
//!
//! ```text
//! keyit.toml              <- committed project locator
//!
//! $KEYIT_DATA_DIR/projects/<kvp_...>/.keyit/
//!   project.toml            <- summary metadata (project id, label, relay URL, ...)
//!   genesis.keyit            <- the signed ProjectGenesis record
//!   membership/
//!     genesis.keyit          <- the signed MembershipGenesis record
//! ```
//!
//! **File format.** Every file here is TOML (the `.keyit` extension on
//! the record files is a naming convention to mark them as Keyit
//! protocol records rather than general config, not a distinct binary
//! format — they parse with an ordinary TOML parser). This is a
//! human-inspectable local metadata format, not Keyit's canonical signed
//! byte encoding. Byte-valued fields (nonces, public keys, signatures)
//! are written as lowercase hex strings.
//!
//! **The signed bytes still come from `keyit-protocol`, not from this
//! module.** `ProjectGenesis`/`MembershipGenesis` are canonicalized and
//! signed entirely through `keyit_protocol::canonical`/`keyit_protocol::signing`
//! before this module ever sees them; this module only encodes the
//! *already-signed* record's fields (including the finished
//! `signature`) as TOML for local storage. Nothing here participates in
//! computing or verifying a signature.

use std::fs;
use std::path::{Path, PathBuf};

use data_encoding::HEXLOWER;
use keyit_protocol::canonical;
use keyit_protocol::canonical::labels;
use keyit_protocol::encryption::{EncryptedPayload, WrappedDataKey};
use keyit_protocol::ids::{DeviceId, EnvironmentId, InviteId, ProjectId, RevisionId};
use keyit_protocol::primitives::{
    HashBytes, NonceBytes, PublicKeyBytes, SignatureBytes, SigningPublicKeyBytes, Timestamp,
};
use keyit_protocol::records::{
    Approval, ApprovalSource, DocumentType, EnvironmentGenesis, Invite, InviteStatus, JoinRequest,
    MembershipGenesis, ProjectGenesis, Revision, Revocation, Role,
};
use keyit_protocol::version::ProtocolVersion;
use serde::{Deserialize, Serialize};

use crate::error::CliError;

/// Filename of the small locator committed to a project repository.
pub const KEYIT_LOCATOR_FILENAME: &str = "keyit.toml";
/// Name of the internal runtime-cache directory.
pub const KEYIT_DIR_NAME: &str = ".keyit";
/// Filename of the project summary metadata file.
pub const PROJECT_TOML_FILENAME: &str = "project.toml";
/// Filename shared by both signed genesis record files.
pub const GENESIS_FILENAME: &str = "genesis.keyit";
/// Name of the subdirectory holding membership records.
pub const MEMBERSHIP_DIR_NAME: &str = "membership";
/// Name of the subdirectory holding invite records.
pub const INVITES_DIR_NAME: &str = "invites";
/// Name of the subdirectory holding join request records.
pub const JOIN_REQUESTS_DIR_NAME: &str = "join-requests";
/// Name of the subdirectory holding approval records.
pub const APPROVALS_DIR_NAME: &str = "approvals";
/// Name of the subdirectory holding revocation records.
pub const REVOCATIONS_DIR_NAME: &str = "revocations";
/// Name of the subdirectory holding environment metadata.
pub const ENVIRONMENTS_DIR_NAME: &str = "environments";
/// Filename of a signed environment genesis record.
pub const ENVIRONMENT_FILENAME: &str = "environment.keyit";
/// Filename of machine-local environment mapping metadata.
pub const LOCAL_TOML_FILENAME: &str = "local.toml";
/// Name of the subdirectory holding local encrypted revision metadata.
pub const REVISIONS_DIR_NAME: &str = "revisions";
/// Name of the subdirectory holding local encrypted payload bytes.
pub const PAYLOADS_DIR_NAME: &str = "payloads";
/// Filename recording the latest local encrypted revision.
pub const LATEST_TOML_FILENAME: &str = "latest.toml";
/// Filename recording the revision currently materialized locally.
pub const MATERIALIZED_TOML_FILENAME: &str = "materialized.toml";
/// Filename recording that an environment needs post-revocation rotation.
pub const ROTATION_REQUIRED_TOML_FILENAME: &str = "rotation-required.toml";

/// Paths written by [`write_keyit_dir`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyitDirLayout {
    /// The internal `.keyit/` runtime-cache directory itself.
    pub keyit_dir: PathBuf,
    /// `.keyit/project.toml`.
    pub project_toml: PathBuf,
    /// `.keyit/genesis.keyit`.
    pub genesis_file: PathBuf,
    /// `.keyit/membership/genesis.keyit`.
    pub membership_genesis_file: PathBuf,
    /// `.keyit/environments`.
    pub environments_dir: PathBuf,
    /// `.keyit/invites`.
    pub invites_dir: PathBuf,
    /// `.keyit/join-requests`.
    pub join_requests_dir: PathBuf,
    /// `.keyit/approvals`.
    pub approvals_dir: PathBuf,
    /// `.keyit/revocations`.
    pub revocations_dir: PathBuf,
}

impl KeyitDirLayout {
    /// Computes the layout's paths under `project_root` without
    /// touching the filesystem — used both by [`write_keyit_dir`] and by
    /// callers (like [`crate::init::run_init`]) that need to check
    /// whether a project is already initialized before doing anything
    /// else.
    pub fn under(project_root: &Path) -> Self {
        let keyit_dir = project_root.join(KEYIT_DIR_NAME);
        let membership_dir = keyit_dir.join(MEMBERSHIP_DIR_NAME);
        let environments_dir = keyit_dir.join(ENVIRONMENTS_DIR_NAME);
        Self {
            project_toml: keyit_dir.join(PROJECT_TOML_FILENAME),
            genesis_file: keyit_dir.join(GENESIS_FILENAME),
            membership_genesis_file: membership_dir.join(GENESIS_FILENAME),
            environments_dir,
            invites_dir: keyit_dir.join(INVITES_DIR_NAME),
            join_requests_dir: keyit_dir.join(JOIN_REQUESTS_DIR_NAME),
            approvals_dir: keyit_dir.join(APPROVALS_DIR_NAME),
            revocations_dir: keyit_dir.join(REVOCATIONS_DIR_NAME),
            keyit_dir,
        }
    }

    pub fn invite_file(&self, invite_id: &InviteId) -> PathBuf {
        self.invites_dir
            .join(format!("{}.keyit", invite_id.as_str()))
    }

    pub fn invite_bundle_file(&self, invite_id: &InviteId) -> PathBuf {
        self.invites_dir
            .join(format!("{}.bundle", invite_id.as_str()))
    }

    pub fn join_request_file(&self, device_id: &DeviceId) -> PathBuf {
        self.join_requests_dir
            .join(format!("{}.keyit", device_id.as_str()))
    }

    pub fn approval_file(&self, device_id: &DeviceId) -> PathBuf {
        self.approvals_dir
            .join(format!("{}.keyit", device_id.as_str()))
    }

    pub fn revocation_file(&self, device_id: &DeviceId) -> PathBuf {
        self.revocations_dir
            .join(format!("{}.keyit", device_id.as_str()))
    }
}

pub fn project_locator_file(project_root: &Path) -> PathBuf {
    project_root.join(KEYIT_LOCATOR_FILENAME)
}

pub fn project_state_root(keyit_data_dir: &Path, project_id: &ProjectId) -> PathBuf {
    keyit_data_dir.join("projects").join(project_id.as_str())
}

pub fn data_layout(keyit_data_dir: &Path, project_id: &ProjectId) -> KeyitDirLayout {
    let root = project_state_root(keyit_data_dir, project_id);
    KeyitDirLayout::under(&root)
}

pub fn project_genesis_hash(project: &ProjectGenesis) -> HashBytes {
    canonical::canonical_hash(labels::SIGN_PROJECT_GENESIS, project)
}

/// Reads the committed project locator.
pub fn read_project_locator(project_root: &Path) -> Result<ProjectLocatorToml, CliError> {
    let path = project_locator_file(project_root);
    let locator: ProjectLocatorToml = read_toml(&path)?;
    if locator.version != 1 {
        return Err(CliError::MalformedRecordFile {
            path,
            reason: format!("unsupported Keyit locator version {}", locator.version),
        });
    }
    Ok(locator)
}

pub fn write_project_locator(
    project_root: &Path,
    project: &ProjectGenesis,
) -> Result<PathBuf, CliError> {
    let path = project_locator_file(project_root);
    let locator = ProjectLocatorToml::from_project(project, &project_genesis_hash(project));
    write_toml(&path, &locator)?;
    Ok(path)
}

pub fn upsert_locator_environment(
    project_root: &Path,
    environment: &EnvironmentGenesis,
    local_path: &Path,
) -> Result<PathBuf, CliError> {
    let path = project_locator_file(project_root);
    let mut locator = read_project_locator(project_root)?;
    let entry = ProjectLocatorEnvironmentToml {
        environment_id: environment.environment_id.as_str().to_string(),
        label: environment.environment_label.clone(),
        local_path: local_path.to_string_lossy().into_owned(),
    };
    if let Some(existing) = locator
        .environments
        .iter_mut()
        .find(|item| item.environment_id == entry.environment_id || item.label == entry.label)
    {
        *existing = entry;
    } else {
        locator.environments.push(entry);
    }
    locator.environments.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then_with(|| a.environment_id.cmp(&b.environment_id))
    });
    write_toml(&path, &locator)?;
    Ok(path)
}

pub fn resolve_project_layout(
    project_root: &Path,
    keyit_data_dir: &Path,
) -> Result<KeyitDirLayout, CliError> {
    let legacy_layout = KeyitDirLayout::under(project_root);
    if legacy_layout.project_toml.exists() {
        return Ok(legacy_layout);
    }

    let locator_path = project_locator_file(project_root);
    if !locator_path.exists() {
        return Err(CliError::NotInitialized { path: locator_path });
    }
    let locator = read_project_locator(project_root)?;
    let project_id = locator.project_id(&locator_path)?;
    Ok(data_layout(keyit_data_dir, &project_id))
}

/// The only Keyit file intended to be committed to an application
/// repository. It is a small trust anchor and locator; all mutable
/// runtime state lives under Keyit's data directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectLocatorToml {
    pub version: u32,
    pub project_id: String,
    pub project_label: String,
    pub genesis_hash: String,
    pub relay_url: String,
    #[serde(default)]
    pub environments: Vec<ProjectLocatorEnvironmentToml>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectLocatorEnvironmentToml {
    pub environment_id: String,
    pub label: String,
    pub local_path: String,
}

impl ProjectLocatorToml {
    pub fn from_project(project: &ProjectGenesis, genesis_hash: &HashBytes) -> Self {
        Self {
            version: 1,
            project_id: project.project_id.as_str().to_string(),
            project_label: project.project_label.clone(),
            genesis_hash: HEXLOWER.encode(genesis_hash.as_bytes()),
            relay_url: project.default_relay_url.clone(),
            environments: Vec::new(),
        }
    }

    pub fn project_id(&self, path: &Path) -> Result<ProjectId, CliError> {
        ProjectId::parse(&self.project_id).map_err(|err| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })
    }

    pub fn genesis_hash(&self, path: &Path) -> Result<HashBytes, CliError> {
        let bytes = decode_hex(path, "genesis_hash", &self.genesis_hash)?;
        let digest: [u8; 32] =
            bytes
                .try_into()
                .map_err(|bytes: Vec<u8>| CliError::MalformedRecordFile {
                    path: path.to_path_buf(),
                    reason: format!("genesis_hash must be 32 bytes, got {}", bytes.len()),
                })?;
        Ok(HashBytes::from_sha256_digest(digest))
    }
}

/// Paths for one environment's metadata directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentDirLayout {
    /// `.keyit/environments/<environment_id>/`.
    pub environment_dir: PathBuf,
    /// `.keyit/environments/<environment_id>/environment.keyit`.
    pub environment_file: PathBuf,
    /// `.keyit/environments/<environment_id>/local.toml`.
    pub local_toml: PathBuf,
    /// `.keyit/environments/<environment_id>/revisions/`.
    pub revisions_dir: PathBuf,
    /// `.keyit/environments/<environment_id>/payloads/`.
    pub payloads_dir: PathBuf,
    /// `.keyit/environments/<environment_id>/latest.toml`.
    pub latest_toml: PathBuf,
    /// `.keyit/environments/<environment_id>/materialized.toml`.
    pub materialized_toml: PathBuf,
    /// `.keyit/environments/<environment_id>/rotation-required.toml`.
    pub rotation_required_toml: PathBuf,
}

impl EnvironmentDirLayout {
    /// Computes an environment's paths below `layout.environments_dir`.
    pub fn under(layout: &KeyitDirLayout, environment_id: &EnvironmentId) -> Self {
        let environment_dir = layout.environments_dir.join(environment_id.as_str());
        let revisions_dir = environment_dir.join(REVISIONS_DIR_NAME);
        let payloads_dir = environment_dir.join(PAYLOADS_DIR_NAME);
        Self {
            environment_file: environment_dir.join(ENVIRONMENT_FILENAME),
            local_toml: environment_dir.join(LOCAL_TOML_FILENAME),
            latest_toml: environment_dir.join(LATEST_TOML_FILENAME),
            materialized_toml: environment_dir.join(MATERIALIZED_TOML_FILENAME),
            rotation_required_toml: environment_dir.join(ROTATION_REQUIRED_TOML_FILENAME),
            revisions_dir,
            payloads_dir,
            environment_dir,
        }
    }

    /// Path to one local revision metadata file.
    pub fn revision_file(&self, revision_id: &RevisionId) -> PathBuf {
        self.revisions_dir
            .join(format!("{}.keyit", revision_id.as_str()))
    }

    /// Path to one local encrypted payload file.
    pub fn payload_file(&self, revision_id: &RevisionId) -> PathBuf {
        self.payloads_dir
            .join(format!("{}.payload", revision_id.as_str()))
    }
}

/// Writes a project's internal runtime metadata: `project.toml`, the signed
/// `ProjectGenesis` (`genesis.keyit`), and the signed `MembershipGenesis`
/// (`membership/genesis.keyit`).
///
/// Only ever creates/truncates exactly these three paths — an existing
/// runtime directory is otherwise left untouched, matching the
/// "`--force` may overwrite only Keyit-generated metadata, not arbitrary
/// user secret files" rule. This
/// function does not itself decide whether overwriting is allowed —
/// callers (see [`crate::init::run_init`]) check
/// [`KeyitDirLayout::project_toml`] against `--force` first.
pub fn write_keyit_dir(
    project_root: &Path,
    project: &ProjectGenesis,
    membership: &MembershipGenesis,
) -> Result<KeyitDirLayout, CliError> {
    let layout = KeyitDirLayout::under(project_root);

    let membership_dir = layout
        .membership_genesis_file
        .parent()
        .expect("membership_genesis_file always has a parent directory")
        .to_path_buf();
    fs::create_dir_all(&membership_dir).map_err(|e| CliError::io(&membership_dir, e))?;

    write_toml(
        &layout.project_toml,
        &ProjectMetadataToml::from_genesis(project),
    )?;
    write_toml(
        &layout.genesis_file,
        &ProjectGenesisToml::from_record(project),
    )?;
    write_toml(
        &layout.membership_genesis_file,
        &MembershipGenesisToml::from_record(membership),
    )?;

    Ok(layout)
}

/// Writes the public project context needed by a joining device before
/// it has membership. This intentionally does not write membership,
/// approval, revision, payload, or key material.
pub fn write_project_bootstrap_dir(
    project_root: &Path,
    project: &ProjectGenesis,
    environments: &[EnvironmentGenesis],
) -> Result<KeyitDirLayout, CliError> {
    let layout = KeyitDirLayout::under(project_root);

    fs::create_dir_all(&layout.keyit_dir).map_err(|e| CliError::io(&layout.keyit_dir, e))?;
    write_toml(
        &layout.project_toml,
        &ProjectMetadataToml::from_genesis(project),
    )?;
    write_toml(
        &layout.genesis_file,
        &ProjectGenesisToml::from_record(project),
    )?;

    for environment in environments {
        write_environment_dir(&layout, environment)?;
    }

    Ok(layout)
}

/// Writes one signed environment genesis record and its local mapping.
pub fn write_environment_dir(
    layout: &KeyitDirLayout,
    environment: &EnvironmentGenesis,
) -> Result<EnvironmentDirLayout, CliError> {
    write_environment_dir_with_local_path(layout, environment, &environment.local_path_hint)
}

pub fn write_environment_dir_with_local_path(
    layout: &KeyitDirLayout,
    environment: &EnvironmentGenesis,
    local_path: &Path,
) -> Result<EnvironmentDirLayout, CliError> {
    let env_layout = EnvironmentDirLayout::under(layout, &environment.environment_id);
    fs::create_dir_all(&env_layout.environment_dir)
        .map_err(|e| CliError::io(&env_layout.environment_dir, e))?;

    write_toml(
        &env_layout.environment_file,
        &EnvironmentGenesisToml::from_record(environment),
    )?;
    let mut local = LocalEnvironmentToml::from_record(environment);
    local.local_path = local_path.to_string_lossy().into_owned();
    write_toml(&env_layout.local_toml, &local)?;

    Ok(env_layout)
}

pub fn write_invite(layout: &KeyitDirLayout, invite: &Invite) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.invites_dir).map_err(|e| CliError::io(&layout.invites_dir, e))?;
    let path = layout.invite_file(&invite.invite_id);
    write_toml(&path, &InviteToml::from_record(invite))?;
    Ok(path)
}

pub fn read_invite(layout: &KeyitDirLayout, invite_id: &InviteId) -> Result<Invite, CliError> {
    let path = layout.invite_file(invite_id);
    let toml: InviteToml = read_toml(&path)?;
    toml.to_record(&path)
}

pub fn import_invite_bytes(
    layout: &KeyitDirLayout,
    invite_id: &InviteId,
    bytes: &[u8],
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.invites_dir).map_err(|e| CliError::io(&layout.invites_dir, e))?;
    let path = layout.invite_file(invite_id);
    fs::write(&path, bytes).map_err(|e| CliError::io(&path, e))?;
    Ok(path)
}

pub fn import_membership_genesis_bytes(
    layout: &KeyitDirLayout,
    bytes: &[u8],
) -> Result<(), CliError> {
    let parent = layout
        .membership_genesis_file
        .parent()
        .expect("membership genesis file has a parent");
    fs::create_dir_all(parent).map_err(|e| CliError::io(parent, e))?;
    fs::write(&layout.membership_genesis_file, bytes)
        .map_err(|e| CliError::io(&layout.membership_genesis_file, e))
}

pub fn write_join_request(
    layout: &KeyitDirLayout,
    request: &JoinRequest,
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.join_requests_dir)
        .map_err(|e| CliError::io(&layout.join_requests_dir, e))?;
    let path = layout.join_request_file(&request.joining_device_id);
    write_toml(&path, &JoinRequestToml::from_record(request))?;
    Ok(path)
}

pub fn read_join_request(
    layout: &KeyitDirLayout,
    device_id: &DeviceId,
) -> Result<JoinRequest, CliError> {
    let path = layout.join_request_file(device_id);
    let toml: JoinRequestToml = read_toml(&path)?;
    toml.to_record(&path)
}

pub fn import_join_request_bytes(
    layout: &KeyitDirLayout,
    device_id: &DeviceId,
    bytes: &[u8],
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.join_requests_dir)
        .map_err(|e| CliError::io(&layout.join_requests_dir, e))?;
    let path = layout.join_request_file(device_id);
    fs::write(&path, bytes).map_err(|e| CliError::io(&path, e))?;
    Ok(path)
}

pub fn write_approval(layout: &KeyitDirLayout, approval: &Approval) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.approvals_dir)
        .map_err(|e| CliError::io(&layout.approvals_dir, e))?;
    let path = layout.approval_file(&approval.approved_device_id);
    write_toml(&path, &ApprovalToml::from_record(approval))?;
    Ok(path)
}

pub fn read_approval(layout: &KeyitDirLayout, device_id: &DeviceId) -> Result<Approval, CliError> {
    let path = layout.approval_file(device_id);
    let toml: ApprovalToml = read_toml(&path)?;
    toml.to_record(&path)
}

pub fn import_approval_bytes(
    layout: &KeyitDirLayout,
    device_id: &DeviceId,
    bytes: &[u8],
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.approvals_dir)
        .map_err(|e| CliError::io(&layout.approvals_dir, e))?;
    let path = layout.approval_file(device_id);
    fs::write(&path, bytes).map_err(|e| CliError::io(&path, e))?;
    Ok(path)
}

pub fn read_approval_records(layout: &KeyitDirLayout) -> Result<Vec<Approval>, CliError> {
    read_record_dir(&layout.approvals_dir, |path| {
        let toml: ApprovalToml = read_toml(path)?;
        toml.to_record(path)
    })
}

pub fn write_revocation(
    layout: &KeyitDirLayout,
    revocation: &Revocation,
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.revocations_dir)
        .map_err(|e| CliError::io(&layout.revocations_dir, e))?;
    let path = layout.revocation_file(&revocation.revoked_device_id);
    write_toml(&path, &RevocationToml::from_record(revocation))?;
    Ok(path)
}

pub fn read_revocation(
    layout: &KeyitDirLayout,
    device_id: &DeviceId,
) -> Result<Revocation, CliError> {
    let path = layout.revocation_file(device_id);
    let toml: RevocationToml = read_toml(&path)?;
    toml.to_record(&path)
}

pub fn import_revocation_bytes(
    layout: &KeyitDirLayout,
    device_id: &DeviceId,
    bytes: &[u8],
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.revocations_dir)
        .map_err(|e| CliError::io(&layout.revocations_dir, e))?;
    let path = layout.revocation_file(device_id);
    fs::write(&path, bytes).map_err(|e| CliError::io(&path, e))?;
    Ok(path)
}

pub fn read_revocation_records(layout: &KeyitDirLayout) -> Result<Vec<Revocation>, CliError> {
    read_record_dir(&layout.revocations_dir, |path| {
        let toml: RevocationToml = read_toml(path)?;
        toml.to_record(path)
    })
}

pub fn read_join_request_records(layout: &KeyitDirLayout) -> Result<Vec<JoinRequest>, CliError> {
    read_record_dir(&layout.join_requests_dir, |path| {
        let toml: JoinRequestToml = read_toml(path)?;
        toml.to_record(path)
    })
}

/// A local encrypted revision plus the paths it was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRevisionBundle {
    pub revision: Revision,
    pub encrypted_payload: EncryptedPayload,
    pub wrapped_deks: Vec<DeviceWrappedDataKey>,
    pub revision_path: PathBuf,
    pub payload_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWrappedDataKey {
    pub device_id: DeviceId,
    pub wrapped_dek: WrappedDataKey,
}

/// Writes a local encrypted revision and marks it as the latest local
/// revision for the environment.
pub fn write_local_revision(
    env_layout: &EnvironmentDirLayout,
    revision: &Revision,
    encrypted_payload: &EncryptedPayload,
    wrapped_deks: &[DeviceWrappedDataKey],
) -> Result<LocalRevisionBundle, CliError> {
    fs::create_dir_all(&env_layout.revisions_dir)
        .map_err(|e| CliError::io(&env_layout.revisions_dir, e))?;
    fs::create_dir_all(&env_layout.payloads_dir)
        .map_err(|e| CliError::io(&env_layout.payloads_dir, e))?;

    let revision_path = env_layout.revision_file(&revision.revision_id);
    let payload_path = env_layout.payload_file(&revision.revision_id);
    fs::write(&payload_path, &encrypted_payload.ciphertext)
        .map_err(|e| CliError::io(&payload_path, e))?;
    write_toml(
        &revision_path,
        &LocalRevisionToml::from_parts(revision, encrypted_payload, wrapped_deks),
    )?;
    write_latest_revision_id(env_layout, &revision.revision_id)?;

    Ok(LocalRevisionBundle {
        revision: revision.clone(),
        encrypted_payload: encrypted_payload.clone(),
        wrapped_deks: wrapped_deks.to_vec(),
        revision_path,
        payload_path,
    })
}

/// Reads the latest local encrypted revision, if one exists.
pub fn read_latest_local_revision(
    env_layout: &EnvironmentDirLayout,
) -> Result<Option<LocalRevisionBundle>, CliError> {
    let Some(revision_id) = read_latest_revision_id(env_layout)? else {
        return Ok(None);
    };
    read_local_revision(env_layout, &revision_id).map(Some)
}

/// Reads one local encrypted revision by ID.
pub fn read_local_revision(
    env_layout: &EnvironmentDirLayout,
    revision_id: &RevisionId,
) -> Result<LocalRevisionBundle, CliError> {
    let revision_path = env_layout.revision_file(revision_id);
    let payload_path = env_layout.payload_file(revision_id);
    let toml: LocalRevisionToml = read_toml(&revision_path)?;
    let mut encrypted_payload = toml.to_encrypted_payload(&revision_path)?;
    encrypted_payload.ciphertext =
        fs::read(&payload_path).map_err(|e| CliError::io(&payload_path, e))?;

    Ok(LocalRevisionBundle {
        revision: toml.to_revision(&revision_path)?,
        wrapped_deks: toml.to_wrapped_deks(&revision_path)?,
        encrypted_payload,
        revision_path,
        payload_path,
    })
}

/// Imports opaque revision metadata and encrypted payload bytes fetched
/// from a relay into the local environment directory, then marks the
/// imported revision as latest locally.
pub fn import_relay_revision_bytes(
    env_layout: &EnvironmentDirLayout,
    revision_id: &RevisionId,
    revision_metadata: &[u8],
    encrypted_payload: &[u8],
) -> Result<LocalRevisionBundle, CliError> {
    fs::create_dir_all(&env_layout.revisions_dir)
        .map_err(|e| CliError::io(&env_layout.revisions_dir, e))?;
    fs::create_dir_all(&env_layout.payloads_dir)
        .map_err(|e| CliError::io(&env_layout.payloads_dir, e))?;

    let revision_path = env_layout.revision_file(revision_id);
    let payload_path = env_layout.payload_file(revision_id);
    fs::write(&revision_path, revision_metadata).map_err(|e| CliError::io(&revision_path, e))?;
    fs::write(&payload_path, encrypted_payload).map_err(|e| CliError::io(&payload_path, e))?;
    write_latest_revision_id(env_layout, revision_id)?;

    read_local_revision(env_layout, revision_id)
}

/// Records the currently materialized local revision.
pub fn write_materialized_revision_id(
    env_layout: &EnvironmentDirLayout,
    revision_id: &RevisionId,
) -> Result<(), CliError> {
    write_toml(
        &env_layout.materialized_toml,
        &RevisionPointerToml {
            revision_id: revision_id.as_str().to_string(),
        },
    )
}

/// Reads the currently materialized local revision marker, if present.
pub fn read_materialized_revision_id(
    env_layout: &EnvironmentDirLayout,
) -> Result<Option<RevisionId>, CliError> {
    read_revision_pointer(&env_layout.materialized_toml)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRequirement {
    pub environment_id: EnvironmentId,
    pub pending_revoked_device_ids: Vec<DeviceId>,
    pub updated_at: Timestamp,
}

pub fn write_rotation_required(
    env_layout: &EnvironmentDirLayout,
    environment_id: &EnvironmentId,
    revoked_device_id: &DeviceId,
    updated_at: Timestamp,
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&env_layout.environment_dir)
        .map_err(|e| CliError::io(&env_layout.environment_dir, e))?;
    let mut requirement = read_rotation_required(env_layout)?.unwrap_or(RotationRequirement {
        environment_id: environment_id.clone(),
        pending_revoked_device_ids: Vec::new(),
        updated_at,
    });

    if requirement.environment_id != *environment_id {
        return Err(CliError::MalformedRecordFile {
            path: env_layout.rotation_required_toml.clone(),
            reason: "rotation marker belongs to a different environment".to_string(),
        });
    }
    if !requirement
        .pending_revoked_device_ids
        .contains(revoked_device_id)
    {
        requirement
            .pending_revoked_device_ids
            .push(revoked_device_id.clone());
    }
    requirement
        .pending_revoked_device_ids
        .sort_by(|a, b| a.as_str().cmp(b.as_str()));
    requirement.updated_at = updated_at;

    write_toml(
        &env_layout.rotation_required_toml,
        &RotationRequirementToml::from_record(&requirement),
    )?;
    Ok(env_layout.rotation_required_toml.clone())
}

pub fn read_rotation_required(
    env_layout: &EnvironmentDirLayout,
) -> Result<Option<RotationRequirement>, CliError> {
    if !env_layout.rotation_required_toml.exists() {
        return Ok(None);
    }
    let toml: RotationRequirementToml = read_toml(&env_layout.rotation_required_toml)?;
    toml.to_record(&env_layout.rotation_required_toml).map(Some)
}

pub fn clear_rotation_required(env_layout: &EnvironmentDirLayout) -> Result<bool, CliError> {
    match fs::remove_file(&env_layout.rotation_required_toml) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(CliError::io(&env_layout.rotation_required_toml, err)),
    }
}

fn write_latest_revision_id(
    env_layout: &EnvironmentDirLayout,
    revision_id: &RevisionId,
) -> Result<(), CliError> {
    write_toml(
        &env_layout.latest_toml,
        &RevisionPointerToml {
            revision_id: revision_id.as_str().to_string(),
        },
    )
}

fn read_latest_revision_id(
    env_layout: &EnvironmentDirLayout,
) -> Result<Option<RevisionId>, CliError> {
    read_revision_pointer(&env_layout.latest_toml)
}

fn read_revision_pointer(path: &Path) -> Result<Option<RevisionId>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    let pointer: RevisionPointerToml = read_toml(path)?;
    RevisionId::parse(&pointer.revision_id)
        .map(Some)
        .map_err(Into::into)
}

fn write_toml(path: &Path, value: &impl Serialize) -> Result<(), CliError> {
    let content = toml::to_string_pretty(value).map_err(|e| CliError::TomlEncode {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    fs::write(path, content).map_err(|e| CliError::io(path, e))
}

fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let content = fs::read_to_string(path).map_err(|e| CliError::io(path, e))?;
    toml::from_str(&content).map_err(|e| CliError::MalformedRecordFile {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

fn read_record_dir<T>(
    dir: &Path,
    mut read_one: impl FnMut(&Path) -> Result<T, CliError>,
) -> Result<Vec<T>, CliError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| CliError::io(dir, e))? {
        let entry = entry.map_err(|e| CliError::io(dir, e))?;
        let path = entry.path();
        if path.is_file() {
            paths.push(path);
        }
    }
    paths.sort();

    let mut records = Vec::with_capacity(paths.len());
    for path in paths {
        records.push(read_one(&path)?);
    }
    Ok(records)
}

fn decode_hex(path: &Path, field: &str, value: &str) -> Result<Vec<u8>, CliError> {
    HEXLOWER
        .decode(value.as_bytes())
        .map_err(|e| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!("field \"{field}\" is not valid lowercase hex: {e}"),
        })
}

fn decode_hash(path: &Path, field: &str, value: &str) -> Result<HashBytes, CliError> {
    let bytes = decode_hex(path, field, value)?;
    Ok(HashBytes::from_sha256_digest(bytes.try_into().map_err(
        |bytes: Vec<u8>| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!("field \"{field}\" is {} bytes, expected 32", bytes.len()),
        },
    )?))
}

fn decode_12_byte_array(path: &Path, field: &str, value: &str) -> Result<[u8; 12], CliError> {
    let bytes = decode_hex(path, field, value)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!("field \"{field}\" is {} bytes, expected 12", bytes.len()),
        })
}

fn require_field_value(
    path: &Path,
    field: &str,
    value: &str,
    expected: &'static str,
) -> Result<(), CliError> {
    if value == expected {
        return Ok(());
    }
    Err(CliError::MalformedRecordFile {
        path: path.to_path_buf(),
        reason: format!("field \"{field}\" has unsupported value \"{value}\""),
    })
}

/// `.keyit/project.toml`: summary metadata about the project, redundant
/// with (a subset of) `genesis.keyit`'s fields, kept as its own small
/// file so a project's identity can be read at a glance without parsing
/// the full signed genesis document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMetadataToml {
    /// See [`keyit_protocol::version::ProtocolVersion::as_str`].
    pub protocol_version: String,
    /// See [`ProjectGenesis::project_id`].
    pub project_id: String,
    /// See [`ProjectGenesis::project_label`].
    pub project_label: String,
    /// See [`ProjectGenesis::default_relay_url`].
    pub default_relay_url: String,
    /// See [`ProjectGenesis::creator_device_id`].
    pub creator_device_id: String,
}

impl ProjectMetadataToml {
    pub(crate) fn from_genesis(genesis: &ProjectGenesis) -> Self {
        Self {
            protocol_version: genesis.protocol_version.as_str().to_string(),
            project_id: genesis.project_id.as_str().to_string(),
            project_label: genesis.project_label.clone(),
            default_relay_url: genesis.default_relay_url.clone(),
            creator_device_id: genesis.creator_device_id.as_str().to_string(),
        }
    }
}

/// `.keyit/genesis.keyit`: every field of a signed
/// [`ProjectGenesis`], hex-encoding its byte-valued fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectGenesisToml {
    pub protocol_version: String,
    pub project_id: String,
    /// Hex-encoded [`ProjectGenesis::genesis_nonce`].
    pub genesis_nonce: String,
    pub created_at: u64,
    pub creator_device_id: String,
    /// Hex-encoded [`ProjectGenesis::creator_device_public_identity`]
    /// (32 bytes).
    pub creator_device_public_identity: String,
    pub project_label: String,
    pub default_relay_url: String,
    pub canonicalization_version: u32,
    /// Hex-encoded [`ProjectGenesis::signature`] (64 bytes).
    pub signature: String,
}

impl ProjectGenesisToml {
    pub(crate) fn from_record(genesis: &ProjectGenesis) -> Self {
        Self {
            protocol_version: genesis.protocol_version.as_str().to_string(),
            project_id: genesis.project_id.as_str().to_string(),
            genesis_nonce: HEXLOWER.encode(genesis.genesis_nonce.as_bytes()),
            created_at: genesis.created_at.unix_seconds(),
            creator_device_id: genesis.creator_device_id.as_str().to_string(),
            creator_device_public_identity: HEXLOWER
                .encode(genesis.creator_device_public_identity.as_bytes()),
            project_label: genesis.project_label.clone(),
            default_relay_url: genesis.default_relay_url.clone(),
            canonicalization_version: genesis.canonicalization_version,
            signature: HEXLOWER.encode(genesis.signature.as_bytes()),
        }
    }

    /// Reconstructs the [`ProjectGenesis`] this TOML represents.
    ///
    /// Used by tests to prove the persisted file round-trips into a
    /// record that still verifies.
    pub fn to_record(&self, path: &Path) -> Result<ProjectGenesis, CliError> {
        let protocol_version: ProtocolVersion = self.protocol_version.parse()?;
        let project_id = ProjectId::parse(&self.project_id)?;
        let creator_device_id = DeviceId::parse(&self.creator_device_id)?;
        let genesis_nonce =
            NonceBytes::from_bytes(decode_hex(path, "genesis_nonce", &self.genesis_nonce)?);
        let creator_device_public_identity = SigningPublicKeyBytes::from_bytes(&decode_hex(
            path,
            "creator_device_public_identity",
            &self.creator_device_public_identity,
        )?)?;
        let signature =
            SignatureBytes::from_bytes(&decode_hex(path, "signature", &self.signature)?)?;

        Ok(ProjectGenesis {
            protocol_version,
            project_id,
            genesis_nonce,
            created_at: Timestamp::from_unix_seconds(self.created_at),
            creator_device_id,
            creator_device_public_identity,
            project_label: self.project_label.clone(),
            default_relay_url: self.default_relay_url.clone(),
            canonicalization_version: self.canonicalization_version,
            signature,
        })
    }
}

/// `.keyit/membership/genesis.keyit`: every field of a signed
/// [`MembershipGenesis`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipGenesisToml {
    pub project_id: String,
    pub member_device_id: String,
    /// [`Role::as_str`] (`"owner"`/`"admin"`/`"member"`). `keyit init`
    /// always writes `"owner"`.
    pub role: String,
    /// Either `"genesis"` or a `kvd_...` device ID string — see
    /// [`ApprovalSource`]. `keyit init` always writes `"genesis"`.
    pub approved_by: String,
    pub created_at: u64,
    /// Hex-encoded [`MembershipGenesis::signature`] (64 bytes).
    pub signature: String,
}

impl MembershipGenesisToml {
    fn from_record(membership: &MembershipGenesis) -> Self {
        Self {
            project_id: membership.project_id.as_str().to_string(),
            member_device_id: membership.member_device_id.as_str().to_string(),
            role: membership.role.as_str().to_string(),
            approved_by: approval_source_to_string(&membership.approved_by),
            created_at: membership.created_at.unix_seconds(),
            signature: HEXLOWER.encode(membership.signature.as_bytes()),
        }
    }

    /// Reconstructs the [`MembershipGenesis`] this TOML represents. See
    /// [`ProjectGenesisToml::to_record`].
    pub fn to_record(&self, path: &Path) -> Result<MembershipGenesis, CliError> {
        let project_id = ProjectId::parse(&self.project_id)?;
        let member_device_id = DeviceId::parse(&self.member_device_id)?;
        let role = parse_role(path, &self.role)?;
        let approved_by = parse_approval_source(path, &self.approved_by)?;
        let signature =
            SignatureBytes::from_bytes(&decode_hex(path, "signature", &self.signature)?)?;

        Ok(MembershipGenesis {
            project_id,
            member_device_id,
            role,
            approved_by,
            created_at: Timestamp::from_unix_seconds(self.created_at),
            signature,
        })
    }
}

/// `.keyit/environments/<kve_...>/environment.keyit`: every field of a
/// signed [`EnvironmentGenesis`], hex-encoding byte-valued fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentGenesisToml {
    pub protocol_version: String,
    pub project_id: String,
    pub environment_id: String,
    pub environment_label: String,
    pub document_type: String,
    pub local_path_hint: String,
    pub created_at: u64,
    pub created_by_device_id: String,
    /// Hex-encoded [`EnvironmentGenesis::parent_project_genesis_hash`].
    pub parent_project_genesis_hash: String,
    /// Hex-encoded [`EnvironmentGenesis::signature`] (64 bytes).
    pub signature: String,
}

impl EnvironmentGenesisToml {
    pub(crate) fn from_record(environment: &EnvironmentGenesis) -> Self {
        Self {
            protocol_version: environment.protocol_version.as_str().to_string(),
            project_id: environment.project_id.as_str().to_string(),
            environment_id: environment.environment_id.as_str().to_string(),
            environment_label: environment.environment_label.clone(),
            document_type: environment.document_type.as_str().to_string(),
            local_path_hint: environment.local_path_hint.to_string_lossy().into_owned(),
            created_at: environment.created_at.unix_seconds(),
            created_by_device_id: environment.created_by_device_id.as_str().to_string(),
            parent_project_genesis_hash: HEXLOWER
                .encode(environment.parent_project_genesis_hash.as_bytes()),
            signature: HEXLOWER.encode(environment.signature.as_bytes()),
        }
    }

    /// Reconstructs the [`EnvironmentGenesis`] this TOML represents.
    pub fn to_record(&self, path: &Path) -> Result<EnvironmentGenesis, CliError> {
        let protocol_version: ProtocolVersion = self.protocol_version.parse()?;
        let project_id = ProjectId::parse(&self.project_id)?;
        let environment_id = EnvironmentId::parse(&self.environment_id)?;
        let document_type = parse_document_type(path, &self.document_type)?;
        let created_by_device_id = DeviceId::parse(&self.created_by_device_id)?;

        let parent_hash = decode_hex(
            path,
            "parent_project_genesis_hash",
            &self.parent_project_genesis_hash,
        )?;
        let parent_project_genesis_hash =
            HashBytes::from_sha256_digest(parent_hash.try_into().map_err(|bytes: Vec<u8>| {
                CliError::MalformedRecordFile {
                    path: path.to_path_buf(),
                    reason: format!(
                        "field \"parent_project_genesis_hash\" is {} bytes, expected 32",
                        bytes.len()
                    ),
                }
            })?);
        let signature =
            SignatureBytes::from_bytes(&decode_hex(path, "signature", &self.signature)?)?;

        Ok(EnvironmentGenesis {
            protocol_version,
            project_id,
            environment_id,
            environment_label: self.environment_label.clone(),
            document_type,
            local_path_hint: PathBuf::from(&self.local_path_hint),
            created_at: Timestamp::from_unix_seconds(self.created_at),
            created_by_device_id,
            parent_project_genesis_hash,
            signature,
        })
    }
}

/// `.keyit/environments/<kve_...>/local.toml`: machine-local
/// materialization mapping for an environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalEnvironmentToml {
    pub environment_id: String,
    pub environment_label: String,
    pub document_type: String,
    pub local_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteToml {
    pub invite_id: String,
    pub project_id: String,
    pub allowed_environment_ids: Vec<String>,
    pub created_by_device_id: String,
    pub nonce: String,
    pub expires_at: u64,
    pub max_uses: u32,
    pub status: String,
    pub signature: String,
}

impl InviteToml {
    pub(crate) fn from_record(invite: &Invite) -> Self {
        Self {
            invite_id: invite.invite_id.as_str().to_string(),
            project_id: invite.project_id.as_str().to_string(),
            allowed_environment_ids: invite
                .allowed_environment_ids
                .iter()
                .map(|id| id.as_str().to_string())
                .collect(),
            created_by_device_id: invite.created_by_device_id.as_str().to_string(),
            nonce: HEXLOWER.encode(invite.nonce.as_bytes()),
            expires_at: invite.expires_at.unix_seconds(),
            max_uses: invite.max_uses,
            status: invite.status.as_str().to_string(),
            signature: HEXLOWER.encode(invite.signature.as_bytes()),
        }
    }

    pub fn to_record(&self, path: &Path) -> Result<Invite, CliError> {
        Ok(Invite {
            invite_id: InviteId::parse(&self.invite_id)?,
            project_id: ProjectId::parse(&self.project_id)?,
            allowed_environment_ids: self
                .allowed_environment_ids
                .iter()
                .map(|id| EnvironmentId::parse(id))
                .collect::<Result<Vec<_>, _>>()?,
            created_by_device_id: DeviceId::parse(&self.created_by_device_id)?,
            nonce: NonceBytes::from_bytes(decode_hex(path, "nonce", &self.nonce)?),
            expires_at: Timestamp::from_unix_seconds(self.expires_at),
            max_uses: self.max_uses,
            status: parse_invite_status(path, &self.status)?,
            signature: SignatureBytes::from_bytes(&decode_hex(
                path,
                "signature",
                &self.signature,
            )?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestToml {
    pub project_id: String,
    pub invite_id: String,
    pub joining_device_id: String,
    pub joining_device_public_identity: String,
    pub joining_device_encryption_public_key: String,
    pub requested_environment_ids: Vec<String>,
    pub device_label: String,
    pub created_at: u64,
    pub proof_signature: String,
}

impl JoinRequestToml {
    pub(crate) fn from_record(request: &JoinRequest) -> Self {
        Self {
            project_id: request.project_id.as_str().to_string(),
            invite_id: request.invite_id.as_str().to_string(),
            joining_device_id: request.joining_device_id.as_str().to_string(),
            joining_device_public_identity: HEXLOWER
                .encode(request.joining_device_public_identity.as_bytes()),
            joining_device_encryption_public_key: HEXLOWER
                .encode(request.joining_device_encryption_public_key.as_bytes()),
            requested_environment_ids: request
                .requested_environment_ids
                .iter()
                .map(|id| id.as_str().to_string())
                .collect(),
            device_label: request.device_label.clone(),
            created_at: request.created_at.unix_seconds(),
            proof_signature: HEXLOWER.encode(request.proof_signature.as_bytes()),
        }
    }

    pub fn to_record(&self, path: &Path) -> Result<JoinRequest, CliError> {
        Ok(JoinRequest {
            project_id: ProjectId::parse(&self.project_id)?,
            invite_id: InviteId::parse(&self.invite_id)?,
            joining_device_id: DeviceId::parse(&self.joining_device_id)?,
            joining_device_public_identity: SigningPublicKeyBytes::from_bytes(&decode_hex(
                path,
                "joining_device_public_identity",
                &self.joining_device_public_identity,
            )?)?,
            joining_device_encryption_public_key: PublicKeyBytes::from_bytes(&decode_hex(
                path,
                "joining_device_encryption_public_key",
                &self.joining_device_encryption_public_key,
            )?)?,
            requested_environment_ids: self
                .requested_environment_ids
                .iter()
                .map(|id| EnvironmentId::parse(id))
                .collect::<Result<Vec<_>, _>>()?,
            device_label: self.device_label.clone(),
            created_at: Timestamp::from_unix_seconds(self.created_at),
            proof_signature: SignatureBytes::from_bytes(&decode_hex(
                path,
                "proof_signature",
                &self.proof_signature,
            )?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToml {
    pub project_id: String,
    pub approved_device_id: String,
    pub approved_environment_ids: Vec<String>,
    pub role: String,
    pub approved_by_device_id: String,
    pub created_at: u64,
    pub signature: String,
}

impl ApprovalToml {
    pub(crate) fn from_record(approval: &Approval) -> Self {
        Self {
            project_id: approval.project_id.as_str().to_string(),
            approved_device_id: approval.approved_device_id.as_str().to_string(),
            approved_environment_ids: approval
                .approved_environment_ids
                .iter()
                .map(|id| id.as_str().to_string())
                .collect(),
            role: approval.role.as_str().to_string(),
            approved_by_device_id: approval.approved_by_device_id.as_str().to_string(),
            created_at: approval.created_at.unix_seconds(),
            signature: HEXLOWER.encode(approval.signature.as_bytes()),
        }
    }

    pub fn to_record(&self, path: &Path) -> Result<Approval, CliError> {
        Ok(Approval {
            project_id: ProjectId::parse(&self.project_id)?,
            approved_device_id: DeviceId::parse(&self.approved_device_id)?,
            approved_environment_ids: self
                .approved_environment_ids
                .iter()
                .map(|id| EnvironmentId::parse(id))
                .collect::<Result<Vec<_>, _>>()?,
            role: parse_role(path, &self.role)?,
            approved_by_device_id: DeviceId::parse(&self.approved_by_device_id)?,
            created_at: Timestamp::from_unix_seconds(self.created_at),
            signature: SignatureBytes::from_bytes(&decode_hex(
                path,
                "signature",
                &self.signature,
            )?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationToml {
    pub project_id: String,
    pub revoked_device_id: String,
    pub affected_environment_ids: Vec<String>,
    pub revoked_by_device_id: String,
    pub created_at: u64,
    pub reason_optional: Option<String>,
    pub signature: String,
}

impl RevocationToml {
    pub(crate) fn from_record(revocation: &Revocation) -> Self {
        Self {
            project_id: revocation.project_id.as_str().to_string(),
            revoked_device_id: revocation.revoked_device_id.as_str().to_string(),
            affected_environment_ids: revocation
                .affected_environment_ids
                .iter()
                .map(|id| id.as_str().to_string())
                .collect(),
            revoked_by_device_id: revocation.revoked_by_device_id.as_str().to_string(),
            created_at: revocation.created_at.unix_seconds(),
            reason_optional: revocation.reason_optional.clone(),
            signature: HEXLOWER.encode(revocation.signature.as_bytes()),
        }
    }

    pub fn to_record(&self, path: &Path) -> Result<Revocation, CliError> {
        Ok(Revocation {
            project_id: ProjectId::parse(&self.project_id)?,
            revoked_device_id: DeviceId::parse(&self.revoked_device_id)?,
            affected_environment_ids: self
                .affected_environment_ids
                .iter()
                .map(|id| EnvironmentId::parse(id))
                .collect::<Result<Vec<_>, _>>()?,
            revoked_by_device_id: DeviceId::parse(&self.revoked_by_device_id)?,
            created_at: Timestamp::from_unix_seconds(self.created_at),
            reason_optional: self.reason_optional.clone(),
            signature: SignatureBytes::from_bytes(&decode_hex(
                path,
                "signature",
                &self.signature,
            )?)?,
        })
    }
}

/// `.keyit/environments/<kve_...>/latest.toml` and
/// `materialized.toml`: a pointer to a local revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionPointerToml {
    pub revision_id: String,
}

/// `.keyit/environments/<kve_...>/rotation-required.toml`: local
/// operator state showing that a post-revocation push still needs to
/// rotate the environment DEK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRequirementToml {
    pub environment_id: String,
    pub pending_revoked_device_ids: Vec<String>,
    pub updated_at: u64,
}

impl RotationRequirementToml {
    fn from_record(requirement: &RotationRequirement) -> Self {
        Self {
            environment_id: requirement.environment_id.as_str().to_string(),
            pending_revoked_device_ids: requirement
                .pending_revoked_device_ids
                .iter()
                .map(|id| id.as_str().to_string())
                .collect(),
            updated_at: requirement.updated_at.unix_seconds(),
        }
    }

    fn to_record(&self, path: &Path) -> Result<RotationRequirement, CliError> {
        Ok(RotationRequirement {
            environment_id: EnvironmentId::parse(&self.environment_id)?,
            pending_revoked_device_ids: self
                .pending_revoked_device_ids
                .iter()
                .map(|id| DeviceId::parse(id))
                .collect::<Result<Vec<_>, _>>()?,
            updated_at: Timestamp::from_unix_seconds(self.updated_at),
        })
        .and_then(|requirement| {
            if requirement.pending_revoked_device_ids.is_empty() {
                return Err(CliError::MalformedRecordFile {
                    path: path.to_path_buf(),
                    reason: "rotation marker has no revoked devices".to_string(),
                });
            }
            Ok(requirement)
        })
    }
}

/// `.keyit/environments/<kve_...>/revisions/<kvr_...>.keyit`: signed
/// revision metadata plus the local encrypted-payload and wrapped-DEK
/// envelope needed to decrypt the payload on this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRevisionToml {
    pub revision_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub parent_revision_id: Option<String>,
    pub parent_revision_hash: Option<String>,
    pub payload_hash: String,
    pub encrypted_payload_ref: String,
    pub author_device_id: String,
    pub created_at: u64,
    pub change_summary: Option<String>,
    pub signature: String,
    pub payload_algorithm: String,
    pub payload_nonce: String,
    #[serde(default)]
    pub wrapped_deks: Vec<DeviceWrappedDataKeyToml>,
    pub dek_wrap_algorithm: Option<String>,
    pub dek_wrap_ephemeral_public_key: Option<String>,
    pub dek_wrap_nonce: Option<String>,
    pub dek_wrap_ciphertext: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceWrappedDataKeyToml {
    pub device_id: String,
    pub dek_wrap_algorithm: String,
    pub dek_wrap_ephemeral_public_key: String,
    pub dek_wrap_nonce: String,
    pub dek_wrap_ciphertext: String,
}

impl LocalRevisionToml {
    fn from_parts(
        revision: &Revision,
        encrypted_payload: &EncryptedPayload,
        wrapped_deks: &[DeviceWrappedDataKey],
    ) -> Self {
        Self {
            revision_id: revision.revision_id.as_str().to_string(),
            project_id: revision.project_id.as_str().to_string(),
            environment_id: revision.environment_id.as_str().to_string(),
            parent_revision_id: revision
                .parent_revision_id
                .as_ref()
                .map(|id| id.as_str().to_string()),
            parent_revision_hash: revision
                .parent_revision_hash
                .as_ref()
                .map(|hash| HEXLOWER.encode(hash.as_bytes())),
            payload_hash: HEXLOWER.encode(revision.payload_hash.as_bytes()),
            encrypted_payload_ref: revision.encrypted_payload_ref.clone(),
            author_device_id: revision.author_device_id.as_str().to_string(),
            created_at: revision.created_at.unix_seconds(),
            change_summary: revision.change_summary.clone(),
            signature: HEXLOWER.encode(revision.signature.as_bytes()),
            payload_algorithm: encrypted_payload.algorithm.to_string(),
            payload_nonce: HEXLOWER.encode(&encrypted_payload.nonce),
            wrapped_deks: wrapped_deks
                .iter()
                .map(DeviceWrappedDataKeyToml::from_record)
                .collect(),
            dek_wrap_algorithm: None,
            dek_wrap_ephemeral_public_key: None,
            dek_wrap_nonce: None,
            dek_wrap_ciphertext: None,
        }
    }

    fn to_revision(&self, path: &Path) -> Result<Revision, CliError> {
        Ok(Revision {
            revision_id: RevisionId::parse(&self.revision_id)?,
            project_id: ProjectId::parse(&self.project_id)?,
            environment_id: EnvironmentId::parse(&self.environment_id)?,
            parent_revision_id: self
                .parent_revision_id
                .as_deref()
                .map(RevisionId::parse)
                .transpose()?,
            parent_revision_hash: self
                .parent_revision_hash
                .as_deref()
                .map(|value| decode_hash(path, "parent_revision_hash", value))
                .transpose()?,
            payload_hash: decode_hash(path, "payload_hash", &self.payload_hash)?,
            encrypted_payload_ref: self.encrypted_payload_ref.clone(),
            author_device_id: DeviceId::parse(&self.author_device_id)?,
            created_at: Timestamp::from_unix_seconds(self.created_at),
            change_summary: self.change_summary.clone(),
            signature: SignatureBytes::from_bytes(&decode_hex(
                path,
                "signature",
                &self.signature,
            )?)?,
        })
    }

    fn to_encrypted_payload(&self, path: &Path) -> Result<EncryptedPayload, CliError> {
        require_field_value(
            path,
            "payload_algorithm",
            &self.payload_algorithm,
            "keyit:v1:aes-256-gcm:environment-payload",
        )?;
        let nonce = decode_12_byte_array(path, "payload_nonce", &self.payload_nonce)?;
        Ok(EncryptedPayload {
            algorithm: "keyit:v1:aes-256-gcm:environment-payload",
            nonce,
            ciphertext: Vec::new(),
        })
    }

    fn to_wrapped_deks(&self, path: &Path) -> Result<Vec<DeviceWrappedDataKey>, CliError> {
        if !self.wrapped_deks.is_empty() {
            return self
                .wrapped_deks
                .iter()
                .map(|wrapped| wrapped.to_record(path))
                .collect();
        }

        let Some(dek_wrap_algorithm) = &self.dek_wrap_algorithm else {
            return Err(CliError::MalformedRecordFile {
                path: path.to_path_buf(),
                reason: "revision contains no wrapped DEKs".to_string(),
            });
        };
        let Some(dek_wrap_ephemeral_public_key) = &self.dek_wrap_ephemeral_public_key else {
            return Err(CliError::MalformedRecordFile {
                path: path.to_path_buf(),
                reason: "legacy revision is missing dek_wrap_ephemeral_public_key".to_string(),
            });
        };
        let Some(dek_wrap_nonce) = &self.dek_wrap_nonce else {
            return Err(CliError::MalformedRecordFile {
                path: path.to_path_buf(),
                reason: "legacy revision is missing dek_wrap_nonce".to_string(),
            });
        };
        let Some(dek_wrap_ciphertext) = &self.dek_wrap_ciphertext else {
            return Err(CliError::MalformedRecordFile {
                path: path.to_path_buf(),
                reason: "legacy revision is missing dek_wrap_ciphertext".to_string(),
            });
        };
        require_field_value(
            path,
            "dek_wrap_algorithm",
            dek_wrap_algorithm,
            "keyit:v1:x25519-hkdf-sha256-aes-256-gcm:dek-wrap",
        )?;
        let ephemeral_public_key = PublicKeyBytes::from_bytes(&decode_hex(
            path,
            "dek_wrap_ephemeral_public_key",
            dek_wrap_ephemeral_public_key,
        )?)?;
        let wrapped_dek = WrappedDataKey {
            algorithm: "keyit:v1:x25519-hkdf-sha256-aes-256-gcm:dek-wrap",
            ephemeral_public_key,
            nonce: decode_12_byte_array(path, "dek_wrap_nonce", dek_wrap_nonce)?,
            ciphertext: decode_hex(path, "dek_wrap_ciphertext", dek_wrap_ciphertext)?,
        };
        Ok(vec![DeviceWrappedDataKey {
            device_id: DeviceId::parse(&self.author_device_id)?,
            wrapped_dek,
        }])
    }
}

impl DeviceWrappedDataKeyToml {
    fn from_record(record: &DeviceWrappedDataKey) -> Self {
        Self {
            device_id: record.device_id.as_str().to_string(),
            dek_wrap_algorithm: record.wrapped_dek.algorithm.to_string(),
            dek_wrap_ephemeral_public_key: HEXLOWER
                .encode(record.wrapped_dek.ephemeral_public_key.as_bytes()),
            dek_wrap_nonce: HEXLOWER.encode(&record.wrapped_dek.nonce),
            dek_wrap_ciphertext: HEXLOWER.encode(&record.wrapped_dek.ciphertext),
        }
    }

    fn to_record(&self, path: &Path) -> Result<DeviceWrappedDataKey, CliError> {
        require_field_value(
            path,
            "dek_wrap_algorithm",
            &self.dek_wrap_algorithm,
            "keyit:v1:x25519-hkdf-sha256-aes-256-gcm:dek-wrap",
        )?;
        Ok(DeviceWrappedDataKey {
            device_id: DeviceId::parse(&self.device_id)?,
            wrapped_dek: WrappedDataKey {
                algorithm: "keyit:v1:x25519-hkdf-sha256-aes-256-gcm:dek-wrap",
                ephemeral_public_key: PublicKeyBytes::from_bytes(&decode_hex(
                    path,
                    "dek_wrap_ephemeral_public_key",
                    &self.dek_wrap_ephemeral_public_key,
                )?)?,
                nonce: decode_12_byte_array(path, "dek_wrap_nonce", &self.dek_wrap_nonce)?,
                ciphertext: decode_hex(path, "dek_wrap_ciphertext", &self.dek_wrap_ciphertext)?,
            },
        })
    }
}

impl LocalEnvironmentToml {
    fn from_record(environment: &EnvironmentGenesis) -> Self {
        Self {
            environment_id: environment.environment_id.as_str().to_string(),
            environment_label: environment.environment_label.clone(),
            document_type: environment.document_type.as_str().to_string(),
            local_path: environment.local_path_hint.to_string_lossy().into_owned(),
        }
    }
}

fn approval_source_to_string(source: &ApprovalSource) -> String {
    match source {
        ApprovalSource::Genesis => "genesis".to_string(),
        ApprovalSource::Device(device_id) => device_id.as_str().to_string(),
    }
}

fn parse_approval_source(path: &Path, value: &str) -> Result<ApprovalSource, CliError> {
    if value == "genesis" {
        return Ok(ApprovalSource::Genesis);
    }
    DeviceId::parse(value)
        .map(ApprovalSource::Device)
        .map_err(|_| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!(
                "field \"approved_by\" is neither \"genesis\" nor a valid device id: \"{value}\""
            ),
        })
}

fn parse_role(path: &Path, value: &str) -> Result<Role, CliError> {
    match value {
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        "member" => Ok(Role::Member),
        other => Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!("field \"role\" has unknown value \"{other}\""),
        }),
    }
}

fn parse_document_type(path: &Path, value: &str) -> Result<DocumentType, CliError> {
    match value {
        "dotenv/v1" => Ok(DocumentType::DotenvV1),
        other => Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!("field \"document_type\" has unknown value \"{other}\""),
        }),
    }
}

fn parse_invite_status(path: &Path, value: &str) -> Result<InviteStatus, CliError> {
    match value {
        "active" => Ok(InviteStatus::Active),
        "revoked" => Ok(InviteStatus::Revoked),
        other => Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!("field \"status\" has unknown value \"{other}\""),
        }),
    }
}

/// Reads back and reconstructs the [`ProjectGenesis`] written at
/// `layout.genesis_file`.
pub fn read_project_genesis(layout: &KeyitDirLayout) -> Result<ProjectGenesis, CliError> {
    let toml: ProjectGenesisToml = read_toml(&layout.genesis_file)?;
    toml.to_record(&layout.genesis_file)
}

/// Reads back and reconstructs the [`MembershipGenesis`] written at
/// `layout.membership_genesis_file`.
pub fn read_membership_genesis(layout: &KeyitDirLayout) -> Result<MembershipGenesis, CliError> {
    let toml: MembershipGenesisToml = read_toml(&layout.membership_genesis_file)?;
    toml.to_record(&layout.membership_genesis_file)
}

/// Reads back [`ProjectMetadataToml`] from `layout.project_toml`.
pub fn read_project_metadata(layout: &KeyitDirLayout) -> Result<ProjectMetadataToml, CliError> {
    read_toml(&layout.project_toml)
}

/// Reads one environment genesis file.
pub fn read_environment_genesis(
    env_layout: &EnvironmentDirLayout,
) -> Result<EnvironmentGenesis, CliError> {
    let toml: EnvironmentGenesisToml = read_toml(&env_layout.environment_file)?;
    toml.to_record(&env_layout.environment_file)
}

/// Reads one local environment mapping file.
pub fn read_local_environment(
    env_layout: &EnvironmentDirLayout,
) -> Result<LocalEnvironmentToml, CliError> {
    read_toml(&env_layout.local_toml)
}

/// Reads all environment genesis records currently stored under
/// `.keyit/environments`.
pub fn read_environment_genesis_records(
    layout: &KeyitDirLayout,
) -> Result<Vec<(EnvironmentDirLayout, EnvironmentGenesis)>, CliError> {
    if !layout.environments_dir.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    for entry in fs::read_dir(&layout.environments_dir)
        .map_err(|e| CliError::io(&layout.environments_dir, e))?
    {
        let entry = entry.map_err(|e| CliError::io(&layout.environments_dir, e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let environment_id = EnvironmentId::parse(name)?;
        let env_layout = EnvironmentDirLayout::under(layout, &environment_id);
        if env_layout.environment_file.exists() {
            let record = read_environment_genesis(&env_layout)?;
            records.push((env_layout, record));
        }
    }

    records.sort_by(|(_, a), (_, b)| a.environment_id.as_str().cmp(b.environment_id.as_str()));
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyit_protocol::signing::SigningKeyPair;

    // Real, 52-character base32 bodies (same fixtures used in
    // `keyit-protocol`'s own tests) — `new_unchecked_for_test` skips
    // validation at construction, but `ProjectGenesisToml::to_record`/
    // `MembershipGenesisToml::to_record` round-trip through
    // `ProjectId::parse`/`DeviceId::parse`, which do enforce the real
    // exact-length identifier shape. A short placeholder body like
    // `"9e107d9d372bb682"` (fine for tests that never re-parse it) fails
    // that parse, so these fixtures need to already be shaped like real
    // identifiers.
    const SAMPLE_PROJECT_ID_BODY: &str = "erbbbzeeg63fk2mau4betkmtngjuunjefebuz345ppjfhm57fqaq";
    const SAMPLE_DEVICE_ID_BODY: &str = "ey5e3psbjch3q4quwabsgoo3xhymrwquyfw7z4jqqs7tyjks5ssq";

    fn sample_project_genesis(keypair: &SigningKeyPair) -> ProjectGenesis {
        let mut genesis = ProjectGenesis {
            protocol_version: ProtocolVersion::CURRENT,
            project_id: ProjectId::new_unchecked_for_test(SAMPLE_PROJECT_ID_BODY),
            genesis_nonce: NonceBytes::from_bytes(vec![9u8; 16]),
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            creator_device_id: DeviceId::new_unchecked_for_test(SAMPLE_DEVICE_ID_BODY),
            creator_device_public_identity: keypair.public_key(),
            project_label: "keyit".to_string(),
            default_relay_url: "https://relay.keyit.sh".to_string(),
            canonicalization_version: 0,
            signature: SignatureBytes::from_bytes(&[0u8; 64])
                .expect("64 zero bytes is validly-shaped"),
        };
        genesis.signature = keypair.sign(
            <ProjectGenesis as keyit_protocol::signing::SignedRecord>::SIGN_LABEL,
            &genesis,
        );
        genesis
    }

    fn sample_membership_genesis(
        keypair: &SigningKeyPair,
        project_id: &ProjectId,
    ) -> MembershipGenesis {
        let mut membership = MembershipGenesis {
            project_id: project_id.clone(),
            member_device_id: DeviceId::new_unchecked_for_test(SAMPLE_DEVICE_ID_BODY),
            role: Role::Owner,
            approved_by: ApprovalSource::Genesis,
            created_at: Timestamp::from_unix_seconds(1_755_878_400),
            signature: SignatureBytes::from_bytes(&[0u8; 64])
                .expect("64 zero bytes is validly-shaped"),
        };
        membership.signature = keypair.sign(
            <MembershipGenesis as keyit_protocol::signing::SignedRecord>::SIGN_LABEL,
            &membership,
        );
        membership
    }

    #[test]
    fn write_keyit_dir_creates_all_three_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keypair = SigningKeyPair::generate();
        let project = sample_project_genesis(&keypair);
        let membership = sample_membership_genesis(&keypair, &project.project_id);

        let layout =
            write_keyit_dir(dir.path(), &project, &membership).expect("write should succeed");

        assert!(layout.project_toml.exists());
        assert!(layout.genesis_file.exists());
        assert!(layout.membership_genesis_file.exists());
    }

    #[test]
    fn project_genesis_round_trips_through_toml_and_still_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keypair = SigningKeyPair::generate();
        let project = sample_project_genesis(&keypair);
        let membership = sample_membership_genesis(&keypair, &project.project_id);

        let layout =
            write_keyit_dir(dir.path(), &project, &membership).expect("write should succeed");

        let reloaded = read_project_genesis(&layout).expect("should read back");
        assert_eq!(reloaded, project);
        reloaded
            .verify_signature()
            .expect("reloaded genesis should still verify");
    }

    #[test]
    fn membership_genesis_round_trips_through_toml_and_still_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keypair = SigningKeyPair::generate();
        let project = sample_project_genesis(&keypair);
        let membership = sample_membership_genesis(&keypair, &project.project_id);

        let layout =
            write_keyit_dir(dir.path(), &project, &membership).expect("write should succeed");

        let reloaded = read_membership_genesis(&layout).expect("should read back");
        assert_eq!(reloaded, membership);
        reloaded
            .verify_signature(&keypair.public_key())
            .expect("reloaded membership should still verify");
    }

    #[test]
    fn project_metadata_toml_contains_the_project_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keypair = SigningKeyPair::generate();
        let project = sample_project_genesis(&keypair);
        let membership = sample_membership_genesis(&keypair, &project.project_id);

        let layout =
            write_keyit_dir(dir.path(), &project, &membership).expect("write should succeed");

        let metadata = read_project_metadata(&layout).expect("should read back");
        assert_eq!(metadata.project_id, project.project_id.as_str());
        assert!(metadata.project_id.starts_with("kvp_"));
    }

    #[test]
    fn signature_field_is_hex_encoded_not_raw_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keypair = SigningKeyPair::generate();
        let project = sample_project_genesis(&keypair);
        let membership = sample_membership_genesis(&keypair, &project.project_id);

        let layout =
            write_keyit_dir(dir.path(), &project, &membership).expect("write should succeed");
        let content = fs::read_to_string(&layout.genesis_file).expect("read genesis file");

        // The signature is a 64-byte value; hex-encoded it is exactly
        // 128 lowercase hex characters between the TOML string's quotes.
        // Raw signature bytes are not valid UTF-8 in general, so a plain
        // `fs::write` of raw bytes into a value meant to sit inside a
        // TOML string would not even parse as TOML at all.
        let signature_line = content
            .lines()
            .find(|line| line.starts_with("signature"))
            .expect("signature field should be present");
        let value = signature_line
            .split('"')
            .nth(1)
            .expect("signature line should have a quoted string value");
        assert_eq!(
            value.len(),
            128,
            "hex-encoded 64-byte signature should be 128 characters"
        );
        assert!(value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
