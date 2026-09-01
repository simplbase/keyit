//! Safe local inspection commands for recovery and support.
//!
//! These commands report project/device/environment/revision metadata
//! without reading plaintext dotenv values or decrypting encrypted
//! payloads.

use std::fs;
use std::path::PathBuf;

use data_encoding::HEXLOWER;
use keyit_protocol::ids::{DeviceId, EnvironmentId, ProjectId, RevisionId};
use keyit_protocol::primitives::Timestamp;

use crate::auth;
use crate::device_identity;
use crate::device_key;
use crate::error::CliError;
use crate::keyit_dir;
use crate::revision;

/// Inputs to [`run_whoami`].
#[derive(Debug, Clone)]
pub struct WhoamiOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub now: Timestamp,
}

/// Inputs to [`run_env_list`].
#[derive(Debug, Clone)]
pub struct EnvListOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
}

/// Inputs to [`run_revision_list`].
#[derive(Debug, Clone)]
pub struct RevisionListOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub environment: String,
}

/// Local device identity and membership status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoamiOutcome {
    pub project_id: ProjectId,
    pub project_label: String,
    pub device_id: DeviceId,
    pub signing_public_key_hex: String,
    pub encryption_public_key_hex: String,
    pub active: bool,
    pub accessible_environment_count: usize,
    pub signing_key_ref: PathBuf,
    pub encryption_key_ref: PathBuf,
}

/// Local environment listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvListOutcome {
    pub project_id: ProjectId,
    pub environments: Vec<EnvListItem>,
}

/// One environment in [`EnvListOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvListItem {
    pub environment_id: EnvironmentId,
    pub label: String,
    pub local_path: PathBuf,
    pub latest_revision_id: Option<RevisionId>,
    pub materialized_revision_id: Option<RevisionId>,
}

/// Local revision listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionListOutcome {
    pub project_id: ProjectId,
    pub environment_id: EnvironmentId,
    pub label: String,
    pub revisions: Vec<RevisionListItem>,
}

/// One local encrypted revision metadata record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionListItem {
    pub revision_id: RevisionId,
    pub parent_revision_id: Option<RevisionId>,
    pub author_device_id: DeviceId,
    pub created_at: Timestamp,
    pub change_summary: Option<String>,
}

/// Runs local `keyit whoami`.
pub fn run_whoami(options: WhoamiOptions) -> Result<WhoamiOutcome, CliError> {
    let layout = revision::require_project(&options.project_root, &options.keyit_data_dir)?;
    let project = revision::load_project(&layout)?;
    let access_state = auth::load_access_state(&layout, &project)?;
    let environments = revision::load_environment_refs(&layout, None)?;

    let (signing_keypair, signing_key_ref) =
        device_key::load_or_create_device_signing_key(&options.keyit_data_dir)?;
    let (encryption_keypair, encryption_key_ref) =
        device_key::load_or_create_device_encryption_key(&options.keyit_data_dir)?;
    let identity =
        device_identity::build_device_identity(&signing_keypair, &encryption_keypair, options.now);

    let active_device = access_state.device(&identity.device_id);
    let accessible_environment_count = active_device
        .map(|device| {
            environments
                .iter()
                .filter(|env| device.can_access_environment(&env.record.environment_id))
                .count()
        })
        .unwrap_or(0);

    Ok(WhoamiOutcome {
        project_id: project.project_id,
        project_label: project.project_label,
        device_id: identity.device_id,
        signing_public_key_hex: HEXLOWER.encode(identity.signing_public_key.as_bytes()),
        encryption_public_key_hex: HEXLOWER.encode(identity.encryption_public_key.as_bytes()),
        active: active_device.is_some(),
        accessible_environment_count,
        signing_key_ref,
        encryption_key_ref,
    })
}

/// Runs local `keyit env list`.
pub fn run_env_list(options: EnvListOptions) -> Result<EnvListOutcome, CliError> {
    let layout = revision::require_project(&options.project_root, &options.keyit_data_dir)?;
    let project = revision::load_project(&layout)?;

    let environments = revision::load_environment_refs(&layout, None)?
        .into_iter()
        .map(|env| {
            let latest_revision_id = keyit_dir::read_latest_local_revision(&env.layout)?
                .map(|bundle| bundle.revision.revision_id);
            let materialized_revision_id = keyit_dir::read_materialized_revision_id(&env.layout)?;
            Ok(EnvListItem {
                environment_id: env.record.environment_id,
                label: env.record.environment_label,
                local_path: env.local_path,
                latest_revision_id,
                materialized_revision_id,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;

    Ok(EnvListOutcome {
        project_id: project.project_id,
        environments,
    })
}

/// Runs local `keyit revision list <environment>`.
pub fn run_revision_list(options: RevisionListOptions) -> Result<RevisionListOutcome, CliError> {
    let layout = revision::require_project(&options.project_root, &options.keyit_data_dir)?;
    let project = revision::load_project(&layout)?;
    let env = revision::select_environment(&layout, &options.environment)?;

    let mut revision_ids = Vec::new();
    if env.layout.revisions_dir.exists() {
        for entry in fs::read_dir(&env.layout.revisions_dir)
            .map_err(|e| CliError::io(&env.layout.revisions_dir, e))?
        {
            let entry = entry.map_err(|e| CliError::io(&env.layout.revisions_dir, e))?;
            let path = entry.path();
            if path.is_file() {
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                revision_ids.push(RevisionId::parse(stem)?);
            }
        }
    }

    revision_ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let mut revisions = revision_ids
        .into_iter()
        .map(|revision_id| {
            let bundle = keyit_dir::read_local_revision(&env.layout, &revision_id)?;
            Ok(RevisionListItem {
                revision_id: bundle.revision.revision_id,
                parent_revision_id: bundle.revision.parent_revision_id,
                author_device_id: bundle.revision.author_device_id,
                created_at: bundle.revision.created_at,
                change_summary: bundle.revision.change_summary,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    revisions.sort_by(|a, b| {
        a.created_at
            .unix_seconds()
            .cmp(&b.created_at.unix_seconds())
            .then_with(|| a.revision_id.as_str().cmp(b.revision_id.as_str()))
    });

    Ok(RevisionListOutcome {
        project_id: project.project_id,
        environment_id: env.record.environment_id,
        label: env.record.environment_label,
        revisions,
    })
}
