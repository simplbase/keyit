//! Local signed access workflow.
//!
//! This module records the first non-genesis access flow:
//!
//! - `invite create` writes a signed [`Invite`].
//! - `join` writes a signed [`JoinRequest`] proving control of the
//!   joining device's signing key.
//! - `approve` writes a signed [`Approval`] by an owner/admin device.
//! - `revoke` writes a signed [`Revocation`] by an owner/admin device.

use std::fs;
use std::path::{Path, PathBuf};

use keyit_protocol::canonical;
use keyit_protocol::canonical::labels;
use keyit_protocol::ids::{DeviceId, EnvironmentId, InviteId, ProjectId};
use keyit_protocol::primitives::{HashBytes, NonceBytes, SignatureBytes, Timestamp};
use keyit_protocol::records::{
    Approval, EnvironmentGenesis, Invite, InviteStatus, JoinRequest, ProjectGenesis, Revocation,
    Role,
};
use keyit_protocol::signing::{SignedRecord, SigningKeyPair};
use keyit_relay::AccessRecordKind;
use serde::{Deserialize, Serialize};

use crate::auth::{load_access_state, AccessState};
use crate::error::CliError;
use crate::keyit_dir::{self, KeyitDirLayout};
use crate::relay_client::RelayHttpClient;
use crate::{device_identity, device_key};

/// Inputs to `keyit invite create`.
#[derive(Debug, Clone)]
pub struct InviteCreateOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub environments: Vec<String>,
    pub expires_at: Timestamp,
    pub max_uses: u32,
    pub relay_url: Option<String>,
    pub now: Timestamp,
}

/// Result of creating a signed invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteCreateOutcome {
    pub project_id: ProjectId,
    pub invite_id: InviteId,
    pub allowed_environment_ids: Vec<EnvironmentId>,
    pub path: PathBuf,
    pub bundle_path: PathBuf,
    pub relay_url: Option<String>,
}

/// Target accepted by `keyit join`.
#[derive(Debug, Clone)]
pub enum JoinTarget {
    /// Join through an invite already present locally, or fetchable from
    /// the configured relay in an initialized checkout.
    InviteId(InviteId),
    /// Bootstrap the checkout from a Keyit invite bundle first, then
    /// fetch the invite record from the relay.
    BundlePath(PathBuf),
}

/// Inputs to `keyit join`.
#[derive(Debug, Clone)]
pub struct JoinOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub target: JoinTarget,
    pub requested_environments: Vec<String>,
    pub device_label: String,
    pub relay_url: Option<String>,
    pub now: Timestamp,
}

/// Result of writing a signed join request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinOutcome {
    pub project_id: ProjectId,
    pub invite_id: InviteId,
    pub joining_device_id: DeviceId,
    pub requested_environment_ids: Vec<EnvironmentId>,
    pub path: PathBuf,
    pub fetched_invite_from_relay: bool,
    pub relay_url: Option<String>,
}

/// Inputs to `keyit approve`.
#[derive(Debug, Clone)]
pub struct ApproveOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub joining_device_id: DeviceId,
    pub role: Role,
    pub relay_url: Option<String>,
    pub now: Timestamp,
}

/// Result of approving a join request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveOutcome {
    pub project_id: ProjectId,
    pub approved_device_id: DeviceId,
    pub approved_environment_ids: Vec<EnvironmentId>,
    pub role: Role,
    pub path: PathBuf,
    pub fetched_join_request_from_relay: bool,
    pub relay_url: Option<String>,
}

/// Inputs to `keyit revoke`.
#[derive(Debug, Clone)]
pub struct RevokeOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub revoked_device_id: DeviceId,
    pub affected_environments: Vec<String>,
    pub reason: Option<String>,
    pub relay_url: Option<String>,
    pub now: Timestamp,
}

/// Result of revoking a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    pub project_id: ProjectId,
    pub revoked_device_id: DeviceId,
    pub affected_environment_ids: Vec<EnvironmentId>,
    pub path: PathBuf,
    pub rotation_required_paths: Vec<PathBuf>,
    pub relay_url: Option<String>,
}

/// Runs `keyit invite create`'s core logic.
pub fn run_invite_create(options: InviteCreateOptions) -> Result<InviteCreateOutcome, CliError> {
    let InviteCreateOptions {
        project_root,
        keyit_data_dir,
        environments,
        expires_at,
        max_uses,
        relay_url,
        now,
    } = options;

    let layout = require_project(&project_root, &keyit_data_dir)?;
    let project = load_project(&layout)?;
    let http_relay_url = configured_http_relay_url(&project, relay_url.as_deref());
    let access_state = load_access_state(&layout, &project)?;
    let (signing_keypair, device_id) = load_local_signing_device(&keyit_data_dir, now)?;
    access_state.require_can_manage_access(&device_id)?;

    if expires_at.unix_seconds() <= now.unix_seconds() {
        return Err(CliError::InviteNotUsable {
            reason: "invite expiry must be in the future".to_string(),
        });
    }
    if max_uses == 0 {
        return Err(CliError::InviteNotUsable {
            reason: "invite max uses must be at least 1".to_string(),
        });
    }

    let allowed_environment_ids = resolve_environment_selectors(&layout, &environments)?;
    let bundle_environments = load_bundle_environments(&layout, &allowed_environment_ids)?;
    let mut nonce_bytes = [0u8; 16];
    getrandom::fill(&mut nonce_bytes).expect("OS CSPRNG should be available");
    let nonce = NonceBytes::from_bytes(nonce_bytes.to_vec());
    let invite_id = InviteId::derive(&project.project_id, &device_id, &nonce, now);

    let mut invite = Invite {
        invite_id: invite_id.clone(),
        project_id: project.project_id.clone(),
        allowed_environment_ids: allowed_environment_ids.clone(),
        created_by_device_id: device_id,
        nonce,
        expires_at,
        max_uses,
        status: InviteStatus::Active,
        signature: zero_signature_placeholder(),
    };
    invite.signature = signing_keypair.sign(Invite::SIGN_LABEL, &invite);
    invite.verify_signature(&signing_keypair.public_key())?;

    let path = keyit_dir::write_invite(&layout, &invite)?;
    let bundle_path =
        write_invite_bundle(&layout, &invite.invite_id, &project, &bundle_environments)?;
    let published_relay_url = if let Some(relay_url) = http_relay_url {
        publish_shared_project_state_to_http_relay(&relay_url, &layout, &project)?;
        publish_access_record_to_http_relay(
            &relay_url,
            &project.project_id,
            AccessRecordKind::Invite,
            invite_id.as_str(),
            &path,
        )?;
        Some(relay_url)
    } else {
        None
    };
    Ok(InviteCreateOutcome {
        project_id: project.project_id,
        invite_id,
        allowed_environment_ids,
        path,
        bundle_path,
        relay_url: published_relay_url,
    })
}

/// Runs `keyit join`'s core logic.
pub fn run_join(options: JoinOptions) -> Result<JoinOutcome, CliError> {
    let JoinOptions {
        project_root,
        keyit_data_dir,
        target,
        requested_environments,
        device_label,
        relay_url,
        now,
    } = options;

    let (layout, invite_id) = prepare_join_project(&project_root, &keyit_data_dir, target)?;
    let project = load_project(&layout)?;
    let http_relay_url = configured_http_relay_url(&project, relay_url.as_deref());
    let access_state = load_access_state(&layout, &project)?;
    let fetched_invite_from_relay =
        fetch_invite_from_http_relay_if_missing(&http_relay_url, &layout, &project, &invite_id)?;
    let invite = keyit_dir::read_invite(&layout, &invite_id)?;
    let (signing_keypair, device_id) = load_local_signing_device(&keyit_data_dir, now)?;
    validate_invite_for_join(&project, &access_state, &invite, &layout, &device_id, now)?;

    let requested_environment_ids =
        resolve_requested_environment_ids(&layout, &invite, &requested_environments)?;
    let (encryption_keypair, _) =
        device_key::load_or_create_device_encryption_key(&keyit_data_dir)?;

    let mut request = JoinRequest {
        project_id: project.project_id.clone(),
        invite_id: invite.invite_id.clone(),
        joining_device_id: device_id.clone(),
        joining_device_public_identity: signing_keypair.public_key(),
        joining_device_encryption_public_key: encryption_keypair.public_key(),
        requested_environment_ids: requested_environment_ids.clone(),
        device_label,
        created_at: now,
        proof_signature: zero_signature_placeholder(),
    };
    request.proof_signature = signing_keypair.sign(JoinRequest::SIGN_LABEL, &request);
    request.verify_signature()?;

    let path = keyit_dir::write_join_request(&layout, &request)?;
    let published_relay_url = if let Some(relay_url) = http_relay_url {
        publish_access_record_to_http_relay(
            &relay_url,
            &project.project_id,
            AccessRecordKind::JoinRequest,
            device_id.as_str(),
            &path,
        )?;
        Some(relay_url)
    } else {
        None
    };
    Ok(JoinOutcome {
        project_id: project.project_id,
        invite_id,
        joining_device_id: device_id,
        requested_environment_ids,
        path,
        fetched_invite_from_relay,
        relay_url: published_relay_url,
    })
}

#[derive(Debug, Clone)]
struct InviteBundle {
    invite_id: InviteId,
    project: ProjectGenesis,
    invite: Invite,
    environments: Vec<EnvironmentGenesis>,
    join_requests: Vec<JoinRequest>,
    approvals: Vec<Approval>,
    revocations: Vec<Revocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InviteBundleToml {
    /// Stable format tag written into and checked against every
    /// invite bundle file. Not a product name — changing it would
    /// make `keyit join` reject bundles created by an older `keyit`
    /// build (and vice versa), so it only changes when the bundle
    /// layout itself has a breaking change.
    format: String,
    invite_id: String,
    project: keyit_dir::ProjectGenesisToml,
    invite: keyit_dir::InviteToml,
    environments: Vec<keyit_dir::EnvironmentGenesisToml>,
    #[serde(default)]
    join_requests: Vec<keyit_dir::JoinRequestToml>,
    #[serde(default)]
    approvals: Vec<keyit_dir::ApprovalToml>,
    #[serde(default)]
    revocations: Vec<keyit_dir::RevocationToml>,
}

fn write_invite_bundle(
    layout: &KeyitDirLayout,
    invite_id: &InviteId,
    project: &ProjectGenesis,
    environments: &[EnvironmentGenesis],
) -> Result<PathBuf, CliError> {
    fs::create_dir_all(&layout.invites_dir).map_err(|e| CliError::io(&layout.invites_dir, e))?;
    let path = layout.invite_bundle_file(invite_id);
    let bundle = InviteBundleToml {
        format: "keyit-invite-bundle-v1".to_string(),
        invite_id: invite_id.as_str().to_string(),
        project: keyit_dir::ProjectGenesisToml::from_record(project),
        invite: keyit_dir::InviteToml::from_record(&keyit_dir::read_invite(layout, invite_id)?),
        environments: environments
            .iter()
            .map(keyit_dir::EnvironmentGenesisToml::from_record)
            .collect(),
        join_requests: keyit_dir::read_join_request_records(layout)?
            .iter()
            .map(keyit_dir::JoinRequestToml::from_record)
            .collect(),
        approvals: keyit_dir::read_approval_records(layout)?
            .iter()
            .map(keyit_dir::ApprovalToml::from_record)
            .collect(),
        revocations: keyit_dir::read_revocation_records(layout)?
            .iter()
            .map(keyit_dir::RevocationToml::from_record)
            .collect(),
    };
    let content = toml::to_string_pretty(&bundle).map_err(|e| CliError::TomlEncode {
        path: path.clone(),
        reason: e.to_string(),
    })?;
    fs::write(&path, content).map_err(|e| CliError::io(&path, e))?;
    Ok(path)
}

fn read_invite_bundle(path: &Path) -> Result<InviteBundle, CliError> {
    let content = fs::read_to_string(path).map_err(|e| CliError::io(path, e))?;
    let bundle: InviteBundleToml =
        toml::from_str(&content).map_err(|e| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
    if bundle.format != "keyit-invite-bundle-v1" {
        return Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!("unsupported invite bundle format \"{}\"", bundle.format),
        });
    }

    let invite_id = InviteId::parse(&bundle.invite_id)?;
    let project = bundle.project.to_record(path)?;
    project.verify_signature()?;
    let invite = bundle.invite.to_record(path)?;
    if invite.invite_id != invite_id || invite.project_id != project.project_id {
        return Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: "bundled invite does not match bundled project".to_string(),
        });
    }
    let project_hash = project_genesis_hash(&project);
    let mut environments = Vec::with_capacity(bundle.environments.len());
    for environment_toml in &bundle.environments {
        let environment = environment_toml.to_record(path)?;
        validate_bundle_environment(path, &project, &project_hash, &environment)?;
        environments.push(environment);
    }
    let join_requests = bundle
        .join_requests
        .iter()
        .map(|record| record.to_record(path))
        .collect::<Result<Vec<_>, _>>()?;
    let approvals = bundle
        .approvals
        .iter()
        .map(|record| record.to_record(path))
        .collect::<Result<Vec<_>, _>>()?;
    let revocations = bundle
        .revocations
        .iter()
        .map(|record| record.to_record(path))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(InviteBundle {
        invite_id,
        project,
        invite,
        environments,
        join_requests,
        approvals,
        revocations,
    })
}

fn prepare_join_project(
    project_root: &Path,
    keyit_data_dir: &Path,
    target: JoinTarget,
) -> Result<(KeyitDirLayout, InviteId), CliError> {
    match target {
        JoinTarget::InviteId(invite_id) => {
            require_project(project_root, keyit_data_dir).map(|layout| (layout, invite_id))
        }
        JoinTarget::BundlePath(path) => {
            let bundle = read_invite_bundle(&path)?;
            let layout = keyit_dir::data_layout(keyit_data_dir, &bundle.project.project_id);
            if layout.project_toml.exists() {
                let local_project = load_project(&layout)?;
                if local_project.project_id != bundle.project.project_id {
                    return Err(CliError::InviteNotUsable {
                        reason: "invite bundle belongs to a different project".to_string(),
                    });
                }
                if !keyit_dir::project_locator_file(project_root).exists() {
                    keyit_dir::write_project_locator(project_root, &bundle.project)?;
                }
                keyit_dir::write_invite(&layout, &bundle.invite)?;
                write_bundle_access_records(&layout, &bundle)?;
                write_bundle_environments(&layout, &bundle.environments)?;
                for environment in &bundle.environments {
                    keyit_dir::upsert_locator_environment(
                        project_root,
                        environment,
                        &environment.local_path_hint,
                    )?;
                }
                return Ok((layout, bundle.invite_id));
            }

            let layout = keyit_dir::write_project_bootstrap_dir(
                &keyit_dir::project_state_root(keyit_data_dir, &bundle.project.project_id),
                &bundle.project,
                &bundle.environments,
            )?;
            keyit_dir::write_invite(&layout, &bundle.invite)?;
            write_bundle_access_records(&layout, &bundle)?;
            keyit_dir::write_project_locator(project_root, &bundle.project)?;
            for environment in &bundle.environments {
                keyit_dir::upsert_locator_environment(
                    project_root,
                    environment,
                    &environment.local_path_hint,
                )?;
            }
            Ok((layout, bundle.invite_id))
        }
    }
}

fn write_bundle_access_records(
    layout: &KeyitDirLayout,
    bundle: &InviteBundle,
) -> Result<(), CliError> {
    for request in &bundle.join_requests {
        keyit_dir::write_join_request(layout, request)?;
    }
    for approval in &bundle.approvals {
        keyit_dir::write_approval(layout, approval)?;
    }
    for revocation in &bundle.revocations {
        keyit_dir::write_revocation(layout, revocation)?;
    }
    Ok(())
}

fn write_bundle_environments(
    layout: &KeyitDirLayout,
    environments: &[EnvironmentGenesis],
) -> Result<(), CliError> {
    for environment in environments {
        keyit_dir::write_environment_dir(layout, environment)?;
    }
    Ok(())
}

fn write_rotation_required_markers(
    layout: &KeyitDirLayout,
    affected_environment_ids: &[EnvironmentId],
    revoked_device_id: &DeviceId,
    now: Timestamp,
) -> Result<Vec<PathBuf>, CliError> {
    affected_environment_ids
        .iter()
        .map(|environment_id| {
            let env_layout = keyit_dir::EnvironmentDirLayout::under(layout, environment_id);
            keyit_dir::write_rotation_required(&env_layout, environment_id, revoked_device_id, now)
        })
        .collect()
}

/// Runs `keyit approve`'s core logic.
pub fn run_approve(options: ApproveOptions) -> Result<ApproveOutcome, CliError> {
    let ApproveOptions {
        project_root,
        keyit_data_dir,
        joining_device_id,
        role,
        relay_url,
        now,
    } = options;

    let layout = require_project(&project_root, &keyit_data_dir)?;
    let project = load_project(&layout)?;
    let http_relay_url = configured_http_relay_url(&project, relay_url.as_deref());
    let access_state = load_access_state(&layout, &project)?;
    let (signing_keypair, device_id) = load_local_signing_device(&keyit_data_dir, now)?;
    access_state.require_can_manage_access(&device_id)?;

    let fetched_join_request_from_relay = fetch_join_request_from_http_relay_if_missing(
        &http_relay_url,
        &layout,
        &project,
        &joining_device_id,
    )?;
    let request = keyit_dir::read_join_request(&layout, &joining_device_id)?;
    request.verify_signature()?;
    if request.project_id != project.project_id {
        return Err(CliError::InviteNotUsable {
            reason: "join request belongs to a different project".to_string(),
        });
    }
    if request.joining_device_id != joining_device_id {
        return Err(CliError::InviteNotUsable {
            reason: "join request device id does not match the approval target".to_string(),
        });
    }

    let mut approval = Approval {
        project_id: project.project_id.clone(),
        approved_device_id: request.joining_device_id.clone(),
        approved_environment_ids: request.requested_environment_ids.clone(),
        role,
        approved_by_device_id: device_id,
        created_at: now,
        signature: zero_signature_placeholder(),
    };
    approval.signature = signing_keypair.sign(Approval::SIGN_LABEL, &approval);
    approval.verify_signature(&signing_keypair.public_key())?;

    let path = keyit_dir::write_approval(&layout, &approval)?;
    let published_relay_url = if let Some(relay_url) = http_relay_url {
        publish_access_record_to_http_relay(
            &relay_url,
            &project.project_id,
            AccessRecordKind::Approval,
            approval.approved_device_id.as_str(),
            &path,
        )?;
        Some(relay_url)
    } else {
        None
    };
    Ok(ApproveOutcome {
        project_id: project.project_id,
        approved_device_id: approval.approved_device_id,
        approved_environment_ids: approval.approved_environment_ids,
        role,
        path,
        fetched_join_request_from_relay,
        relay_url: published_relay_url,
    })
}

/// Runs `keyit revoke`'s core logic.
pub fn run_revoke(options: RevokeOptions) -> Result<RevokeOutcome, CliError> {
    let RevokeOptions {
        project_root,
        keyit_data_dir,
        revoked_device_id,
        affected_environments,
        reason,
        relay_url,
        now,
    } = options;

    let layout = require_project(&project_root, &keyit_data_dir)?;
    let project = load_project(&layout)?;
    let http_relay_url = configured_http_relay_url(&project, relay_url.as_deref());
    let access_state = load_access_state(&layout, &project)?;
    let (signing_keypair, device_id) = load_local_signing_device(&keyit_data_dir, now)?;
    access_state.require_can_manage_access(&device_id)?;

    if revoked_device_id == project.creator_device_id {
        return Err(CliError::NotProjectOwner {
            reason: "revoking the genesis owner is not supported".to_string(),
        });
    }
    let revoked =
        access_state
            .device(&revoked_device_id)
            .ok_or_else(|| CliError::NotProjectOwner {
                reason: format!("device {revoked_device_id} is not an active project member"),
            })?;
    let affected_environment_ids = if affected_environments.is_empty() {
        revoked.environment_ids.clone()
    } else {
        resolve_environment_selectors(&layout, &affected_environments)?
    };

    let mut revocation = Revocation {
        project_id: project.project_id.clone(),
        revoked_device_id: revoked_device_id.clone(),
        affected_environment_ids: affected_environment_ids.clone(),
        revoked_by_device_id: device_id,
        created_at: now,
        reason_optional: reason,
        signature: zero_signature_placeholder(),
    };
    revocation.signature = signing_keypair.sign(Revocation::SIGN_LABEL, &revocation);
    revocation.verify_signature(&signing_keypair.public_key())?;

    let path = keyit_dir::write_revocation(&layout, &revocation)?;
    let rotation_required_paths = write_rotation_required_markers(
        &layout,
        &affected_environment_ids,
        &revoked_device_id,
        now,
    )?;
    let published_relay_url = if let Some(relay_url) = http_relay_url {
        publish_access_record_to_http_relay(
            &relay_url,
            &project.project_id,
            AccessRecordKind::Revocation,
            revoked_device_id.as_str(),
            &path,
        )?;
        Some(relay_url)
    } else {
        None
    };
    Ok(RevokeOutcome {
        project_id: project.project_id,
        revoked_device_id,
        affected_environment_ids,
        path,
        rotation_required_paths,
        relay_url: published_relay_url,
    })
}

pub(crate) fn sync_local_device_access_from_http_relay(
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
    keyit_data_dir: &Path,
    relay_url: &str,
) -> Result<(), CliError> {
    let (signing_keypair, _) = device_key::load_or_create_device_signing_key(keyit_data_dir)?;
    let (encryption_keypair, _) = device_key::load_or_create_device_encryption_key(keyit_data_dir)?;
    let identity = device_identity::build_device_identity(
        &signing_keypair,
        &encryption_keypair,
        project.created_at,
    );
    if let Some(device) = load_access_state(layout, project)?.device(&identity.device_id) {
        if device.role == Role::Owner {
            return Ok(());
        }
    }
    let client = RelayHttpClient::new(relay_url)?;

    if !layout.join_request_file(&identity.device_id).exists() {
        if let Some(bytes) = client.fetch_access_record(
            &project.project_id,
            AccessRecordKind::JoinRequest,
            identity.device_id.as_str(),
        )? {
            keyit_dir::import_join_request_bytes(layout, &identity.device_id, &bytes)?;
        }
    }
    if !layout.approval_file(&identity.device_id).exists() {
        if let Some(bytes) = client.fetch_access_record(
            &project.project_id,
            AccessRecordKind::Approval,
            identity.device_id.as_str(),
        )? {
            keyit_dir::import_approval_bytes(layout, &identity.device_id, &bytes)?;
        }
    }
    if let Some(bytes) = client.fetch_access_record(
        &project.project_id,
        AccessRecordKind::Revocation,
        identity.device_id.as_str(),
    )? {
        keyit_dir::import_revocation_bytes(layout, &identity.device_id, &bytes)?;
    }
    Ok(())
}

fn publish_access_record_to_http_relay(
    relay_url: &str,
    project_id: &ProjectId,
    kind: AccessRecordKind,
    object_id: &str,
    path: &Path,
) -> Result<(), CliError> {
    let bytes = fs::read(path).map_err(|e| CliError::io(path, e))?;
    RelayHttpClient::new(relay_url)?.publish_access_record(project_id, kind, object_id, &bytes)
}

pub(crate) fn publish_shared_project_state_to_http_relay(
    relay_url: &str,
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
) -> Result<(), CliError> {
    publish_access_record_to_http_relay(
        relay_url,
        &project.project_id,
        AccessRecordKind::ProjectGenesis,
        project.project_id.as_str(),
        &layout.genesis_file,
    )?;
    if layout.membership_genesis_file.exists() {
        publish_access_record_to_http_relay(
            relay_url,
            &project.project_id,
            AccessRecordKind::MembershipGenesis,
            "genesis",
            &layout.membership_genesis_file,
        )?;
    }
    for (env_layout, environment) in keyit_dir::read_environment_genesis_records(layout)? {
        publish_access_record_to_http_relay(
            relay_url,
            &project.project_id,
            AccessRecordKind::Environment,
            environment.environment_id.as_str(),
            &env_layout.environment_file,
        )?;
    }
    Ok(())
}

fn fetch_invite_from_http_relay_if_missing(
    relay_url: &Option<String>,
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
    invite_id: &InviteId,
) -> Result<bool, CliError> {
    if layout.invite_file(invite_id).exists() {
        return Ok(false);
    }
    let Some(relay_url) = relay_url else {
        return Ok(false);
    };
    let Some(bytes) = RelayHttpClient::new(relay_url)?.fetch_access_record(
        &project.project_id,
        AccessRecordKind::Invite,
        invite_id.as_str(),
    )?
    else {
        return Ok(false);
    };
    keyit_dir::import_invite_bytes(layout, invite_id, &bytes)?;
    Ok(true)
}

fn fetch_join_request_from_http_relay_if_missing(
    relay_url: &Option<String>,
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
    device_id: &DeviceId,
) -> Result<bool, CliError> {
    if layout.join_request_file(device_id).exists() {
        return Ok(false);
    }
    let Some(relay_url) = relay_url else {
        return Ok(false);
    };
    let Some(bytes) = RelayHttpClient::new(relay_url)?.fetch_access_record(
        &project.project_id,
        AccessRecordKind::JoinRequest,
        device_id.as_str(),
    )?
    else {
        return Ok(false);
    };
    keyit_dir::import_join_request_bytes(layout, device_id, &bytes)?;
    Ok(true)
}

fn configured_http_relay_url(
    project: &ProjectGenesis,
    override_url: Option<&str>,
) -> Option<String> {
    let configured = override_url.unwrap_or(&project.default_relay_url);
    (configured.starts_with("http://") || configured.starts_with("https://"))
        .then(|| configured.to_string())
}

fn require_project(
    project_root: &std::path::Path,
    keyit_data_dir: &std::path::Path,
) -> Result<KeyitDirLayout, CliError> {
    let layout = crate::project_state::require_project_layout(project_root, keyit_data_dir)?;
    if !layout.project_toml.exists() {
        return Err(CliError::NotInitialized {
            path: layout.project_toml,
        });
    }
    Ok(layout)
}

fn load_project(layout: &KeyitDirLayout) -> Result<ProjectGenesis, CliError> {
    let project = keyit_dir::read_project_genesis(layout)?;
    project.verify_signature()?;
    Ok(project)
}

fn load_local_signing_device(
    keyit_data_dir: &std::path::Path,
    created_at: Timestamp,
) -> Result<(SigningKeyPair, DeviceId), CliError> {
    let (signing_keypair, _) = device_key::load_or_create_device_signing_key(keyit_data_dir)?;
    let (encryption_keypair, _) = device_key::load_or_create_device_encryption_key(keyit_data_dir)?;
    let identity =
        device_identity::build_device_identity(&signing_keypair, &encryption_keypair, created_at);
    Ok((signing_keypair, identity.device_id))
}

fn resolve_environment_selectors(
    layout: &KeyitDirLayout,
    selectors: &[String],
) -> Result<Vec<EnvironmentId>, CliError> {
    let records = keyit_dir::read_environment_genesis_records(layout)?;
    let mut resolved = Vec::with_capacity(selectors.len());

    for selector in selectors {
        let (_, environment) = records
            .iter()
            .find(|(_, environment)| {
                environment.environment_id.as_str() == selector
                    || environment.environment_label == *selector
            })
            .ok_or_else(|| CliError::EnvironmentNotFound {
                selector: selector.clone(),
            })?;
        if !resolved.contains(&environment.environment_id) {
            resolved.push(environment.environment_id.clone());
        }
    }

    Ok(resolved)
}

fn resolve_requested_environment_ids(
    layout: &KeyitDirLayout,
    invite: &Invite,
    requested_environments: &[String],
) -> Result<Vec<EnvironmentId>, CliError> {
    let requested = if requested_environments.is_empty() {
        invite.allowed_environment_ids.clone()
    } else {
        resolve_environment_selectors(layout, requested_environments)?
    };

    for environment_id in &requested {
        if !invite.allowed_environment_ids.contains(environment_id) {
            return Err(CliError::InviteNotUsable {
                reason: format!(
                    "invite {} does not allow environment {}",
                    invite.invite_id, environment_id
                ),
            });
        }
    }

    Ok(requested)
}

fn load_bundle_environments(
    layout: &KeyitDirLayout,
    allowed_environment_ids: &[EnvironmentId],
) -> Result<Vec<EnvironmentGenesis>, CliError> {
    let records = keyit_dir::read_environment_genesis_records(layout)?;
    let mut environments = Vec::with_capacity(allowed_environment_ids.len());

    for environment_id in allowed_environment_ids {
        let (_, environment) = records
            .iter()
            .find(|(_, environment)| &environment.environment_id == environment_id)
            .ok_or_else(|| CliError::EnvironmentNotFound {
                selector: environment_id.as_str().to_string(),
            })?;
        environments.push(environment.clone());
    }

    Ok(environments)
}

fn validate_bundle_environment(
    path: &Path,
    project: &ProjectGenesis,
    project_hash: &HashBytes,
    environment: &EnvironmentGenesis,
) -> Result<(), CliError> {
    if environment.project_id != project.project_id {
        return Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!(
                "environment {} belongs to a different project",
                environment.environment_id
            ),
        });
    }
    if environment.created_by_device_id != project.creator_device_id {
        return Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!(
                "environment {} was not created by the project creator",
                environment.environment_id
            ),
        });
    }
    if &environment.parent_project_genesis_hash != project_hash {
        return Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!(
                "environment {} does not match the bundled project genesis",
                environment.environment_id
            ),
        });
    }
    environment.verify_signature(&project.creator_device_public_identity)?;
    Ok(())
}

fn validate_invite_for_join(
    project: &ProjectGenesis,
    access_state: &AccessState,
    invite: &Invite,
    layout: &KeyitDirLayout,
    joining_device_id: &DeviceId,
    now: Timestamp,
) -> Result<(), CliError> {
    if invite.project_id != project.project_id {
        return Err(CliError::InviteNotUsable {
            reason: "invite belongs to a different project".to_string(),
        });
    }
    let creator = access_state
        .device(&invite.created_by_device_id)
        .ok_or_else(|| CliError::InviteNotUsable {
            reason: format!(
                "invite creator {} is not an active member",
                invite.created_by_device_id
            ),
        })?;
    if !creator.can_manage_access() {
        return Err(CliError::InviteNotUsable {
            reason: format!(
                "invite creator {} is not an owner or admin",
                invite.created_by_device_id
            ),
        });
    }
    invite.verify_signature(&creator.signing_public_key)?;
    if invite.status != InviteStatus::Active {
        return Err(CliError::InviteNotUsable {
            reason: format!("invite {} is not active", invite.invite_id),
        });
    }
    if invite.expires_at.unix_seconds() <= now.unix_seconds() {
        return Err(CliError::InviteNotUsable {
            reason: format!("invite {} has expired", invite.invite_id),
        });
    }
    if invite.max_uses == 0 {
        return Err(CliError::InviteNotUsable {
            reason: format!("invite {} has no remaining uses", invite.invite_id),
        });
    }

    // Local-only backstop: when a project has no relay configured (or
    // this is a fully offline/bundle-exchange checkout), nothing else
    // counts an invite's uses, so check the join requests this checkout
    // already has on disk directly. A device re-joining with a join
    // request it already wrote (e.g. re-running `keyit join` after
    // fetching new environments) is not a new use of the invite.
    //
    // This is a courtesy check, not the enforcement of record: it only
    // sees join requests that happen to already be present in this
    // checkout (synced from the relay, or imported via an invite
    // bundle), so it cannot stop two *different* devices from
    // redeeming the same invite past `max_uses` purely locally without
    // ever exchanging state. The relay (see
    // `keyit_relay::FileRelayStore::publish_join_request_checked`) is
    // the actual source of truth for hosted projects, which is exactly
    // the case that matters — multiple devices redeeming the same
    // invite.
    let existing_uses = keyit_dir::read_join_request_records(layout)?
        .into_iter()
        .filter(|request| {
            request.invite_id == invite.invite_id && &request.joining_device_id != joining_device_id
        })
        .count();
    if existing_uses as u32 >= invite.max_uses {
        return Err(CliError::InviteNotUsable {
            reason: format!(
                "invite {} has already reached its maximum of {} use(s)",
                invite.invite_id, invite.max_uses
            ),
        });
    }
    Ok(())
}

fn zero_signature_placeholder() -> SignatureBytes {
    SignatureBytes::from_bytes(&[0u8; 64]).expect("64 zero bytes is a validly-shaped signature")
}

fn project_genesis_hash(project: &ProjectGenesis) -> HashBytes {
    canonical::canonical_hash(labels::SIGN_PROJECT_GENESIS, project)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::{run_env_add, EnvAddOptions};
    use crate::init::{run_init, InitOptions};

    struct Fixture {
        _project_dir: tempfile::TempDir,
        _owner_data_dir: tempfile::TempDir,
        _joining_data_dir: tempfile::TempDir,
        project_root: PathBuf,
        owner_data_dir: PathBuf,
        joining_data_dir: PathBuf,
    }

    fn fixture() -> Fixture {
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let owner_data_dir = tempfile::tempdir().expect("owner data tempdir");
        let joining_data_dir = tempfile::tempdir().expect("joining data tempdir");
        let project_root = project_dir.path().to_path_buf();
        let owner_data_dir_path = owner_data_dir.path().to_path_buf();
        let joining_data_dir_path = joining_data_dir.path().to_path_buf();

        run_init(InitOptions {
            project_root: project_root.clone(),
            keyit_data_dir: owner_data_dir_path.clone(),
            project_label: Some("fixture".to_string()),
            relay_url: Some("file://local-test-relay".to_string()),
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_400),
        })
        .expect("init project");
        run_env_add(EnvAddOptions {
            project_root: project_root.clone(),
            keyit_data_dir: owner_data_dir_path.clone(),
            environment_label: "development".to_string(),
            local_path: PathBuf::from(".env.local"),
            now: Timestamp::from_unix_seconds(1_755_878_500),
        })
        .expect("add environment");

        Fixture {
            _project_dir: project_dir,
            _owner_data_dir: owner_data_dir,
            _joining_data_dir: joining_data_dir,
            project_root,
            owner_data_dir: owner_data_dir_path,
            joining_data_dir: joining_data_dir_path,
        }
    }

    fn import_join_request(project_root: &Path, data_dir: &Path, join: &JoinOutcome) {
        let layout = require_project(project_root, data_dir).expect("layout");
        let bytes = fs::read(&join.path).expect("read join request");
        keyit_dir::import_join_request_bytes(&layout, &join.joining_device_id, &bytes)
            .expect("import join request");
    }

    fn import_approval(project_root: &Path, data_dir: &Path, approval: &ApproveOutcome) {
        let layout = require_project(project_root, data_dir).expect("layout");
        let bytes = fs::read(&approval.path).expect("read approval");
        keyit_dir::import_approval_bytes(&layout, &approval.approved_device_id, &bytes)
            .expect("import approval");
    }

    #[test]
    fn invite_create_writes_a_signed_invite() {
        let fixture = fixture();

        let outcome = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("create invite");

        assert!(outcome.invite_id.as_str().starts_with("kvi_"));
        assert_eq!(outcome.allowed_environment_ids.len(), 1);
        assert!(outcome.path.exists());
        assert!(outcome.bundle_path.exists());
    }

    #[test]
    fn invite_bundle_bootstraps_public_project_context() {
        let fixture = fixture();
        let joiner_project_dir = tempfile::tempdir().expect("joiner project tempdir");
        let invite = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir,
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("create invite");

        let (layout, invite_id) = prepare_join_project(
            joiner_project_dir.path(),
            &fixture.joining_data_dir,
            JoinTarget::BundlePath(invite.bundle_path),
        )
        .expect("bundle bootstrap");

        assert_eq!(invite_id, invite.invite_id);
        assert!(joiner_project_dir.path().join("keyit.toml").exists());
        assert!(!joiner_project_dir.path().join(".keyit").exists());
        assert!(layout.project_toml.exists());
        assert!(layout.genesis_file.exists());
        assert!(!layout.membership_genesis_file.exists());
        assert_eq!(
            keyit_dir::read_environment_genesis_records(&layout)
                .expect("read environments")
                .len(),
            1
        );
    }

    #[test]
    fn join_writes_a_signed_join_request() {
        let fixture = fixture();
        let invite = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("create invite");

        let outcome = run_join(JoinOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.joining_data_dir.clone(),
            target: JoinTarget::BundlePath(invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "joining device".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("join request");

        assert!(outcome.joining_device_id.as_str().starts_with("kvd_"));
        assert_eq!(outcome.requested_environment_ids.len(), 1);
        assert!(outcome.path.exists());
    }

    #[test]
    fn approve_writes_a_signed_approval() {
        let fixture = fixture();
        let invite = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("create invite");
        let join = run_join(JoinOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.joining_data_dir.clone(),
            target: JoinTarget::BundlePath(invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "joining device".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("join request");
        import_join_request(&fixture.project_root, &fixture.owner_data_dir, &join);

        let outcome = run_approve(ApproveOptions {
            project_root: fixture.project_root,
            keyit_data_dir: fixture.owner_data_dir,
            joining_device_id: join.joining_device_id,
            role: Role::Member,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_800),
        })
        .expect("approve request");

        assert_eq!(outcome.role, Role::Member);
        assert_eq!(outcome.approved_environment_ids.len(), 1);
        assert!(outcome.path.exists());
    }

    #[test]
    fn join_rejects_environment_not_allowed_by_invite() {
        let fixture = fixture();
        let invite = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir,
            environments: Vec::new(),
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("create invite");

        let err = run_join(JoinOptions {
            project_root: fixture.project_root,
            keyit_data_dir: fixture.joining_data_dir,
            target: JoinTarget::BundlePath(invite.bundle_path.clone()),
            requested_environments: vec!["development".to_string()],
            device_label: "joining device".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect_err("join should reject disallowed environment");

        assert!(matches!(err, CliError::EnvironmentNotFound { .. }));
    }

    #[test]
    fn approved_admin_can_invite_and_approve_another_device() {
        let fixture = fixture();
        let member_data_dir = tempfile::tempdir().expect("member data tempdir");

        let admin_invite = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("create admin invite");
        let admin_join = run_join(JoinOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.joining_data_dir.clone(),
            target: JoinTarget::BundlePath(admin_invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "admin device".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("admin join request");
        import_join_request(&fixture.project_root, &fixture.owner_data_dir, &admin_join);
        let admin_approval = run_approve(ApproveOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir.clone(),
            joining_device_id: admin_join.joining_device_id.clone(),
            role: Role::Admin,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_800),
        })
        .expect("approve admin");
        import_approval(
            &fixture.project_root,
            &fixture.joining_data_dir,
            &admin_approval,
        );

        let member_invite = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.joining_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_900),
        })
        .expect("admin creates invite");
        let member_join = run_join(JoinOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: member_data_dir.path().to_path_buf(),
            target: JoinTarget::BundlePath(member_invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "member device".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_879_000),
        })
        .expect("member join request");
        import_join_request(
            &fixture.project_root,
            &fixture.joining_data_dir,
            &member_join,
        );
        let member_approval = run_approve(ApproveOptions {
            project_root: fixture.project_root,
            keyit_data_dir: fixture.joining_data_dir,
            joining_device_id: member_join.joining_device_id,
            role: Role::Member,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_879_100),
        })
        .expect("admin approves member");

        assert_eq!(member_approval.role, Role::Member);
        assert_eq!(member_approval.approved_environment_ids.len(), 1);
    }

    #[test]
    fn revoke_writes_a_signed_revocation() {
        let fixture = fixture();
        let invite = run_invite_create(InviteCreateOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("create invite");
        let join = run_join(JoinOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.joining_data_dir,
            target: JoinTarget::BundlePath(invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "joining device".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("join request");
        import_join_request(&fixture.project_root, &fixture.owner_data_dir, &join);
        run_approve(ApproveOptions {
            project_root: fixture.project_root.clone(),
            keyit_data_dir: fixture.owner_data_dir.clone(),
            joining_device_id: join.joining_device_id.clone(),
            role: Role::Member,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_800),
        })
        .expect("approve request");

        let outcome = run_revoke(RevokeOptions {
            project_root: fixture.project_root,
            keyit_data_dir: fixture.owner_data_dir,
            revoked_device_id: join.joining_device_id,
            affected_environments: Vec::new(),
            reason: Some("device retired".to_string()),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_900),
        })
        .expect("revoke device");

        assert_eq!(outcome.affected_environment_ids.len(), 1);
        assert!(outcome.path.exists());
    }
}
