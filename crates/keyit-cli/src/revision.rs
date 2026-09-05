//! Encrypted revision creation and materialization.
//!
//! `keyit push` writes encrypted payload bytes and signed revision
//! metadata under the local Keyit data directory, while `keyit pull`
//! decrypts the latest revision and writes the mapped dotenv file.
//! When `--relay-dir` is supplied, push/pull publish/fetch opaque
//! encrypted bytes through the filesystem-backed relay store. When an
//! HTTP(S) relay URL is supplied or configured in project genesis,
//! push/pull use the signed HTTP relay API.

use std::fs;
use std::path::{Path, PathBuf};

use keyit_protocol::canonical::{self, CanonicalBytes, Canonicalize};
use keyit_protocol::dotenv::DotenvDocument;
use keyit_protocol::encryption::{
    decrypt_payload, encrypt_payload, unwrap_dek_for_device, wrap_dek_for_device, EncryptedPayload,
    EnvironmentDataKey, KeyAgreementKeyPair,
};
use keyit_protocol::ids::{EnvironmentId, ProjectId, RevisionId};
use keyit_protocol::primitives::{HashBytes, SignatureBytes, Timestamp};
use keyit_protocol::records::{EnvironmentGenesis, ProjectGenesis, Revision};
use keyit_protocol::signing::{SignedRecord, SigningKeyPair};
use keyit_relay::FileRelayStore;
use keyit_relay::{RelayAuthorizationEnvelope, RelayRevisionEnvelope};

use crate::access::{
    publish_shared_project_state_to_http_relay, sync_local_device_access_from_http_relay,
};
use crate::auth::load_access_state;
use crate::error::CliError;
use crate::keyit_dir::{
    self, DeviceWrappedDataKey, EnvironmentDirLayout, KeyitDirLayout, LocalRevisionBundle,
};
use crate::relay_client::RelayHttpClient;
use crate::{device_identity, device_key};

/// Inputs to local `keyit push`.
#[derive(Debug, Clone)]
pub struct PushOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub environment: String,
    pub change_summary: Option<String>,
    pub relay_dir: Option<PathBuf>,
    pub relay_url: Option<String>,
    pub now: Timestamp,
}

/// Inputs to local `keyit pull`.
#[derive(Debug, Clone)]
pub struct PullOptions {
    pub project_root: PathBuf,
    pub keyit_data_dir: PathBuf,
    pub environment: String,
    pub relay_dir: Option<PathBuf>,
    pub relay_url: Option<String>,
    pub force: bool,
    pub now: Timestamp,
}

/// Result of creating a local encrypted revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    pub project_id: ProjectId,
    pub environment_id: EnvironmentId,
    pub label: String,
    pub revision_id: RevisionId,
    pub key_count: usize,
    pub revision_path: PathBuf,
    pub payload_path: PathBuf,
    pub relay_revision_path: Option<PathBuf>,
    pub relay_payload_path: Option<PathBuf>,
    pub relay_url: Option<String>,
    pub rotation_cleared: bool,
}

/// Result of materializing a local encrypted revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullOutcome {
    pub project_id: ProjectId,
    pub environment_id: EnvironmentId,
    pub label: String,
    pub revision_id: RevisionId,
    pub key_count: usize,
    pub local_path: PathBuf,
    pub fetched_from_relay: bool,
    pub relay_url: Option<String>,
}

/// A decrypted local revision used by status/diff/pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecryptedRevision {
    pub revision: Revision,
    pub document: DotenvDocument,
    pub plaintext: String,
}

/// Runs local `keyit push`.
pub fn run_push(options: PushOptions) -> Result<PushOutcome, CliError> {
    let layout = require_project(&options.project_root, &options.keyit_data_dir)?;
    let project = load_project(&layout)?;
    let access_state = load_access_state(&layout, &project)?;

    let selected = select_environment(&layout, &options.environment)?;
    selected
        .record
        .verify_signature(&project.creator_device_public_identity)?;

    let (signing_keypair, encryption_keypair, device_id) =
        load_local_device(&options.keyit_data_dir, options.now)?;
    let local_device =
        access_state.require_environment_access(&device_id, &selected.record.environment_id)?;
    let rotation_required = keyit_dir::read_rotation_required(&selected.layout)?;
    if rotation_required.is_some() && !local_device.can_manage_access() {
        return Err(CliError::RevisionConflict {
            reason: format!(
                "environment {} requires owner/admin rotation after revocation; ask an owner/admin to run `keyit push {}`",
                selected.record.environment_label, selected.record.environment_label
            ),
        });
    }

    let local_path = resolve_local_path(&options.project_root, &selected.local_path);
    let plaintext = fs::read_to_string(&local_path).map_err(|e| CliError::io(&local_path, e))?;
    let document = DotenvDocument::parse(&plaintext)?;

    let latest = keyit_dir::read_latest_local_revision(&selected.layout)?;
    ensure_local_push_base_is_latest(&selected.layout, latest.as_ref())?;
    let parent_revision_id = latest
        .as_ref()
        .map(|bundle| bundle.revision.revision_id.clone());
    let expected_parent_revision_id = parent_revision_id.clone();
    let parent_revision_hash = latest
        .as_ref()
        .map(|bundle| revision_metadata_hash(&bundle.revision));

    let dek = EnvironmentDataKey::generate();
    let payload_aad = payload_associated_data(&project.project_id, &selected.record);
    let encrypted_payload = encrypt_payload(&dek, &payload_aad, document.source().as_bytes())?;
    let payload_hash = encrypted_payload_hash(&encrypted_payload);
    let revision_id = RevisionId::derive(
        &project.project_id,
        &selected.record.environment_id,
        parent_revision_hash.as_ref(),
        &payload_hash,
        &device_id,
        options.now,
    );

    let mut revision = Revision {
        revision_id: revision_id.clone(),
        project_id: project.project_id.clone(),
        environment_id: selected.record.environment_id.clone(),
        parent_revision_id,
        parent_revision_hash,
        payload_hash,
        encrypted_payload_ref: format!("local://{revision_id}/payload"),
        author_device_id: device_id.clone(),
        created_at: options.now,
        change_summary: options.change_summary.clone(),
        signature: zero_signature_field(),
    };
    revision.signature = signing_keypair.sign(Revision::SIGN_LABEL, &revision);
    revision.verify_signature(&signing_keypair.public_key())?;

    let wrapped_deks = wrap_dek_for_active_devices(
        &access_state,
        &device_id,
        &encryption_keypair,
        &selected.record.environment_id,
        &dek,
        &revision,
    )?;
    let bundle = keyit_dir::write_local_revision(
        &selected.layout,
        &revision,
        &encrypted_payload,
        &wrapped_deks,
    )?;
    keyit_dir::write_materialized_revision_id(&selected.layout, &revision.revision_id)?;

    let http_relay_url = configured_http_relay_url(&project, options.relay_url.as_deref());
    let (relay_revision_path, relay_payload_path, published_relay_url) =
        if let Some(relay_dir) = &options.relay_dir {
            let published = publish_local_revision_to_relay(
                relay_dir,
                &project.project_id,
                &selected.record.environment_id,
                &revision.revision_id,
                expected_parent_revision_id.as_ref(),
                &bundle.revision_path,
                &bundle.payload_path,
            )?;
            (
                Some(published.revision_path),
                Some(published.payload_path),
                None,
            )
        } else if let Some(relay_url) = http_relay_url {
            publish_shared_project_state_to_http_relay(&relay_url, &layout, &project)?;
            publish_local_revision_to_http_relay(HttpRelayPublishInput {
                relay_url: &relay_url,
                layout: &layout,
                project: &project,
                environment_id: &selected.record.environment_id,
                revision_id: &revision.revision_id,
                expected_parent_revision_id: expected_parent_revision_id.as_ref(),
                revision_path: &bundle.revision_path,
                payload_path: &bundle.payload_path,
                signing_keypair: &signing_keypair,
                device_id: &device_id,
                now: options.now,
            })?;
            (None, None, Some(relay_url))
        } else {
            (None, None, None)
        };
    let rotation_cleared = if rotation_required.is_some() {
        keyit_dir::clear_rotation_required(&selected.layout)?
    } else {
        false
    };

    Ok(PushOutcome {
        project_id: project.project_id,
        environment_id: selected.record.environment_id,
        label: selected.record.environment_label,
        revision_id,
        key_count: document.entries().len(),
        revision_path: bundle.revision_path,
        payload_path: bundle.payload_path,
        relay_revision_path,
        relay_payload_path,
        relay_url: published_relay_url,
        rotation_cleared,
    })
}

/// Runs local `keyit pull`.
pub fn run_pull(options: PullOptions) -> Result<PullOutcome, CliError> {
    let layout = require_project(&options.project_root, &options.keyit_data_dir)?;
    let project = load_project(&layout)?;
    let selected = select_environment(&layout, &options.environment)?;
    let http_relay_url = configured_http_relay_url(&project, options.relay_url.as_deref());
    if options.relay_dir.is_none() {
        if let Some(relay_url) = &http_relay_url {
            sync_local_device_access_from_http_relay(
                &layout,
                &project,
                &options.keyit_data_dir,
                relay_url,
            )?;
        }
    }
    let (fetched_from_relay, fetched_relay_url) = if let Some(relay_dir) = &options.relay_dir {
        fetch_latest_revision_from_relay(
            relay_dir,
            &project.project_id,
            &selected.record.environment_id,
            &selected.layout,
        )?
        .then_some(())
        .map(|()| (true, None))
        .unwrap_or((false, None))
    } else if let Some(relay_url) = http_relay_url {
        let fetched = fetch_latest_revision_from_http_relay(
            &relay_url,
            &layout,
            &project,
            &selected.record.environment_id,
            &selected.layout,
            &options.keyit_data_dir,
            options.now,
        )?;
        (fetched, fetched.then_some(relay_url))
    } else {
        (false, None)
    };
    let Some(decrypted) = decrypt_latest_revision(
        &options.keyit_data_dir,
        &project,
        &layout,
        &selected.record,
        &selected.layout,
    )?
    else {
        return Err(CliError::NoLocalRevision {
            environment: selected.record.environment_label,
        });
    };

    let local_path = resolve_local_path(&options.project_root, &selected.local_path);
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent).map_err(|e| CliError::io(parent, e))?;
    }
    let plaintext = decrypted.plaintext;
    ensure_pull_can_write_local_path(PullWriteSafetyInput {
        local_path: &local_path,
        materialized: &plaintext,
        force: options.force,
        keyit_data_dir: &options.keyit_data_dir,
        project: &project,
        layout: &layout,
        environment: &selected.record,
        env_layout: &selected.layout,
    })?;
    fs::write(&local_path, plaintext).map_err(|e| CliError::io(&local_path, e))?;
    keyit_dir::write_materialized_revision_id(&selected.layout, &decrypted.revision.revision_id)?;

    Ok(PullOutcome {
        project_id: project.project_id,
        environment_id: selected.record.environment_id,
        label: selected.record.environment_label,
        revision_id: decrypted.revision.revision_id,
        key_count: decrypted.document.entries().len(),
        local_path: selected.local_path,
        fetched_from_relay,
        relay_url: fetched_relay_url,
    })
}

struct PullWriteSafetyInput<'a> {
    local_path: &'a Path,
    materialized: &'a str,
    force: bool,
    keyit_data_dir: &'a Path,
    project: &'a ProjectGenesis,
    layout: &'a KeyitDirLayout,
    environment: &'a EnvironmentGenesis,
    env_layout: &'a EnvironmentDirLayout,
}

fn ensure_pull_can_write_local_path(input: PullWriteSafetyInput<'_>) -> Result<(), CliError> {
    if input.force || !input.local_path.exists() {
        return Ok(());
    }
    let current =
        fs::read_to_string(input.local_path).map_err(|e| CliError::io(input.local_path, e))?;
    if current == input.materialized
        || local_file_matches_materialized_revision(
            input.keyit_data_dir,
            input.project,
            input.layout,
            input.environment,
            input.env_layout,
            &current,
        )?
    {
        return Ok(());
    }

    Err(CliError::PullWouldOverwriteLocalChanges {
        path: input.local_path.to_path_buf(),
    })
}

fn local_file_matches_materialized_revision(
    keyit_data_dir: &Path,
    project: &ProjectGenesis,
    layout: &KeyitDirLayout,
    environment: &EnvironmentGenesis,
    env_layout: &EnvironmentDirLayout,
    current: &str,
) -> Result<bool, CliError> {
    let Some(revision_id) = keyit_dir::read_materialized_revision_id(env_layout)? else {
        return Ok(false);
    };
    let bundle = match keyit_dir::read_local_revision(env_layout, &revision_id) {
        Ok(bundle) => bundle,
        Err(CliError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    let (signing_keypair, encryption_keypair) = load_local_device_keys(keyit_data_dir)?;
    let identity = device_identity::build_device_identity(
        &signing_keypair,
        &encryption_keypair,
        project.created_at,
    );
    let access_state = load_access_state(layout, project)?;
    let decrypted = decrypt_revision_bundle(
        project,
        &access_state,
        environment,
        &bundle,
        &identity.device_id,
        &encryption_keypair,
    )?;
    if decrypted.plaintext == current {
        return Ok(true);
    }
    let Ok(current_document) = DotenvDocument::parse(current) else {
        return Ok(false);
    };
    Ok(decrypted.document.normalize() == current_document.normalize())
}

fn publish_local_revision_to_relay(
    relay_dir: &Path,
    project_id: &ProjectId,
    environment_id: &EnvironmentId,
    revision_id: &RevisionId,
    expected_parent_revision_id: Option<&RevisionId>,
    revision_path: &Path,
    payload_path: &Path,
) -> Result<keyit_relay::PublishedRevision, CliError> {
    let revision_metadata = fs::read(revision_path).map_err(|e| CliError::io(revision_path, e))?;
    let encrypted_payload = fs::read(payload_path).map_err(|e| CliError::io(payload_path, e))?;
    let store = FileRelayStore::new(relay_dir);
    store
        .publish_revision_checked(
            project_id,
            environment_id,
            revision_id,
            expected_parent_revision_id,
            &revision_metadata,
            &encrypted_payload,
        )
        .map_err(Into::into)
}

fn publish_local_revision_to_http_relay(input: HttpRelayPublishInput<'_>) -> Result<(), CliError> {
    let revision_metadata =
        fs::read(input.revision_path).map_err(|e| CliError::io(input.revision_path, e))?;
    let encrypted_payload =
        fs::read(input.payload_path).map_err(|e| CliError::io(input.payload_path, e))?;
    let envelope = RelayRevisionEnvelope {
        project_id: input.project.project_id.clone(),
        environment_id: input.environment_id.clone(),
        revision_id: input.revision_id.clone(),
        parent_revision_id: input.expected_parent_revision_id.cloned(),
        revision_metadata,
        encrypted_payload,
    };
    RelayHttpClient::new(input.relay_url)?.publish_revision_checked(
        envelope,
        build_relay_authorization(input.layout, input.project)?,
        input.device_id.clone(),
        input.signing_keypair,
        input.now,
    )
}

#[derive(Debug)]
struct HttpRelayPublishInput<'a> {
    relay_url: &'a str,
    layout: &'a KeyitDirLayout,
    project: &'a ProjectGenesis,
    environment_id: &'a EnvironmentId,
    revision_id: &'a RevisionId,
    expected_parent_revision_id: Option<&'a RevisionId>,
    revision_path: &'a Path,
    payload_path: &'a Path,
    signing_keypair: &'a SigningKeyPair,
    device_id: &'a keyit_protocol::ids::DeviceId,
    now: Timestamp,
}

fn ensure_local_push_base_is_latest(
    env_layout: &EnvironmentDirLayout,
    latest: Option<&LocalRevisionBundle>,
) -> Result<(), CliError> {
    let Some(latest) = latest else {
        return Ok(());
    };
    let materialized = keyit_dir::read_materialized_revision_id(env_layout)?;
    if materialized.as_ref() != Some(&latest.revision.revision_id) {
        return Err(CliError::RevisionConflict {
            reason: format!(
                "local file is based on {}, but latest local revision is {}; run `keyit pull` before pushing",
                materialized
                    .as_ref()
                    .map(|id| id.as_str())
                    .unwrap_or("none"),
                latest.revision.revision_id
            ),
        });
    }
    Ok(())
}

fn fetch_latest_revision_from_relay(
    relay_dir: &Path,
    project_id: &ProjectId,
    environment_id: &EnvironmentId,
    env_layout: &EnvironmentDirLayout,
) -> Result<bool, CliError> {
    let store = FileRelayStore::new(relay_dir);
    let Some(stored) = store.fetch_latest_revision(project_id, environment_id)? else {
        return Ok(false);
    };
    keyit_dir::import_relay_revision_bytes(
        env_layout,
        &stored.revision_id,
        &stored.revision_metadata,
        &stored.encrypted_payload,
    )?;
    Ok(true)
}

fn fetch_latest_revision_from_http_relay(
    relay_url: &str,
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
    environment_id: &EnvironmentId,
    env_layout: &EnvironmentDirLayout,
    keyit_data_dir: &Path,
    now: Timestamp,
) -> Result<bool, CliError> {
    let (signing_keypair, encryption_keypair) = load_local_device_keys(keyit_data_dir)?;
    let identity = device_identity::build_device_identity(
        &signing_keypair,
        &encryption_keypair,
        project.created_at,
    );
    let Some(envelope) = RelayHttpClient::new(relay_url)?.fetch_latest_revision(
        &project.project_id,
        environment_id,
        build_relay_authorization(layout, project)?,
        identity.device_id,
        &signing_keypair,
        now,
    )?
    else {
        return Ok(false);
    };
    keyit_dir::import_relay_revision_bytes(
        env_layout,
        &envelope.revision_id,
        &envelope.revision_metadata,
        &envelope.encrypted_payload,
    )?;
    Ok(true)
}

pub(crate) fn decrypt_latest_revision(
    keyit_data_dir: &Path,
    project: &ProjectGenesis,
    layout: &KeyitDirLayout,
    environment: &EnvironmentGenesis,
    env_layout: &EnvironmentDirLayout,
) -> Result<Option<DecryptedRevision>, CliError> {
    let Some(bundle) = keyit_dir::read_latest_local_revision(env_layout)? else {
        return Ok(None);
    };
    let (signing_keypair, encryption_keypair) = load_local_device_keys(keyit_data_dir)?;
    let identity = device_identity::build_device_identity(
        &signing_keypair,
        &encryption_keypair,
        project.created_at,
    );
    let access_state = load_access_state(layout, project)?;
    decrypt_revision_bundle(
        project,
        &access_state,
        environment,
        &bundle,
        &identity.device_id,
        &encryption_keypair,
    )
    .map(Some)
}

fn build_relay_authorization(
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
) -> Result<RelayAuthorizationEnvelope, CliError> {
    Ok(RelayAuthorizationEnvelope {
        project: project.clone(),
        join_requests: keyit_dir::read_join_request_records(layout)?,
        approvals: keyit_dir::read_approval_records(layout)?,
        revocations: keyit_dir::read_revocation_records(layout)?,
    })
}

fn configured_http_relay_url(
    project: &ProjectGenesis,
    override_url: Option<&str>,
) -> Option<String> {
    let configured = override_url.unwrap_or(&project.default_relay_url);
    (configured.starts_with("http://") || configured.starts_with("https://"))
        .then(|| configured.to_string())
}

fn decrypt_revision_bundle(
    project: &ProjectGenesis,
    access_state: &crate::auth::AccessState,
    environment: &EnvironmentGenesis,
    bundle: &LocalRevisionBundle,
    local_device_id: &keyit_protocol::ids::DeviceId,
    encryption_keypair: &KeyAgreementKeyPair,
) -> Result<DecryptedRevision, CliError> {
    let revision = &bundle.revision;
    if revision.project_id != project.project_id
        || revision.environment_id != environment.environment_id
    {
        return Err(CliError::MalformedRecordFile {
            path: bundle.revision_path.clone(),
            reason: "revision project/environment does not match its environment directory"
                .to_string(),
        });
    }
    let author = access_state
        .require_environment_access(&revision.author_device_id, &revision.environment_id)?;
    revision.verify_signature(&author.signing_public_key)?;

    let derived_revision_id = RevisionId::derive(
        &revision.project_id,
        &revision.environment_id,
        revision.parent_revision_hash.as_ref(),
        &revision.payload_hash,
        &revision.author_device_id,
        revision.created_at,
    );
    if derived_revision_id != revision.revision_id {
        return Err(CliError::MalformedRecordFile {
            path: bundle.revision_path.clone(),
            reason: "revision_id does not match revision metadata".to_string(),
        });
    }

    let actual_payload_hash = encrypted_payload_hash(&bundle.encrypted_payload);
    if actual_payload_hash != revision.payload_hash {
        return Err(CliError::MalformedRecordFile {
            path: bundle.payload_path.clone(),
            reason: "encrypted payload hash does not match revision metadata".to_string(),
        });
    }

    let wrapped_dek = bundle
        .wrapped_deks
        .iter()
        .find(|wrapped| &wrapped.device_id == local_device_id)
        .ok_or_else(|| CliError::MalformedRecordFile {
            path: bundle.revision_path.clone(),
            reason: format!("revision has no wrapped DEK for local device {local_device_id}"),
        })?;
    let dek = unwrap_dek_for_device(
        &wrapped_dek.wrapped_dek,
        encryption_keypair,
        &dek_wrap_context(revision),
    )?;
    let plaintext = decrypt_payload(
        &dek,
        &payload_associated_data(&project.project_id, environment),
        &bundle.encrypted_payload,
    )?;
    let text = String::from_utf8(plaintext).map_err(|e| CliError::MalformedRecordFile {
        path: bundle.payload_path.clone(),
        reason: format!("decrypted payload is not UTF-8: {e}"),
    })?;
    let document = DotenvDocument::parse(&text)?;

    Ok(DecryptedRevision {
        revision: revision.clone(),
        document,
        plaintext: text,
    })
}

fn wrap_dek_for_active_devices(
    access_state: &crate::auth::AccessState,
    local_device_id: &keyit_protocol::ids::DeviceId,
    local_encryption_keypair: &KeyAgreementKeyPair,
    environment_id: &EnvironmentId,
    dek: &EnvironmentDataKey,
    revision: &Revision,
) -> Result<Vec<DeviceWrappedDataKey>, CliError> {
    let mut recipients: Vec<(
        keyit_protocol::ids::DeviceId,
        keyit_protocol::primitives::PublicKeyBytes,
    )> = Vec::new();
    recipients.push((
        local_device_id.clone(),
        local_encryption_keypair.public_key(),
    ));

    for device in access_state.active_devices() {
        if &device.device_id == local_device_id || !device.can_access_environment(environment_id) {
            continue;
        }
        if let Some(public_key) = &device.encryption_public_key {
            recipients.push((device.device_id.clone(), *public_key));
        }
    }
    recipients.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    recipients.dedup_by(|a, b| a.0 == b.0);

    recipients
        .into_iter()
        .map(|(device_id, public_key)| {
            let wrapped_dek = wrap_dek_for_device(dek, &public_key, &dek_wrap_context(revision))?;
            Ok(DeviceWrappedDataKey {
                device_id,
                wrapped_dek,
            })
        })
        .collect()
}

pub(crate) fn require_project(
    project_root: &Path,
    keyit_data_dir: &Path,
) -> Result<KeyitDirLayout, CliError> {
    let layout = crate::project_state::require_project_layout(project_root, keyit_data_dir)?;
    if !layout.project_toml.exists() {
        return Err(CliError::NotInitialized {
            path: layout.project_toml,
        });
    }
    Ok(layout)
}

pub(crate) fn load_project(layout: &KeyitDirLayout) -> Result<ProjectGenesis, CliError> {
    let project = keyit_dir::read_project_genesis(layout)?;
    project.verify_signature()?;
    Ok(project)
}

pub(crate) fn select_environment(
    layout: &KeyitDirLayout,
    selector: &str,
) -> Result<SelectedEnvironment, CliError> {
    for (env_layout, record) in keyit_dir::read_environment_genesis_records(layout)? {
        if record.environment_label == selector || record.environment_id.as_str() == selector {
            let local = keyit_dir::read_local_environment(&env_layout)?;
            return Ok(SelectedEnvironment {
                layout: env_layout,
                local_path: PathBuf::from(local.local_path),
                record,
            });
        }
    }
    Err(CliError::EnvironmentNotFound {
        selector: selector.to_string(),
    })
}

pub(crate) fn load_environment_refs(
    layout: &KeyitDirLayout,
    selector: Option<&str>,
) -> Result<Vec<SelectedEnvironment>, CliError> {
    let mut refs = Vec::new();
    for (env_layout, record) in keyit_dir::read_environment_genesis_records(layout)? {
        let local = keyit_dir::read_local_environment(&env_layout)?;
        refs.push(SelectedEnvironment {
            layout: env_layout,
            local_path: PathBuf::from(local.local_path),
            record,
        });
    }

    if let Some(selector) = selector {
        refs.retain(|env| {
            env.record.environment_label == selector
                || env.record.environment_id.as_str() == selector
        });
        if refs.is_empty() {
            return Err(CliError::EnvironmentNotFound {
                selector: selector.to_string(),
            });
        }
    }

    refs.sort_by(|a, b| a.record.environment_label.cmp(&b.record.environment_label));
    Ok(refs)
}

#[derive(Debug, Clone)]
pub(crate) struct SelectedEnvironment {
    pub layout: EnvironmentDirLayout,
    pub record: EnvironmentGenesis,
    pub local_path: PathBuf,
}

pub(crate) fn resolve_local_path(project_root: &Path, local_path: &Path) -> PathBuf {
    if local_path.is_absolute() {
        local_path.to_path_buf()
    } else {
        project_root.join(local_path)
    }
}

fn load_local_device(
    keyit_data_dir: &Path,
    created_at: Timestamp,
) -> Result<
    (
        SigningKeyPair,
        KeyAgreementKeyPair,
        keyit_protocol::ids::DeviceId,
    ),
    CliError,
> {
    let (signing_keypair, encryption_keypair) = load_local_device_keys(keyit_data_dir)?;
    let identity =
        device_identity::build_device_identity(&signing_keypair, &encryption_keypair, created_at);
    Ok((signing_keypair, encryption_keypair, identity.device_id))
}

fn load_local_device_keys(
    keyit_data_dir: &Path,
) -> Result<(SigningKeyPair, KeyAgreementKeyPair), CliError> {
    let (signing_keypair, _) = device_key::load_or_create_device_signing_key(keyit_data_dir)?;
    let (encryption_keypair, _) = device_key::load_or_create_device_encryption_key(keyit_data_dir)?;
    Ok((signing_keypair, encryption_keypair))
}

fn payload_associated_data(project_id: &ProjectId, environment: &EnvironmentGenesis) -> Vec<u8> {
    format!(
        "keyit:v1:payload:{}:{}:{}",
        project_id,
        environment.environment_id,
        environment.document_type.as_str()
    )
    .into_bytes()
}

fn dek_wrap_context(revision: &Revision) -> Vec<u8> {
    format!(
        "keyit:v1:dek-wrap:{}:{}:{}",
        revision.project_id, revision.environment_id, revision.author_device_id
    )
    .into_bytes()
}

fn encrypted_payload_hash(payload: &EncryptedPayload) -> HashBytes {
    canonical::canonical_hash(
        "keyit:v1:local-encrypted-payload",
        &EncryptedPayloadHashInput(payload),
    )
}

fn revision_metadata_hash(revision: &Revision) -> HashBytes {
    canonical::canonical_hash("keyit:v1:local-revision-metadata", revision)
}

fn zero_signature_field() -> SignatureBytes {
    SignatureBytes::from_bytes(&[0u8; 64]).expect("64 zero bytes is a validly-shaped signature")
}

struct EncryptedPayloadHashInput<'a>(&'a EncryptedPayload);

impl Canonicalize for EncryptedPayloadHashInput<'_> {
    fn write_canonical(&self, buf: &mut CanonicalBytes) {
        buf.push_str(self.0.algorithm);
        buf.push_bytes(&self.0.nonce);
        buf.push_bytes(&self.0.ciphertext);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{
        run_approve, run_invite_create, run_join, run_revoke, ApproveOptions, InviteCreateOptions,
        JoinOptions, JoinTarget, RevokeOptions,
    };
    use crate::environment::{run_env_add, EnvAddOptions};
    use crate::init::{run_init, InitOptions};
    use keyit_relay::serve_http_blocking;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    struct Fixture {
        _project_dir: tempfile::TempDir,
        _data_dir: tempfile::TempDir,
        project_root: PathBuf,
        keyit_data_dir: PathBuf,
    }

    fn fixture() -> Fixture {
        let project_dir = tempfile::tempdir().expect("project tempdir");
        let data_dir = tempfile::tempdir().expect("data tempdir");
        let project_root = project_dir.path().to_path_buf();
        let keyit_data_dir = data_dir.path().to_path_buf();
        run_init(InitOptions {
            project_root: project_root.clone(),
            keyit_data_dir: keyit_data_dir.clone(),
            project_label: None,
            relay_url: Some("file://local-test-relay".to_string()),
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_400),
        })
        .expect("init");
        run_env_add(EnvAddOptions {
            project_root: project_root.clone(),
            keyit_data_dir: keyit_data_dir.clone(),
            environment_label: "development".to_string(),
            local_path: PathBuf::from(".env.local"),
            now: Timestamp::from_unix_seconds(1_755_878_500),
        })
        .expect("env add");
        Fixture {
            _project_dir: project_dir,
            _data_dir: data_dir,
            project_root,
            keyit_data_dir,
        }
    }

    fn import_join_request(
        project_root: &Path,
        data_dir: &Path,
        join: &crate::access::JoinOutcome,
    ) {
        let layout = require_project(project_root, data_dir).expect("layout");
        let bytes = fs::read(&join.path).expect("read join request");
        keyit_dir::import_join_request_bytes(&layout, &join.joining_device_id, &bytes)
            .expect("import join request");
    }

    fn import_approval(
        project_root: &Path,
        data_dir: &Path,
        approval: &crate::access::ApproveOutcome,
    ) {
        let layout = require_project(project_root, data_dir).expect("layout");
        let bytes = fs::read(&approval.path).expect("read approval");
        keyit_dir::import_approval_bytes(&layout, &approval.approved_device_id, &bytes)
            .expect("import approval");
    }

    fn import_revocation(
        project_root: &Path,
        data_dir: &Path,
        revocation: &crate::access::RevokeOutcome,
    ) {
        let layout = require_project(project_root, data_dir).expect("layout");
        let bytes = fs::read(&revocation.path).expect("read revocation");
        keyit_dir::import_revocation_bytes(&layout, &revocation.revoked_device_id, &bytes)
            .expect("import revocation");
    }

    #[test]
    fn hosted_default_relay_url_is_active() {
        let fx = fixture();
        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let project = keyit_dir::read_project_genesis(&layout).expect("project");
        let mut hosted_project = project.clone();
        hosted_project.default_relay_url = "https://relay.keyit.sh".to_string();

        assert_eq!(
            configured_http_relay_url(&hosted_project, None).as_deref(),
            Some("https://relay.keyit.sh")
        );
    }

    #[test]
    fn non_http_default_relay_url_is_ignored_for_http_sync() {
        let fx = fixture();
        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let project = keyit_dir::read_project_genesis(&layout).expect("project");

        assert_eq!(project.default_relay_url, "file://local-test-relay");
        assert_eq!(configured_http_relay_url(&project, None), None);
    }

    #[test]
    fn explicit_relay_url_overrides_project_default() {
        let fx = fixture();
        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let project = keyit_dir::read_project_genesis(&layout).expect("project");

        assert_eq!(
            configured_http_relay_url(&project, Some("http://127.0.0.1:8787")).as_deref(),
            Some("http://127.0.0.1:8787")
        );
    }

    #[test]
    fn push_creates_encrypted_local_revision_without_plaintext_payload() {
        let fx = fixture();
        fs::write(
            fx.project_root.join(".env.local"),
            "API_KEY=super-secret\nLOG_LEVEL=debug\n",
        )
        .expect("write dotenv");

        let outcome = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("push");

        assert_eq!(outcome.key_count, 2);
        let payload = fs::read_to_string(&outcome.payload_path).unwrap_or_default();
        assert!(!payload.contains("super-secret"));
        assert!(outcome.revision_path.exists());
    }

    #[test]
    fn pull_materializes_latest_revision() {
        let fx = fixture();
        fs::write(
            fx.project_root.join(".env.local"),
            "# DEV\nAPI_KEY=super-secret\nLOG_LEVEL=debug\n",
        )
        .expect("write dotenv");

        let pushed = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("push");
        fs::remove_file(fx.project_root.join(".env.local")).expect("remove local dotenv");

        let pulled = run_pull(PullOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            relay_dir: None,
            relay_url: None,
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("pull");

        assert_eq!(pulled.revision_id, pushed.revision_id);
        let materialized =
            fs::read_to_string(fx.project_root.join(".env.local")).expect("read materialized");
        assert_eq!(
            materialized,
            "# DEV\nAPI_KEY=super-secret\nLOG_LEVEL=debug\n"
        );
    }

    #[test]
    fn pull_fails_without_a_local_revision() {
        let fx = fixture();
        let err = run_pull(PullOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            relay_dir: None,
            relay_url: None,
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .unwrap_err();

        assert!(matches!(err, CliError::NoLocalRevision { .. }));
    }

    #[test]
    fn pull_rejects_local_dotenv_edits_without_force() {
        let fx = fixture();
        fs::write(fx.project_root.join(".env.local"), "A=one\n").expect("write dotenv");
        run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("push");

        fs::write(fx.project_root.join(".env.local"), "A=local-edit\n").expect("edit dotenv");
        let err = run_pull(PullOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            relay_dir: None,
            relay_url: None,
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect_err("pull should reject local edits");

        assert!(matches!(
            err,
            CliError::PullWouldOverwriteLocalChanges { .. }
        ));
    }

    #[test]
    fn pull_force_overwrites_local_dotenv_edits() {
        let fx = fixture();
        fs::write(fx.project_root.join(".env.local"), "A=one\n").expect("write dotenv");
        run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("push");

        fs::write(fx.project_root.join(".env.local"), "A=local-edit\n").expect("edit dotenv");
        run_pull(PullOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            relay_dir: None,
            relay_url: None,
            force: true,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("forced pull");

        let materialized =
            fs::read_to_string(fx.project_root.join(".env.local")).expect("read materialized");
        assert!(materialized.contains("A=one"));
    }

    #[test]
    fn second_push_links_to_parent_revision() {
        let fx = fixture();
        fs::write(fx.project_root.join(".env.local"), "A=one\n").expect("write dotenv");
        let first = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("first push");

        fs::write(fx.project_root.join(".env.local"), "A=two\n").expect("write dotenv");
        let second = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("second push");

        assert_ne!(first.revision_id, second.revision_id);
        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let selected = select_environment(&layout, "development").expect("env");
        let latest = keyit_dir::read_latest_local_revision(&selected.layout)
            .expect("latest")
            .expect("revision");
        assert_eq!(latest.revision.parent_revision_id, Some(first.revision_id));
        assert!(latest.revision.parent_revision_hash.is_some());
    }

    #[test]
    fn encrypted_payload_hash_changes_when_ciphertext_changes() {
        let a = EncryptedPayload {
            algorithm: "keyit:v1:aes-256-gcm:environment-payload",
            nonce: [1u8; 12],
            ciphertext: vec![1, 2, 3],
        };
        let b = EncryptedPayload {
            algorithm: "keyit:v1:aes-256-gcm:environment-payload",
            nonce: [1u8; 12],
            ciphertext: vec![1, 2, 4],
        };

        assert_ne!(encrypted_payload_hash(&a), encrypted_payload_hash(&b));
    }

    #[test]
    fn dotenv_document_round_trips_through_revision_decryption() {
        let fx = fixture();
        fs::write(fx.project_root.join(".env.local"), "# DEV\nA=one\nB=two\n")
            .expect("write dotenv");
        run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("push");

        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let project = load_project(&layout).expect("project");
        let selected = select_environment(&layout, "development").expect("env");
        let decrypted = decrypt_latest_revision(
            &fx.keyit_data_dir,
            &project,
            &layout,
            &selected.record,
            &selected.layout,
        )
        .expect("decrypt")
        .expect("latest");

        assert_eq!(decrypted.document.entries().len(), 2);
        assert_eq!(decrypted.plaintext, "# DEV\nA=one\nB=two\n");
    }

    #[test]
    fn push_wraps_dek_for_approved_device_and_that_device_can_pull() {
        let fx = fixture();
        let member_data_dir = tempfile::tempdir().expect("member data tempdir");

        let invite = run_invite_create(InviteCreateOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("invite");
        let join = run_join(JoinOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: member_data_dir.path().to_path_buf(),
            target: JoinTarget::BundlePath(invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "member".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("join");
        import_join_request(&fx.project_root, &fx.keyit_data_dir, &join);
        let approval = run_approve(ApproveOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            joining_device_id: join.joining_device_id.clone(),
            role: keyit_protocol::records::Role::Member,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_800),
        })
        .expect("approve");
        import_approval(&fx.project_root, member_data_dir.path(), &approval);

        fs::write(
            fx.project_root.join(".env.local"),
            "API_KEY=super-secret\nLOG_LEVEL=debug\n",
        )
        .expect("write dotenv");
        run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_900),
        })
        .expect("owner push");

        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let selected = select_environment(&layout, "development").expect("env");
        let latest = keyit_dir::read_latest_local_revision(&selected.layout)
            .expect("latest")
            .expect("revision");
        assert_eq!(latest.wrapped_deks.len(), 2);
        let member_layout =
            require_project(&fx.project_root, member_data_dir.path()).expect("layout");
        let member_selected = select_environment(&member_layout, "development").expect("env");
        let revision_metadata = fs::read(&latest.revision_path).expect("read revision metadata");
        let encrypted_payload = fs::read(&latest.payload_path).expect("read payload");
        keyit_dir::import_relay_revision_bytes(
            &member_selected.layout,
            &latest.revision.revision_id,
            &revision_metadata,
            &encrypted_payload,
        )
        .expect("import revision");

        fs::remove_file(fx.project_root.join(".env.local")).expect("remove local dotenv");
        run_pull(PullOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: member_data_dir.path().to_path_buf(),
            environment: "development".to_string(),
            relay_dir: None,
            relay_url: None,
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("member pull");

        let materialized =
            fs::read_to_string(fx.project_root.join(".env.local")).expect("read materialized");
        assert!(materialized.contains("API_KEY=super-secret"));
    }

    #[test]
    fn revoked_device_cannot_push_future_revisions() {
        let fx = fixture();
        let member_data_dir = tempfile::tempdir().expect("member data tempdir");

        let invite = run_invite_create(InviteCreateOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("invite");
        let join = run_join(JoinOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: member_data_dir.path().to_path_buf(),
            target: JoinTarget::BundlePath(invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "member".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("join");
        import_join_request(&fx.project_root, &fx.keyit_data_dir, &join);
        let approval = run_approve(ApproveOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            joining_device_id: join.joining_device_id.clone(),
            role: keyit_protocol::records::Role::Member,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_800),
        })
        .expect("approve");
        import_approval(&fx.project_root, member_data_dir.path(), &approval);
        let revocation = run_revoke(RevokeOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            revoked_device_id: join.joining_device_id,
            affected_environments: Vec::new(),
            reason: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_900),
        })
        .expect("revoke");
        import_revocation(&fx.project_root, member_data_dir.path(), &revocation);

        fs::write(fx.project_root.join(".env.local"), "A=one\n").expect("write dotenv");
        let err = run_push(PushOptions {
            project_root: fx.project_root,
            keyit_data_dir: member_data_dir.path().to_path_buf(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_879_000),
        })
        .expect_err("revoked member push should fail");

        assert!(err.to_string().contains("not an active project member"));
    }

    #[test]
    fn owner_push_clears_rotation_required_after_revocation() {
        let fx = fixture();
        let member_data_dir = tempfile::tempdir().expect("member data tempdir");

        let invite = run_invite_create(InviteCreateOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environments: vec!["development".to_string()],
            expires_at: Timestamp::from_unix_seconds(1_755_900_000),
            max_uses: 1,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("invite");
        let join = run_join(JoinOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: member_data_dir.path().to_path_buf(),
            target: JoinTarget::BundlePath(invite.bundle_path.clone()),
            requested_environments: Vec::new(),
            device_label: "member".to_string(),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("join");
        import_join_request(&fx.project_root, &fx.keyit_data_dir, &join);
        run_approve(ApproveOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            joining_device_id: join.joining_device_id.clone(),
            role: keyit_protocol::records::Role::Member,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_800),
        })
        .expect("approve");

        fs::write(fx.project_root.join(".env.local"), "A=one\n").expect("write dotenv");
        run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_900),
        })
        .expect("initial push");

        let revoked = run_revoke(RevokeOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            revoked_device_id: join.joining_device_id,
            affected_environments: Vec::new(),
            reason: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_879_000),
        })
        .expect("revoke");
        assert_eq!(revoked.rotation_required_paths.len(), 1);
        assert!(revoked.rotation_required_paths[0].exists());

        fs::write(fx.project_root.join(".env.local"), "A=rotated\n").expect("write dotenv");
        let rotated = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: Some("rotate after revocation".to_string()),
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_879_100),
        })
        .expect("rotation push");
        assert!(rotated.rotation_cleared);
        assert!(!revoked.rotation_required_paths[0].exists());

        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let selected = select_environment(&layout, "development").expect("env");
        let latest = keyit_dir::read_latest_local_revision(&selected.layout)
            .expect("latest")
            .expect("revision");
        assert_eq!(latest.wrapped_deks.len(), 1);
    }

    #[test]
    fn push_rejects_stale_local_materialized_revision() {
        let fx = fixture();
        fs::write(fx.project_root.join(".env.local"), "A=one\n").expect("write dotenv");
        let first = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("first push");

        fs::write(fx.project_root.join(".env.local"), "A=two\n").expect("write dotenv");
        run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("second push");

        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let selected = select_environment(&layout, "development").expect("env");
        keyit_dir::write_materialized_revision_id(&selected.layout, &first.revision_id)
            .expect("rewind materialized marker");
        fs::write(fx.project_root.join(".env.local"), "A=three\n").expect("write dotenv");

        let err = run_push(PushOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: None,
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_800),
        })
        .expect_err("stale local base should be rejected");

        assert!(matches!(err, CliError::RevisionConflict { .. }));
    }

    #[test]
    fn push_with_relay_dir_rejects_stale_remote_parent() {
        let fx = fixture();
        let relay_dir = tempfile::tempdir().expect("relay tempdir");
        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let project = load_project(&layout).expect("project");
        let selected = select_environment(&layout, "development").expect("env");
        let remote_revision_id = RevisionId::new_unchecked_for_test(
            "e6g2ph2r4afg3divn6cm6s3k2oz3zz22ie4zqq6r56ljveqlx7va",
        );
        FileRelayStore::new(relay_dir.path())
            .publish_revision_checked(
                &project.project_id,
                &selected.record.environment_id,
                &remote_revision_id,
                None,
                b"remote revision",
                b"remote payload",
            )
            .expect("seed remote latest");

        fs::write(fx.project_root.join(".env.local"), "A=one\n").expect("write dotenv");
        let err = run_push(PushOptions {
            project_root: fx.project_root,
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: None,
            relay_dir: Some(relay_dir.path().to_path_buf()),
            relay_url: None,
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect_err("stale relay parent should be rejected");

        assert!(err.to_string().contains("relay conflict"));
    }

    #[test]
    #[ignore = "requires binding a local loopback port"]
    fn push_and_pull_round_trip_through_http_relay() {
        let fx = fixture();
        let relay_dir = tempfile::tempdir().expect("relay tempdir");
        let addr = free_local_addr();
        let relay_url = format!("http://{addr}");
        let store = FileRelayStore::new(relay_dir.path());
        thread::spawn(move || {
            serve_http_blocking(store, addr).expect("relay server");
        });
        thread::sleep(Duration::from_millis(50));

        fs::write(
            fx.project_root.join(".env.local"),
            "API_KEY=super-secret\nLOG_LEVEL=debug\n",
        )
        .expect("write dotenv");

        let pushed = run_push(PushOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            change_summary: Some("http relay".to_string()),
            relay_dir: None,
            relay_url: Some(relay_url.clone()),
            now: Timestamp::from_unix_seconds(1_755_878_600),
        })
        .expect("http push");
        assert_eq!(pushed.relay_url.as_deref(), Some(relay_url.as_str()));

        let layout = require_project(&fx.project_root, &fx.keyit_data_dir).expect("layout");
        let selected = select_environment(&layout, "development").expect("env");
        fs::remove_dir_all(&selected.layout.revisions_dir).expect("remove local revisions");
        fs::remove_dir_all(&selected.layout.payloads_dir).expect("remove local payloads");
        fs::remove_file(&selected.layout.latest_toml).expect("remove latest pointer");
        fs::remove_file(&selected.layout.materialized_toml).expect("remove materialized pointer");
        fs::remove_file(fx.project_root.join(".env.local")).expect("remove local dotenv");

        let pulled = run_pull(PullOptions {
            project_root: fx.project_root.clone(),
            keyit_data_dir: fx.keyit_data_dir.clone(),
            environment: "development".to_string(),
            relay_dir: None,
            relay_url: Some(relay_url.clone()),
            force: false,
            now: Timestamp::from_unix_seconds(1_755_878_700),
        })
        .expect("http pull");

        assert_eq!(pulled.revision_id, pushed.revision_id);
        assert_eq!(pulled.relay_url.as_deref(), Some(relay_url.as_str()));
        let materialized =
            fs::read_to_string(fx.project_root.join(".env.local")).expect("read materialized");
        assert!(materialized.contains("API_KEY=super-secret"));
        assert!(materialized.contains("LOG_LEVEL=debug"));
    }

    fn free_local_addr() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
        listener.local_addr().expect("local addr")
    }
}
