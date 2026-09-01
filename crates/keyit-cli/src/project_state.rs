//! Project locator resolution and relay-backed local cache bootstrap.

use std::path::{Path, PathBuf};

use keyit_protocol::ids::EnvironmentId;
use keyit_protocol::records::{EnvironmentGenesis, ProjectGenesis};
use keyit_relay::AccessRecordKind;

use crate::error::CliError;
use crate::keyit_dir::{self, KeyitDirLayout, ProjectLocatorEnvironmentToml, ProjectLocatorToml};
use crate::relay_client::RelayHttpClient;

pub fn require_project_layout(
    project_root: &Path,
    keyit_data_dir: &Path,
) -> Result<KeyitDirLayout, CliError> {
    let layout = keyit_dir::resolve_project_layout(project_root, keyit_data_dir)?;
    if layout.project_toml.exists() {
        return Ok(layout);
    }

    let locator_path = keyit_dir::project_locator_file(project_root);
    let locator = keyit_dir::read_project_locator(project_root)?;
    bootstrap_from_relay(project_root, keyit_data_dir, &locator_path, &locator)
}

fn bootstrap_from_relay(
    project_root: &Path,
    keyit_data_dir: &Path,
    locator_path: &Path,
    locator: &ProjectLocatorToml,
) -> Result<KeyitDirLayout, CliError> {
    let project_id = locator.project_id(locator_path)?;
    let client = RelayHttpClient::new(&locator.relay_url)?;
    let Some(project_bytes) = client.fetch_access_record(
        &project_id,
        AccessRecordKind::ProjectGenesis,
        project_id.as_str(),
    )?
    else {
        return Err(CliError::RelayHttp {
            reason: format!("relay has no project genesis for {project_id}"),
        });
    };
    let project = decode_project_genesis(locator_path, &project_bytes)?;
    if project.project_id != project_id {
        return Err(CliError::MalformedRecordFile {
            path: locator_path.to_path_buf(),
            reason: "locator project ID does not match relay project genesis".to_string(),
        });
    }
    project.verify_signature()?;
    let expected_hash = locator.genesis_hash(locator_path)?;
    let actual_hash = keyit_dir::project_genesis_hash(&project);
    if actual_hash != expected_hash {
        return Err(CliError::MalformedRecordFile {
            path: locator_path.to_path_buf(),
            reason: "relay project genesis does not match locator genesis hash".to_string(),
        });
    }

    let environments = fetch_locator_environments(&client, locator_path, locator, &project)?;
    let state_root = keyit_dir::project_state_root(keyit_data_dir, &project.project_id);
    let layout = keyit_dir::write_project_bootstrap_dir(&state_root, &project, &[])?;
    for (locator_env, environment) in locator.environments.iter().zip(environments) {
        keyit_dir::write_environment_dir_with_local_path(
            &layout,
            &environment,
            &PathBuf::from(&locator_env.local_path),
        )?;
    }
    import_membership_genesis_if_available(&client, &layout, &project)?;
    keyit_dir::write_project_locator(project_root, &project)?;
    for locator_env in &locator.environments {
        let environment =
            keyit_dir::read_environment_genesis(&keyit_dir::EnvironmentDirLayout::under(
                &layout,
                &EnvironmentId::parse(&locator_env.environment_id)?,
            ))?;
        keyit_dir::upsert_locator_environment(
            project_root,
            &environment,
            &PathBuf::from(&locator_env.local_path),
        )?;
    }
    Ok(layout)
}

fn fetch_locator_environments(
    client: &RelayHttpClient,
    locator_path: &Path,
    locator: &ProjectLocatorToml,
    project: &ProjectGenesis,
) -> Result<Vec<EnvironmentGenesis>, CliError> {
    let mut environments = Vec::with_capacity(locator.environments.len());
    let project_hash = keyit_dir::project_genesis_hash(project);
    for locator_env in &locator.environments {
        let environment_id = EnvironmentId::parse(&locator_env.environment_id)?;
        let Some(bytes) = client.fetch_access_record(
            &project.project_id,
            AccessRecordKind::Environment,
            environment_id.as_str(),
        )?
        else {
            return Err(CliError::RelayHttp {
                reason: format!("relay has no environment genesis for {environment_id}"),
            });
        };
        let environment = decode_environment_genesis(locator_path, &bytes)?;
        validate_environment(
            locator_path,
            project,
            &project_hash,
            locator_env,
            &environment,
        )?;
        environments.push(environment);
    }
    Ok(environments)
}

fn import_membership_genesis_if_available(
    client: &RelayHttpClient,
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
) -> Result<(), CliError> {
    let Some(bytes) = client.fetch_access_record(
        &project.project_id,
        AccessRecordKind::MembershipGenesis,
        "genesis",
    )?
    else {
        return Ok(());
    };
    keyit_dir::import_membership_genesis_bytes(layout, &bytes)
}

fn validate_environment(
    path: &Path,
    project: &ProjectGenesis,
    project_hash: &keyit_protocol::primitives::HashBytes,
    locator_env: &ProjectLocatorEnvironmentToml,
    environment: &EnvironmentGenesis,
) -> Result<(), CliError> {
    if environment.project_id != project.project_id
        || environment.environment_id.as_str() != locator_env.environment_id
        || environment.environment_label != locator_env.label
        || &environment.parent_project_genesis_hash != project_hash
    {
        return Err(CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: format!(
                "relay environment {} does not match locator",
                locator_env.environment_id
            ),
        });
    }
    environment.verify_signature(&project.creator_device_public_identity)?;
    Ok(())
}

fn decode_project_genesis(path: &Path, bytes: &[u8]) -> Result<ProjectGenesis, CliError> {
    let content = std::str::from_utf8(bytes).map_err(|err| CliError::MalformedRecordFile {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    let toml: keyit_dir::ProjectGenesisToml =
        toml::from_str(content).map_err(|err| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    toml.to_record(path)
}

fn decode_environment_genesis(path: &Path, bytes: &[u8]) -> Result<EnvironmentGenesis, CliError> {
    let content = std::str::from_utf8(bytes).map_err(|err| CliError::MalformedRecordFile {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    let toml: keyit_dir::EnvironmentGenesisToml =
        toml::from_str(content).map_err(|err| CliError::MalformedRecordFile {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    toml.to_record(path)
}
