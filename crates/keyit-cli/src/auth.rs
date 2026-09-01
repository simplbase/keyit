//! Local authorization reconstruction from signed access records.

use std::collections::BTreeMap;
use std::path::Path;

use keyit_protocol::ids::{DeviceId, EnvironmentId};
use keyit_protocol::primitives::{PublicKeyBytes, SigningPublicKeyBytes};
use keyit_protocol::records::{JoinRequest, ProjectGenesis, Role};

use crate::error::CliError;
use crate::keyit_dir::{self, KeyitDirLayout};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedDevice {
    pub device_id: DeviceId,
    pub signing_public_key: SigningPublicKeyBytes,
    pub encryption_public_key: Option<PublicKeyBytes>,
    pub role: Role,
    pub environment_ids: Vec<EnvironmentId>,
}

impl AuthorizedDevice {
    pub fn can_manage_access(&self) -> bool {
        matches!(self.role, Role::Owner | Role::Admin)
    }

    pub fn can_access_environment(&self, environment_id: &EnvironmentId) -> bool {
        self.role == Role::Owner || self.environment_ids.contains(environment_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessState {
    devices: BTreeMap<String, AuthorizedDevice>,
    join_requests: BTreeMap<String, JoinRequest>,
}

impl AccessState {
    pub fn device(&self, device_id: &DeviceId) -> Option<&AuthorizedDevice> {
        self.devices.get(device_id.as_str())
    }

    pub fn join_request(&self, device_id: &DeviceId) -> Option<&JoinRequest> {
        self.join_requests.get(device_id.as_str())
    }

    pub fn active_devices(&self) -> impl Iterator<Item = &AuthorizedDevice> {
        self.devices.values()
    }

    pub fn require_can_manage_access(
        &self,
        device_id: &DeviceId,
    ) -> Result<&AuthorizedDevice, CliError> {
        let device = self
            .device(device_id)
            .ok_or_else(|| CliError::NotProjectOwner {
                reason: format!("device {device_id} is not an active project member"),
            })?;
        if !device.can_manage_access() {
            return Err(CliError::NotProjectOwner {
                reason: format!("device {device_id} is not an owner or admin"),
            });
        }
        Ok(device)
    }

    pub fn require_environment_access(
        &self,
        device_id: &DeviceId,
        environment_id: &EnvironmentId,
    ) -> Result<&AuthorizedDevice, CliError> {
        let device = self
            .device(device_id)
            .ok_or_else(|| CliError::NotProjectOwner {
                reason: format!("device {device_id} is not an active project member"),
            })?;
        if !device.can_access_environment(environment_id) {
            return Err(CliError::NotProjectOwner {
                reason: format!(
                    "device {device_id} is not approved for environment {environment_id}"
                ),
            });
        }
        Ok(device)
    }
}

pub fn load_access_state(
    layout: &KeyitDirLayout,
    project: &ProjectGenesis,
) -> Result<AccessState, CliError> {
    let mut join_requests = BTreeMap::new();
    for request in keyit_dir::read_join_request_records(layout)? {
        request.verify_signature()?;
        if request.project_id != project.project_id {
            return Err(CliError::MalformedRecordFile {
                path: layout.join_request_file(&request.joining_device_id),
                reason: "join request belongs to a different project".to_string(),
            });
        }
        join_requests.insert(request.joining_device_id.as_str().to_string(), request);
    }

    let mut devices = BTreeMap::new();
    devices.insert(
        project.creator_device_id.as_str().to_string(),
        AuthorizedDevice {
            device_id: project.creator_device_id.clone(),
            signing_public_key: project.creator_device_public_identity,
            encryption_public_key: None,
            role: Role::Owner,
            environment_ids: Vec::new(),
        },
    );

    let mut approvals = keyit_dir::read_approval_records(layout)?;
    approvals.sort_by_key(|approval| approval.created_at.unix_seconds());
    for approval in approvals {
        if approval.project_id != project.project_id {
            return Err(CliError::MalformedRecordFile {
                path: layout.approval_file(&approval.approved_device_id),
                reason: "approval belongs to a different project".to_string(),
            });
        }
        let signer = devices
            .get(approval.approved_by_device_id.as_str())
            .ok_or_else(|| CliError::NotProjectOwner {
                reason: format!(
                    "approval signer {} is not an active member",
                    approval.approved_by_device_id
                ),
            })?;
        if !signer.can_manage_access() {
            return Err(CliError::NotProjectOwner {
                reason: format!(
                    "approval signer {} is not an owner or admin",
                    approval.approved_by_device_id
                ),
            });
        }
        approval.verify_signature(&signer.signing_public_key)?;
        let request = join_requests
            .get(approval.approved_device_id.as_str())
            .ok_or_else(|| CliError::MalformedRecordFile {
                path: layout.approval_file(&approval.approved_device_id),
                reason: "approval target has no join request carrying device public keys"
                    .to_string(),
            })?;
        let environment_ids = if signer.role == Role::Owner {
            approval.approved_environment_ids.clone()
        } else {
            ensure_subset(
                &layout.approval_file(&approval.approved_device_id),
                &approval.approved_environment_ids,
                &signer.environment_ids,
            )?;
            approval.approved_environment_ids.clone()
        };
        devices.insert(
            approval.approved_device_id.as_str().to_string(),
            AuthorizedDevice {
                device_id: approval.approved_device_id,
                signing_public_key: request.joining_device_public_identity,
                encryption_public_key: Some(request.joining_device_encryption_public_key),
                role: approval.role,
                environment_ids,
            },
        );
    }

    let mut revocations = keyit_dir::read_revocation_records(layout)?;
    revocations.sort_by_key(|revocation| revocation.created_at.unix_seconds());
    for revocation in revocations {
        if revocation.project_id != project.project_id {
            return Err(CliError::MalformedRecordFile {
                path: layout.revocation_file(&revocation.revoked_device_id),
                reason: "revocation belongs to a different project".to_string(),
            });
        }
        let signer = devices
            .get(revocation.revoked_by_device_id.as_str())
            .ok_or_else(|| CliError::NotProjectOwner {
                reason: format!(
                    "revocation signer {} is not an active member",
                    revocation.revoked_by_device_id
                ),
            })?;
        if !signer.can_manage_access() {
            return Err(CliError::NotProjectOwner {
                reason: format!(
                    "revocation signer {} is not an owner or admin",
                    revocation.revoked_by_device_id
                ),
            });
        }
        revocation.verify_signature(&signer.signing_public_key)?;
        devices.remove(revocation.revoked_device_id.as_str());
    }

    Ok(AccessState {
        devices,
        join_requests,
    })
}

fn ensure_subset(
    path: &Path,
    requested: &[EnvironmentId],
    allowed: &[EnvironmentId],
) -> Result<(), CliError> {
    for environment_id in requested {
        if !allowed.contains(environment_id) {
            return Err(CliError::MalformedRecordFile {
                path: path.to_path_buf(),
                reason: format!(
                    "approval grants environment {environment_id} outside signer scope"
                ),
            });
        }
    }
    Ok(())
}
