use anyhow::{Context, Result};
use bpfjailer_common::{PodId, RoleId};
use log::info;
use std::path::Path;
use std::sync::Arc;
use crate::process_tracker::ProcessTracker;
use crate::policy::PolicyManager;

pub struct AlternativeEnrollment {
    process_tracker: Arc<ProcessTracker>,
    policy_manager: Arc<PolicyManager>,
}

impl AlternativeEnrollment {
    pub fn new(
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<PolicyManager>,
    ) -> Self {
        Self {
            process_tracker,
            policy_manager,
        }
    }

    pub async fn enroll_by_executable_path(
        &self,
        executable_path: &str,
        pod_id: PodId,
        role_id: RoleId,
    ) -> Result<()> {
        info!("Enrolling by executable path: {} -> Pod {} Role {}", executable_path, pod_id.0, role_id.0);

        if !Path::new(executable_path).exists() {
            return Err(anyhow::anyhow!("Executable path does not exist: {}", executable_path));
        }

        Ok(())
    }

    pub async fn enroll_by_cgroup_path(
        &self,
        cgroup_path: &str,
        pod_id: PodId,
        role_id: RoleId,
    ) -> Result<()> {
        info!("Enrolling by cgroup path: {} -> Pod {} Role {}", cgroup_path, pod_id.0, role_id.0);

        if !Path::new(cgroup_path).exists() {
            return Err(anyhow::anyhow!("Cgroup path does not exist: {}", cgroup_path));
        }

        Ok(())
    }

    pub async fn enroll_by_xattr(
        &self,
        executable_path: &str,
        pod_id: PodId,
        role_id: RoleId,
    ) -> Result<()> {
        info!("Enrolling by xattr: {} -> Pod {} Role {}", executable_path, pod_id.0, role_id.0);

        let xattr_name = "user.bpfjailer.pod_id";
        let pod_id_bytes = pod_id.0.to_le_bytes();

        xattr::set(executable_path, xattr_name, &pod_id_bytes)
            .context("Failed to set xattr")?;

        Ok(())
    }

    pub async fn check_xattr_enrollment(&self, executable_path: &str) -> Result<Option<(PodId, RoleId)>> {
        let xattr_name = "user.bpfjailer.pod_id";

        if let Some(value) = xattr::get(executable_path, xattr_name)? {
            if value.len() == 8 {
                let pod_id = u64::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                ]);

                let role_xattr = "user.bpfjailer.role_id";
                if let Some(role_value) = xattr::get(executable_path, role_xattr)? {
                    if role_value.len() == 4 {
                        let role_id = u32::from_le_bytes([
                            role_value[0], role_value[1], role_value[2], role_value[3],
                        ]);
                        return Ok(Some((PodId(pod_id), RoleId(role_id))));
                    }
                }
            }
        }

        Ok(None)
    }
}
