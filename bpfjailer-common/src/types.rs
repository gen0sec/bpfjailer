use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PodId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub pod_id: PodId,
    pub role_id: RoleId,
    pub stack_depth: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFlags {
    pub allow_file_access: bool,
    pub allow_network: bool,
    pub allow_exec: bool,
    pub require_signed_binary: bool,
    pub allow_setuid: bool,
    pub allow_ptrace: bool,
}

impl Default for PolicyFlags {
    fn default() -> Self {
        Self {
            allow_file_access: false,
            allow_network: false,
            allow_exec: false,
            require_signed_binary: false,
            allow_setuid: false,
            allow_ptrace: false,
        }
    }
}
