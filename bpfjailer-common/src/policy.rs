use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::{RoleId, PolicyFlags};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPattern {
    pub pattern: String,
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub protocol: String,
    pub address: Option<String>,
    /// Single port (e.g., 80)
    pub port: Option<u16>,
    /// Port range start (e.g., 8000). Use with port_end.
    pub port_start: Option<u16>,
    /// Port range end (e.g., 8100). Use with port_start.
    pub port_end: Option<u16>,
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRule {
    pub binary_path: String,
    pub args_pattern: Option<String>,
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub flags: PolicyFlags,
    pub file_paths: Vec<PathPattern>,
    pub network_rules: Vec<NetworkRule>,
    pub execution_rules: Vec<ExecutionRule>,
    pub require_signed_binary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pod {
    pub id: u64,
    pub role_id: RoleId,
    pub stack_depth: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub roles: HashMap<String, Role>,
    pub pods: Vec<Pod>,
}

impl PolicyConfig {
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            pods: Vec::new(),
        }
    }

    pub fn get_role(&self, name: &str) -> Option<&Role> {
        self.roles.get(name)
    }

    pub fn get_role_by_id(&self, id: RoleId) -> Option<&Role> {
        self.roles.values().find(|r| r.id == id)
    }
}
