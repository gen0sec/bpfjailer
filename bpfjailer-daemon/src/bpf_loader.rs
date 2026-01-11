use anyhow::Result;
use libbpf_rs::{MapFlags, Object, ObjectBuilder};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// Wrapper to make Object Send + Sync
// libbpf-rs Object contains NonNull pointers that aren't Send/Sync by default
// but in practice they're safe to share if we use Mutex for synchronization
pub struct BpfJailerBpf {
    object: Arc<Mutex<Object>>,
}

// Safety: Object is safe to send/share across threads when protected by Mutex
// The underlying libbpf handles are thread-safe for concurrent access
unsafe impl Send for BpfJailerBpf {}
unsafe impl Sync for BpfJailerBpf {}

impl BpfJailerBpf {
    pub fn load() -> Result<Self> {
        log::info!("Loading BpfJailer eBPF programs with libbpf-rs...");

        // Try multiple possible paths for the compiled BPF object
        let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(PathBuf::from)
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let possible_paths = [
            workspace_root.join("target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            workspace_root.join("target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
            workspace_root.join("bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            workspace_root.join("bpfjailer-bpf/target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
            PathBuf::from("target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            PathBuf::from("target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
            PathBuf::from("bpfjailer-bpf/target/bpfel-unknown-none/release/bpfjailer.bpf.o"),
            PathBuf::from("bpfjailer-bpf/target/bpfel-unknown-none/debug/bpfjailer.bpf.o"),
        ];

        let obj_path = possible_paths.iter()
            .find(|p| p.exists())
            .ok_or_else(|| anyhow::anyhow!("bpfjailer.bpf.o not found in any expected location"))?;

        log::info!("Loading BPF object from: {:?}", obj_path);

        // Load BPF object using libbpf-rs
        // open_file returns OpenObject, then load() returns Object
        let mut object_builder = ObjectBuilder::default();
        let open_object = object_builder.open_file(obj_path)?;

        // Try to load - this will create maps including task_storage
        let mut object = match open_object.load() {
            Ok(obj) => obj,
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("task_storage") || err_str.contains("EINVAL") {
                    log::error!("Failed to load BPF object - task_storage map creation failed");
                    log::error!("This may be a kernel issue. Error: {}", err_str);
                    log::error!("Kernel version: {}", std::process::Command::new("uname")
                        .arg("-r")
                        .output()
                        .ok()
                        .and_then(|o| String::from_utf8(o.stdout).ok())
                        .unwrap_or_else(|| "unknown".to_string()));
                    log::error!("BPF LSM status: {}", std::fs::read_to_string("/sys/kernel/security/lsm")
                        .unwrap_or_else(|_| "unknown".to_string()));
                }
                return Err(anyhow::Error::from(e));
            }
        };

        log::info!("BPF object loaded successfully");

        // Check that maps exist
        if object.map("pod_to_role").is_none() {
            return Err(anyhow::anyhow!("pod_to_role map not found"));
        }
        if object.map("role_flags").is_none() {
            return Err(anyhow::anyhow!("role_flags map not found"));
        }
        if object.map("pending_enrollments").is_none() {
            return Err(anyhow::anyhow!("pending_enrollments map not found"));
        }
        log::info!("✓ pending_enrollments map available for enrollment");

        if object.map("network_rules").is_none() {
            return Err(anyhow::anyhow!("network_rules map not found"));
        }
        log::info!("✓ network_rules map available for port/protocol filtering");

        // Note: task_storage map is automatically handled by libbpf-rs
        // It's created but we don't need to access it from userspace
        if object.map("task_storage").is_some() {
            log::info!("✓ task_storage map created successfully");
        }

        // Load and attach LSM programs
        log::info!("Loading and attaching LSM programs...");
        let program_names = [
            "task_alloc",
            "file_open",
            "socket_bind",
            "socket_connect",
            "bprm_check_security",
        ];

        // LSM programs must be explicitly attached
        for name in &program_names {
            match object.prog_mut(name) {
                Some(prog) => {
                    match prog.attach() {
                        Ok(link) => {
                            // Keep the link alive by leaking it (daemon keeps running)
                            // In production, you'd store these in a Vec
                            std::mem::forget(link);
                            log::info!("✓ Program {} attached", name);
                        }
                        Err(e) => {
                            log::error!("Failed to attach program {}: {}", name, e);
                            return Err(anyhow::anyhow!("Failed to attach {}: {}", name, e));
                        }
                    }
                }
                None => {
                    log::warn!("Program {} not found in eBPF object", name);
                }
            }
        }

        log::info!("All eBPF programs loaded and attached successfully");

        Ok(Self {
            object: Arc::new(Mutex::new(object)),
        })
    }

    pub fn update_pod_role(&self, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("pod_to_role")
            .ok_or_else(|| anyhow::anyhow!("pod_to_role map not found"))?;
        let key = pod_id.to_ne_bytes();
        let value = role_id.to_ne_bytes();
        map.update(&key, &value, MapFlags::empty())?;
        Ok(())
    }

    pub fn update_role_flags(&self, role_id: u32, flags: u8) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("role_flags")
            .ok_or_else(|| anyhow::anyhow!("role_flags map not found"))?;
        let key = role_id.to_ne_bytes();
        let value = [flags];
        map.update(&key, &value, MapFlags::empty())?;
        Ok(())
    }

    /// Enroll a process by PID. The BPF code will migrate this to task_storage
    /// on the next syscall (file_open, exec, etc.)
    pub fn enroll_pending_process(&self, pid: u32, pod_id: u64, role_id: u32) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("pending_enrollments")
            .ok_or_else(|| anyhow::anyhow!("pending_enrollments map not found"))?;

        let key = pid.to_ne_bytes();

        // struct process_info { u64 pod_id; u32 role_id; u8 stack_depth; u8 flags; }
        // Layout: 8 bytes + 4 bytes + 1 byte + 1 byte = 14 bytes (padded to 16)
        let mut value = [0u8; 16];
        value[0..8].copy_from_slice(&pod_id.to_ne_bytes());
        value[8..12].copy_from_slice(&role_id.to_ne_bytes());
        value[12] = 0; // stack_depth
        value[13] = 0; // flags

        map.update(&key, &value, MapFlags::empty())?;
        log::debug!("Added pending enrollment for PID {} -> pod_id={}, role_id={}", pid, pod_id, role_id);
        Ok(())
    }

    /// Add a network rule for a role
    /// protocol: 6 = TCP, 17 = UDP
    /// direction: 0 = bind, 1 = connect
    /// allowed: true = allow, false = deny
    pub fn add_network_rule(&self, role_id: u32, port: u16, protocol: u8, direction: u8, allowed: bool) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("network_rules")
            .ok_or_else(|| anyhow::anyhow!("network_rules map not found"))?;

        // struct net_rule_key { u32 role_id; u16 port; u8 protocol; u8 direction; }
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[4..6].copy_from_slice(&port.to_ne_bytes());
        key[6] = protocol;
        key[7] = direction;

        let value = [if allowed { 1u8 } else { 0u8 }];
        map.update(&key, &value, MapFlags::empty())?;

        let proto_name = match protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "UNKNOWN",
        };
        let dir_name = if direction == 0 { "bind" } else { "connect" };
        let action = if allowed { "ALLOW" } else { "DENY" };
        log::info!("Network rule: role={} {}:{} {} -> {}", role_id, proto_name, port, dir_name, action);

        Ok(())
    }

    /// Remove a network rule
    #[allow(dead_code)]
    pub fn remove_network_rule(&self, role_id: u32, port: u16, protocol: u8, direction: u8) -> Result<()> {
        let object = self.object.lock().unwrap();
        let map = object.map("network_rules")
            .ok_or_else(|| anyhow::anyhow!("network_rules map not found"))?;

        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&role_id.to_ne_bytes());
        key[4..6].copy_from_slice(&port.to_ne_bytes());
        key[6] = protocol;
        key[7] = direction;

        map.delete(&key)?;
        Ok(())
    }
}
