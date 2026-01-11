mod bpf_loader;
mod process_tracker;
mod policy;
mod enrollment;
mod enrollment_alternatives;
mod path_matcher;
mod signed_binary;

use anyhow::Result;
use log::{error, info, warn};
use std::env;
use std::path::Path;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;

const DEFAULT_POLICY_PATH: &str = "/etc/bpfjailer/policy.json";
const LOCAL_POLICY_PATH: &str = "config/policy.json";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("BpfJailer daemon starting...");

    let bpf = match bpf_loader::BpfJailerBpf::load() {
        Ok(b) => Arc::new(b),
        Err(e) => {
            error!("Failed to load eBPF programs: {}", e);
            return Err(e);
        }
    };

    // Initialize policy manager with default roles
    let mut policy_manager = policy::PolicyManager::new()?;

    // Load policy from file if available
    let policy_path = env::var("BPFJAILER_POLICY")
        .ok()
        .or_else(|| {
            if Path::new(DEFAULT_POLICY_PATH).exists() {
                Some(DEFAULT_POLICY_PATH.to_string())
            } else if Path::new(LOCAL_POLICY_PATH).exists() {
                Some(LOCAL_POLICY_PATH.to_string())
            } else {
                None
            }
        });

    if let Some(path) = policy_path {
        match policy_manager.load_from_file(&path).await {
            Ok(()) => info!("Loaded policy from {}", path),
            Err(e) => warn!("Failed to load policy from {}: {}", path, e),
        }
    } else {
        info!("No policy file found, using default roles");
    }

    let policy_manager = Arc::new(RwLock::new(policy_manager));
    let process_tracker = Arc::new(process_tracker::ProcessTracker::new(bpf.clone())?);
    let _path_matcher = Arc::new(path_matcher::PathMatcher::new(bpf.clone())?);
    let _signed_binary = Arc::new(signed_binary::SignedBinaryManager::new(bpf.clone())?);

    let enrollment_server = enrollment::EnrollmentServer::new(
        process_tracker.clone(),
        policy_manager.clone(),
    );

    let server_handle = tokio::spawn(async move {
        if let Err(e) = enrollment_server.run().await {
            error!("Enrollment server error: {}", e);
        }
    });

    info!("BpfJailer daemon started");
    info!("Press Ctrl+C to shutdown");

    signal::ctrl_c().await?;
    info!("Shutting down...");

    server_handle.abort();

    info!("BpfJailer daemon stopped");
    Ok(())
}
