use anyhow::{Context, Result};
use bpfjailer_client::{EnrollmentRequest, EnrollmentResponse};
use bpfjailer_common::RoleId;
use log::{debug, error, info};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener as AsyncUnixListener, UnixStream as AsyncUnixStream};
use tokio::sync::RwLock;
use crate::process_tracker::ProcessTracker;
use crate::policy::PolicyManager;

const SOCKET_PATH: &str = "/run/bpfjailer/enrollment.sock";

pub struct EnrollmentServer {
    process_tracker: Arc<ProcessTracker>,
    policy_manager: Arc<RwLock<PolicyManager>>,
}

impl EnrollmentServer {
    pub fn new(
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<RwLock<PolicyManager>>,
    ) -> Self {
        Self {
            process_tracker,
            policy_manager,
        }
    }

    pub async fn run(&self) -> Result<()> {
        if Path::new(SOCKET_PATH).exists() {
            std::fs::remove_file(SOCKET_PATH)?;
        }

        if let Some(parent) = Path::new(SOCKET_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = AsyncUnixListener::bind(SOCKET_PATH)
            .context("Failed to bind enrollment socket")?;

        info!("Enrollment server listening on {}", SOCKET_PATH);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let process_tracker = self.process_tracker.clone();
                    let policy_manager = self.policy_manager.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(stream, process_tracker, policy_manager).await {
                            error!("Error handling enrollment client: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }

    async fn handle_client(
        mut stream: AsyncUnixStream,
        process_tracker: Arc<ProcessTracker>,
        policy_manager: Arc<RwLock<PolicyManager>>,
    ) -> Result<()> {
        let peer_creds = stream.peer_cred()
            .context("Failed to get peer credentials")?;

        let pid = peer_creds.pid().unwrap_or(0);
        debug!("Handling enrollment request from PID {}", pid);

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let request: EnrollmentRequest = serde_json::from_str(&line)
            .context("Failed to parse enrollment request")?;

        let response = match request {
            EnrollmentRequest::Enroll { pod_id, role_id } => {
                debug!("Enrollment request: PID {} -> Pod {} Role {}", pid, pod_id.0, role_id.0);

                let pm = policy_manager.read().await;
                match pm.get_role(role_id) {
                    None => EnrollmentResponse::Error(format!("Unknown role ID: {}", role_id.0)),
                    Some(role) => {
                        let role = role.clone();
                        drop(pm); // Release the lock

                        // Set the role policy flags in BPF
                        if let Err(e) = process_tracker.set_role_policy(role_id, &role.flags) {
                            EnrollmentResponse::Error(format!("Failed to set role policy: {}", e))
                        } else {
                            // Apply network rules from the role
                            if let Err(e) = process_tracker.apply_network_rules(role_id, &role.network_rules) {
                                error!("Failed to apply network rules: {}", e);
                            }

                            match process_tracker.enroll_process(pid as u32, pod_id, role_id) {
                                Ok(()) => EnrollmentResponse::Success,
                                Err(e) => EnrollmentResponse::Error(format!("Enrollment failed: {}", e)),
                            }
                        }
                    }
                }
            }
            EnrollmentRequest::Query { pid: query_pid } => {
                debug!("Query request for PID {}", query_pid);
                match process_tracker.get_process_info(query_pid) {
                    Ok(Some((pod_id, role_id))) => {
                        EnrollmentResponse::ProcessInfo { pod_id, role_id }
                    }
                    Ok(None) => {
                        EnrollmentResponse::Error("Process not found or not enrolled".to_string())
                    }
                    Err(e) => {
                        EnrollmentResponse::Error(format!("Query failed: {}", e))
                    }
                }
            }
        };

        let response_json = serde_json::to_string(&response)?;
        stream.write_all(response_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        Ok(())
    }
}
