use bpfjailer_client::EnrollmentClient;
use bpfjailer_common::{PodId, RoleId};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let socket_path = std::env::var("BPFJAILER_SOCKET")
        .unwrap_or_else(|_| "/run/bpfjailer/enrollment.sock".to_string());

    println!("Connecting to BpfJailer at: {}", socket_path);

    let client = EnrollmentClient::new(&socket_path);

    // Wait a bit for daemon to be ready
    sleep(Duration::from_secs(1)).await;

    let pod_id = PodId(1);
    let role_id = RoleId(1);
    let pid = std::process::id();

    println!("Enrolling process {} into Pod {} with Role {}", pid, pod_id.0, role_id.0);

    match client.enroll(pod_id, role_id).await {
        Ok(()) => {
            println!("✓ Enrollment successful!");
        }
        Err(e) => {
            eprintln!("✗ Enrollment failed: {}", e);
            return Err(e.into());
        }
    }

    println!("Querying enrollment status...");
    match client.query(pid).await {
        Ok((pod_id, role_id)) => {
            println!("✓ Process {} is enrolled:", pid);
            println!("  Pod ID: {}", pod_id.0);
            println!("  Role ID: {}", role_id.0);
        }
        Err(e) => {
            eprintln!("✗ Query failed: {}", e);
            return Err(e.into());
        }
    }

    println!("\nProcess is now enrolled and subject to BpfJailer policies.");
    println!("Try accessing files or network - restrictions should apply.");

    // Keep process alive for testing
    println!("Process will sleep for 60 seconds for testing...");
    sleep(Duration::from_secs(60)).await;

    Ok(())
}
