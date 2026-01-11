use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").unwrap();

    let bpf_target = if target.contains("aarch64") || target.contains("x86_64") {
        "bpfel-unknown-none"
    } else {
        panic!("Unsupported target architecture: {}", target);
    };

    let out_dir = format!("target/{}/release", bpf_target);
    std::fs::create_dir_all(&out_dir).unwrap();

    let src = "src/main.bpf.c";
    let output = format!("{}/test_task_storage.bpf.o", out_dir);

    println!("cargo:rerun-if-changed={}", src);

    compile_bpf_program(src, &output);
}

fn compile_bpf_program(src: &str, output: &str) {
    let mut cmd = Command::new("clang");
    let mut args = Vec::new();

    // Include libbpf headers
    if PathBuf::from("/usr/include/bpf").exists() {
        args.push("-I".to_string());
        args.push("/usr/include".to_string());
    }

    args.extend_from_slice(&[
        "-O2".to_string(),
        "-g".to_string(),
        "-target".to_string(),
        "bpfel-unknown-none".to_string(),
        "-c".to_string(),
        src.to_string(),
        "-o".to_string(),
        output.to_string(),
        "-Wno-unknown-attributes".to_string(),
        "-Wno-address-of-packed-member".to_string(),
        "-Wno-unused-value".to_string(),
        "-Wno-pointer-sign".to_string(),
    ]);

    cmd.args(&args);

    let output_cmd = cmd.output().expect("Failed to execute clang");
    if !output_cmd.status.success() {
        eprintln!("Clang stderr: {}", String::from_utf8_lossy(&output_cmd.stderr));
        eprintln!("Clang command: clang {}", args.join(" "));
        panic!("Failed to compile BPF program: {}", src);
    }

    println!("✅ Compiled BPF program: {}", output);
}
