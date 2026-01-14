# QEMU/Libvirt Test Environment for BpfJailer Bootstrap

Tests the daemonless bootstrap mode in a clean Ubuntu 24.04 VM using libvirt.

## Prerequisites

```bash
sudo apt-get install -y libvirt-daemon-system libvirt-clients virtinst \
    qemu-system-x86 qemu-utils cloud-image-utils wget sshpass
sudo systemctl start libvirtd
sudo usermod -aG libvirt $USER  # Re-login after this
```

## Quick Start

```bash
# 1. Set up VM
./setup_vm.sh

# 2. Build bootstrap
cd ../.. && cargo build -p bpfjailer-bootstrap --release && cd tests/qemu

# 3. Run tests
./run_test.sh          # Interactive bootstrap test
./run_test_headless.sh # Automated bootstrap test
./test_enrollment.sh   # Alternative enrollment test with nginx
```

## VM Management

```bash
virsh list --all              # List VMs
virsh start bpfjailer-test    # Start VM
virsh console bpfjailer-test  # Console access
virsh destroy bpfjailer-test  # Stop VM
virsh undefine bpfjailer-test # Remove VM
```

## BPF LSM

GRUB is auto-configured to enable BPF LSM. After first boot, reboot to apply:

```bash
virsh reboot bpfjailer-test
```

Verify:
```bash
cat /sys/kernel/security/lsm  # Should include: bpf
```

## Files

- `setup_vm.sh` - Downloads image, creates VM
- `run_test.sh` - Interactive bootstrap test
- `run_test_headless.sh` - Automated bootstrap test
- `test_enrollment.sh` - Alternative enrollment test (nginx auto-enrollment)
- `test_restrictions.sh` - Restriction enforcement test (network, exec, file path)
- `vm/share/` - Shared directory for binaries
