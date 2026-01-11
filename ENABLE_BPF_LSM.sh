#!/bin/bash
# Script to enable BPF LSM at boot

set -e

echo "This script will enable BPF LSM by adding it to the kernel boot parameters."
echo "You will need to reboot for changes to take effect."
echo ""

GRUB_FILE="/etc/default/grub"
BACKUP_FILE="${GRUB_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    exit 1
fi

# Backup grub file
echo "Backing up ${GRUB_FILE} to ${BACKUP_FILE}..."
cp "$GRUB_FILE" "$BACKUP_FILE"

# Check current LSM setting
CURRENT_LSM=$(grep "GRUB_CMDLINE_LINUX" "$GRUB_FILE" | grep -oP 'lsm=[^"]*' || echo "")

if [ -z "$CURRENT_LSM" ]; then
    echo "No LSM parameter found. Adding BPF LSM..."
    sed -i 's/^GRUB_CMDLINE_LINUX="/&lsm=lockdown,capability,landlock,yama,apparmor,bpf /' "$GRUB_FILE"
elif echo "$CURRENT_LSM" | grep -q "bpf"; then
    echo "BPF LSM already in boot parameters."
else
    echo "Adding 'bpf' to existing LSM list..."
    sed -i "s/lsm=[^\" ]*/&,bpf/" "$GRUB_FILE"
fi

echo ""
echo "Updated GRUB configuration:"
grep "GRUB_CMDLINE_LINUX" "$GRUB_FILE"

echo ""
echo "To apply changes:"
echo "  1. Run: sudo update-grub"
echo "  2. Reboot: sudo reboot"
echo ""
echo "After reboot, verify with: cat /sys/kernel/security/lsm | grep bpf"
