# BpfJailer Docker Integration for AI Agents

This example demonstrates how to run AI agents with BpfJailer security controls using Docker Compose.

## Architecture

```
+---------------------------+      +---------------------------+
|   bpfjailer (privileged)  |      |  ai-agent (unprivileged)  |
|   - Loads BPF programs    |      |  - Python AI agent        |
|   - Manages security      |----->|  - Auto-enrolled via      |
|   - Host PID namespace    |      |    cgroup path matching   |
+---------------------------+      +---------------------------+
            |                                    |
            v                                    v
+----------------------------------------------------------+
|                  Host Kernel (BPF LSM)                    |
|  - IP/CIDR filtering (blocks private networks)           |
|  - Secrets protection (blocks ~/.ssh, ~/.aws, etc.)      |
|  - Domain filtering (allows only LLM API endpoints)      |
|  - Exec blocking (prevents command injection)            |
+----------------------------------------------------------+
```

## Prerequisites

- Linux kernel 5.15+ with BPF LSM enabled
- Docker 20.10+ with Docker Compose v2
- Root access (for BpfJailer privileged container)

### Check Kernel Support

```bash
# Check if BPF LSM is enabled
cat /sys/kernel/security/lsm | grep bpf

# If not listed, enable it (requires kernel cmdline change):
# GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
```

## Quick Start

1. **Build and start the containers:**

   ```bash
   cd examples/docker
   docker-compose up --build -d
   ```

2. **View AI agent logs:**

   ```bash
   docker-compose logs -f ai-agent
   ```

3. **Test security controls:**

   ```bash
   # Exec into the ai-agent container
   docker-compose exec ai-agent bash

   # Try to access secrets (should be blocked)
   cat /root/.ssh/id_rsa

   # Try to connect to internal network (should be blocked)
   curl http://10.0.0.1/

   # Try to access cloud metadata (should be blocked)
   curl http://169.254.169.254/
   ```

4. **Stop the containers:**

   ```bash
   docker-compose down
   ```

## Security Features

### 1. IP/CIDR Filtering (SSRF Protection)

Blocks connections to private network ranges:
- `10.0.0.0/8` - Private Class A
- `172.16.0.0/12` - Private Class B
- `192.168.0.0/16` - Private Class C
- `169.254.169.254/32` - Cloud metadata endpoint

### 2. Secrets Protection

Blocks access to sensitive file paths:
- `~/.ssh/` - SSH keys
- `~/.aws/` - AWS credentials
- `~/.config/gcloud/` - Google Cloud credentials
- `/etc/shadow` - System passwords
- `/proc/*/environ` - Environment variables

### 3. Domain Filtering

Only allows DNS resolution and connections to approved domains:
- `api.openai.com`
- `api.anthropic.com`
- `generativelanguage.googleapis.com`
- `api.cohere.ai`
- `api.mistral.ai`

### 4. Exec Blocking

Prevents the AI agent from spawning child processes, blocking:
- Command injection attacks
- Reverse shells
- Crypto miners

## Configuration

### Policy File

Edit `policy.json` to customize security rules:

```json
{
  "roles": {
    "ai_agent": {
      "file_paths": [
        {"pattern": "/workspace/", "allow": true},
        {"pattern": "/.ssh/", "allow": false}
      ],
      "ip_rules": [
        {"cidr": "10.0.0.0/8", "allow": false}
      ],
      "domain_rules": [
        {"domain": "api.openai.com", "allow": true}
      ]
    }
  }
}
```

### Cgroup Enrollment

Containers are automatically enrolled based on cgroup path matching:

```json
{
  "cgroup_enrollments": [
    {
      "cgroup_path": "/sys/fs/cgroup/system.slice/docker-*.scope",
      "pod_id": 1000,
      "role": "ai_agent"
    }
  ]
}
```

## Proxy Enforcement (Optional)

To force all egress traffic through an HTTP proxy:

1. Uncomment the `proxy` service in `docker-compose.yml`

2. Update policy.json:
   ```json
   {
     "proxy": {
       "address": "127.0.0.1:8080",
       "required": true
     }
   }
   ```

3. Restart the stack:
   ```bash
   docker-compose up -d
   ```

## Troubleshooting

### BpfJailer fails to start

Check kernel requirements:
```bash
# BPF LSM must be enabled
cat /sys/kernel/security/lsm

# BTF must be available
ls /sys/kernel/btf/vmlinux
```

### Container not enrolled

Check cgroup path matching:
```bash
# Find container cgroup
docker inspect ai-agent --format '{{.HostConfig.CgroupParent}}'

# Check BpfJailer logs
docker-compose logs bpfjailer
```

### Connections blocked unexpectedly

Check IP rules and domain rules in policy.json. Enable debug logging:
```bash
docker-compose run -e RUST_LOG=debug bpfjailer
```

## Security Considerations

- The `bpfjailer` container runs with `--privileged` and host PID namespace
- Keep the policy.json restrictive - use allowlists not blocklists
- Monitor audit logs for policy violations
- Regularly update allowed domain lists

## License

Apache 2.0 - See LICENSE file in repository root.
