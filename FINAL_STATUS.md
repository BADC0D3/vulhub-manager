# VulhubWeb - All Vulnerable Applications Ready! ✅

**ALL 25 applications are fully functional** for penetration testing and security training.

## Remote Access URLs (10.10.30.21)

### 🌐 Web Applications (6)
- **DVWA**: `http://10.10.30.21:8081` - Damn Vulnerable Web Application
- **WebGoat**: `http://10.10.30.21:8080/WebGoat` - OWASP WebGoat  
- **Juice Shop**: `http://10.10.30.21:8082` - OWASP Juice Shop
- **RailsGoat**: `http://10.10.30.21:8083` - OWASP RailsGoat
- **WordPress**: `http://10.10.30.21:8087` - Vulnerable WordPress
- **NodeGoat**: `http://10.10.30.21:9090` - OWASP NodeGoat

### 🔌 API Applications (5)
- **VAmPI**: `http://10.10.30.21:8088` - Vulnerable API
- **crAPI**: `http://10.10.30.21:8888` - Completely Ridiculous API
- **DVGA**: `http://10.10.30.21:8089` - Damn Vulnerable GraphQL
- **DVRestaurant**: `http://10.10.30.21:8083` - Restaurant API (JWT, IDOR, SQLi)
- **GraphQL Security**: `http://10.10.30.21:5013` - GraphQL vulnerabilities

### 🛠️ Framework Applications (4)
- **Laravel**: `http://10.10.30.21:8094` - Laravel vulnerabilities
- **Django**: `http://10.10.30.21:8095` - Django vulnerabilities  
- **Spring**: `http://10.10.30.21:8096` - Spring vulnerabilities
- **Express**: `http://10.10.30.21:8097` - Express.js vulnerabilities

### 🚨 Real-world Vulnerabilities (4)
- **Log4Shell**: `http://10.10.30.21:8084` - CVE-2021-44228
- **Spring4Shell**: `http://10.10.30.21:8085` - Spring Framework RCE
- **Struts2**: `http://10.10.30.21:8086` - Apache Struts vulnerabilities
- **GitLab**: `http://10.10.30.21:8092` - GitLab CE 13.12.0

### 🔬 Advanced Labs (3)
- **SSRF Lab**: `http://10.10.30.21:8090` - Server-Side Request Forgery
- **XXE Lab**: `http://10.10.30.21:8091` - XML External Entity injection
- **Deserialization Lab**: 
  - Java: `http://10.10.30.21:8092`
  - Python: `http://10.10.30.21:5000`
  - PHP: `http://10.10.30.21:8095`

### 📦 Container Security (3)
- **Docker Escape**: `http://10.10.30.21:8093` - Container escape techniques
- **Kubernetes Goat**: `http://10.10.30.21:1234` - K8s security
- **Serverless Goat**: `http://10.10.30.21:4566` - Serverless vulnerabilities

## Quick Start

### Starting Any Application:
```bash
cd vulnerabilities/<category>/<app-name>
docker compose up -d
```

### Applications That Build on First Run:
These 4 apps build from source (2-5 minutes first time only):
```bash
# Add --build flag on first run
docker compose up -d --build
```
- DVRestaurant
- XXE Lab
- Deserialization Lab
- Docker Escape

### Stopping Applications:
```bash
docker compose down
```

## Example Usage

```bash
# Start DVWA
cd vulnerabilities/web/dvwa
docker compose up -d
# Access at http://10.10.30.21:8081

# Start Deserialization Lab (builds on first run)
cd vulnerabilities/advanced/deserialization-lab
docker compose up -d --build
# Java: http://10.10.30.21:8092
# Python: http://10.10.30.21:5000
# PHP: http://10.10.30.21:8095
```

## Useful Commands

```bash
# Pull all pre-built images (if on new machine)
./pull-all-images.sh

# View running containers
docker ps

# View logs
docker compose logs -f

# Clean up all containers and networks
docker system prune -a
```

## ⚠️ Security Warning

These are **intentionally vulnerable applications**:
- Never expose to the internet
- Use only in isolated lab environments
- Some apps are resource-intensive (GitLab, crAPI) 