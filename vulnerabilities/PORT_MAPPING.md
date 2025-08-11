# Port Mapping for Vulnerable Applications

This document lists all port mappings to avoid conflicts with the VulhubWeb manager (port 3000).

## Port Assignments

| Application | Host Port | Container Port | Notes |
|-------------|-----------|----------------|-------|
| **VulhubWeb Manager** | 3000 | 3000 | Main management interface |
| **Juice Shop** | 3001 | 3000 | OWASP modern web app |
| **Rails Goat** | 3002 | 3000 | Ruby on Rails vulnerabilities |
| **Express Vulnerable** | 3003 | 3000 | Node.js/Express vulnerabilities |
| **NodeGoat** | 4000 | 4000 | Node.js OWASP app |
| **DVGA** | 5013 | 5013 | GraphQL vulnerabilities |
| **VAmPI** | 5000 | 5000 | REST API vulnerabilities |
| **GraphQL Security** | 5000 | 5000 | ⚠️ Conflicts with VAmPI |
| **Python Deser** | 5000 | 5000 | ⚠️ Conflicts with VAmPI |
| **DVWA** | 8081 | 80 | PHP web vulnerabilities |
| **WebGoat** | 8082, 9090 | 8080, 9090 | Java security training |
| **DVRestaurant** | 8083 | 8080 | Restaurant API |
| **Spring Vulnerable** | 8084 | 8080 | Spring Boot vulnerabilities |
| **Spring4Shell** | 8085 | 8080 | CVE-2022-22965 |
| **Struts2** | 8086 | 8080 | Apache Struts vulnerabilities |
| **WordPress** | 8087 | 80 | CMS vulnerabilities |
| **GitLab CE** | 8088, 8444, 2223 | 80, 443, 22 | DevOps platform vulnerabilities |
| **Log4Shell** | 8089, 1389, 8888 | 8080, 1389, 8888 | CVE-2021-44228 |
| **XXE Lab** | 8090 | 8080 | XML vulnerabilities |
| **SSRF Lab** | 8091 | 8080 | Server-side request forgery |
| **Deserialization (Java)** | 8092 | 8080 | Java deserialization |
| **Deserialization (PHP)** | 8081 | 80 | ⚠️ Conflicts with DVWA |
| **Django Vulnerable** | 8093 | 8000 | Django vulnerabilities |
| **Laravel Vulnerable** | 8094 | 80 | Laravel vulnerabilities |
| **crAPI** | 8888, 8025 | 80, 8025 | API vulnerabilities |
| **Kubernetes Goat** | 1234, 1235 | 1234, 3000 | Container security |
| **Docker Escape** | 2222 | 22 | SSH for container escape |
| **Serverless Goat** | 4566, 4571 | 4566, 4571 | LocalStack ports |

## Remaining Conflicts

The following applications still have port conflicts that need manual resolution:

1. **Port 5000**: VAmPI, GraphQL Security, and Python Deserialization all use port 5000
2. **Port 8081**: DVWA and PHP Deserialization both map to port 8081

## Recommendations

1. **Before starting an application**, check if its ports are free:
   ```bash
   netstat -tlnp | grep <port>
   ```

2. **To change a port**, edit the `docker-compose.yml` file:
   ```yaml
   ports:
     - "NEW_PORT:CONTAINER_PORT"
   ```

3. **For applications with conflicts**, consider:
   - Running them one at a time
   - Modifying their ports before use
   - Using a reverse proxy to manage multiple applications

## Quick Port Check Script

```bash
#!/bin/bash
# Check which ports are in use
echo "Checking common ports..."
for port in 3000 3001 3002 3003 4000 5000 5013 8080-8094 9090; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "Port $port is in use"
    fi
done
``` 