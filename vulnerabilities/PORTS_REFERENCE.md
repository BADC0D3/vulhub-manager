# Port Reference for Vulnerable Applications

## Quick Reference Table

| Application | Category | Host Port | Access URL |
|-------------|----------|-----------|------------|
| **VulhubWeb Manager** | - | 3000 | http://localhost:3000 |
| **Juice Shop** | web | 3001 | http://localhost:3001 |
| **DVWA** | web | 8081 | http://localhost:8081 |
| **WebGoat** | web | 8082, 9090 | http://localhost:8082/WebGoat (WebWolf: http://localhost:9090/WebWolf) |
| **DVNA** (NodeJS) | web | 4000 | http://localhost:4000 |
| **WordPress** | web | 8087 | http://localhost:8087 |
| **crAPI** | api | 8888, 8025 | http://localhost:8888 (MailHog: 8025) |
| **VAmPI** | api | 5000 | http://localhost:5000 |
| **DVRestaurant** | api | 8083 | http://localhost:8083 |
| **DVGA** | api | 5013 | http://localhost:5013 |
| **GraphQL Security** | api | 5001 | http://localhost:5001 |
| **Kubernetes Goat** | container | 1234, 1235 | http://localhost:1234 |
| **Docker Escape** | container | 2222 | SSH on port 2222 |
| **Serverless Goat** | container | 4566, 4571 | http://localhost:4566 |
| **Django Vulnerable** | framework | 8093 | http://localhost:8093 |
| **Rails Goat** | framework | 3002 | http://localhost:3002 |
| **Spring Vulnerable** | framework | 8084 | http://localhost:8084 |
| **Laravel Vulnerable** | framework | 8094 | http://localhost:8094 |
| **Express Vulnerable** | framework | 3003 | http://localhost:3003 |
| **Log4Shell** | realworld | 8089, 1389, 8888 | http://localhost:8089 |
| **Spring4Shell** | realworld | 8085 | http://localhost:8085 |
| **Struts2** | realworld | 8086 | http://localhost:8086 |
| **GitLab CE** | realworld | 8088, 8444, 2223 | http://localhost:8088 |
| **XXE Lab** | advanced | 8090 | http://localhost:8090 |
| **SSRF Lab** | advanced | 8091 | http://localhost:8091 |
| **Deserialization Lab** | advanced | 8092, 5000, 8095 | Java: 8092, Python: 5000, PHP: 8095 |

## Notes
- All ports have been adjusted to avoid conflicts with VulhubWeb Manager (port 3000)
- Some applications use multiple ports (e.g., WebGoat uses 8082 for main app and 9090 for WebWolf)
- Before starting an application, ensure its ports are not in use
- To change a port, edit the `docker-compose.yml` file in the application's directory

## Checking Port Usage
```bash
# Check if a port is in use
lsof -i :PORT_NUMBER

# List all listening ports
netstat -tlnp

# Docker-specific port check
docker ps --format "table {{.Names}}\t{{.Ports}}"
``` 