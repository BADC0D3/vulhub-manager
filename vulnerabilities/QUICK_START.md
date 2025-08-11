# Quick Start Guide - Vulnerable Applications

## How to Use

1. **Access VulhubWeb Manager**: http://localhost:3000
2. Select an application from the categorized list
3. Click "Start" to launch the container
4. Wait for status to show "Running"
5. Access the application using the URLs below

## Application Access URLs

### Web Applications
- **Juice Shop**: http://localhost:3001
- **DVWA**: http://localhost:8081
  - First time: Click "Create / Reset Database"
  - Login: admin / password
- **WebGoat**: http://localhost:8082/WebGoat
  - WebWolf: http://localhost:9090/WebWolf
  - No login required, create account on first use
- **DVNA** (NodeJS vulnerabilities): http://localhost:4000
  - Default login: admin / admin
- **WordPress**: http://localhost:8087/wp-admin
  - Set up admin account on first access

### API Applications
- **crAPI**: http://localhost:8888
  - MailHog: http://localhost:8025
- **VAmPI**: http://localhost:5000
- **DVRestaurant**: http://localhost:8083
- **DVGA**: http://localhost:5013/graphiql
- **GraphQL Security**: http://localhost:5001

### Container/Cloud Security
- **Kubernetes Goat**: http://localhost:1234
- **Docker Escape**: SSH to port 2222
  ```bash
  ssh root@localhost -p 2222
  ```
- **Serverless Goat**: http://localhost:4566

### Framework Applications
- **Django Vulnerable**: http://localhost:8093
- **Rails Goat**: http://localhost:3002
- **Spring Vulnerable**: http://localhost:8084
- **Laravel Vulnerable**: http://localhost:8094
- **Express Vulnerable**: http://localhost:3003

### Real-World CVEs
- **Log4Shell**: http://localhost:8089
  - LDAP Server: port 1389
  - Exploit Server: http://localhost:8888
- **Spring4Shell**: http://localhost:8085
- **Struts2**: http://localhost:8086
- **GitLab CE**: http://localhost:8088
  - First start takes 5-10 minutes
  - Default: root / 5iveL!fe

### Advanced Exploitation
- **XXE Lab**: http://localhost:8090
- **SSRF Lab**: http://localhost:8091
- **Deserialization Lab**:
  - Java: http://localhost:8092
  - Python: http://localhost:5000
  - PHP: http://localhost:8095

## Common Issues

### Application shows 404
Some applications have specific context paths:
- WebGoat: `/WebGoat`
- WebWolf: `/WebWolf`

### Port Already in Use
Check which application is using the port:
```bash
docker ps --format "table {{.Names}}\t{{.Ports}}"
```

### Application Won't Start
1. Check logs in VulhubWeb interface
2. Verify no port conflicts
3. Some apps (GitLab) need more time to start

### Database Connection Issues
Some applications need their database initialized:
- DVWA: Click "Create / Reset Database" button
- WordPress: Complete installation wizard

## Security Warning
⚠️ These applications are deliberately vulnerable. Only run in isolated environments! 