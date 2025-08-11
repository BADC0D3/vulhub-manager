# Vulnerable Docker Applications for Security Training

This collection contains 25 modern vulnerable applications for security training and penetration testing. Each application is containerized using Docker Compose for easy deployment and management through VulhubWeb.

⚠️ **WARNING**: These applications contain deliberate security vulnerabilities. Only run them in isolated environments for educational purposes.

## Quick Start

1. Update your VulhubWeb `.env` file:
   ```
   VULHUB_PATH=/home/badc0d3/repo/vulhubWeb/vulnerabilities
   ```

2. Restart VulhubWeb:
   ```bash
   docker compose restart
   ```

3. Access applications through the VulhubWeb interface at http://localhost:3000

## Applications Overview

### 1. **OWASP Juice Shop** (`juice-shop`)
- **Type**: Modern e-commerce application
- **Technologies**: Node.js, Express, Angular, SQLite
- **Key Vulnerabilities**: SQL Injection, XSS, XXE, SSRF, Broken Authentication
- **Port**: 3001
- **Difficulty**: Beginner to Expert

### 2. **DVWA - Damn Vulnerable Web Application** (`dvwa`)
- **Type**: PHP web application
- **Technologies**: PHP, MySQL
- **Key Vulnerabilities**: SQL Injection, XSS, Command Injection, CSRF, File Upload
- **Port**: 8081
- **Default Login**: admin/password
- **Difficulty**: Adjustable (Low/Medium/High)

### 3. **WebGoat** (`webgoat`)
- **Type**: Java-based security training
- **Technologies**: Spring Boot, Java
- **Key Vulnerabilities**: OWASP Top 10 with lessons
- **Ports**: 8080, 9090
- **Difficulty**: Progressive learning

### 4. **Damn Vulnerable GraphQL Application** (`dvga`)
- **Type**: GraphQL API
- **Technologies**: Python, GraphQL
- **Key Vulnerabilities**: GraphQL-specific attacks, Information Disclosure, DoS
- **Port**: 5013
- **Difficulty**: Intermediate

### 5. **NodeGoat** (`nodegoat`)
- **Type**: Node.js application
- **Technologies**: Node.js, MongoDB, Express
- **Key Vulnerabilities**: NoSQL Injection, Insecure Direct Object References
- **Port**: 4000
- **Difficulty**: Intermediate

### 6. **crAPI - Completely Ridiculous API** (`crapi`)
- **Type**: Modern API with microservices
- **Technologies**: Python, Go, PostgreSQL, MongoDB
- **Key Vulnerabilities**: API Security Top 10, JWT issues, BOLA
- **Ports**: 8888 (Web), 8025 (MailHog)
- **Difficulty**: Intermediate to Advanced

### 7. **VAmPI - Vulnerable API** (`vampi`)
- **Type**: REST API
- **Technologies**: Python Flask
- **Key Vulnerabilities**: API security issues, SQL Injection, Unauthorized Access
- **Port**: 5000
- **Difficulty**: Beginner to Intermediate

### 8. **Damn Vulnerable RESTaurant** (`dvrestaurant`)
- **Type**: Restaurant API
- **Technologies**: Node.js
- **Key Vulnerabilities**: JWT vulnerabilities, IDOR, Rate Limiting bypass
- **Port**: 8083
- **Difficulty**: Intermediate

### 9. **GraphQL Security Testing** (`graphql-security`)
- **Type**: GraphQL endpoint testing
- **Technologies**: Python, GraphQL
- **Key Vulnerabilities**: Query depth attacks, Introspection, Batching attacks
- **Port**: 5001
- **Difficulty**: Intermediate

### 10. **Kubernetes Goat** (`kubernetes-goat`)
- **Type**: Container/Kubernetes security
- **Technologies**: Kubernetes, Docker
- **Key Vulnerabilities**: Container escape, Misconfigured RBAC, Secrets exposure
- **Ports**: 1234, 1235
- **Difficulty**: Advanced

### 11. **Docker Escape Lab** (`docker-escape`)
- **Type**: Container security
- **Technologies**: Docker
- **Key Vulnerabilities**: Container breakout, Privileged containers, Docker socket exposure
- **Port**: 2222 (SSH)
- **Difficulty**: Advanced

### 12. **Serverless Goat** (`serverless-goat`)
- **Type**: Serverless security
- **Technologies**: LocalStack, Lambda
- **Key Vulnerabilities**: Function injection, Event injection, IAM misconfigurations
- **Port**: 4566
- **Difficulty**: Advanced

### 13. **Django Vulnerable App** (`django-vulnerable`)
- **Type**: Python web framework
- **Technologies**: Django, PostgreSQL
- **Key Vulnerabilities**: Template injection, ORM injection, Debug mode
- **Port**: 8093
- **Difficulty**: Intermediate

### 14. **Rails Goat** (`railsgoat`)
- **Type**: Ruby on Rails application
- **Technologies**: Ruby on Rails
- **Key Vulnerabilities**: Mass assignment, Unsafe redirects, Command injection
- **Port**: 3002
- **Difficulty**: Intermediate

### 15. **Spring Boot Vulnerable App** (`spring-vulnerable`)
- **Type**: Java Spring application
- **Technologies**: Spring Boot, MySQL
- **Key Vulnerabilities**: SpEL injection, Actuator exposure, Deserialization
- **Port**: 8084
- **Difficulty**: Intermediate

### 16. **Laravel Vulnerable App** (`laravel-vulnerable`)
- **Type**: PHP framework application
- **Technologies**: Laravel, MySQL
- **Key Vulnerabilities**: Blade template injection, Mass assignment, Debug mode
- **Port**: 8094
- **Difficulty**: Intermediate

### 17. **Express.js Vulnerable App** (`express-vulnerable`)
- **Type**: Node.js web application
- **Technologies**: Express.js, MongoDB
- **Key Vulnerabilities**: NoSQL injection, JWT secret issues, Prototype pollution
- **Port**: 3003
- **Difficulty**: Intermediate

### 18. **Log4Shell Lab** (`log4shell`)
- **Type**: Log4j vulnerability
- **Technologies**: Java, Log4j
- **Key Vulnerabilities**: CVE-2021-44228 (Log4Shell), RCE via JNDI
- **Ports**: 8080 (App), 1389 (LDAP), 8888 (Exploit server)
- **Difficulty**: Intermediate

### 19. **Spring4Shell Lab** (`spring4shell`)
- **Type**: Spring Framework vulnerability
- **Technologies**: Spring Framework
- **Key Vulnerabilities**: CVE-2022-22965, RCE via data binding
- **Port**: 8085
- **Difficulty**: Intermediate

### 20. **Struts2 Vulnerabilities** (`struts2`)
- **Type**: Apache Struts framework
- **Technologies**: Java, Struts2
- **Key Vulnerabilities**: Multiple Struts CVEs, OGNL injection, RCE
- **Port**: 8086
- **Difficulty**: Intermediate

### 21. **WordPress Vulnerable** (`wordpress-vulnerable`)
- **Type**: CMS application
- **Technologies**: WordPress 5.8.1, MySQL
- **Key Vulnerabilities**: Plugin vulnerabilities, Theme issues, XXE, SQLi
- **Port**: 8087
- **Default Login**: Create admin account on first run
- **Difficulty**: Beginner to Intermediate

### 22. **GitLab CE Vulnerable** (`gitlab-vulnerable`)
- **Type**: DevOps platform
- **Technologies**: GitLab CE 13.12.0
- **Key Vulnerabilities**: CVE-2021-22205 (RCE), SSRF, Information disclosure
- **Ports**: 8080 (HTTP), 8443 (HTTPS), 2222 (SSH)
- **Difficulty**: Advanced

### 23. **XXE Lab** (`xxe-lab`)
- **Type**: XML processing application
- **Technologies**: Various
- **Key Vulnerabilities**: XXE injection, File disclosure, SSRF via XXE
- **Port**: 8090
- **Difficulty**: Intermediate

### 24. **SSRF Testing Lab** (`ssrf-lab`)
- **Type**: Server-Side Request Forgery
- **Technologies**: Various
- **Key Vulnerabilities**: SSRF, Internal network scanning, Cloud metadata access
- **Port**: 8091
- **Difficulty**: Intermediate

### 25. **Deserialization Lab** (`deserialization-lab`)
- **Type**: Multi-language deserialization
- **Technologies**: Java, Python, PHP
- **Key Vulnerabilities**: Insecure deserialization, RCE, Object injection
- **Ports**: 8080 (Java), 5000 (Python), 8081 (PHP)
- **Difficulty**: Advanced

## Security Best Practices

1. **Isolation**: Run these applications only in isolated networks
2. **Monitoring**: Monitor for any suspicious activity
3. **Cleanup**: Remove containers and data after use
4. **Updates**: Regularly update the images for the latest vulnerabilities
5. **Access Control**: Restrict access to authorized users only

## Adding Custom Applications

To add a new vulnerable application:

1. Create a new directory: `mkdir vulnerabilities/app-name`
2. Add `docker-compose.yml` with your configuration
3. Add a `README.md` with vulnerability documentation
4. The application will automatically appear in VulhubWeb

## Port Management

To avoid port conflicts, consider using a reverse proxy or modifying the port mappings in the docker-compose.yml files.

## Quick Reference

- **Port Mapping**: See [PORT_MAPPING.md](PORT_MAPPING.md) for all port assignments
- **Quick Start**: See [QUICK_START.md](QUICK_START.md) for URLs and credentials
- **VulhubWeb Interface**: http://localhost:3000
- **Total Applications**: 25 vulnerable applications
- **Categories**: web, api, container, framework, realworld, advanced

## Troubleshooting

- **Port conflicts**: Check [PORT_MAPPING.md](PORT_MAPPING.md) and change host ports in docker-compose.yml
- **Image not found**: Some applications have been updated to use alternative images
- **Access issues**: Some apps require context paths (e.g., WebGoat uses /WebGoat)
- **Performance issues**: Limit concurrent running environments in VulhubWeb
- **Network issues**: Check Docker network configuration and firewall settings

## Security Warning

⚠️ **CRITICAL SECURITY WARNING** ⚠️

These applications contain **REAL SECURITY VULNERABILITIES** and are designed to be exploited:
- **NEVER** expose these applications to the public internet
- **ONLY** run in isolated, controlled lab environments
- **USE** network isolation (VPN, local network only)
- **MONITOR** for any unauthorized access attempts
- **DESTROY** containers immediately after training sessions

## Contributing

To contribute new vulnerable applications:
1. Ensure the application is legally distributable
2. Include comprehensive documentation and exploitation guides
3. Test the Docker Compose configuration thoroughly
4. Follow the existing directory structure (category/app-name/)
5. Submit a pull request with your additions

## License

Each application may have its own license. Please check individual application repositories for specific licensing information. This collection is assembled for educational and security training purposes only. 