# VulhubWeb Documentation Index

## 📚 Main Documentation Files

### Core Documentation
1. **[README.md](../README.md)**
   - Main project documentation
   - Features, installation, configuration
   - Quick start guide
   - Links to all other documentation

2. **[DEPLOYMENT.md](DEPLOYMENT.md)**
   - Production deployment guide
   - Reverse proxy configuration
   - Security hardening
   - Performance optimization
   - Backup and maintenance

3. **[HOST_CONFIGURATION.md](HOST_CONFIGURATION.md)**
   - Dynamic host configuration
   - Remote access setup
   - Environment variables
   - Network configuration examples

4. **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**
   - Common issues and solutions
   - Performance tips
   - Debug commands
   - Getting help

5. **[Learning Center](learning/README.md)**
   - Interactive security tutorials
   - Progressive hint system
   - Hands-on vulnerability practice
   - Defense strategies

## 🔒 Vulnerable Applications Documentation

### Overview Files
1. **[vulnerabilities/README.md](../vulnerabilities/README.md)**
   - Overview of all 25 vulnerable applications
   - Categories and descriptions
   - Security warnings
   - Quick reference

2. **[vulnerabilities/PORT_MAPPING.md](../vulnerabilities/PORT_MAPPING.md)**
   - Complete port assignments table
   - Conflict resolution guide
   - Port checking commands
   - Recommendations

3. **[vulnerabilities/QUICK_START.md](../vulnerabilities/QUICK_START.md)**
   - Quick access URLs for all applications
   - Default credentials
   - Initial setup steps
   - Category organization

### Individual Application READMEs
Each vulnerable application has its own detailed README with:
- Vulnerability descriptions
- Exploitation examples
- Default credentials
- Learning objectives
- Prevention techniques

**All 25 Applications Have READMEs:**

#### Web Applications (5)
- `../vulnerabilities/web/juice-shop/README.md` - OWASP Juice Shop
- `../vulnerabilities/web/dvwa/README.md` - Damn Vulnerable Web Application
- `../vulnerabilities/web/webgoat/README.md` - WebGoat & WebWolf
- `../vulnerabilities/web/nodegoat/README.md` - DVNA (NodeJS vulnerabilities)
- `../vulnerabilities/web/wordpress-vulnerable/README.md` - WordPress vulnerabilities

#### API Applications (5)
- `../vulnerabilities/api/crapi/README.md` - Completely Ridiculous API
- `../vulnerabilities/api/vampi/README.md` - Vulnerable API
- `../vulnerabilities/api/dvrestaurant/README.md` - Restaurant API vulnerabilities
- `../vulnerabilities/api/dvga/README.md` - Damn Vulnerable GraphQL Application
- `../vulnerabilities/api/graphql-security/README.md` - GraphQL security testing

#### Container/Cloud Applications (3)
- `../vulnerabilities/container/docker-escape/README.md` - Docker escape techniques
- `../vulnerabilities/container/kubernetes-goat/README.md` - Kubernetes vulnerabilities
- `../vulnerabilities/container/serverless-goat/README.md` - Serverless/FaaS vulnerabilities

#### Framework Applications (5)
- `../vulnerabilities/framework/django-vulnerable/README.md` - Django vulnerabilities
- `../vulnerabilities/framework/railsgoat/README.md` - Ruby on Rails vulnerabilities
- `../vulnerabilities/framework/spring-vulnerable/README.md` - Spring Boot vulnerabilities
- `../vulnerabilities/framework/laravel-vulnerable/README.md` - Laravel vulnerabilities
- `../vulnerabilities/framework/express-vulnerable/README.md` - Express.js vulnerabilities

#### Real-world CVEs (4)
- `../vulnerabilities/realworld/log4shell/README.md` - Log4j RCE (CVE-2021-44228)
- `../vulnerabilities/realworld/spring4shell/README.md` - Spring RCE (CVE-2022-22965)
- `../vulnerabilities/realworld/struts2/README.md` - Apache Struts vulnerabilities
- `../vulnerabilities/realworld/gitlab-vulnerable/README.md` - GitLab CE vulnerabilities

#### Advanced Techniques (3)
- `../vulnerabilities/advanced/xxe-lab/README.md` - XML External Entity attacks
- `../vulnerabilities/advanced/ssrf-lab/README.md` - Server-Side Request Forgery
- `../vulnerabilities/advanced/deserialization-lab/README.md` - Java/Python/PHP deserialization

## 🗂️ Documentation Organization

```
.
├── README.md                    # Main project documentation
├── DEPLOYMENT.md               # Production deployment guide
├── HOST_CONFIGURATION.md       # Host and network configuration
├── TROUBLESHOOTING.md         # Troubleshooting guide
├── DOCUMENTATION_INDEX.md     # This file
└── vulnerabilities/
    ├── README.md              # Vulnerable apps overview
    ├── PORT_MAPPING.md        # Port assignments reference
    ├── QUICK_START.md         # Quick access guide
    └── [category]/[app]/README.md  # Individual app docs
```

## 📋 Removed Files

The following files were removed during cleanup as they were temporary or redundant:
- `UPDATES_SUMMARY.md` - Temporary update notes
- `vulnerabilities/PORTS_REFERENCE.md` - Duplicate of PORT_MAPPING.md
- `vulnerabilities/STATUS.md` - Temporary status tracking

## 🚀 Quick Navigation

- **New to VulhubWeb?** Start with [README.md](../README.md)
- **Setting up production?** See [DEPLOYMENT.md](DEPLOYMENT.md)
- **Remote access needed?** Check [HOST_CONFIGURATION.md](HOST_CONFIGURATION.md)
- **Having issues?** Read [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **Looking for apps?** Browse [vulnerabilities/README.md](../vulnerabilities/README.md)
- **Need ports info?** Reference [vulnerabilities/PORT_MAPPING.md](../vulnerabilities/PORT_MAPPING.md)
- **Want quick access?** Use [vulnerabilities/QUICK_START.md](../vulnerabilities/QUICK_START.md) 