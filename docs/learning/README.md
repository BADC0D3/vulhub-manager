# 🎓 VulhubWeb Learning Center

Welcome to the VulhubWeb Learning Center! This is your guided journey into understanding web application security through hands-on practice with real vulnerabilities.

## 🎯 Learning Approach

Our tutorials follow a structured approach:
1. **Understand** - Learn what the vulnerability is and why it matters
2. **Identify** - Discover how to find these vulnerabilities
3. **Exploit** - Practice exploitation in a safe environment
4. **Defend** - Learn how to prevent these vulnerabilities

Each tutorial includes:
- 📖 Detailed explanations
- 🎯 Step-by-step instructions
- 💡 Hints when you're stuck
- 🔓 Hidden solutions (reveal when needed)
- ✅ Practice challenges
- 🛡️ Defense strategies

## 📚 Available Learning Paths

### 🌐 Web Application Vulnerabilities

#### Beginner Level
1. **[SQL Injection (SQLi)](sql-injection.md)** ⭐⭐⭐
   - Understand database queries and how they can be manipulated
   - Practice with DVWA, WebGoat, and Juice Shop
   - Time: 2-3 hours

2. **[Cross-Site Scripting (XSS)](xss.md)** ⭐⭐⭐
   - Learn about reflected, stored, and DOM-based XSS
   - Practice with multiple vulnerable applications
   - Time: 2-3 hours

3. **[Broken Authentication](broken-authentication.md)** ⭐⭐
   - Explore weak passwords, session management, and credential stuffing
   - Practice with various authentication bypasses
   - Time: 2 hours

#### Intermediate Level
4. **[XML External Entity (XXE)](xxe.md)** ⭐⭐⭐⭐
   - Understand XML parsing vulnerabilities
   - Learn file reading and SSRF through XXE
   - Time: 2-3 hours

5. **[Server-Side Request Forgery (SSRF)](ssrf.md)** ⭐⭐⭐⭐
   - Make servers request resources on your behalf
   - Bypass firewalls and access internal services
   - Time: 2-3 hours

6. **[Insecure Deserialization](deserialization.md)** ⭐⭐⭐⭐⭐
   - Understand object serialization vulnerabilities
   - Practice with Java, Python, and PHP
   - Time: 3-4 hours

### 🔌 API Security

#### Beginner Level
7. **[Broken Object Level Authorization (BOLA)](bola.md)** ⭐⭐
   - Access other users' resources through API endpoints
   - Practice with crAPI and VAmPI
   - Time: 2 hours

8. **[API Rate Limiting](rate-limiting.md)** ⭐⭐
   - Understand and bypass rate limiting mechanisms
   - Practice brute force and resource exhaustion
   - Time: 1-2 hours

#### Intermediate Level
9. **[JWT Vulnerabilities](jwt.md)** ⭐⭐⭐⭐
   - Understand JSON Web Tokens and their weaknesses
   - Practice signature bypass and token manipulation
   - Time: 2-3 hours

10. **[GraphQL Security](graphql.md)** ⭐⭐⭐⭐
    - Query manipulation and introspection attacks
    - Practice with DVGA and GraphQL Security
    - Time: 2-3 hours

### 🐳 Container & Infrastructure

#### Advanced Level
11. **[Docker Container Escape](docker-escape.md)** ⭐⭐⭐⭐⭐
    - Understand container isolation and breakout techniques
    - Practice privilege escalation
    - Time: 3-4 hours

12. **[Kubernetes Security](kubernetes.md)** ⭐⭐⭐⭐⭐
    - Explore K8s misconfigurations and attacks
    - Practice with Kubernetes Goat
    - Time: 4-5 hours

### 🏢 Real-World CVEs

13. **[Log4Shell (CVE-2021-44228)](log4shell.md)** ⭐⭐⭐⭐
    - Understand the Log4j RCE vulnerability
    - Practice exploitation and detection
    - Time: 2 hours

14. **[Spring4Shell (CVE-2022-22965)](spring4shell.md)** ⭐⭐⭐⭐⭐
    - Learn about Spring Framework RCE
    - Practice exploitation techniques
    - Time: 2-3 hours

## 🚀 Getting Started

### Prerequisites
- Basic understanding of HTTP/HTTPS
- Familiarity with browser developer tools
- Basic command line knowledge
- VulhubWeb environment set up and running

### Recommended Learning Path

#### For Complete Beginners:
1. Start with **SQL Injection** → 2. **XSS** → 3. **Broken Authentication** → 4. **BOLA**

#### For Developers:
1. **BOLA** → 2. **JWT Vulnerabilities** → 3. **XXE** → 4. **Deserialization**

#### For Security Enthusiasts:
1. **SSRF** → 2. **XXE** → 3. **Docker Escape** → 4. **Real-world CVEs**

## 📋 Learning Features

### 💡 Progressive Hints System
Each tutorial includes multiple levels of hints:
1. **Gentle Nudge** - A small hint to point you in the right direction
2. **Clear Direction** - More specific guidance on what to try
3. **Detailed Steps** - Step-by-step instructions (still requires thinking)
4. **Full Solution** - Complete solution with explanation

### 🎯 Practice Challenges
Each topic includes:
- **Guided Practice** - Follow along with instructions
- **Solo Challenges** - Test your understanding
- **Real-World Scenarios** - Apply knowledge to realistic situations

### 📊 Progress Tracking
- Track completed tutorials
- Monitor time spent on each topic
- See your learning statistics

## 🛡️ Ethical Guidelines

Remember:
- **Only practice on the provided lab environments**
- **Never test on systems you don't own**
- **Use knowledge responsibly**
- **Report vulnerabilities through proper channels**

## 🤝 Community & Support

- Join discussions in each tutorial
- Share your learning experience
- Help others when they're stuck
- Contribute improvements to tutorials

## 🎮 Gamification

Earn badges as you progress:
- 🥉 **Bronze Badge** - Complete your first vulnerability
- 🥈 **Silver Badge** - Complete 5 different vulnerability types
- 🥇 **Gold Badge** - Complete all tutorials in a category
- 💎 **Diamond Badge** - Master all learning paths

---

Ready to start your security learning journey? Choose a vulnerability type above and let's begin! Remember, the goal is not just to exploit, but to understand and ultimately defend against these vulnerabilities. 