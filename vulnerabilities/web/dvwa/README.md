# DVWA - Damn Vulnerable Web Application

## Description
DVWA is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment.

## Access
- URL: http://localhost:8081
- Default Login: admin / password

## Security Levels
DVWA has four security levels:
- **Low**: No security measures
- **Medium**: Basic security measures
- **High**: Advanced security measures  
- **Impossible**: Secure implementation

## Vulnerabilities

### 1. SQL Injection
- **Location**: SQL Injection page
- **Low Level**: `' or '1'='1`
- **Medium Level**: Use numeric payloads
- **High Level**: Use LIMIT bypass techniques

### 2. XSS (Reflected)
- **Location**: XSS (Reflected) page
- **Low Level**: `<script>alert('XSS')</script>`
- **Medium Level**: `<ScRiPt>alert('XSS')</ScRiPt>`
- **High Level**: Use event handlers

### 3. Command Injection
- **Location**: Command Injection page
- **Low Level**: `127.0.0.1; ls`
- **Medium Level**: `127.0.0.1 && ls`
- **High Level**: `127.0.0.1 | ls`

### 4. File Upload
- **Location**: File Upload page
- **Low Level**: Upload PHP shell directly
- **Medium Level**: Use double extensions
- **High Level**: Use image with embedded PHP

### 5. CSRF
- **Location**: CSRF page
- **Attack**: Create malicious form to change admin password

## Setup Database
Click "Create / Reset Database" button on first access.

## Tools
- Burp Suite
- SQLMap
- OWASP ZAP
- Nikto 