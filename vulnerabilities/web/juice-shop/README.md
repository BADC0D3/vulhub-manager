# OWASP Juice Shop

## Description
OWASP Juice Shop is probably the most modern and sophisticated insecure web application! It encompasses vulnerabilities from the entire OWASP Top Ten along with many other security flaws found in real-world applications.

## Vulnerabilities
- SQL Injection
- Cross-Site Scripting (XSS)
- Broken Authentication
- Sensitive Data Exposure
- XML External Entities (XXE)
- Broken Access Control
- Security Misconfiguration
- Insecure Deserialization
- Using Components with Known Vulnerabilities
- Insufficient Logging & Monitoring

## Usage
Access the application at: http://localhost:3001

## Default Credentials
- Admin: admin@juice-sh.op / admin123
- User: jim@juice-sh.op / ncc-1701
- User: bender@juice-sh.op / OhG0dPlease1nsertLiquor!

## Exploitation Guide
1. **SQL Injection**: Try `' or 1=1--` in the login form
2. **XSS**: Search for `<script>alert('XSS')</script>`
3. **Admin Access**: Navigate to http://localhost:3000/#/administration
4. **Score Board**: Access hidden score board at http://localhost:3000/#/score-board 