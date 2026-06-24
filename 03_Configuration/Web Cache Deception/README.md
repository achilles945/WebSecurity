# Web Cache Deception 

## Table of Contents

1. [What is Web Cache Deception?](#1-what-is-web-cache-deception)
2. [Web Cache Deception vs Web Cache Poisoning](#2-web-cache-deception-vs-web-cache-poisoning)
3. [How Web Caches Work — Foundation](#3-how-web-caches-work--foundation)
4. [Cache Keys](#4-cache-keys)
5. [Cache Rules — The Three Targets](#5-cache-rules--the-three-targets)
6. [The General Attack Construction Process](#6-the-general-attack-construction-process)
7. [Testing Setup — Cache Busters & Detecting Cached Responses](#7-testing-setup--cache-busters--detecting-cached-responses)
8. [Exploiting Static Extension Cache Rules](#8-exploiting-static-extension-cache-rules)
   - 8.1 [Path Mapping Discrepancies](#81-path-mapping-discrepancies)
   - 8.2 [Delimiter Discrepancies](#82-delimiter-discrepancies)
   - 8.3 [Delimiter Decoding Discrepancies](#83-delimiter-decoding-discrepancies)
9. [Exploiting Static Directory Cache Rules](#9-exploiting-static-directory-cache-rules)
   - 9.1 [Normalization Discrepancies](#91-normalization-discrepancies)
   - 9.2 [Detecting Normalization by the Origin Server](#92-detecting-normalization-by-the-origin-server)
   - 9.3 [Detecting Normalization by the Cache Server](#93-detecting-normalization-by-the-cache-server)
   - 9.4 [Exploiting Origin Server Normalization](#94-exploiting-origin-server-normalization)
   - 9.5 [Exploiting Cache Server Normalization](#95-exploiting-cache-server-normalization)
10. [Exploiting File Name Cache Rules](#10-exploiting-file-name-cache-rules)
11. [Impact Assessment](#11-impact-assessment)
12. [Defense & Prevention](#12-defense--prevention)
13. [Quick Reference Cheat Sheet](#13-quick-reference-cheat-sheet)

---

## 1. What is Web Cache Deception?

Web cache deception is a vulnerability that lets an attacker **trick a web cache into storing sensitive, dynamic content** — content that was never meant to be cached at all, such as a page containing another user's private API key, profile data, or CSRF token.

### The Root Cause

It's caused by a **discrepancy** between how the cache server and the origin server interpret the same request. The cache looks at the URL and thinks "this looks like a static file, I'll store it." The origin server looks at the same URL and thinks "this is actually a request for sensitive dynamic data" — and returns that sensitive data anyway, ignoring the parts of the URL that confused it.

### Attack Flow

```
1. Attacker crafts an ambiguous URL
        │
        ▼
2. Attacker persuades victim to visit it (phishing, malicious link, etc.)
        │
        ▼
3. Victim's browser sends the request through the cache
        │
        ▼
4. Cache misinterprets it as a request for a static resource → caches the response
   Origin server interprets it as a request for sensitive dynamic content → returns it
        │
        ▼
5. The victim's sensitive response is now sitting in the cache, tied to that URL
        │
        ▼
6. Attacker requests the SAME URL → cache serves the victim's cached sensitive data directly
```

---

## 2. Web Cache Deception vs Web Cache Poisoning

These are frequently confused because both abuse caching infrastructure — but the mechanism and goal are inverted.

| Aspect | Web Cache Poisoning | Web Cache Deception |
|--------|---------------------|---------------------|
| **What's manipulated** | The cache key | Cache rules (what qualifies for caching) |
| **What gets stored** | Malicious content injected by the attacker | Legitimate sensitive content belonging to a victim |
| **Who is harmed** | Other users who later request the poisoned URL | The specific victim whose private data gets cached and exposed |
| **Attacker's payload** | Malicious script/header that the cache unknowingly serves to everyone | None — the attacker doesn't inject anything malicious into the response |
| **Direction of harm** | Attacker → cache → many victims | Victim's own private data → cache → attacker |

**The one-sentence distinction:** Poisoning makes the cache **serve attacker content to victims**. Deception makes the cache **store victim content for the attacker to retrieve**.

---

## 3. How Web Caches Work — Foundation

A web cache is a system sitting between the origin server and the user.

```
Client Request
     │
     ▼
[ Cache Layer ]
     │
     ├─── Cache HIT  → Cache serves the stored response directly (origin never contacted)
     │
     └─── Cache MISS → Request forwarded to origin server
                              │
                              ▼
                       Origin server processes and responds
                              │
                              ▼
                       Cache evaluates its rules: should this response be stored?
                              │
                              ▼
                       Response sent to the client (and possibly stored for next time)
```

### Why Caching Exists

Caching — especially via **Content Delivery Networks (CDNs)** — is fundamental to modern web performance. CDNs distribute copies of content across servers worldwide so users are served from the server physically closest to them, cutting load times by minimizing the distance data has to travel.

---

## 4. Cache Keys

When a request arrives, the cache decides whether it already has a matching stored response by generating a **cache key** from elements of the request — typically the **URL path and query parameters**, though some caches also factor in headers or content type.

If an incoming request's cache key **matches** a previously cached key, the cache treats them as equivalent and serves the stored copy — **regardless of any other differences in the request**, including who's actually making it.

This is the structural reason deception works: the cache key is built from the **literal URL string**, but the *meaning* of that URL string can differ completely depending on which server is parsing it.

> **Note:** Cache key manipulation is the foundation of **web cache poisoning**, not deception — see Section 2 for the distinction.

---

## 5. Cache Rules — The Three Targets

Cache rules determine **what** gets cached and **for how long**. They're generally configured to cache static resources (which rarely change and are reused across many pages) while excluding dynamic content (which is more likely to be sensitive and needs to stay fresh per-request).

Web cache deception specifically exploits how these rules are applied — particularly rules based on **defined strings in the URL path**. There are three primary rule types:

| Rule Type | What It Matches | Example |
|-----------|-----------------|---------|
| **Static file extension rules** | The file extension of the requested resource | `.css`, `.js`, `.ico` |
| **Static directory rules** | Any URL path starting with a specific prefix | `/static`, `/assets`, `/scripts` |
| **File name rules** | An exact, specific file name | `robots.txt`, `favicon.ico`, `index.html` |

Caches may also implement custom rules based on additional criteria such as URL parameters or dynamic content analysis — but the three above are the classic, most commonly exploitable targets.

---

## 6. The General Attack Construction Process

Every web cache deception attack — regardless of which rule type is targeted — follows the same three-step skeleton:

```
Step 1: Identify a target endpoint that returns sensitive dynamic data
        → Review full responses in Burp (not just the rendered page —
          sensitive data may be present in the HTML/JSON but not visibly
          displayed in the browser)
        → Focus on endpoints supporting GET, HEAD, or OPTIONS — caches
          generally don't store responses to state-changing methods (POST, etc.)

Step 2: Identify a discrepancy in how the cache and origin server parse the URL path
        → Differences in how they MAP URLs to resources
        → Differences in how they process DELIMITER characters
        → Differences in how they NORMALIZE paths (decode/resolve traversal sequences)

Step 3: Craft a malicious URL exploiting that discrepancy
        → Deliver it to the victim
        → Victim's sensitive response gets cached under that URL
        → Attacker requests the same URL via Burp (not the browser — some apps
          redirect unauthenticated users or invalidate local data, which can mask
          a real vulnerability) to retrieve the victim's cached sensitive data
```

---

## 7. Testing Setup — Cache Busters & Detecting Cached Responses

### Using a Cache Buster

While probing for discrepancies, **every test request must produce a unique cache key** — otherwise you'll be served a previously cached response and your results will be misleading.

**Manual approach:** Append a changing query string to each request.

**Automated approach (recommended):** Install the **Param Miner** Burp extension, then enable **Param miner > Settings > Add dynamic cachebuster**. Burp will automatically append a unique query string to every outgoing request — visible in the **Logger** tab.

### Detecting Cached Responses

You need a reliable way to tell whether a given response came from the cache or the origin server.

**Response headers to check:**

| Header / Value | Meaning |
|-----------------|---------|
| `X-Cache: hit` | Served from the cache |
| `X-Cache: miss` | Not found in cache for this key → fetched from origin (and likely now cached — resend to confirm `hit`) |
| `X-Cache: dynamic` | Origin generated the content dynamically — generally not cacheable |
| `X-Cache: refresh` | Cached content was stale and had to be refreshed/revalidated |
| `Cache-Control: public, max-age=N` | *Suggests* the resource is cacheable for N seconds — not a guarantee, since the cache itself can override this directive |

**Timing-based detection:** A noticeably faster response time for an identical request strongly suggests it was served from the cache rather than freshly generated by the origin.

---

## 8. Exploiting Static Extension Cache Rules

Cache rules frequently target requests by file extension (`.css`, `.js`, etc.) — this is the **default behavior in most CDNs**. If the cache and origin server disagree about how to parse the URL path, you can craft a request that the cache sees as a static file but the origin server sees as a request for sensitive dynamic content.

### 8.1 Path Mapping Discrepancies

**Concept:** Different frameworks map URL paths to resources in fundamentally different ways.

**Traditional URL mapping** — direct filesystem path:
```
http://example.com/path/in/filesystem/resource.html
```
The path corresponds literally to a location on disk.

**RESTful URL mapping** — abstracted, logical path:
```
http://example.com/path/resource/param1/param2
```
`/path/resource/` is an API endpoint; `param1` and `param2` are parameters consumed by application logic, not literal file paths.

**The exploitable discrepancy:**
```
http://example.com/user/123/profile/wcd.css
```
- A REST-style **origin server** interprets this as the `/user/123/profile` endpoint and **ignores** `wcd.css` as an insignificant trailing parameter — it returns the user's profile data normally.
- A **cache** using traditional URL mapping interprets the *entire* path literally — sees a file named `wcd.css` and, if it has a rule for the `.css` extension, **caches the profile data as if it were a stylesheet**.

**Testing methodology:**

```
Step 1 — Test origin server abstraction:
  Add an arbitrary path segment: /api/orders/123  →  /api/orders/123/foo
  If the response STILL contains the same sensitive data → origin abstracts
  the path and ignores the extra segment.

Step 2 — Test cache extension matching:
  Add a static extension to that same segment: /api/orders/123/foo.js
  If the response IS cached → confirms:
    (a) the cache interprets the full literal path including the extension
    (b) there's a cache rule for requests ending in .js

Step 3 — Try a range of extensions: .css, .ico, .exe, etc. — different
  caches/CDNs have different configured extension lists.
```

**Important scope limitation:** This attack is specific to the **exact endpoint tested** — origin servers often apply different path-abstraction rules per endpoint, so a working payload on `/my-account` won't necessarily transfer to `/api/orders/123`.

> Burp Scanner automatically detects path-mapping-discrepancy-based WCD during audits. The **Web Cache Deception Scanner** BApp extension can also be used for dedicated detection.

---

### 8.2 Delimiter Discrepancies

**Concept:** Delimiters mark boundaries between URL elements (`?` separating path from query string is the universal example). Because the URI specification is permissive, different frameworks implement **additional**, non-standard delimiters inconsistently.

**Example — Java Spring's `;` (matrix variables):**
```
/profile;foo.css
```
- **Java Spring origin server:** uses `;` to denote matrix-variable parameters — truncates the path after `/profile` and returns profile data, discarding everything after the semicolon.
- **A cache not built for Spring:** treats `;foo.css` as a literal part of the path. If it has a `.css` extension rule, it caches the profile data.

**Example — Ruby on Rails' `.` (format specifier):**
```
/profile        → default HTML formatter → returns profile info
/profile.css    → recognized as CSS extension, no CSS formatter exists → error
/profile.ico    → .ico NOT recognized by Rails → falls back to default HTML formatter → returns profile info
```
If the cache has a `.ico` rule, `/profile.ico` becomes an exploitable WCD vector — Rails ignores the unrecognized extension and serves the real data, while the cache stores it as if it were an icon file.

**Example — encoded null byte delimiter (OpenLiteSpeed):**
```
/profile%00foo.js
```
- OpenLiteSpeed origin servers treat the decoded `%00` as a delimiter → path becomes `/profile`.
- Most other server software errors out on `%00` in a URL — but caches like **Akamai or Fastly** may simply treat `%00foo.js` as literal path content, applying the `.js` extension rule.

**Testing methodology:**

```
Step 1 — Establish a reference (non-delimiter baseline):
  Add an arbitrary string with NO delimiter: /settings/users/list → /settings/users/listaaa
  Note this response as your baseline.

  ⚠ If this response is IDENTICAL to the original (un-modified) request,
  the request is likely being redirected — pick a different endpoint.

Step 2 — Test candidate delimiter characters:
  Insert a candidate character between path and string: /settings/users/list;aaa
    - Response MATCHES the ORIGINAL (un-modified) request → ";" IS a delimiter
      (origin server truncated at /settings/users/list)
    - Response MATCHES the BASELINE (step 1, with arbitrary string) → ";" is
      NOT a delimiter (origin treated it as literal path content)

Step 3 — Test whether the CACHE also recognizes that delimiter:
  Add a static extension after the delimiter: /settings/users/list;aaa.js
    - If response IS cached → cache does NOT use ";" as a delimiter (sees the
      full literal path + extension) → exploitable discrepancy confirmed

Step 4 — Build the exploit:
  /settings/users/list;aaa.js
    Cache interprets:  /settings/users/list;aaa.js  (matches .js rule → caches it)
    Origin interprets: /settings/users/list          (returns real dynamic data)
```

**Practical advantage:** Delimiter usage tends to be **consistent across an entire server/framework**, so a working delimiter discovered on one endpoint often transfers successfully to many other endpoints on the same target.

**Browser-level pre-processing caveat:** Some delimiter characters get modified by the **victim's own browser before the request ever reaches the cache** — for instance, browsers URL-encode `{`, `}`, `<`, `>` automatically, and treat `#` as a fragment marker that gets stripped client-side and never sent to the server at all. These specific raw characters can't be used directly in a delivered exploit URL — though encoded variants may still work if the cache or origin decodes them (see Section 8.3).

> Use **Burp Intruder** with a candidate delimiter wordlist for efficient testing. Disable Intruder's automatic character encoding under **Payloads > Payload encoding** so your delimiter characters aren't mangled before sending.

---

### 8.3 Delimiter Decoding Discrepancies

**Concept:** Even when cache and origin server agree on *which characters* function as delimiters, they may disagree on whether to **decode** an encoded version of that character before treating it as one.

**Example — encoded `#`:**
```
/profile%23wcd.css
```
- **Origin server:** decodes `%23` → `#`, treats `#` as a delimiter → interprets path as `/profile` → returns real profile data.
- **Cache:** also uses `#` as a delimiter in principle, but does **not** decode `%23` first → sees the literal string `/profile%23wcd.css` → if a `.css` extension rule exists, caches the profile response.

**Example — order-of-operations discrepancy:**
```
/myaccount%3fwcd.css
```
- **Cache:** applies its cache rules against the **encoded** path first (`/myaccount%3fwcd.css` matches the `.css` rule → decides to cache) — *then* decodes `%3f` → `?` and forwards the rewritten request onward.
- **Origin server:** receives the already-decoded `/myaccount?wcd.css`, treats `?` as a delimiter → interprets the real path as `/myaccount`.

This shows that **decoding order**, not just *whether* decoding happens, can independently create exploitable discrepancies.

**Testing methodology:** Apply the same delimiter-testing process from Section 8.2, but test **encoded variants** of every candidate delimiter character. Specifically prioritize encoded non-printable characters — `%00`, `%0A`, `%09` — since these are especially likely to truncate parsing differently across different parser implementations if decoded.

---

## 9. Exploiting Static Directory Cache Rules

Static directory rules cache anything under a known prefix like `/static`, `/assets`, `/scripts`, or `/images`. Exploiting these requires combining a **path traversal** payload with a **normalization discrepancy**.

> Understanding basic path traversal mechanics (`../`, encoded variants) is a prerequisite here.

### 9.1 Normalization Discrepancies

**Normalization** is the process of converting various representations of a URL path into one standardized form — this often includes decoding percent-encoded characters and resolving `../` (dot-segment) sequences, but implementations vary widely.

**Example — `/static/..%2fprofile`:**
- An origin server that **decodes slashes and resolves dot-segments** normalizes this to `/profile` → returns real profile data.
- A cache that does **not** resolve dot-segments interprets the literal string `/static/..%2fprofile` → if it has a `/static` prefix rule, it caches the profile response.

**Critical encoding requirement:** Every dot-segment in your traversal sequence must be **encoded** (`%2f` for `/`, etc.) — otherwise the **victim's own browser** will resolve the traversal locally before the request is ever sent, defeating the attack before it reaches the server at all. An exploitable discrepancy fundamentally requires that at least one of the two servers (cache or origin) performs its own decode-and-resolve step server-side.

---

### 9.2 Detecting Normalization by the Origin Server

```
Step 1: Pick a NON-CACHEABLE resource — ideally one using a non-idempotent
        method like POST, since these are essentially never cached, ensuring
        your test results reflect ORIGIN behavior only, uncontaminated by
        caching effects.

Step 2: Add a path traversal sequence + arbitrary directory at the START:
        /profile  →  /aaa/..%2fprofile

Step 3: Compare to the baseline (original /profile) response:
        - MATCHES baseline (returns same profile data) → origin DECODES the
          slash and RESOLVES the dot-segment → normalizes to /profile
        - DOESN'T match (e.g. 404) → origin does NOT decode/resolve →
          interprets literal path /aaa/..%2fprofile
```

**Testing nuance:** Start by encoding only the **second** slash in the dot-segment sequence (not the first) — some CDNs specifically pattern-match the slash immediately following a static directory prefix, so leaving the first slash unencoded avoids accidentally tripping that separate matching logic. You can also try fully encoding the entire traversal sequence, or encoding the dot characters instead of the slash — different encoding choices can change whether a given parser decodes the sequence at all.

---

### 9.3 Detecting Normalization by the Cache Server

```
Step 1: Identify candidate static directories.
        In Proxy > HTTP history, filter to 2xx responses with script/image/CSS
        MIME types, and look for common prefixes like /resources, /assets, /static.

Step 2: Pick a request showing evidence of caching under that prefix.
        Add a path traversal + arbitrary directory at the START of the FULL path:
        /assets/js/stockCheck.js  →  /aaa/..%2fassets/js/stockCheck.js

        - Response NO LONGER cached → cache does NOT normalize before mapping
          → confirms a /assets prefix-based rule exists (the leading aaa/../
          broke the prefix match, so the rule no longer applies)
        - Response STILL cached → may indicate cache HAS normalized the path
          back down to /assets/js/stockCheck.js

Step 3: Cross-check by adding traversal AFTER the prefix instead:
        /assets/js/stockCheck.js  →  /assets/..%2fjs/stockCheck.js

        - Response NO LONGER cached → cache DECODES the slash and RESOLVES
          the dot-segment, interpreting this as /js/stockCheck.js (outside the
          /assets prefix, so the rule no longer matches) → confirms /assets
          prefix rule + cache normalization behavior
        - Response STILL cached → cache has NOT decoded/resolved, still sees
          literal /assets/..%2fjs/stockCheck.js (which still starts with
          /assets, so the prefix rule still matches)

Step 4: Rule out a DIFFERENT cache rule being responsible (e.g. extension-based)
        by testing an arbitrary string instead of a real resource path:
        /assets/aaa
        If THIS is still cached → confirms the rule is specifically based on
        the /assets PREFIX, not something else like file extension.
```

**Caveat on 404 responses:** A response no longer appearing cached doesn't always conclusively rule out a static-directory rule — some cache configurations specifically don't cache `404` responses regardless of path matching, which can produce a false negative during testing. In some cases you may not be able to definitively confirm cache normalization behavior without actually attempting the full exploit.

---

### 9.4 Exploiting Origin Server Normalization

**Applies when:** the **origin server** decodes/resolves dot-segments, but the **cache** does not.

**Payload structure:**
```
/<static-directory-prefix>/..%2f<dynamic-path>
```

**Example — `/assets/..%2fprofile`:**
```
Cache interprets:  /assets/..%2fprofile   (matches the /assets prefix rule → caches it)
Origin interprets: /profile               (decodes & resolves → returns real profile data)
```

The origin server returns the genuine dynamic profile information, which then gets stored by the cache under a URL that still starts with the trusted `/assets` prefix.

---

### 9.5 Exploiting Cache Server Normalization

**Applies when:** the **cache** decodes/resolves dot-segments, but the **origin server** does not. This is the inverse scenario — and notably **harder to exploit**, requiring an additional ingredient.

**Why path traversal alone isn't enough here:**
```
Payload: /profile%2f%2e%2e%2fstatic

Cache interprets:  /static                          (decodes everything → resolves to /static)
Origin interprets: /profile%2f%2e%2e%2fstatic        (doesn't decode → treats literally)
```
The origin server, receiving the un-decoded literal string, is very likely to throw an **error** rather than return the real profile data — because that literal string doesn't correspond to any valid route.

**The fix — combine with a delimiter the origin recognizes but the cache doesn't:**

```
Payload: /profile;%2f%2e%2e%2fstatic

Origin server: uses ";" as a delimiter → truncates path at /profile → returns real profile data
Cache server:  decodes everything, including past the ";" → resolves to /static → matches the
               static-directory rule → caches the response
```

Result:
```
Cache interprets:  /static    (caches the response under this key)
Origin interprets: /profile   (returns the genuine dynamic data)
```

**Testing process for finding the right delimiter in this scenario:** Add candidate delimiter characters into the payload immediately **after** the dynamic path portion, and observe:
- If the **origin server** recognizes the delimiter → it truncates and returns the real dynamic data (success signal)
- If the **cache** does **not** recognize that same delimiter → it doesn't truncate, fully resolves the traversal, and caches the response (success signal)

**Encoding requirement for this variant:** Encode **every** character in the path traversal sequence (not selectively, as in Section 9.2) — this avoids unpredictable interactions with the delimiter character itself, and since the cache is the one performing the decode-and-resolve step here, there's no need to leave any slash unencoded for browser-level pre-processing reasons.

---

## 10. Exploiting File Name Cache Rules

Certain universally-required files — `robots.txt`, `index.html`, `favicon.ico` — change infrequently and are commonly cached by **exact file name match** rather than extension or directory prefix.

**Detecting the rule:** Send a `GET` request for a candidate well-known file and check whether the response shows caching evidence (`X-Cache: miss` → resend → `hit`).

**Detecting origin server normalization:** Identical methodology to Section 9.2 (non-cacheable resource + leading traversal sequence).

**Detecting cache normalization for file-name rules:**
```
/profile%2f%2e%2e%2findex.html

- Response IS cached → cache normalizes the path down to /index.html
- Response is NOT cached → cache does not decode/resolve, treats the literal
  string /profile%2f%2e%2e%2findex.html as the path (which doesn't match
  the exact file name rule for index.html)
```

**The key exploitability constraint for this rule type:**

Because file-name rules require an **exact match** on the file name itself, you can **only** exploit a discrepancy where the **cache server** resolves the dot-segments but the **origin server** does not. (The reverse case — origin resolves, cache doesn't — isn't usable here, because the cache would never recognize the literal unresolved string as matching the exact target file name in the first place.)

**Exploitation method:** Identical to Section 9.5 (Exploiting Cache Server Normalization) — simply substitute the static directory prefix with the specific target file name in the payload structure. You'll still typically need to combine it with a delimiter the origin recognizes but the cache doesn't, for the same reasons described in 9.5.

---

## 11. Impact Assessment

| Cache Rule Exploited | Typical Sensitive Data Exposed |
|----------------------|--------------------------------|
| Static extension rules | API keys, account details, session-bound data rendered on dynamic pages |
| Static directory rules | Same as above, when dynamic endpoints can be path-traversed into a trusted static prefix |
| File name rules | CSRF tokens, account details — especially powerful against admin-only pages if the victim can be lured |

### Escalation Path

```
Web Cache Deception Confirmed
        │
        ├── Victim's API key cached → attacker retrieves it → full API access as victim
        │
        ├── Victim's CSRF token cached → attacker retrieves it
        │        │
        │        └── Attacker forges a state-changing request using the
        │             stolen token (e.g. change email) → triggers password
        │             reset to attacker-controlled address → full account takeover
        │
        └── If victim is an ADMINISTRATOR → token/data theft → full
             administrative account compromise
```

**Why targeting administrators specifically matters:** If an attacker can lure a privileged user (administrator, support staff) into visiting the crafted URL, the cached sensitive data belongs to that high-privilege account — turning a single successful deception into full administrative compromise rather than a single regular-user account.

---

## 12. Defense & Prevention

### Defense 1 — Explicit Cache-Control Headers on All Dynamic Responses

This is the most direct fix. Every endpoint returning dynamic, sensitive, or user-specific content should explicitly declare itself non-cacheable:

```
Cache-Control: no-store, private
```

`no-store` instructs caches and browsers never to store the response at all, under any circumstances. `private` additionally signals that the response is specific to one user and must not be shared across users even if some caching layer were to retain it.

### Defense 2 — Ensure CDN Configuration Respects Cache-Control

Setting the header alone isn't sufficient if the CDN's own configured caching rules are allowed to **override** it. Explicitly configure your CDN so that path-extension, path-prefix, or file-name based caching rules **never take precedence over** an explicit `Cache-Control: no-store, private` header from the origin.

### Defense 3 — Enable CDN-Specific Anti-Deception Protections

Many CDNs provide a built-in protection mechanism that verifies the response's actual `Content-Type` matches the file extension implied by the *request's* URL — rejecting cache storage when there's a mismatch (e.g., a request ending in `.css` that actually returns `Content-Type: application/json`). Example: **Cloudflare's Cache Deception Armor**. Activate and properly configure any equivalent feature your CDN provider offers.

### Defense 4 — Eliminate Parsing Discrepancies Between Cache and Origin

The deepest fix is architectural: ensure the cache and origin server **agree** on how they interpret URL paths — specifically:
- Consistent **path mapping** (does the path get abstracted/ignored beyond a certain point, or interpreted literally, the same way on both sides?)
- Consistent **delimiter handling** (do both treat the same characters — `;`, `?`, `#`, encoded variants — as boundaries, or neither?)
- Consistent **normalization** (do both decode percent-encoding and resolve `../` sequences identically, or neither?)

In practice this usually means choosing cache/CDN infrastructure that is explicitly tested against and compatible with your specific backend framework's URL parsing conventions, rather than assuming generic compatibility.

---

## 13. Quick Reference Cheat Sheet

### Detection Signal Reference

```
X-Cache: hit       → served from cache
X-Cache: miss      → not cached (yet) — resend to check if subsequent hit
X-Cache: dynamic   → origin-generated, not cacheable
X-Cache: refresh   → stale cache entry was revalidated
Cache-Control: public, max-age=N  → suggests cacheable (not guaranteed)
Noticeably faster response time   → secondary signal of cache hit
```

### General Testing Skeleton (Apply to Any Rule Type)

```
1. Confirm target endpoint leaks sensitive data (full response, not just rendered page)
2. Confirm method is GET/HEAD/OPTIONS (state-changing methods generally aren't cached)
3. Probe origin server path interpretation (does it abstract/ignore extra segments?)
4. Probe cache path interpretation (does adding a static extension trigger caching?)
5. If no immediate match → test delimiters (;,?,#,%00,%23,%3f, etc.) on both sides
6. If still no match → test normalization (encoded dot-segment path traversal)
7. Build payload exploiting whichever discrepancy was found
8. Deliver to victim with a cache-busting parameter so it gets its own cache entry
9. Retrieve the cached response via Burp Repeater (not the browser)
```

### Path Mapping Discrepancy Payloads

```
/api/orders/123/foo          → tests origin abstraction
/api/orders/123/foo.js       → tests cache extension rule
/user/123/profile/wcd.css    → classic REST-vs-traditional mapping exploit
```

### Delimiter Discrepancy Payloads

```
/path;arbitrary.js     → Java Spring-style ; delimiter
/path.ico              → Ruby on Rails unrecognized-extension fallback
/path%00arbitrary.js   → OpenLiteSpeed null-byte delimiter
/path%23arbitrary.css  → encoded # delimiter decoding discrepancy
/path%3farbitrary.css  → encoded ? delimiter decoding discrepancy
```

### Normalization Discrepancy Payloads

```
Origin-server normalization exploit (static directory):
  /<static-prefix>/..%2f<dynamic-path>
  e.g.  /assets/..%2fprofile

Cache-server normalization exploit (static directory — needs a delimiter too):
  /<dynamic-path>;%2f%2e%2e%2f<static-prefix>
  e.g.  /profile;%2f%2e%2e%2fstatic

File name rule exploit (exact match — cache-server normalization variant only):
  /<dynamic-path>;%2f%2e%2e%2f<exact-file-name>
  e.g.  /my-account;%2f%2e%2e%2frobots.txt
```

### Burp Workflow Checklist

```
[ ] Install Param Miner → enable dynamic cachebuster
[ ] Send target GET request to Repeater
[ ] Test arbitrary path segment → check origin abstraction
[ ] Send to Intruder with §delimiter§ position → test full ASCII charset
      (disable auto URL-encoding under Payloads > Payload encoding)
[ ] Sort Intruder results by status code / response length to spot delimiters
[ ] Confirm caching with X-Cache header before/after resend
[ ] Build exploit URL combining confirmed discrepancy
[ ] Deliver via exploit server / phishing link with unique cache-buster param
[ ] Retrieve victim's cached response via Repeater within the cache TTL window
```

### Decision Tree

```
Does the endpoint leak sensitive data on GET/HEAD/OPTIONS?
├── No  → not exploitable via WCD
└── Yes → does adding an arbitrary path segment still return the same data?
          ├── Yes (origin abstracts path) → try static EXTENSION rule (Section 8.1)
          └── No → does a delimiter character (;, ?, #, %00...) truncate the
                   origin's interpretation?
                   ├── Yes → try delimiter-based extension exploit (Section 8.2/8.3)
                   └── No  → does encoded path traversal (..%2f) get resolved
                            differently by cache vs origin?
                            ├── Origin resolves, cache doesn't → static directory
                            │   exploit, Section 9.4
                            └── Cache resolves, origin doesn't → static directory
                                OR file-name exploit + delimiter, Section 9.5/10
```