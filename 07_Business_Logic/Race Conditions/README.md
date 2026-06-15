# Race Conditions

## Table of Contents

1. [What Are Race Conditions?](#1-what-are-race-conditions)
2. [Core Concept: Sub-States & Race Windows](#2-core-concept-sub-states--race-windows)
3. [The Challenge: Timing](#3-the-challenge-timing)
4. [Attack Techniques: How to Win the Race](#4-attack-techniques-how-to-win-the-race)
5. [Race Condition Types & Exploitation](#5-race-condition-types--exploitation)
   - 5.1 [Limit Overrun (TOCTOU)](#51-limit-overrun-toctou)
   - 5.2 [Multi-Endpoint Race Conditions](#52-multi-endpoint-race-conditions)
   - 5.3 [Single-Endpoint Race Conditions](#53-single-endpoint-race-conditions)
   - 5.4 [Partial Construction Race Conditions](#54-partial-construction-race-conditions)
   - 5.5 [Time-Sensitive Attacks (Token Prediction)](#55-time-sensitive-attacks-token-prediction)
6. [Hidden Multi-Step Sequences](#6-hidden-multi-step-sequences)
7. [Detection Methodology](#7-detection-methodology)
8. [Obstacles & How to Beat Them](#8-obstacles--how-to-beat-them)
9. [Defense & Prevention](#9-defense--prevention)
10. [Quick Reference Cheat Sheet](#10-quick-reference-cheat-sheet)

---

## 1. What Are Race Conditions?

Race conditions happen when a web application **processes multiple requests concurrently** but doesn't properly protect shared data from being accessed at the same time. Two threads "race" to read/write the same record, and their operations **collide** in a way the developer never intended.

### Simple Analogy

Imagine two cashiers at a bank (two request threads) both checking your balance at the same moment. Your balance is $100. Both see $100, both approve a $100 withdrawal. You end up getting $200 out of a $100 account. Neither cashier was wrong — they just both acted on the same snapshot of data before either could record the withdrawal.

### Relationship to Business Logic Flaws

Race conditions are a **time-sensitive subtype** of business logic vulnerabilities. The flaw isn't in what the application does, but in the **order and timing** of when it does it.

---

## 2. Core Concept: Sub-States & Race Windows

### What Is a Sub-State?

A **sub-state** is a temporary, invisible state that an application passes through during the processing of a single request — before the operation is fully complete.

**Example — Discount Code Redemption:**
```
Step 1: Check if code has been used   ← Reads DB
Step 2: Apply discount to order       ← Modifies in-memory state
Step 3: Mark code as used in DB       ← Writes DB
         ↑___________________________↑
                 SUB-STATE
         Code is "not used yet" in DB while steps 1-3 are in flight
```

If two requests hit Step 1 at the same time, both see the code as "not used," both apply the discount, and only then does Step 3 run — but it may only run once (or for both, depending on implementation).

### What Is a Race Window?

The **race window** is the tiny time gap between when a check happens and when the state change that closes that check is committed. It could be:

- Microseconds between two SQL queries
- Milliseconds between a read and a write to a session
- The time it takes for a background thread to send an email

```
Timeline:
[Request A starts] ──────────────────────────[Request A: Write to DB]
       │
       └─── [Request B starts here] ─── [Request B: Read from DB — sees stale state!]
            ↑_____________________________↑
                     RACE WINDOW
```

---

## 3. The Challenge: Timing

The hardest part of race condition exploitation is **getting two requests to hit the race window at the same time**. Problems include:

| Problem | Description |
|---------|-------------|
| **Network jitter** | Packets arrive at unpredictable times due to network latency variance |
| **TCP handshake overhead** | Each new connection takes time before the first byte of the request is sent |
| **Server-side queuing** | Some frameworks (e.g. PHP sessions) process requests for the same session serially |
| **Endpoint processing time mismatch** | One endpoint may be much slower than another |

### Solution: Single-Packet Attack (HTTP/2)

Burp Suite (v2023.9+) solves network jitter by sending **20-30 requests inside a single TCP packet**. Since all requests arrive at the server in the same network event, they are all queued for processing simultaneously — eliminating jitter at the network layer.

```
Traditional approach:         Single-Packet Attack:
[Req 1] ──→ arrives at t=0   [Req 1 + Req 2 + ... + Req 20] ──→ all arrive at t=0
[Req 2] ──→ arrives at t=2ms  (packed in one TCP packet)
[Req 3] ──→ arrives at t=5ms  Server sees all 20 simultaneously
```

### Last-Byte Synchronization (HTTP/1 Fallback)

For servers that only support HTTP/1, Burp uses **last-byte sync**: it sends all request headers and body bytes **except the final byte** across all connections, then sends the last byte for all connections simultaneously — causing all requests to be fully received at the same moment.

---

## 4. Attack Techniques: How to Win the Race

### Using Burp Repeater (Built-In)

1. Send the target request to Repeater.
2. Create a **tab group** with duplicates (right-click → Duplicate Tab × 19).
3. **Baseline:** Send group in sequence (separate connections) — establish normal behavior.
4. **Attack:** Send group in parallel — triggers race condition.
5. Watch for any response that deviates from baseline (different status, message, or second-order effect).

### Using Turbo Intruder (Advanced)

Required for: large-scale attacks, staggered timing, multiple retries, or complex multi-step workflows.

**Key configuration for single-packet attack:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,    # Must be 1 for single-packet
        engine=Engine.BURP2         # HTTP/2 engine
    )
    for i in range(20):
        engine.queue(target.req, gate='1')  # All go into gate '1'
    engine.openGate('1')                    # Release all at once
```

> **Note:** Turbo Intruder requires HTTP/2 support on the target for the single-packet attack. Use `Engine.BURP1` + `lastFlushedRequest=True` for HTTP/1 last-byte sync.

---

## 5. Race Condition Types & Exploitation

### 5.1 Limit Overrun (TOCTOU)

**What it is:** The most classic race condition. Exploits the gap between a **check** (Time-Of-Check) and the **use/update** of that check result (Time-Of-Use).

**Vulnerable Pattern (pseudocode):**
```python
if not coupon_used(user_id, code):      # CHECK (READ)
    apply_discount(cart, code)          # USE
    mark_coupon_used(user_id, code)     # UPDATE
```

If two requests both pass the `if` check before either marks the coupon as used, both get the discount.

**Real-World Targets:**
- Discount/promo codes (apply multiple times)
- Gift card redemption (redeem same card twice)
- Voting/rating systems (rate the same product twice)
- Cash withdrawals (exceed account balance)
- Anti-brute-force rate limits (bypass login attempt counter)
- CAPTCHA reuse (submit same solution twice)

**Detection Tip:** Look for endpoints that return a "already used / already done" message on the second attempt — these are limit-enforcement endpoints and prime candidates for TOCTOU testing.

---

### 5.2 Multi-Endpoint Race Conditions

**What it is:** Sending requests to **two different endpoints simultaneously**, where both interact with the same underlying data. One endpoint validates a condition, the other modifies state — and by racing them, you can bypass the validation.

**Classic Example — Cart Checkout:**
```
Normal flow:
[POST /cart/checkout] → validates payment → confirms order → done

Race attack:
[POST /cart/checkout]  ←──── sent simultaneously ────→  [POST /cart]
     validates payment ← race window exists here →  adds expensive item to cart
     confirms order (now with extra item included!)
```

The checkout validation runs against the cart at time T. The `POST /cart` adds the expensive item at time T+1ms. But the confirmation happens at T+2ms — and includes the newly added item.

**Alignment Challenge:** Different endpoints take different amounts of time to process. The race window for each may not naturally overlap.

**Fix: Connection Warming**

Before your actual attack, send a throwaway request (e.g., `GET /`) over the same connection to warm it up. This eliminates the initial TCP setup delay, making subsequent requests arrive more synchronously.

```
Tab Group Setup (in order):
1. GET /          ← warming request (throwaway)
2. POST /cart/checkout   ← attack request 1
3. POST /cart            ← attack request 2

Send: "Send group in sequence (single connection)" first to warm
Then: "Send group in parallel" for the actual attack
```

---

### 5.3 Single-Endpoint Race Conditions

**What it is:** Sending multiple parallel requests to the **same endpoint** with **different parameter values** to cause a collision on shared session/database state.

**Example — Password Reset Token Collision:**
```python
session['reset-user'] = username_from_request
session['reset-token'] = generate_token()
send_email(session['reset-user'], session['reset-token'])
```

Two parallel requests:
- Request A: `username=attacker`
- Request B: `username=victim`

**Race outcome (one possible ordering):**
```
Req A writes: session['reset-user'] = 'attacker'
Req B writes: session['reset-user'] = 'victim'      ← overwrites
Req A writes: session['reset-token'] = token_1234
Req B: email sent to 'victim' with token_1234        ← attacker's token!
```

The session now has `victim`'s user ID but `attacker` receives (or knows) the token. The attacker uses their token to reset the victim's password.

**Why email operations are especially vulnerable:** Emails are often sent by a **background thread** after the HTTP response is already returned. This means the race window between "token generated" and "email sent" is wider and more predictable.

---

### 5.4 Partial Construction Race Conditions

**What it is:** Applications that create objects in **multiple sequential steps** leave a temporary window where the object exists in an **incomplete/uninitialized state**.

**Example — User Registration:**
```sql
-- Step 1: Create user record
INSERT INTO users (username, email) VALUES ('newuser', 'x@y.com');

-- Step 2: Set API key (separate operation)
UPDATE users SET api_key = 'abc123xyz' WHERE username = 'newuser';
```

Between Step 1 and Step 2, the user exists but `api_key = NULL`.

**Exploitation Trick:**

If you can send an API request during that window using a value that **matches NULL**, you can authenticate as the new user before they even have a proper key.

In PHP, you can pass an empty array instead of a string:
```
# Normal request:
GET /api/user/info?user=victim&api-key=abc123

# Attack during partial construction window:
GET /api/user/info?user=victim&api-key[]=
```
`api-key[]=` translates to an empty array `[]` server-side. When compared to an uninitialized (null) DB value, it may match — granting access.

**Framework-Specific Null Tricks:**

| Framework | Syntax | Result |
|-----------|--------|--------|
| PHP | `param[]=` | Empty array `[]` |
| PHP | `param[]=foo&param[]=bar` | `['foo', 'bar']` |
| Ruby on Rails | `param[key]` | `{"key" => nil}` |

---

### 5.5 Time-Sensitive Attacks (Token Prediction)

**What it is:** Not a race condition in the traditional sense, but uses the same **precise parallel timing technique** to exploit tokens generated from **timestamps** instead of cryptographically random values.

**Vulnerable token generation:**
```python
token = hash(timestamp + some_static_value)  # Predictable if timestamp is known
```

**Attack:**
1. Trigger two password reset requests **in parallel** for two different users.
2. If both requests are processed at the same millisecond, both get the **same timestamp input** → **same token**.
3. You receive your own reset email with the token.
4. Change the username in the reset URL to the victim's username — same token works.

**Diagnosis Step — Detect Timestamp-Based Tokens:**
- Request multiple resets for yourself.
- If tokens are different each time → some internal state (timestamp, counter, RNG) is involved.
- Send parallel resets → if you get the same token in both emails → timestamp is the source.

**Obstacle — PHP Session Locking:**
PHP processes only one request per session at a time. So parallel requests from the same session run sequentially — killing the attack.

**Bypass:**
- Fetch a fresh session cookie by making a request without any cookie.
- Use one session token for Request A, the new session token for Request B.
- Now both sessions are independent → process truly in parallel.

---

## 6. Hidden Multi-Step Sequences

A single HTTP request can trigger multiple internal operations, transitioning the application through several **invisible sub-states** before completing.

### Example — MFA Bypass via Race Condition

```python
session['userid'] = user.userid          # Sub-state 1: logged in, but MFA not enforced yet
if user.mfa_enabled:
    session['enforce_mfa'] = True        # Sub-state 2: MFA flag set
    generate_and_send_mfa_code(user)
    redirect_to_mfa_form()
```

**Race window:** Between `session['userid']` being set and `session['enforce_mfa']` being set, there is a tiny moment where the user is **authenticated but MFA is not yet enforced**. If an attacker sends a request to a protected endpoint **during that window**, they can access it without completing MFA.

This is a time-sensitive version of the classic "force browsing" MFA bypass, except instead of navigating directly after Step 1, the attacker races against the server's own internal execution.

---

## 7. Detection Methodology

### Step 1 — Predict Potential Collisions

Don't test everything. Ask these filtering questions:

- **Is this endpoint security-critical?** (login, payment, discount codes, account changes, permissions)
- **Does this endpoint interact with shared data?** (same DB record, same session variable, same file)
- **Do two different users/requests modify the same record?** (single-record password reset vs. per-user-record)

### Step 2 — Probe for Clues (Benchmarking)

1. Group your requests in Burp Repeater.
2. **Baseline:** Send group in sequence (separate connections) → record normal behavior.
3. **Attack:** Send group in parallel (single-packet) → compare responses.

**Clues to watch for:**
- Different HTTP status code in one of the responses
- Different response message than expected (e.g., "success" when "already used" was expected)
- Unexpected change in application state (extra balance, double discount)
- **Second-order effects:** Different email content, changed value in DB viewed through UI

### Step 3 — Prove the Concept

- Strip away unnecessary requests — confirm the minimum set needed to reproduce.
- Repeat multiple times — race conditions are probabilistic. Reproducibility varies.
- Think about it as a **structural weakness**, not just a single bug — the same root cause may have multiple exploitation paths.

---

## 8. Obstacles & How to Beat Them

| Obstacle | Cause | Fix |
|----------|-------|-----|
| Requests processed sequentially | PHP session locking | Use a different session token for each parallel request |
| Responses arrive at very different times | Endpoint processing time mismatch | Use connection warming (preflight GET request) |
| Race still unreliable on single endpoint | Back-end processing delay | Use Turbo Intruder + trigger server-side delay via rate/resource limit abuse |
| Single-packet attack not working | Server only supports HTTP/1 | Use last-byte sync (Burp handles this automatically) |
| Attack works locally, not in prod | High network jitter on internet-facing target | Use single-packet attack to neutralize jitter |

### Connection Warming in Detail

```
Tab Group Order:
┌─────────────────────────────────┐
│  1. GET /homepage  (throwaway)  │  ← Warms up back-end connection
│  2. POST /cart/checkout         │  ← Real attack request 1
│  3. POST /cart (add jacket)     │  ← Real attack request 2
└─────────────────────────────────┘
Send mode: "Send group in sequence (single connection)" first to warm
Then switch to: "Send group in parallel"
```

### Abusing Rate Limits to Force Synchronization

If endpoints have mismatched processing times and warming doesn't fix it:
1. Send a flood of dummy requests to trigger the server's rate limiter.
2. The server starts queuing incoming requests.
3. Your real attack requests (arriving at the same time) get queued together and processed nearly simultaneously.
4. This makes the single-packet attack viable even when server-side delays exist.


---

## 9. Defense & Prevention

### Core Principle: Eliminate Sub-States

The root cause of all race conditions is the existence of temporary, exploitable sub-states. The goal of defense is to make sensitive operations **atomic** — they either fully complete or fully don't. There is no in-between visible to concurrent requests.

### Strategy 1: Use Atomic Database Operations

Instead of separate read → modify → write queries, use a **single atomic transaction**:

```sql
-- VULNERABLE (three separate operations):
SELECT used FROM coupons WHERE code = 'SAVE20';  -- check
UPDATE orders SET total = total * 0.8;            -- apply
UPDATE coupons SET used = TRUE WHERE code = 'SAVE20'; -- record

-- SAFE (single atomic transaction):
BEGIN TRANSACTION;
  UPDATE coupons SET used = TRUE
  WHERE code = 'SAVE20' AND used = FALSE;  -- check + update atomically
  
  IF rows_affected = 1 THEN
    UPDATE orders SET total = total * 0.8;
  END IF;
COMMIT;
```

### Strategy 2: Use Database Constraints

Add **uniqueness constraints** and integrity rules at the database level as a defense-in-depth measure — even if application code has a race window, the DB will reject a duplicate:

```sql
ALTER TABLE coupon_usage ADD CONSTRAINT unique_user_coupon
UNIQUE (user_id, coupon_code);
```

Any second insertion for the same user+coupon will throw a DB error, regardless of application-level timing.

### Strategy 3: Don't Mix Storage Layers for Security

Don't use sessions to protect database-level limits. Sessions are not transactional — don't use `$_SESSION['coupon_applied'] = true` as your only guard if the actual data is in a database. These two layers can get out of sync.

### Strategy 4: Keep Sessions Internally Consistent

Update session variables **in a single batch operation**, not one by one. Updating them individually creates sub-states within the session itself. This applies equally to ORMs — if you use one, make sure it uses transactions for multi-field updates.

### Strategy 5: Watch Out for Object Partial Construction

When creating objects that require multiple steps (e.g., create user → set API key), either:
- Do it in a single transaction, or
- Don't allow the object to be "used" until all steps complete (use a status flag: `is_ready = false` until finalization)

### Strategy 6: Detect and Handle Session-Based Locking Correctly

If you use PHP (or similar frameworks with per-session locking), be aware that this **masks** race conditions during testing — they may still exist in other paths or with different session handling.

### Strategy 7: Stateless Architecture (Advanced)

For some systems, avoid server-side state entirely. Use encrypted tokens (JWTs) to push state client-side. This eliminates shared mutable server state — but introduces its own risks (JWT attacks), so weigh carefully.

---

## 10. Quick Reference Cheat Sheet

### Signs a Endpoint May Be Vulnerable

- Returns "already used / already applied / rate limited" on repeated attempts
- Involves: payments, discounts, vouchers, votes, withdrawals, login attempts
- Multiple DB operations in sequence (read then write)
- Email sent in background thread (email change, password reset, registration confirmation)
- Token generation based on timestamp rather than CSPRNG

### Burp Repeater Attack Setup

```
1. Send request to Repeater
2. Add to Group → Duplicate Tab × 19 (= 20 total)
3. Sequential (separate connections) = baseline
4. Parallel = attack
5. Watch for ANY response that deviates from baseline
```

### Turbo Intruder Single-Packet Template

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )
    for payload in wordlists.clipboard:
        engine.queue(target.req, payload, gate='1')
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

### Common Race Condition Types Summary

| Type | Target | Key Symptom | Attack Method |
|------|--------|-------------|---------------|
| Limit Overrun (TOCTOU) | Coupons, rate limits | "Already used" on retry | Parallel duplicate requests |
| Multi-Endpoint | Cart + checkout | Validation on different request than action | Parallel cross-endpoint requests |
| Single-Endpoint | Password reset, email change | Shared session/DB record | Parallel same-endpoint, different params |
| Partial Construction | Registration, API key creation | Null/empty accepted during init | Null-param trick during creation window |
| Time-Sensitive | Token generation | Token identical in parallel resets | Parallel requests, different sessions |

### Response Headers / Indicators

| Signal | Meaning |
|--------|---------|
| Multiple `200 OK` where only one is expected | Limit overrun likely succeeded |
| `302` in one response when others return `200` | Login success during brute-force race |
| Same token in two different emails | Timestamp-based token generation confirmed |
| Confirmation email sent to wrong address | Single-endpoint session collision |
| `Invalid token: Array` | Null-param trick accepted (partial construction candidate) |

---
