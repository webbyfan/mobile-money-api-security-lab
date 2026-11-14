# Penetration Test Report — Mobile-Money Wallet API Security Lab

| | |
|---|---|
| **Target** | Mobile-Money Wallet API (fictional lab application) |
| **Repository** | `mobile-money-api-security-lab` |
| **Version tested** | `v1-vulnerable` |
| **Test type** | Authenticated black-box / gray-box API penetration test |
| **Methodology** | OWASP API Security Top 10 (2023), OWASP WSTG |
| **Tester** | Ashenafi Belete Geleta |
| **Environment** | Isolated local lab (Docker, `127.0.0.1` only), synthetic test accounts and data |

> **Scope note:** This is a fictional application built specifically to practice and demonstrate API penetration testing skills. No real financial institution, customer data, or production system was involved. All findings were confirmed against a local, disposable lab instance.

---

## Executive Summary

Eleven distinct vulnerabilities were identified across authentication, authorization, business logic, and configuration controls. one finding is rated **Critical**, three **High**, and seven **Medium**. A chained exploit scenario demonstrates that two of these findings combine to allow complete authentication bypass and full account takeover without valid credentials.

| ID | Finding | OWASP API Category | CVSS v3.1 | Severity |
|---|---|---|---|---|
| F-01 | Broken Object Level Authorization (wallet balance & history) | API1:2023 | 6.5 | Medium |
| F-02 | NoSQL Injection & Excessive Data Exposure | API3:2023 | 6.5 | Medium |
| F-03 | Broken Function Level Authorization (admin endpoints) | API5:2023 | 8.0 | High |
| F-04 | Mass Assignment — Privilege Escalation & Balance Tampering | API3:2023 | 7.7 | High |
| F-05 | Forgotten Legacy Endpoint Bypasses PIN Control | API9:2023 | 6.5 | Medium |
| F-06 | Negative-Amount Transfer (Business Logic Flaw) | API6:2023 | 6.5 | Medium |
| F-07 | Server-Side Request Forgery (webhook test) | API7:2023 | 4.3 | Medium |
| F-08 | Verbose Errors Expose Internal Stack Traces | API8:2023 | 5.3 | Medium |
| F-09 | No Rate Limiting on Transaction PIN (Brute Force) | API4:2023 | 6.5 | Medium |
| F-10 | Hardcoded/Weak JWT Signing Secret | API2:2023 | 9.8 | Critical |
| F-11 | Race Condition in Fund Transfer (TOCTOU / Double-Spend) | API6:2023 | 7.7 | High |
| **CH-01** | **Chained: Forged Admin Token via Weak Secret + Privilege Escalation** | API2/API3 | 10.0 | **Critical** |

CVSS v3.1 base scores were calculated using the FIRST CVSS calculator methodology; recompute independently before including in a final client-facing report, as minor contextual adjustments (e.g. Scope) are a matter of professional judgment.

---

## Methodology

1. Authenticated testing was performed using two standard test accounts (`alice`, `bob`) and one administrative account (`admin`), seeded directly into the database.
2. Burp Suite (Community Edition) was used for request interception, repeating, and brute-force simulation (Intruder).
3. Custom Python scripts (`httpx`, `asyncio`) were used to demonstrate timing-sensitive business logic flaws (race conditions).
4. `hashcat` (CPU/PoCL backend) was used to attempt offline recovery of the JWT signing secret from a small wordlist.
5. All testing was performed against `http://127.0.0.1:3000`, bound to loopback only, using synthetic accounts and data.

---

## Detailed Findings

### F-01 — Broken Object Level Authorization (BOLA): Wallet Balance & Transaction History

**OWASP Category:** API1:2023 – Broken Object Level Authorization
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — **6.5 (Medium)**

**Affected Endpoints:**
- `GET /api/wallets/:id`
- `GET /api/wallets/:id/transactions`

**Description:** Both endpoints accept a user-supplied `id` and return the corresponding wallet's balance or transaction history without verifying that the requesting user owns that wallet.

**Steps to Reproduce:**
1. Authenticate as Alice and obtain a valid JWT.
2. Request `GET /api/wallets/<Bob's user ID>` using Alice's token.

**Evidence:**
```
GET /api/wallets/6af74e95f81df7a12c8f98c5 HTTP/1.1
Authorization: Bearer <Alice's token>

200 OK
{"_id":"6af74e95f81df7a12c8f98c5","phone":"0911000002","name":"Bob","balance":1000}
```

**Business Impact:** Any authenticated user can view any other customer's account balance and complete transaction history by guessing or enumerating object IDs — a direct violation of financial privacy expectations and likely regulatory disclosure obligations.

**Remediation:** Enforce ownership checks on every object-level route (`req.user.id === resource.ownerId`, or role-based exception for admin-only paths). Never trust a client-supplied identifier as sufficient authorization.

---

### F-02 — NoSQL Injection & Excessive Data Exposure (User Search)

**OWASP Category:** API3:2023 – Broken Object Property Level Authorization
**CWE:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic), CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — **6.5 (Medium)**

**Affected Endpoint:** `GET /api/users/search?phone=<value>`

**Description:** The `phone` query parameter is passed directly into a Mongoose query without type validation. Because Express's extended query parser converts bracket syntax into nested objects, an attacker can inject MongoDB query operators (e.g. `$regex`). The response also returns full user documents, including password hashes and plaintext transaction PINs.

**Steps to Reproduce:**
```
GET /api/users/search?phone[$regex]=.* HTTP/1.1
Authorization: Bearer <any valid token>
```

**Evidence:**
```json
[
  {
    "_id": "6af74e95f81df7a12c8f98c4",
    "phone": "0911000001",
    "name": "Alice",
    "passwordHash": "72fbe5547828dd7201cf5a59f40782bc:8ec42c4212485c178795062cc7d98de3f52f1a978e41aa1",
    "pin": "1234",
    "role": "user",
    "balance": 1000
  },
  { "...": "Bob, Admin — same fields exposed" }
]
```

**Business Impact:** Critical — this single endpoint discloses every customer's plaintext PIN and password hash in one request with no filtering. Combined with F-10 (weak JWT secret), this provides a complete path to full account compromise across the entire customer base.

**Remediation:** Reject non-string input for query parameters (disable or sanitize the extended query parser), validate and coerce types explicitly before building queries, and apply a response projection that excludes `passwordHash` and `pin` from every API response, regardless of endpoint.

---

### F-03 — Broken Function Level Authorization: Admin Endpoints

**OWASP Category:** API5:2023 – Broken Function Level Authorization
**CWE:** CWE-285 (Improper Authorization)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` — **8.0 (High)**

**Affected Endpoints:**
- `GET /api/admin/users`
- `POST /api/admin/adjust`

**Description:** Both routes are protected only by the generic `auth` middleware (valid JWT), with no check that `req.user.role === 'admin'`. Any authenticated standard user can list every account and arbitrarily credit or debit any balance.

**Steps to Reproduce:**
```
GET /api/admin/users HTTP/1.1
Authorization: Bearer <Alice's standard-user token>

200 OK  → returns all 3 user documents
```

**Business Impact:** A standard customer can mint unlimited funds into their own account or drain any other account directly, with no privilege check whatsoever. This is a complete breakdown of the authorization model for administrative functions.

**Remediation:** Add explicit role-based middleware (`requireRole('admin')`) on every administrative route. Fail closed by default — new routes should require explicit role grants rather than inheriting broad access.

---

### F-04 — Mass Assignment: Privilege Escalation & Balance Tampering

**OWASP Category:** API3:2023 – Broken Object Property Level Authorization
**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` — **7.7 (High)**

**Affected Endpoint:** `PATCH /api/users/me`

**Description:** The handler applies `Object.assign(user, req.body)` directly, with no allowlist. A caller can set any field on their own document, including `role` and `balance`.

**Steps to Reproduce:**
```
PATCH /api/users/me HTTP/1.1
Authorization: Bearer <Alice's token>
Content-Type: application/json

{"role":"admin","balance":999999}
```

**Evidence:**
```json
{"_id":"...","phone":"0911000001","role":"admin","balance":999999,"...":"..."}
```

**Business Impact:** Any customer can self-escalate to administrator and set their own balance to an arbitrary value with a single request — no further exploitation technique required.

**Remediation:** Use an explicit allowlist / schema-validated update (e.g. `zod`/`joi`) that only accepts user-editable fields such as `name`. Never pass raw request bodies into a document update.

---

### F-05 — Forgotten Legacy Endpoint Bypasses PIN Control

**OWASP Category:** API9:2023 – Improper Inventory Management
**CWE:** CWE-862 (Missing Authorization)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — **6.5 (Medium)**

**Affected Endpoint:** `POST /api/v0/transfer`

**Description:** An undocumented legacy transfer route shares the current transfer logic but omits the PIN verification step that the current `/api/transfer` endpoint enforces.

**Steps to Reproduce:**
```
POST /api/v0/transfer HTTP/1.1
Authorization: Bearer <Alice's token>
Content-Type: application/json

{"to":"0911000002","amount":5}
```

**Evidence:** `200 OK {"ok":true,"txId":"..."}` — funds moved with no PIN supplied at all.

**Business Impact:** Transaction-level authentication (the PIN, a second factor on top of session authentication) is entirely bypassed through an old API version that was never decommissioned.

**Remediation:** Maintain an authoritative API inventory and decommission or redirect deprecated versions. Apply security controls at a shared middleware/service layer so a forgotten route cannot silently omit a control enforced elsewhere.

---

### F-06 — Negative-Amount Transfer (Business Logic Flaw)

**OWASP Category:** API6:2023 – Unrestricted Access to Sensitive Business Flows
**CWE:** CWE-20 (Improper Input Validation)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — **6.5 (Medium)**

**Affected Endpoint:** `POST /api/transfer`

**Description:** The `amount` field is cast to a number but never checked for a positive value. Submitting a negative amount reverses the direction of the transfer — effectively pulling funds from the intended recipient into the sender's own account.

**Steps to Reproduce:**
```
POST /api/transfer HTTP/1.1
Authorization: Bearer <Alice's token>

{"to":"0911000002","amount":-50,"pin":"1234"}
```

**Evidence:** `200 OK {"ok":true,...}` — Alice's balance increased by 50 and Bob's decreased by 50, despite Alice being the nominal sender.

**Business Impact:** A malicious user can drain any counterparty's account (within transfer relationships they can initiate) simply by sending a negative value, with no additional authorization from the victim.

**Remediation:** Validate `amount > 0` server-side (do not rely on client-side or type-coercion assumptions), and reject or clamp any value outside an explicit, sane range.

---

### F-07 — Server-Side Request Forgery (Webhook Test)

**OWASP Category:** API7:2023 – Server Side Request Forgery
**CWE:** CWE-918 (Server-Side Request Forgery)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` — **4.3 (Medium)**
*(Score reflects the lab's demonstrated impact; internal network reachability to higher-value services — e.g. cloud metadata endpoints — would raise this substantially in a real deployment.)*

**Affected Endpoint:** `POST /api/users/me/webhook/test`

**Description:** The server fetches a client-supplied URL on the caller's behalf with no allowlist or destination validation, and returns the response body to the client.

**Steps to Reproduce:**
```
POST /api/users/me/webhook/test HTTP/1.1
Authorization: Bearer <Alice's token>

{"url":"http://mongo:27017"}
```

**Evidence:**
```json
{"status":200,"body":"It looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n"}
```

**Business Impact:** Confirms the API server can be used as a proxy to reach internal-only services (here, the database container) that are not meant to be reachable from outside the Docker network. In production, this pattern is routinely used to reach cloud metadata services and internal admin panels.

**Remediation:** Maintain an allowlist of permitted outbound destinations, block requests to private/internal IP ranges (including the Docker bridge network and `169.254.169.254`), and disable HTTP redirects on the outbound fetch.

---

### F-08 — Verbose Errors Expose Internal Stack Traces

**OWASP Category:** API8:2023 – Security Misconfiguration
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` — **5.3 (Medium)**

**Affected Endpoint:** Global error handler (any route that throws, e.g. `GET /api/wallets/abc`)

**Description:** The global Express error handler returns `err.stack` directly to the client in the JSON response.

**Steps to Reproduce:**
```
GET /api/wallets/abc HTTP/1.1
Authorization: Bearer <any valid token>
```

**Evidence:** Response includes full internal file paths (`/usr/src/app/node_modules/mongoose/lib/...`) and library internals, revealing the application's directory structure, framework versions, and dependency tree.

**Business Impact:** Aids an attacker in fingerprinting the technology stack and crafting targeted exploits against known library versions; also a common compliance finding under secure coding standards.

**Remediation:** Return generic error messages to clients in all environments outside local development; log full stack traces server-side only (e.g. via `pino`), never in the HTTP response body.

---

### F-09 — No Rate Limiting on Transaction PIN (Brute Force)

**OWASP Category:** API4:2023 – Unrestricted Resource Consumption
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — **6.5 (Medium)**

**Affected Endpoint:** `POST /api/transfer` (PIN check)

**Description:** The 4-digit transaction PIN (10,000 possible values) has no attempt limiting, lockout, or delay. An attacker holding a valid session token can brute-force the PIN in a fully automated, unthrottled loop.

**Steps to Reproduce:** Five sequential guesses against `/api/transfer` returned instant, unthrottled responses:
```
pin=0000 -> 403
pin=1111 -> 403
pin=1234 -> 200   (correct)
pin=4321 -> 403
pin=9999 -> 403
```
A full Burp Intruder sweep of all 10,000 values would complete in well under a minute at this response rate, with no blocking observed.

**Business Impact:** If session tokens are exposed through any other means (e.g. device theft, XSS in a hypothetical client app), the transaction PIN — the control meant to provide a second layer of protection — offers no meaningful resistance.

**Remediation:** Apply per-account and per-IP rate limiting with exponential backoff and a lockout threshold (e.g. 5 failed attempts) on any PIN or password verification endpoint.

---

### F-10 — Hardcoded / Weak JWT Signing Secret

**OWASP Category:** API2:2023 – Broken Authentication
**CWE:** CWE-798 (Use of Hard-coded Credentials)
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` — **9.8 (Critical)**

**Affected Component:** JWT signing (application-wide), secret value `dev-only-placeholder`

**Description:** The JWT signing secret is a short, guessable, hardcoded string sourced from an environment variable with an insecure default. It was recovered via an offline dictionary attack against a captured token in under one second.

**Steps to Reproduce:**
```bash
hashcat -m 16500 token.txt words.txt
```

**Evidence:**
```
eyJhbGciOiJIUzI1NiIs...i5jmo68F415lEhxoa1BheSEh8DKHqwazffpyITK-_jg:dev-only-placeholder
Recovered: 1/1 (100.00%)
```

**Business Impact:** Recovering the signing secret allows an attacker to **forge arbitrary JWTs offline**, for any user ID and any role — including `"role":"admin"` — without ever authenticating. This is a complete authentication bypass for the entire application. See CH-01 below for the demonstrated chain.

**Remediation:** Generate a cryptographically random secret of at least 256 bits per environment (never a human-readable placeholder), store it in a secrets manager (not source control or a default-value environment variable), rotate it periodically, and consider asymmetric signing (RS256) so verification keys can be public without exposing the signing key.

---

### F-11 — Race Condition in Fund Transfer (TOCTOU / Double-Spend)

**OWASP Category:** API6:2023 – Unrestricted Access to Sensitive Business Flows
**CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization, "Race Condition")
**CVSS v3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` — **7.7 (High)**

**Affected Endpoint:** `POST /api/transfer`

**Description:** The transfer handler checks the sender's balance, then separately updates both balances in two non-atomic operations with no locking, transaction, or idempotency key. Concurrent requests can all pass the balance check before any of them commit their debit.

**Steps to Reproduce:** 20 concurrent transfer requests of 600 units each were fired against an account with a starting balance of 1000 (`exploits/race.py`).

**Evidence (two separate runs):**
```
Run 1: before=1000  after=400    successful_transfers=1  (max possible: 1)
Run 2: before=1000  after=-2000  successful_transfers=5  (max possible: 1)
```
Run 2 demonstrates five transfers succeeding simultaneously — each reading the same stale balance before any debit was committed — driving the account to a **negative balance** and creating 2,500 units of value that should not exist.

**Business Impact:** Direct, reproducible financial loss. In a real payment system this is the highest-value business-logic flaw a tester can find, as it allows fabricating money rather than merely moving or exposing it.

**Remediation:** Perform the balance check and debit as a single atomic operation (e.g. `updateOne({_id, balance: {$gte: amt}}, {$inc: {balance: -amt}})` and verify the write actually matched), or wrap the full transfer in a MongoDB multi-document transaction using the replica set. Add a client-supplied idempotency key to collapse duplicate/retried requests to a single effect.

---

## Chained Exploit Scenario

### CH-01 — Unauthenticated Admin Account Takeover (F-04 → F-10 chain)

**Combined CVSS v3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` — **10.0 (Critical)**

**Narrative:**
1. An attacker registers a throwaway account and uses **F-04 (Mass Assignment)** to PATCH their own `role` field to `"admin"`.
2. The attacker logs in; because the JWT payload is built from the live user document, the resulting token now legitimately encodes `"role":"admin"`.
3. Separately, the attacker captures any token (their own is sufficient) and recovers the signing secret offline using **F-10 (Weak JWT Secret)** — no server interaction required after the one captured token.
4. With the secret in hand, the attacker can now **forge new tokens from scratch**, for *any* `phone` and `role` value, including targeting a victim's real account ID with `role: "admin"`, without ever knowing that victim's password or PIN.

**Why this matters more than the sum of its parts:** F-04 alone is contained to the attacker's own account. F-10 alone requires an attacker to already hold a token. Together, they remove every remaining barrier: once the secret is known, authentication becomes entirely client-side fiction — any identity, any privilege level, generated offline, with no rate limit, lockout, or server round-trip to detect it.

**Remediation priority:** Fixing F-10 (strong, rotated secret) alone breaks this chain even if F-04 is not yet patched, since forged tokens become infeasible. Both should still be fixed independently — defense in depth.

---

## Remediation Roadmap (Priority Order)

| Priority | Findings | Action |
|---|---|---|
| **Immediate** | F-10, CH-01 | Replace JWT secret with a strong, randomly generated value; rotate immediately |
| **Immediate** | F-04 | Add allowlist-based input validation on `PATCH /api/users/me` |
| **Immediate** | F-03 | Add role-based middleware to all `/api/admin/*` routes |
| **High** | F-11 | Make transfer balance checks atomic; add idempotency keys |
| **High** | F-01, F-05 | Add ownership checks to wallet routes; remove/secure legacy `/api/v0/*` |
| **Medium** | F-02, F-06, F-09 | Input validation (query params, amount sign), PIN rate limiting, response field filtering |
| **Medium** | F-07, F-08 | Outbound request allowlisting; generic error responses |

---

## Appendix: Tools Used

| Tool | Purpose |
|---|---|
| Burp Suite Community Edition | Request interception, Repeater, Intruder (brute force) |
| curl / jq | Scripted API testing |
| Python 3 (httpx, asyncio) | Race-condition proof-of-concept |
| hashcat (mode 16500, PoCL CPU backend) | JWT signing-secret recovery |
| Docker Compose | Isolated, reproducible lab environment |

---

*This report documents findings against a disposable lab instance (`v1-vulnerable` tag) built for the sole purpose of demonstrating and practicing API penetration testing methodology. A fixed version (`v2-secure`) with corresponding regression tests addresses every finding above.*
