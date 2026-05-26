# Cloud Bucket Discovery From Source / JavaScript

## Core Idea

Cloud storage buckets are often exposed through frontend code.

Static sites and modern web apps frequently load assets, documents, images, backups, and JavaScript from services like:

```txt
AWS S3
Google Cloud Storage
Azure Blob Storage
CloudFront
CDNs
```

The source article specifically recommends looking inside page source, JavaScript files, image URLs, and API responses for bucket names, including patterns like `company-assets.s3.amazonaws.com`, `storage.googleapis.com`, and `blob.core.windows.net`. It also notes that public buckets are only reportable when they expose unintended sensitive files such as backups, internal documents, configuration files, secrets, private assets, or source code.

---

## Main Domain vs Subdomains

Check both the root domain and subdomains.

Cloud bucket references are often environment-specific. The main marketing site may only expose public asset buckets, while subdomains may reveal upload buckets, staging buckets, document storage, CDN origins, or old backup locations.

Examples:

```txt
example.com                  → public images/CSS/JS
app.example.com              → user-upload storage
admin.example.com            → internal documents
staging.example.com          → old backups or test buckets
support.example.com          → attachments and screenshots
cdn.example.com              → CDN or CloudFront origin clues
```
---

## Why This Matters

A bucket reference in JavaScript can lead to:

```txt
Publicly listable buckets
Sensitive files
Backups
Internal documents
Private assets
Source code
Configuration files
Secrets
Direct origin access
CDN/WAF bypasses
```

The mistake beginners make is thinking:

```txt
Public bucket = vulnerability
```

Wrong.

The real question is:

```txt
Does the bucket expose sensitive or unintended content?
```

Public images, CSS, and JS are usually normal.

---

## Where To Find Bucket References

Look inside:

```txt
Page source
JavaScript files
Image URLs
CSS files
API responses
Source maps
robots.txt
sitemap.xml
Wayback URLs
HAR files
Burp/Caido history
GitHub search
```

High-value places:

```txt
main.js
app.js
config.js
runtime.js
env.js
settings.js
firebase config files
source maps
old archived JS
```

---

## Bucket URL Patterns

### AWS S3

```txt
https://s3.amazonaws.com/<bucket-name>
https://<bucket-name>.s3.amazonaws.com
https://<bucket-name>.s3.<region>.amazonaws.com
https://s3.<region>.amazonaws.com/<bucket-name>
```

Examples:

```txt
https://company-assets.s3.amazonaws.com
https://company-backups.s3.us-east-1.amazonaws.com
https://s3.amazonaws.com/company-prod
https://s3.us-west-2.amazonaws.com/company-static
```

### Google Cloud Storage

```txt
https://storage.googleapis.com/<bucket-name>
https://<bucket-name>.storage.googleapis.com
```

Examples:

```txt
https://storage.googleapis.com/company-assets
https://company-assets.storage.googleapis.com
```

### Azure Blob Storage

```txt
https://<account>.blob.core.windows.net/<container>
```

Examples:

```txt
https://companyassets.blob.core.windows.net/public
https://companyprod.blob.core.windows.net/backups
```

### CloudFront / CDN

```txt
https://<distribution>.cloudfront.net
https://cdn.example.com
https://assets.example.com
https://static.example.com
```

CloudFront itself is not the bucket, but it may reveal or proxy the origin.

---

## Manual Search Patterns

Search source and JavaScript for:

```txt
s3.amazonaws.com
amazonaws.com
storage.googleapis.com
blob.core.windows.net
cloudfront.net
cdn.
assets.
static.
uploads.
media.
backups.
```

Also search for bucket-like variable names:

```txt
bucket
bucketName
storageBucket
assetBucket
s3Bucket
cdnUrl
assetUrl
uploadUrl
mediaUrl
staticUrl
storageUrl
backupUrl
```

---

## grep Examples

After downloading JavaScript files:

```bash
grep -RiE "s3\.amazonaws\.com|amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|cloudfront\.net" .
```

Search for storage-related variables:

```bash
grep -RiE "bucket|bucketName|storageBucket|assetBucket|s3Bucket|cdnUrl|assetUrl|uploadUrl|mediaUrl|staticUrl|storageUrl|backupUrl" .
```

Search for sensitive file references:

```bash
grep -RiE "backup|dump|\.zip|\.tar\.gz|\.sql|\.env|config|secret|private|internal|admin|staging|dev" .
```

---

## JavaScript Recon Workflow

```txt
1. Crawl the target
2. Collect JavaScript files
3. Beautify/minify if needed
4. Grep for cloud storage patterns
5. Extract bucket/container URLs
6. Test direct access
7. Check for listing or predictable sensitive files
8. Prove sensitive exposure before reporting
```

---

## HAR-Based Workflow

If using browser traffic:

```txt
1. Open DevTools or Burp/Caido
2. Browse important pages
3. Export HAR
4. Extract JS, image, document, and API URLs
5. Search for cloud storage patterns
6. Test discovered buckets directly
```

Useful because buckets often appear in:

```txt
Image URLs
Download links
PDF links
Upload endpoints
Static asset paths
API responses
```

---

## Quick curl Tests

### AWS S3

```bash
curl -i https://s3.amazonaws.com/company-assets
curl -i https://company-assets.s3.amazonaws.com
curl -i https://company-assets.s3.us-east-1.amazonaws.com
```

### Google Cloud Storage

```bash
curl -i https://storage.googleapis.com/company-assets
curl -i https://company-assets.storage.googleapis.com
```

### Azure Blob

```bash
curl -i https://companyassets.blob.core.windows.net/public
```

---

## What To Look For

Useful signs:

```txt
XML bucket listing
Directory-style listing
Downloadable files
Backup archives
Database dumps
Internal PDFs
Private images
Source code
Configuration files
Environment files
Credentials
Old deployment artifacts
```

Interesting filenames:

```txt
backup.zip
backups.zip
site.zip
source.zip
src.zip
app.zip
www.zip
public_html.zip
dump.sql
database.sql
prod.sql
staging.sql
.env
.env.production
config.json
secrets.json
credentials.json
```

---

## AWS S3 Listing Signs

A listable S3 bucket may return XML like:

```xml
<ListBucketResult>
  <Name>company-assets</Name>
  <Contents>
    <Key>backup.zip</Key>
  </Contents>
</ListBucketResult>
```

Common S3 errors:

```txt
AccessDenied
NoSuchBucket
AllAccessDisabled
PermanentRedirect
```

`AccessDenied` usually means the bucket exists but is not listable.

That is not automatically a vulnerability.

---

## Google Cloud Storage Listing Signs

A public GCS bucket may expose object listings through:

```txt
https://storage.googleapis.com/<bucket-name>
```

Useful file paths may appear as object names.

Common findings:

```txt
public docs
backups
exports
old assets
configuration files
```

---

## Azure Blob Listing Signs

Azure containers may expose blobs if public access is enabled.

Look for:

```txt
Blob listing XML
Downloadable files
Container names
Public documents
Backups
Exports
```

Common container names:

```txt
public
assets
static
media
uploads
documents
backups
exports
```

---

## Direct Origin / CDN Bypass Angle

Sometimes a CDN blocks or hides content, but the original bucket remains accessible directly.

Test both:

```txt
https://cdn.example.com/private/file.pdf
https://company-assets.s3.amazonaws.com/private/file.pdf
```

Possible impact:

```txt
Bypass CDN access rules
Bypass WAF restrictions
Bypass rate limits
Access files blocked at CDN layer
Reach original storage directly
```

This is only valid if direct origin access changes the security behavior.

---

## Wordlist For Sensitive Objects

Create `cloud-sensitive-files.txt`:

```txt
backup.zip
backups.zip
site.zip
source.zip
src.zip
app.zip
www.zip
public_html.zip
backup.tar.gz
site.tar.gz
source.tar.gz
src.tar.gz
app.tar.gz
dump.sql
database.sql
prod.sql
production.sql
staging.sql
dev.sql
.env
.env.production
.env.staging
config.json
config.js
settings.json
secrets.json
credentials.json
firebase.json
service-account.json
```

Use it against known bucket base URLs.

Example:

```bash
while read file; do
  echo "https://company-assets.s3.amazonaws.com/$file"
done < cloud-sensitive-files.txt
```

Then request the generated URLs carefully.

---

## What Makes This Reportable?

Reportable examples:

```txt
S3 bucket exposes backup.zip containing source code
GCS bucket exposes internal documents
Azure container exposes private user-uploaded files
Direct S3 origin bypasses CDN access restrictions
Bucket exposes .env or credentials.json
Bucket exposes database dumps
Bucket exposes private assets not linked from the public site
```

Usually weak examples:

```txt
Bucket only contains public images
Bucket only contains CSS and JS already loaded by the site
Bucket exists but returns AccessDenied
CloudFront distribution serves normal public static assets
Bucket name is guessable but no sensitive files are accessible
```

---

## Impact Checklist

Before reporting, answer:

```txt
Is the bucket/container actually accessible?
Can files be listed or downloaded?
Are the files intended to be public?
Do they contain sensitive information?
Are exposed credentials active?
Does direct bucket access bypass CDN/WAF/access controls?
Does it expose user data, internal docs, source code, or secrets?
Can the exposure be chained into another attack?
```

If you cannot prove sensitive exposure, keep it as recon.

---

## Report Title Ideas

```txt
Public Cloud Storage Bucket Exposes Sensitive Files
Exposed S3 Bucket Leaks Source Code Backup
Public GCS Bucket Exposes Internal Documents
Azure Blob Container Exposes Private Assets
Direct S3 Origin Access Bypasses CDN Restrictions
```

---

## Report Template

### Summary

A cloud storage bucket/container was discovered through frontend source or JavaScript files. The bucket is publicly accessible and exposes sensitive files that should not be available to unauthenticated users.

### Discovery Source

```txt
https://target.com/static/js/main.js
```

The JavaScript file referenced:

```txt
https://company-assets.s3.amazonaws.com
```

### Affected Resource

```txt
https://company-assets.s3.amazonaws.com/backup.zip
```

### Evidence

The following sensitive file is publicly accessible:

```txt
https://company-assets.s3.amazonaws.com/backup.zip
```

It exposes:

```txt
[Describe sensitive content here]
```

### Impact

An attacker could use this exposure to:

```txt
Download sensitive files
Access internal documents
Review source code
Extract secrets
Discover internal endpoints
Bypass CDN restrictions
Chain into further attacks
```

### Recommendation

Restrict public access to the bucket/container.

Remove sensitive files from public storage.

Use least-privilege bucket policies.

Ensure only intended public assets are accessible.

Rotate any exposed secrets.

Review logs for unauthorized access.

If using a CDN, ensure the origin bucket is not directly accessible unless intentionally public.

---

## Mental Model

Do not report “I found an S3 bucket.”

That is not enough.

The useful chain is:

```txt
Source/JS leaks bucket reference
        ↓
Bucket or direct object is publicly accessible
        ↓
Sensitive or unintended files are exposed
        ↓
Exposure creates real security impact
```

Best workflow:

```txt
Extract cloud references from JS → test direct access → inspect objects → prove sensitive exposure → report impact
```

This technique is powerful because frontend code often reveals the storage layer developers forgot attackers could access directly.
