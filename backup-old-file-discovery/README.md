# Backup / Old File Discovery

## Core Idea

Backup and old files are often forgotten in production.

A developer may clean the live file but leave behind an older copy such as:

```txt
config.js.bak
index.html.old
style.css~
backup.zip
dump.sql
```

These files can expose source code, secrets, internal endpoints, database exports, old comments, or removed functionality.

This technique is high signal when you generate backup variations from files that actually exist on the target.

---

## Why This Matters

Backup files may contain:

```txt
API keys
Old secrets
Internal endpoints
Admin routes
Database dumps
Credentials
Debug information
Removed functionality
Sensitive configuration
```

The main file might be harmless, but the forgotten copy may leak what used to be there.

Example:

```txt
/config.js       → public production config
/config.js.bak   → old version with API keys and internal endpoints
```

---

## Common Backup Patterns

### Appended Extensions

```txt
.bak
.old
.backup
.save
.orig
.tmp
.temp
~
.swp
.swo
```

### Archive / Dump Extensions

```txt
.zip
.tar
.tar.gz
.tgz
.7z
.rar
.sql
.db
.sqlite
```

---

## Manual Test Examples

```txt
/index.html.bak
/index.html.old
/index.html~
/index.php.old
/config.js.bak
/config.js.old
/config.js~
/backup.zip
/backup.tar.gz
/db.sql
/dump.sql
```

The original source specifically mentioned examples like `index.html.bak`, `index_old.html`, `style.css~`, `backup.zip`, `backup.tar.gz`, and `dump.sql` as common forgotten files. :contentReference[oaicite:0]{index=0}

---

## Better Workflow

Do not randomly brute force thousands of backup filenames first.

Better workflow:

```txt
1. Crawl the target
2. Collect real files
3. Generate backup variations
4. Filter by response size/status/content
5. Inspect only meaningful hits
```

Sources for real files:

```txt
JavaScript files
Wayback URLs
gau
waybackurls
katana
robots.txt
sitemap.xml
Burp/Caido history
Directory listings
Source maps
GitHub search
```

---

## File Mutation Examples

If you discover:

```txt
/config.js
```

Test:

```txt
/config.js.bak
/config.js.old
/config.js.backup
/config.js.save
/config.js.orig
/config.js.tmp
/config.js.temp
/config.js~
/config.js.swp
/config.js.swo
```

If you discover:

```txt
/index.html
```

Test:

```txt
/index.html.bak
/index.html.old
/index.html.backup
/index.html.save
/index.html.orig
/index.html.tmp
/index.html.temp
/index.html~
/index.html.swp
/index.html.swo
```

---

## Extension Replacement Tests

Sometimes the backup replaces the original extension instead of appending to it.

If the file is:

```txt
/index.html
```

Also test:

```txt
/index.bak
/index.old
/index.backup
/index.save
/index.orig
/index.tmp
/index.zip
```

If the file is:

```txt
/config.js
```

Also test:

```txt
/config.bak
/config.old
/config.backup
/config.save
/config.orig
/config.tmp
/config.zip
```

---

## Directory Archive Tests

If you find interesting directories:

```txt
/admin/
/api/
/assets/
/static/
/uploads/
/js/
```

Test archive versions:

```txt
/admin.zip
/admin.tar.gz
/api.zip
/api.tar.gz
/assets.zip
/assets.tar.gz
/static.zip
/static.tar.gz
/uploads.zip
/uploads.tar.gz
/js.zip
/js.tar.gz
```

Also test generic root archives:

```txt
/backup.zip
/backup.tar.gz
/site.zip
/site.tar.gz
/www.zip
/www.tar.gz
/public.zip
/public.tar.gz
/public_html.zip
/public_html.tar.gz
/source.zip
/source.tar.gz
/src.zip
/src.tar.gz
/app.zip
/app.tar.gz
```

---

## Quick curl Tests

```bash
curl -i https://target.com/config.js.bak
curl -i https://target.com/config.js.old
curl -i https://target.com/config.js~
curl -i https://target.com/backup.zip
curl -i https://target.com/db.sql
```

---

## Generate Backup Candidates From Known Files

Create a file called `known-files.txt`:

```txt
config.js
app.js
main.js
index.html
login.html
admin.html
```

Generate backup candidates:

```bash
while read file; do
  echo "$file.bak"
  echo "$file.old"
  echo "$file.backup"
  echo "$file.save"
  echo "$file.orig"
  echo "$file.tmp"
  echo "$file.temp"
  echo "$file~"
  echo "$file.swp"
  echo "$file.swo"
done < known-files.txt > backup-candidates.txt
```

Run with ffuf:

```bash
ffuf -u https://target.com/FUZZ -w backup-candidates.txt -mc all
```

Filter common false positives:

```bash
ffuf -u https://target.com/FUZZ -w backup-candidates.txt -mc 200,206,301,302,403 -fs <known_404_size>
```

---

## What To Search For Inside Found Files

If a backup file is accessible, inspect it for:

```txt
api_key
secret
token
password
passwd
bearer
authorization
client_secret
private_key
aws_access_key_id
aws_secret_access_key
firebase
stripe
sendgrid
twilio
slack
webhook
internal
staging
dev
admin
debug
database
```

Example:

```bash
grep -RiE "api_key|secret|token|password|bearer|client_secret|private_key|aws_access_key_id|aws_secret_access_key|firebase|stripe|sendgrid|twilio|slack|webhook|internal|staging|dev|admin|debug|database" .
```

---

## What Makes This Reportable?

Reportable examples:

```txt
/config.js.bak exposes active API keys
/backup.zip contains source code and environment variables
/dump.sql exposes user data or password hashes
/index.html.old reveals hidden admin endpoints
/.env.old exposes secrets
```

Usually weak examples:

```txt
/style.css.bak only exposes old CSS
/index.html.bak contains the same public homepage
/backup.zip only contains public images
A backup file returns 200 but is actually a soft 404 page
```

---

## Impact Checklist

Before reporting, answer:

```txt
Does the file expose sensitive data?
Are the exposed secrets active?
Does it reveal hidden functionality?
Does it expose internal endpoints?
Does it contain source code?
Does it contain user data?
Does it contain database exports?
Can the leaked information be chained into a stronger attack?
```

If the answer is no, it is probably just recon value.

---

## Report Title Ideas

```txt
Exposed Backup File Leaks Sensitive Configuration
Publicly Accessible Backup Archive Exposes Source Code
Exposed Database Dump via Forgotten Backup File
Old JavaScript Backup Exposes Internal API Endpoints
```

---

## Report Template

### Summary

A publicly accessible backup file was discovered on the server. The file appears to be an old or temporary copy of a production file and exposes sensitive information.

### Affected URL

```txt
https://target.com/config.js.bak
```

### Evidence

The production file is available at:

```txt
https://target.com/config.js
```

A backup copy is also publicly accessible:

```txt
https://target.com/config.js.bak
```

The backup file exposes:

```txt
[Describe the sensitive data here]
```

### Impact

An attacker could use the exposed information to:

```txt
Access internal endpoints
Abuse exposed API keys
Discover hidden admin functionality
Understand application logic
Access private data
Chain into further attacks
```

### Recommendation

Remove backup, temporary, and old files from the public web root.

Rotate any exposed secrets.

Add deployment checks to block files matching backup extensions such as:

```txt
*.bak
*.old
*.backup
*.save
*.orig
*.tmp
*.temp
*~
*.swp
*.swo
*.sql
*.zip
*.tar
*.tar.gz
*.tgz
*.7z
*.rar
```

---

## Mental Model

Backup file discovery is not about guessing random filenames.

It is about finding real files the application uses, then asking:

```txt
Did an older copy of this file get left behind?
```

Best workflow:

```txt
Collect real paths → generate backup variants → filter responses → inspect meaningful hits → prove impact
```
