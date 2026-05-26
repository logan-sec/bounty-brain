# Exposed Development Files

## Core Idea

Development files should not be publicly accessible.

Files and directories like `.git`, `.env`, `.vscode`, and `.idea` can expose source code, secrets, internal paths, repository history, project settings, and developer-specific configuration.

Common files/directories to check:

```txt
/.git/
/.env
/.vscode/
/.idea/
/.DS_Store
```

The original source specifically calls out `.env`, `.git/`, `.DS_Store`, `.vscode/`, and `.idea/` as files/directories worth checking during directory and file busting. It also notes that exposed `.git/config` can reveal repository URLs, remote origins, and sometimes credentials, while leaked `.env` files can expose highly sensitive secrets.

---

## Why This Matters

These files are dangerous because they often reveal information developers never intended to ship.

Possible exposure:

```txt
Source code
Environment variables
API keys
Database credentials
Repository URLs
Internal paths
Cloud credentials
Debug settings
IDE project structure
Staging domains
Deployment details
```

The value is not the file existing.

The value is what the file exposes.

---

## High-Value Targets

### `.env`

Environment files often contain secrets.

Check:

```txt
/.env
/.env.local
/.env.dev
/.env.development
/.env.prod
/.env.production
/.env.staging
/.env.test
/.env.backup
/.env.bak
/.env.old
```

Look for:

```txt
API_KEY=
SECRET=
TOKEN=
PASSWORD=
DATABASE_URL=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
STRIPE_SECRET_KEY=
SENDGRID_API_KEY=
TWILIO_AUTH_TOKEN=
SLACK_WEBHOOK_URL=
JWT_SECRET=
PRIVATE_KEY=
```

Strong finding examples:

```txt
/.env exposes active AWS keys
/.env.production exposes database credentials
/.env.old exposes JWT signing secret
/.env.staging exposes internal API credentials
```

Weak examples:

```txt
/.env exists but is empty
/.env only contains public frontend config
/.env returns a soft 404 page
```

---

### `.git/`

An exposed `.git` directory can allow source code reconstruction.

Check:

```txt
/.git/
/.git/config
/.git/HEAD
/.git/index
/.git/logs/HEAD
/.git/refs/heads/main
/.git/refs/heads/master
```

Interesting signs:

```txt
/.git/HEAD returns ref: refs/heads/main
/.git/config exposes remote repository URL
/.git/index is downloadable
/.git/logs/HEAD exposes commit history
```

If accessible, try reconstructing safely:

```bash
git-dumper https://target.com/.git/ dumped-repo
```

Then inspect locally:

```bash
grep -RiE "api_key|secret|token|password|bearer|client_secret|private_key|aws_access_key_id|aws_secret_access_key|firebase|stripe|sendgrid|twilio|slack|webhook|internal|staging|dev|admin|debug|database" dumped-repo/
```

Strong finding examples:

```txt
/.git/ allows full source code reconstruction
/.git/config exposes private repo URL with credentials
/.git history contains removed secrets
/.git reveals internal endpoints and deployment logic
```

Weak examples:

```txt
/.git/ returns 403 with no accessible objects
/.git/config only exposes a public GitHub repo
/.git/ exists but cannot be dumped or used
```

---

### `.vscode/`

VS Code project files can reveal local development settings, debug configs, internal paths, and command-line arguments.

Check:

```txt
/.vscode/
/.vscode/settings.json
/.vscode/launch.json
/.vscode/tasks.json
/.vscode/extensions.json
```

Look for:

```txt
Environment variables
Debug arguments
Local/internal hostnames
Hardcoded credentials
Deployment commands
Build commands
API base URLs
Internal file paths
```

Strong finding examples:

```txt
/.vscode/launch.json exposes API tokens in debug environment variables
/.vscode/settings.json exposes internal API base URL
/.vscode/tasks.json exposes deployment command with credentials
```

Weak examples:

```txt
/.vscode/extensions.json only lists recommended extensions
/.vscode/settings.json only contains formatting preferences
```

---

### `.idea/`

JetBrains project files may expose project structure, workspace settings, database configs, deployment mappings, and internal paths.

Check:

```txt
/.idea/
/.idea/workspace.xml
/.idea/misc.xml
/.idea/modules.xml
/.idea/vcs.xml
/.idea/dataSources.xml
/.idea/dataSources.local.xml
/.idea/webServers.xml
/.idea/deployment.xml
```

Look for:

```txt
Database connection strings
Internal paths
Deployment servers
Project structure
VCS repository URLs
Local usernames
Internal hostnames
Credentials
```

Strong finding examples:

```txt
/.idea/dataSources.xml exposes database connection info
/.idea/webServers.xml exposes deployment server details
/.idea/deployment.xml exposes internal paths or server mappings
/.idea/vcs.xml exposes private repository information
```

Weak examples:

```txt
/.idea/misc.xml only exposes generic project metadata
/.idea/modules.xml only shows non-sensitive module names
```

---

## Manual Test List

```txt
/.env
/.env.local
/.env.dev
/.env.development
/.env.prod
/.env.production
/.env.staging
/.env.test
/.env.bak
/.env.old
/.git/
/.git/config
/.git/HEAD
/.git/index
/.git/logs/HEAD
/.vscode/
/.vscode/settings.json
/.vscode/launch.json
/.vscode/tasks.json
/.idea/
/.idea/workspace.xml
/.idea/dataSources.xml
/.idea/dataSources.local.xml
/.idea/webServers.xml
/.idea/deployment.xml
/.DS_Store
```

---

## Quick curl Tests

```bash
curl -i https://target.com/.env
curl -i https://target.com/.git/config
curl -i https://target.com/.git/HEAD
curl -i https://target.com/.vscode/settings.json
curl -i https://target.com/.vscode/launch.json
curl -i https://target.com/.idea/workspace.xml
curl -i https://target.com/.idea/dataSources.xml
```

---

## ffuf Wordlist

Create `dev-files.txt`:

```txt
.env
.env.local
.env.dev
.env.development
.env.prod
.env.production
.env.staging
.env.test
.env.bak
.env.old
.git/
.git/config
.git/HEAD
.git/index
.git/logs/HEAD
.vscode/
.vscode/settings.json
.vscode/launch.json
.vscode/tasks.json
.vscode/extensions.json
.idea/
.idea/workspace.xml
.idea/misc.xml
.idea/modules.xml
.idea/vcs.xml
.idea/dataSources.xml
.idea/dataSources.local.xml
.idea/webServers.xml
.idea/deployment.xml
.DS_Store
```

Run:

```bash
ffuf -u https://target.com/FUZZ -w dev-files.txt -mc all
```

Filter obvious noise:

```bash
ffuf -u https://target.com/FUZZ -w dev-files.txt -mc 200,206,301,302,403 -fs <known_404_size>
```

---

## What To Search For Inside Found Files

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
database_url
jwt_secret
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
```

Example:

```bash
grep -RiE "api_key|secret|token|password|passwd|bearer|authorization|client_secret|private_key|aws_access_key_id|aws_secret_access_key|database_url|jwt_secret|firebase|stripe|sendgrid|twilio|slack|webhook|internal|staging|dev|admin|debug" .
```

---

## Validation Checklist

Before reporting, answer:

```txt
Is the file actually accessible?
Is it a real file, not a soft 404?
Does it expose sensitive data?
Are any secrets active?
Does it reveal internal endpoints?
Does it reveal source code?
Does it reveal private repository details?
Does it expose database or cloud credentials?
Can the exposed data be chained into a stronger attack?
```

Do not report just because `/.git/` or `/.env` returns an interesting status code.

Report the exposure only when you can prove meaningful security impact.

---

## What Makes This Reportable?

Reportable examples:

```txt
/.env exposes active credentials
/.git/ allows repository reconstruction
/.git/config exposes private repo URL or credentials
/.vscode/launch.json exposes debug secrets
/.idea/dataSources.xml exposes database connection details
/.idea/deployment.xml exposes internal deployment server info
```

Usually weak examples:

```txt
/.git/ returns 403 and no files can be accessed
/.vscode/extensions.json only lists recommended extensions
/.idea/misc.xml only exposes generic metadata
/.env contains only public frontend variables
A file returns 200 but is actually a soft 404
```

---

## Report Title Ideas

```txt
Exposed .env File Leaks Sensitive Credentials
Publicly Accessible .git Directory Allows Source Code Reconstruction
Exposed IDE Configuration Leaks Internal Development Details
Public .vscode Debug Configuration Exposes Secrets
Exposed .idea Project Files Reveal Database Connection Details
```

---

## Report Template

### Summary

A development file or directory is publicly accessible on the web server. The exposed file contains sensitive information that should not be available to unauthenticated users.

### Affected URL

```txt
https://target.com/.env
```

### Evidence

The following file is publicly accessible:

```txt
https://target.com/.env
```

It exposes:

```txt
[Describe exposed data here]
```

Example sensitive values found:

```txt
[Redact secrets. Show only partial values.]
```

### Impact

An attacker could use this information to:

```txt
Access internal services
Abuse exposed API keys
Reconstruct source code
Discover hidden endpoints
Identify internal infrastructure
Access databases or cloud resources
Chain into further attacks
```

### Recommendation

Remove development files from the public web root.

Block access to sensitive paths such as:

```txt
/.env
/.git/
/.vscode/
/.idea/
/.DS_Store
```

Rotate any exposed secrets.

Review logs to determine whether the files were accessed.

Add CI/CD checks to prevent development files from being deployed.

---

## Prevention Notes

Defenders should block access to:

```txt
.env*
.git/
.git/*
.vscode/
.vscode/*
.idea/
.idea/*
.DS_Store
```

Example Nginx-style deny rule:

```nginx
location ~ /\.(env|git|vscode|idea) {
    deny all;
    return 404;
}
```

Also ensure `.git`, `.env`, `.vscode`, and `.idea` are excluded from deployment artifacts.

---

## Mental Model

This is not “file fuzzing for random junk.”

The real question is:

```txt
Did development-only material accidentally ship to production?
```

Best workflow:

```txt
Check known dev files → inspect accessible hits → extract sensitive value → validate impact → report only meaningful exposure
```

Exposed development files are valuable because they can collapse the distance between recon and impact.

One leaked `.env` or dumpable `.git` directory can turn a boring static site into source code access, cloud access, or internal endpoint discovery.
