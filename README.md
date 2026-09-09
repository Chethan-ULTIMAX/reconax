# ⚡ ReconAx

### Know your website. In one command.

ReconAx is a **lightweight website analyzer** that turns a URL into a clean, useful report.

```bash
reconax example.com
```

That's it. ⚡

It checks the things developers, students, and security learners commonly want to see — **HTTP, headers, cookies, HTML, links, robots.txt, and DNS** — without requiring a pile of different commands.

---

## ✨ What do you get?

```text
╭──────────────────────────────────────────────╮
│              ⚡ ReconAx Report                │
│              https://example.com             │
╰──────────────────────────────────────────────╯

HTTP
  Status          200 OK
  Response Time   184 ms
  Final URL       https://example.com/
  HTTP Version    HTTP/1.1
  Content-Type    text/html

Security Headers
  ✓ Strict-Transport-Security
  ✓ X-Content-Type-Options
  ✓ X-Frame-Options
  ✗ Content-Security-Policy

Cookies
  session         Secure ✓  HttpOnly ✓  SameSite=Lax

HTML
  Title           Example Domain
  Links           3 internal · 2 external
  Scripts         2
  Images          1

robots.txt
  Found           ✓
  Disallow Rules  2
  Sitemaps        1

DNS
  A               93.184.216.34
  AAAA            none
  MX              none
  NS              example.com
```

**One URL → one report.**

---

## 🚀 Install

```bash
pip install reconax
```

Then:

```bash
reconax example.com
```

You can use either:

```bash
reconax example.com
```

or:

```bash
reconax https://example.com
```

---

## 🔍 What ReconAx checks

### 🌐 HTTP

<<<<<<< HEAD
- Status code
- Response time
- Redirects
- Final URL
- HTTP version
- Content type
- Content length
- Response headers
=======
* Status code
* Response time
* Redirects
* Final URL
* HTTP version
* Content type
* Content length
* Response headers
>>>>>>> f69ca0d (docs: improve project README and metadata)

### 🛡️ Security Headers

Checks commonly used headers such as:

<<<<<<< HEAD
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
=======
* `Strict-Transport-Security`
* `Content-Security-Policy`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `Referrer-Policy`
* `Permissions-Policy`
>>>>>>> f69ca0d (docs: improve project README and metadata)

### 🍪 Cookies

Shows cookie names and security flags:

```text
Secure
HttpOnly
SameSite
```

Cookie values are **never included** in the report.

### 🧩 HTML

Extracts:

<<<<<<< HEAD
- Page title
- Meta description
- Internal links
- External links
- Scripts
- Images
=======
* Page title
* Meta description
* Internal links
* External links
* Scripts
* Images
>>>>>>> f69ca0d (docs: improve project README and metadata)

### 🤖 robots.txt

Checks:

```text
/robots.txt
```

and shows:

<<<<<<< HEAD
- Disallow rules
- Sitemap URLs
=======
* Disallow rules
* Sitemap URLs
>>>>>>> f69ca0d (docs: improve project README and metadata)

### 🌎 DNS

Looks up:

```text
A
AAAA
MX
NS
TXT
```

---

# ⚡ Useful commands

### Basic analysis

```bash
reconax example.com
```

### JSON output

```bash
reconax example.com --json
```

Perfect for scripts and automation.

### Save a report

```bash
reconax example.com -o report.json
```

### Explain security headers

```bash
reconax example.com --explain
```

### Skip DNS

```bash
reconax example.com --no-dns
```

### Change timeout

```bash
reconax example.com --timeout 20
```

---

# 🐍 Use it in Python

ReconAx isn't only a CLI tool.

```python
from reconax import ReconAx

report = ReconAx(
    "https://example.com"
).analyze()

print(report.status_code)
print(report.html.title)
```

Access the information you need:

```python
print(report.final_url)

print(report.headers.present)

print(report.headers.missing)

print(report.html.internal_links)

print(report.html.external_links)

print(report.dns.a)
```

---

# 📄 Export reports

Turn the result into a Python dictionary:

```python
data = report.to_dict()
```

Or save it directly as JSON:

```python
report.to_json("report.json")
```

Example:

```json
{
  "requested_url": "https://example.com",
  "status_code": 200,
  "elapsed_ms": 184.21,
  "html": {
    "title": "Example Domain"
  }
}
```

---

# 🎯 Why ReconAx?

### Before

```text
HTTP information      → command 1
Headers               → command 2
HTML                  → command 3
DNS                   → command 4
robots.txt            → command 5

Then manually connect everything.
```

### With ReconAx

```text
                 YOUR URL
                    │
                    ▼
               ⚡ ReconAx
                    │
                    ▼
             ONE CLEAN REPORT
```

Simple.

Lightweight.

Useful.

---

# 🔐 Built to be respectful

ReconAx focuses on **lightweight public-information analysis**.

It does not perform:

<<<<<<< HEAD
- Port scanning
- Brute forcing
- Exploitation
- Credential attacks
- Authentication bypass
- Aggressive scanning
=======
* Port scanning
* Brute forcing
* Exploitation
* Credential attacks
* Authentication bypass
* Aggressive scanning
>>>>>>> f69ca0d (docs: improve project README and metadata)

Use ReconAx only on websites and systems you're authorized to analyze.

---

# 📦 Project status

ReconAx is currently in **early development**.

The core analyzer and CLI are being actively developed and tested.

---

# ⭐ Like ReconAx?

If you find it useful, consider giving the project a ⭐ on GitHub.

**ReconAx — one URL, one command, one clear report. ⚡**
