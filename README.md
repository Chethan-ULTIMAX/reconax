# ⚡ ReconAx

**A lightweight Python library and CLI for passive website analysis.**

Analyze websites for HTTP information, security headers, cookies, TLS, DNS, technologies, metadata, public endpoints, resources, and more.

**No API keys · Local analysis · Passive by design**

⭐ Star the repo if you find ReconAx useful.

---

## ✨ Features

- 🌐 HTTP & redirects
- 🛡️ Security headers
- 🍪 Cookie analysis
- 📄 HTML & metadata
- 🔐 TLS / certificate information
- 🌍 DNS records
- 🧠 Technology detection
- 🔄 CORS & CSP
- 🔒 SRI
- 🤖 robots.txt & sitemap
- 🔗 Public endpoints
- 📦 External resources
- 🎯 Passive attack surface
- 📊 Website Hygiene Score
- 📋 JSON output

---

## 📦 Installation

### Windows

```bash
git clone https://github.com/Chethan-ULTIMAX/reconax.git
cd reconax

python -m venv .venv
.venv\Scripts\activate

python -m pip install --upgrade pip
pip install -e .
```

### Linux / macOS

```bash
git clone https://github.com/Chethan-ULTIMAX/reconax.git
cd reconax

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e .
```

### PyPI

```bash
pip install reconax
```

---

## 🚀 CLI

Analyze a website:

```bash
reconax analyze example.com
```

JSON output:

```bash
reconax analyze example.com --json
```

Save JSON:

```bash
reconax analyze example.com --json -o report.json
```

Individual modules:

```bash
reconax headers example.com
reconax cookies example.com
reconax html example.com
reconax dns example.com
reconax tls example.com
reconax tech example.com
reconax csp example.com
reconax cors example.com
reconax endpoints example.com
reconax attack-surface example.com
reconax score example.com
```

See all commands:

```bash
reconax --help
```

---

## 🐍 Python

Run a complete analysis:

```python
import reconax

report = reconax.analyze("https://example.com")

print(report.http.status_code)
print(report.tls.tls_version)
print(report.score.score)
```

Use individual modules:

```python
import reconax

headers = reconax.headers("https://example.com")

print(headers.present)
print(headers.missing)
print(headers.verdict)
```

Inspect the complete report:

```python
report = reconax.analyze("https://github.com")

print(report.http)
print(report.headers)
print(report.cookies)
print(report.tls)
print(report.tech)
print(report.endpoints)
print(report.attack_surface)
print(report.score)
```

---

## 📊 Website Hygiene Score

ReconAx provides a simple **0–100 Website Hygiene Score** based on passive configuration checks.

```python
report = reconax.analyze("https://example.com")

print(report.score.score)
print(report.score.grade)
```

The score is **not a vulnerability score** and does not guarantee that a website is secure.

---

## 🛡️ Passive by Design

ReconAx focuses on lightweight analysis of publicly accessible website information.

It does **not** perform:

- brute forcing
- exploitation
- port scanning
- credential attacks
- authentication bypass
- aggressive crawling

Only analyze systems you own or have permission to test.

---

## 🖥️ GUI

A graphical interface is planned for a future version.

The current release focuses on the **Python API + CLI**.

---

## 🧪 Development

Install the development version:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
python -m pytest -q
```

---

## 🛠️ Common Issues

### `reconax` is not recognized

Try:

```bash
python -m reconax.cli --help
```

If this works, your Python Scripts directory may not be in `PATH`.

### `pytest` is not recognized

Use:

```bash
python -m pytest
```

### Windows Unicode / encoding errors

Try:

```bash
chcp 65001
```

ReconAx configures CLI output for UTF-8 on Windows.

### SSL errors

If necessary, certificate verification can be disabled through the Python API:

```python
reconax.analyze("https://example.com", verify_ssl=False)
```

Use this only when you understand the implications.

---

## 📄 License

MIT License.

---

## ⭐ Support ReconAx

If ReconAx is useful to you:

**⭐ Star it · 🐛 Report bugs · 💡 Suggest ideas**

**ReconAx — one URL, one clear report. ⚡**
