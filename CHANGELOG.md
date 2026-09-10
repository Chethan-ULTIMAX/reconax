# Changelog

All notable changes to ReconAx are documented in this file.

The project follows a lightweight versioning approach based on semantic versioning principles.

---

## [0.2.0] — 2026-09-10

### Added

- Modular analysis architecture with a shared analysis context
- TLS and certificate analysis
- Passive technology detection
- Sitemap analysis
- CORS analysis
- Content Security Policy (CSP) analysis
- Subresource Integrity (SRI) analysis
- `security.txt` analysis
- Website metadata analysis
- External resource analysis
- Public endpoint discovery from page content
- Passive attack-surface analysis
- Website Hygiene Score
- Expanded Python API with individual analysis functions
- Expanded CLI with module-specific commands
- JSON output support across analysis workflows
- Redirect-chain information
- Verdicts, flags, and explanations for analysis results

### Improved

- HTTP response handling and caching
- Cookie parsing and security-attribute handling
- Windows UTF-8 CLI compatibility
- Python 3.14 compatibility
- Error handling for real-world websites
- Rich terminal output
- Test coverage and module reliability
- Documentation and installation guidance

### Security

- ReconAx remains passive by design
- No port scanning, brute forcing, exploitation, credential attacks, or authentication bypass
- Cookie values are not included in analysis results

### Testing

- Expanded automated test suite
- Real-world website integration testing
- Verified clean package installation from built artifacts

---

## [0.1.0] — 2026-09-09

### Added

- Initial ReconAx project structure
- `ReconAx` Python API
- URL normalization
- HTTP GET client
- HTTP redirect following
- Response timing
- HTTP response metadata
- Structured `ReconReport`
- Security-related HTTP header analysis
- Cookie metadata extraction
- HTML parsing
- Internal/external link detection
- Script extraction
- Image extraction
- `robots.txt` analysis
- Basic DNS lookups
- JSON report output
- Rich terminal output
- CLI commands and options
- Initial automated test suite

### Security

- Cookie values are intentionally excluded from reports.
- ReconAx performs lightweight public-information analysis.
- No active exploitation or brute-force functionality is included.

### Status

Early development / Alpha.
