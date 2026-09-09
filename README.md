# ReconAx

A simple, developer-friendly website analyzer for students, developers, and security learners.

ReconAx collects a small set of public website information and presents it as one clean report. It is designed to be lightweight and respectful rather than an aggressive scanning framework.

## Planned MVP

- HTTP status, timing, redirects, content type, and response metadata
- Security-related response headers
- Cookie names and security flags without exposing cookie values
- HTML title, meta description, links, scripts, and images
- `robots.txt` and `sitemap.xml`
- Basic DNS records: A, AAAA, MX, NS, and TXT
- Pretty CLI output and JSON export

## Non-goals

ReconAx is not intended to perform port scanning, brute forcing, exploitation, authentication bypass, or aggressive automated scanning.

## Development

```bash
pip install -e ".[dev]"
reconax https://example.com
```

## Status

Early development — version `0.1.0`.
