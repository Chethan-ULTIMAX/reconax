from __future__ import annotations

from urllib.parse import urlparse

import dns.exception
import dns.resolver

from ..models import DNSAnalysis


def _get_hostname(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.hostname


def _resolve(resolver: dns.resolver.Resolver, hostname: str, record_type: str) -> list[str]:
    try:
        answers = resolver.resolve(hostname, record_type)
    except (dns.exception.DNSException, OSError):
        return []

    results: list[str] = []
    for answer in answers:
        value = str(answer)
        if record_type in {"MX", "NS", "CNAME"}:
            value = value.rstrip(".")
        results.append(value)
    return results


def lookup_dns(url: str) -> DNSAnalysis:
    """Perform basic DNS lookups for a hostname."""
    hostname = _get_hostname(url)
    if not hostname:
        return DNSAnalysis(hostname="")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0

    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"):
        records[record_type] = _resolve(resolver, hostname, record_type)

    return DNSAnalysis(hostname=hostname, records=records, errors=errors)
