from __future__ import annotations

from urllib.parse import urlparse

import dns.resolver

from ..models import DNSReport


def _query(host: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(host, record_type, lifetime=3)
        return [str(answer).rstrip(".") for answer in answers]
    except Exception:
        return []


def lookup_dns(url: str) -> DNSReport:
    host = urlparse(url).hostname
    if not host:
        return DNSReport()
    return DNSReport(
        A=_query(host, "A"),
        AAAA=_query(host, "AAAA"),
        MX=_query(host, "MX"),
        NS=_query(host, "NS"),
        TXT=_query(host, "TXT"),
    )
