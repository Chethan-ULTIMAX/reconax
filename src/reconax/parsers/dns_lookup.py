from __future__ import annotations

from urllib.parse import urlparse

import dns.exception
import dns.resolver

from ..models import DNSAnalysis


def _get_hostname(
    url: str,
) -> str | None:
    """Extract hostname from a URL."""

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        return None

    return hostname


def _resolve(
    resolver: dns.resolver.Resolver,
    hostname: str,
    record_type: str,
) -> list[str]:
    """Resolve one DNS record type safely."""

    try:
        answers = resolver.resolve(
            hostname,
            record_type,
        )

    except (
        dns.exception.DNSException,
        OSError,
    ):
        return []

    results: list[str] = []

    for answer in answers:

        value = str(answer)

        # dnspython often returns a trailing dot
        # for DNS names.
        if record_type in {
            "MX",
            "NS",
        }:
            value = value.rstrip(".")

        results.append(value)

    return results


def lookup_dns(
    url: str,
) -> DNSAnalysis:
    """
    Perform basic DNS lookups for a hostname.

    Returns empty lists when a record type cannot be resolved.
    """

    hostname = _get_hostname(url)

    if not hostname:
        return DNSAnalysis()

    resolver = dns.resolver.Resolver()

    resolver.timeout = 3.0
    resolver.lifetime = 5.0

    return DNSAnalysis(
        a=_resolve(
            resolver,
            hostname,
            "A",
        ),
        aaaa=_resolve(
            resolver,
            hostname,
            "AAAA",
        ),
        mx=_resolve(
            resolver,
            hostname,
            "MX",
        ),
        ns=_resolve(
            resolver,
            hostname,
            "NS",
        ),
        txt=_resolve(
            resolver,
            hostname,
            "TXT",
        ),
    )