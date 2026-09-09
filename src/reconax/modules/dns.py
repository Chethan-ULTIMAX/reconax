"""
DNS analysis module.
"""

from __future__ import annotations

from urllib.parse import urlparse

import dns.exception
import dns.resolver

from ..context import AnalysisContext
from ..models import DNSAnalysis
from .base import Module


class DNSModule(Module[DNSAnalysis]):
    """Resolve selected DNS record types."""

    name = "dns"

    RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "CAA",
        "SOA",
    )

    def _hostname(self) -> str:
        parsed = urlparse(
            self.context.normalized_url
        )

        hostname = parsed.hostname

        if not hostname:
            raise ValueError(
                "Unable to determine hostname."
            )

        return hostname

    def analyze(self) -> DNSAnalysis:
        hostname = self._hostname()

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.context.timeout
        resolver.lifetime = self.context.timeout

        records: dict[str, list[str]] = {}
        errors: dict[str, str] = {}

        for record_type in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(
                    hostname,
                    record_type,
                )

                values: list[str] = []

                for answer in answers:
                    if record_type == "MX":
                        value = str(
                            answer.exchange
                        ).rstrip(".")
                        value = (
                            f"{answer.preference} "
                            f"{value}"
                        )
                    elif record_type == "SOA":
                        value = str(answer)
                    elif record_type == "TXT":
                        value = str(answer).strip('"')
                    else:
                        value = str(answer).rstrip(".")

                    values.append(value)

                if values:
                    records[record_type] = values

            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
            ):
                continue

            except (
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.exception.DNSException,
            ) as exc:
                errors[record_type] = str(exc)

        flags: list[str] = []
        explanations: list[str] = []

        if not records:
            flags.append(
                "No supported DNS records were resolved."
            )
            verdict = "WARN"
        else:
            verdict = "PASS"

        if errors:
            explanations.append(
                "Some DNS record types could not be resolved; "
                "this does not necessarily indicate a problem with the site."
            )

        return DNSAnalysis(
            hostname=hostname,
            records=records,
            errors=errors,
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )