"""
Security header analysis module.
"""

from __future__ import annotations

from ..models import HeaderAnalysis
from ..context import AnalysisContext
from .base import Module


class HeadersModule(Module[HeaderAnalysis]):
    """Analyze important HTTP security headers."""

    name = "headers"

    SECURITY_HEADERS = (
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
    )

    INFORMATIONAL_HEADERS = (
        "Server",
        "X-Powered-By",
        "Cache-Control",
    )

    def analyze(self) -> HeaderAnalysis:
        response = self.context.response()

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        present: dict[str, str] = {}
        missing: list[str] = []
        informational: dict[str, str] = []
        flags: list[str] = []
        explanations: list[str] = []

        for header in self.SECURITY_HEADERS:
            value = headers.get(header.lower())

            if value:
                present[header] = value
            else:
                missing.append(header)

        for header in self.INFORMATIONAL_HEADERS:
            value = headers.get(header.lower())

            if value:
                informational[header] = value

        if "Content-Security-Policy" not in present:
            flags.append(
                "Content-Security-Policy is not present."
            )
            explanations.append(
                "CSP can reduce the impact of certain classes "
                "of browser-side injection."
            )

        if "Strict-Transport-Security" not in present:
            flags.append(
                "Strict-Transport-Security is not present."
            )
            explanations.append(
                "HSTS tells compatible browsers to prefer HTTPS "
                "for the site."
            )

        if "X-Content-Type-Options" not in present:
            flags.append(
                "X-Content-Type-Options is not present."
            )

        if "X-Frame-Options" not in present:
            flags.append(
                "X-Frame-Options is not present."
            )

        if "Server" in informational:
            flags.append(
                "Server response header is exposed."
            )

        if "X-Powered-By" in informational:
            flags.append(
                "X-Powered-By response header is exposed."
            )

        # The module uses WARN when an important configuration item
        # is absent, but does not call the website vulnerable.
        verdict = "WARN" if missing else "PASS"

        return HeaderAnalysis(
            present=present,
            missing=missing,
            informational=informational,
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )