from __future__ import annotations

from ..models import HeaderAnalysis


SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def analyze_headers(
    headers: dict[str, str],
) -> HeaderAnalysis:
    """
    Analyze security-related HTTP response headers.

    The result describes which headers are present or missing.
    It is not a vulnerability scanner.
    """

    # HTTP header names are case-insensitive.
    normalized_headers = {
        name.lower(): value
        for name, value in headers.items()
    }

    present: dict[str, str] = {}
    missing: list[str] = []

    for header_name in SECURITY_HEADERS:
        if header_name in normalized_headers:
            present[header_name] = normalized_headers[
                header_name
            ]
        else:
            missing.append(header_name)

    return HeaderAnalysis(
        present=present,
        missing=missing,
    )