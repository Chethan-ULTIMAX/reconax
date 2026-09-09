from __future__ import annotations

from ..models import HeaderReport


SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def analyze_headers(headers: dict[str, str]) -> HeaderReport:
    normalized = {key.lower(): value for key, value in headers.items()}
    present = [name for name in SECURITY_HEADERS if name in normalized]
    missing = [name for name in SECURITY_HEADERS if name not in normalized]
    values = {name: normalized[name] for name in present}
    return HeaderReport(present, missing, values)
