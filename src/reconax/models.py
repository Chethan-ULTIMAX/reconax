from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


@dataclass(slots=True)
class HeaderAnalysis:
    """Analysis of HTTP security-related headers."""

    present: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CookieInfo:
    """Safe representation of a cookie.

    Cookie values are intentionally never stored.
    """

    name: str
    secure: bool
    httponly: bool
    samesite: str | None


@dataclass(slots=True)
class HTMLAnalysis:
    """Information extracted from an HTML document."""

    title: str | None = None
    meta_description: str | None = None

    links: list[str] = field(default_factory=list)
    internal_links: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)

    scripts: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RobotsAnalysis:
    """robots.txt information."""

    found: bool = False
    disallow_rules: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DNSAnalysis:
    """Basic DNS information."""

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReconReport:
    """Complete ReconAx analysis result."""

    requested_url: str
    final_url: str

    status_code: int
    reason_phrase: str

    http_version: str

    content_type: str | None
    content_length: int | None

    elapsed_ms: float

    headers: HeaderAnalysis
    cookies: list[CookieInfo]

    html: HTMLAnalysis

    robots: RobotsAnalysis

    dns: DNSAnalysis

    def to_dict(self) -> dict[str, Any]:
        """Convert the report into a Python dictionary."""

        return asdict(self)

    def to_json(
        self,
        path: str | None = None,
    ) -> str:
        """
        Convert the report to JSON.

        If path is provided, the JSON is also written to that file.
        """

        data = json.dumps(
            self.to_dict(),
            indent=2,
            ensure_ascii=False,
        )

        if path:
            with open(path, "w", encoding="utf-8") as file:
                file.write(data)

        return data