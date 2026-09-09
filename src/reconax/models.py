from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any


@dataclass(slots=True)
class HeaderReport:
    present: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class CookieInfo:
    name: str
    http_only: bool = False
    secure: bool = False
    same_site: str | None = None


@dataclass(slots=True)
class HTMLReport:
    title: str | None = None
    meta_description: str | None = None
    links: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)

    @property
    def internal_link_count(self) -> int:
        return len(self.links)

    @property
    def external_link_count(self) -> int:
        return len(self.external_links)


@dataclass(slots=True)
class RobotsReport:
    found: bool = False
    disallow_rules: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DNSReport:
    A: list[str] = field(default_factory=list)
    AAAA: list[str] = field(default_factory=list)
    MX: list[str] = field(default_factory=list)
    NS: list[str] = field(default_factory=list)
    TXT: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReconReport:
    requested_url: str
    final_url: str
    status_code: int
    reason_phrase: str
    http_version: str
    content_type: str | None
    content_length: int | None
    elapsed_ms: float
    headers: HeaderReport
    cookies: list[CookieInfo]
    html: HTMLReport
    robots: RobotsReport
    dns: DNSReport

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, path: str | None = None) -> str:
        data = json.dumps(self.to_dict(), indent=2)
        if path:
            with open(path, "w", encoding="utf-8") as file:
                file.write(data)
        return data
