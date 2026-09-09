"""
Data models used throughout ReconAx.

All analysis modules return structured dataclasses. This keeps the
analysis layer independent from the CLI and output formatters.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


def _serialize(value: Any) -> Any:
    """Recursively convert ReconAx objects into JSON-compatible values."""
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()

    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]

    if hasattr(value, "__dataclass_fields__"):
        return {
            key: _serialize(item)
            for key, item in asdict(value).items()
        }

    return value


@dataclass
class HTTPResponse:
    """Information collected from the primary HTTP request."""

    requested_url: str
    final_url: str
    status_code: int
    response_time_ms: float
    http_version: str
    content_type: str
    content_length: int | None
    content: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def successful(self) -> bool:
        """Return True for a normal 2xx response."""
        return 200 <= self.status_code < 300

    @property
    def redirect_count(self) -> int:
        """Return the number of redirects encountered."""
        return len(self.redirect_chain)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)

        # Avoid placing a potentially large HTML document in normal
        # serialized analysis output.
        data.pop("content", None)

        data["successful"] = self.successful
        data["redirect_count"] = self.redirect_count

        return _serialize(data)


@dataclass
class HeaderAnalysis:
    """Security and informational HTTP header analysis."""

    present: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    informational: dict[str, str] = field(default_factory=dict)
    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class CookieInfo:
    """Security-relevant information about one HTTP cookie."""

    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    path: str | None = None
    domain: str | None = None
    expires: str | None = None
    max_age: int | None = None
    raw_attributes: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class CookieAnalysis:
    """Complete cookie analysis."""

    cookies: list[CookieInfo] = field(default_factory=list)
    count: int = 0
    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class HTMLAnalysis:
    """Analysis of the returned HTML document."""

    title: str | None = None
    meta_description: str | None = None
    canonical: str | None = None
    language: str | None = None
    charset: str | None = None
    viewport: str | None = None

    link_count: int = 0
    internal_links: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)

    script_count: int = 0
    style_count: int = 0
    image_count: int = 0
    iframe_count: int = 0
    form_count: int = 0

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class RobotsAnalysis:
    """Analysis of robots.txt."""

    found: bool = False
    status_code: int | None = None
    user_agents: list[str] = field(default_factory=list)
    allow_rules: list[str] = field(default_factory=list)
    disallow_rules: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    raw_content: str = ""
    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)

        # robots.txt may contain a substantial amount of text.
        # Keep raw_content out of ordinary JSON reports.
        data.pop("raw_content", None)

        return _serialize(data)


@dataclass
class DNSAnalysis:
    """DNS records observed for the target hostname."""

    hostname: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class TLSAnalysis:
    """TLS connection and certificate information."""

    hostname: str
    port: int = 443
    tls_version: str | None = None
    cipher: str | None = None

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    serial_number: str | None = None

    valid_from: str | None = None
    valid_until: str | None = None
    days_remaining: int | None = None

    hostname_match: bool | None = None
    subject_alt_names: list[str] = field(default_factory=list)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class Technology:
    """One passively detected technology."""

    name: str
    category: str = "Unknown"
    confidence: str = "likely"
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class TechAnalysis:
    """Passive technology detection result."""

    technologies: list[Technology] = field(default_factory=list)
    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class SitemapAnalysis:
    """Sitemap discovery and parsing information."""

    found: bool = False
    sitemap_type: str | None = None
    status_code: int | None = None
    sitemap_urls: list[str] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    url_count: int = 0
    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class CORSAnalysis:
    """Passive analysis of CORS response headers."""

    allow_origin: str | None = None
    allow_credentials: bool | None = None
    allow_methods: str | None = None
    allow_headers: str | None = None
    expose_headers: str | None = None
    max_age: str | None = None

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class CSPAnalysis:
    """Parsed Content-Security-Policy information."""

    present: bool = False
    directives: dict[str, list[str]] = field(default_factory=dict)
    unsafe_inline: bool = False
    unsafe_eval: bool = False
    wildcard_sources: list[str] = field(default_factory=list)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class SRIAnalysis:
    """Subresource Integrity analysis."""

    external_scripts: int = 0
    external_stylesheets: int = 0
    protected_resources: int = 0
    unprotected_resources: int = 0
    resources: list[dict[str, Any]] = field(default_factory=list)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class SecurityTxtAnalysis:
    """Analysis of /.well-known/security.txt."""

    found: bool = False
    status_code: int | None = None
    contact: list[str] = field(default_factory=list)
    expires: str | None = None
    policy: list[str] = field(default_factory=list)
    canonical: list[str] = field(default_factory=list)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class MetadataAnalysis:
    """Public HTML metadata."""

    title: str | None = None
    description: str | None = None
    canonical: str | None = None
    generator: str | None = None
    charset: str | None = None
    language: str | None = None
    viewport: str | None = None
    robots: str | None = None

    open_graph: dict[str, str] = field(default_factory=dict)
    twitter: dict[str, str] = field(default_factory=dict)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class ResourceInfo:
    """One resource referenced by a page."""

    url: str
    resource_type: str
    origin: str
    tag: str | None = None
    attribute: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class ResourceAnalysis:
    """External and first-party resource analysis."""

    resources: list[ResourceInfo] = field(default_factory=list)
    first_party_count: int = 0
    third_party_count: int = 0
    by_type: dict[str, int] = field(default_factory=dict)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class EndpointInfo:
    """One publicly observed endpoint-like URL."""

    url: str
    path: str
    source: str
    category: str = "other"

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class EndpointAnalysis:
    """Passive endpoint intelligence."""

    endpoints: list[EndpointInfo] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    api_like: list[str] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class AttackSurfaceAnalysis:
    """Passive public attack-surface summary."""

    pages: list[str] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    api_like_urls: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    external_domains: list[str] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    robots_rules: list[str] = field(default_factory=list)

    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class ScoreItem:
    """One component of the website hygiene score."""

    name: str
    score: int
    maximum: int
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class ScoreReport:
    """Transparent 0-100 website hygiene score."""

    score: int = 0
    maximum: int = 100
    grade: str = "N/A"
    categories: list[ScoreItem] = field(default_factory=list)
    verdict: str = "INFO"
    flags: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass
class ReconReport:
    """Complete ReconAx v0.2.0 analysis report."""

    target: str
    normalized_url: str

    http: HTTPResponse | None = None
    headers: HeaderAnalysis | None = None
    cookies: CookieAnalysis | None = None
    html: HTMLAnalysis | None = None
    robots: RobotsAnalysis | None = None
    dns: DNSAnalysis | None = None
    tls: TLSAnalysis | None = None
    tech: TechAnalysis | None = None
    sitemap: SitemapAnalysis | None = None
    cors: CORSAnalysis | None = None
    csp: CSPAnalysis | None = None
    sri: SRIAnalysis | None = None
    security_txt: SecurityTxtAnalysis | None = None
    metadata: MetadataAnalysis | None = None
    resources: ResourceAnalysis | None = None
    endpoints: EndpointAnalysis | None = None
    attack_surface: AttackSurfaceAnalysis | None = None
    score: ScoreReport | None = None

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))

    def to_json(self, indent: int = 2) -> str:
        """Return the report as formatted JSON."""
        return json.dumps(
            self.to_dict(),
            indent=indent,
            ensure_ascii=False,
        )