"""
ReconAx - Lightweight, developer-friendly website analyzer.

ReconAx provides a modular, passive analysis toolkit for inspecting
publicly observable website information such as HTTP behavior, security
headers, cookies, HTML, DNS, TLS, technologies, sitemaps, and security
configuration.

The package is designed to be useful from both Python code and the CLI.
"""

from .core import ReconAx
from .models import (
    ReconReport,
    HTTPResponse,
    HeaderAnalysis,
    CookieInfo,
    HTMLAnalysis,
    RobotsAnalysis,
    DNSAnalysis,
    TLSAnalysis,
    TechAnalysis,
    SitemapAnalysis,
    CORSAnalysis,
    CSPAnalysis,
    SRIAnalysis,
    SecurityTxtAnalysis,
    MetadataAnalysis,
    ResourceAnalysis,
    EndpointAnalysis,
    AttackSurfaceAnalysis,
    ScoreReport,
)
from .shortcuts import (
    analyze,
    headers,
    cookies,
    html,
    robots,
    dns,
    tls,
    tech,
    sitemap,
    cors,
    csp,
    sri,
    security_txt,
    metadata,
    resources,
    endpoints,
    attack_surface,
    score,
)

__version__ = "0.2.0"

__all__ = [
    "ReconAx",
    "ReconReport",
    "HTTPResponse",
    "HeaderAnalysis",
    "CookieInfo",
    "HTMLAnalysis",
    "RobotsAnalysis",
    "DNSAnalysis",
    "TLSAnalysis",
    "TechAnalysis",
    "SitemapAnalysis",
    "CORSAnalysis",
    "CSPAnalysis",
    "SRIAnalysis",
    "SecurityTxtAnalysis",
    "MetadataAnalysis",
    "ResourceAnalysis",
    "EndpointAnalysis",
    "AttackSurfaceAnalysis",
    "ScoreReport",
    "analyze",
    "headers",
    "cookies",
    "html",
    "robots",
    "dns",
    "tls",
    "tech",
    "sitemap",
    "cors",
    "csp",
    "sri",
    "security_txt",
    "metadata",
    "resources",
    "endpoints",
    "attack_surface",
    "score",
    "__version__",
]