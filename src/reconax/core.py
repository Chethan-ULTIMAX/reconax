"""
High-level ReconAx API.

ReconAx coordinates the individual analysis modules while keeping each
module independently usable.

The class is deliberately thin: analysis logic belongs inside modules.
"""

from __future__ import annotations

from typing import Optional

from .context import AnalysisContext
from .models import ReconReport

from .modules.http import HTTPModule
from .modules.headers import HeadersModule
from .modules.cookies import CookiesModule
from .modules.html import HTMLModule
from .modules.robots import RobotsModule
from .modules.dns import DNSModule
from .modules.tls import TLSModule
from .modules.tech import TechModule
from .modules.sitemap import SitemapModule
from .modules.cors import CORSModule
from .modules.csp import CSPModule
from .modules.sri import SRIModule
from .modules.security_txt import SecurityTxtModule
from .modules.metadata import MetadataModule
from .modules.resources import ResourcesModule
from .modules.endpoints import EndpointsModule
from .modules.attack_surface import AttackSurfaceModule
from .modules.score import ScoreModule


class ReconAx:
    """
    Main ReconAx analysis interface.

    Example
    -------
    >>> recon = ReconAx("https://example.com")
    >>> report = recon.analyze()

    Individual modules are also available:

    >>> recon.headers()
    >>> recon.cookies()
    >>> recon.tls()
    >>> recon.tech()
    >>> recon.score()
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        verify_ssl: bool = True,
    ) -> None:
        self.context = AnalysisContext(
            url=url,
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    @property
    def url(self) -> str:
        """Return the original target URL."""
        return self.context.url

    @property
    def normalized_url(self) -> str:
        """Return the normalized target URL."""
        return self.context.normalized_url

    def http(self):
        """Run HTTP analysis."""
        return HTTPModule(self.context).analyze()

    def headers(self):
        """Run security-header analysis."""
        return HeadersModule(self.context).analyze()

    def cookies(self):
        """Run cookie analysis."""
        return CookiesModule(self.context).analyze()

    def html(self):
        """Run HTML analysis."""
        return HTMLModule(self.context).analyze()

    def robots(self):
        """Run robots.txt analysis."""
        return RobotsModule(self.context).analyze()

    def dns(self):
        """Run DNS analysis."""
        return DNSModule(self.context).analyze()

    def tls(self):
        """Run TLS/certificate analysis."""
        return TLSModule(self.context).analyze()

    def tech(self):
        """Run passive technology detection."""
        return TechModule(self.context).analyze()

    def sitemap(self):
        """Run sitemap analysis."""
        return SitemapModule(self.context).analyze()

    def cors(self):
        """Run passive CORS analysis."""
        return CORSModule(self.context).analyze()

    def csp(self):
        """Run Content-Security-Policy analysis."""
        return CSPModule(self.context).analyze()

    def sri(self):
        """Run Subresource Integrity analysis."""
        return SRIModule(self.context).analyze()

    def security_txt(self):
        """Analyze /.well-known/security.txt."""
        return SecurityTxtModule(self.context).analyze()

    def metadata(self):
        """Analyze public HTML metadata."""
        return MetadataModule(self.context).analyze()

    def resources(self):
        """Analyze resources referenced by the page."""
        return ResourcesModule(self.context).analyze()

    def endpoints(self):
        """Extract publicly observed endpoint-like URLs."""
        return EndpointsModule(self.context).analyze()

    def attack_surface(self):
        """Build a passive public attack-surface summary."""
        return AttackSurfaceModule(self.context).analyze()

    def score(self):
        """Calculate the website hygiene score."""
        return ScoreModule(self.context).analyze()

    def analyze(
        self,
        *,
        include_dns: bool = True,
    ) -> ReconReport:
        """
        Run the complete ReconAx analysis.

        The initial HTTP response is shared between modules through the
        AnalysisContext. Additional explicitly required resources such
        as robots.txt, sitemap.xml, security.txt, DNS, and TLS are fetched
        only by their respective modules.
        """
        report = ReconReport(
            target=self.url,
            normalized_url=self.normalized_url,
            http=self.http(),
            headers=self.headers(),
            cookies=self.cookies(),
            html=self.html(),
            robots=self.robots(),
            dns=self.dns() if include_dns else None,
            tls=self.tls(),
            tech=self.tech(),
            sitemap=self.sitemap(),
            cors=self.cors(),
            csp=self.csp(),
            sri=self.sri(),
            security_txt=self.security_txt(),
            metadata=self.metadata(),
            resources=self.resources(),
            endpoints=self.endpoints(),
            attack_surface=self.attack_surface(),
            score=None,
        )

        # Score is calculated after the other relevant analyses exist.
        report.score = self.score()

        return report

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self.context.close()

    def __enter__(self) -> "ReconAx":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()