"""High-level ReconAx API."""

from __future__ import annotations

from .context import AnalysisContext
from .models import ReconReport


class ReconAx:
    """Main public interface for ReconAx analysis."""

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
        return self.context.url

    @property
    def normalized_url(self) -> str:
        return self.context.normalized_url

    def http(self):
        return self.context.http_result()

    def headers(self):
        return self.context.headers_result()

    def cookies(self):
        return self.context.cookies_result()

    def html(self):
        return self.context.html_result()

    def robots(self):
        return self.context.robots_result()

    def dns(self):
        return self.context.dns_result()

    def tls(self):
        return self.context.tls_result()

    def tech(self):
        return self.context.tech_result()

    def sitemap(self):
        return self.context.sitemap_result()

    def cors(self):
        return self.context.cors_result()

    def csp(self):
        return self.context.csp_result()

    def sri(self):
        return self.context.sri_result()

    def security_txt(self):
        return self.context.security_txt_result()

    def metadata(self):
        return self.context.metadata_result()

    def resources(self):
        return self.context.resources_result()

    def endpoints(self):
        return self.context.endpoints_result()

    def attack_surface(self):
        return self.context.attack_surface_result()

    def score(self):
        return self.context.score_result()

    def analyze(self, *, include_dns: bool = True) -> ReconReport:
        """Run the complete passive analysis using shared module caches."""
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
            score=self.score(),
        )
        return report

    def close(self) -> None:
        self.context.close()

    def __enter__(self) -> "ReconAx":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
