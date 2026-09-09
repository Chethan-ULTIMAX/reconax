"""Shared analysis context for ReconAx."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .http_client import HTTPClient


@dataclass
class AnalysisContext:
    """Shared state and lazy caches for one ReconAx target."""

    url: str
    timeout: float = 10.0
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        self._client = HTTPClient(
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
        )
        self._response: Optional[Any] = None
        self._soup: Optional[BeautifulSoup] = None
        self._results: dict[str, Any] = {}

    @property
    def normalized_url(self) -> str:
        """Return the URL normalized by the HTTP client."""
        return self._client.normalize_url(self.url)

    def response(self, refresh: bool = False):
        """Return the cached primary HTTP response."""
        if self._response is None or refresh:
            self._response = self._client.fetch(self.url)
            self._soup = None
            self._results.clear()
        return self._response

    def html(self) -> BeautifulSoup:
        """Return the lazily parsed primary HTML document."""
        if self._soup is None:
            self._soup = BeautifulSoup(
                self.response().content or "",
                "lxml",
            )
        return self._soup

    @property
    def body(self) -> str:
        return self.response().content or ""

    @property
    def response_headers(self) -> dict[str, str]:
        return self.response().headers

    @property
    def final_url(self) -> str:
        return self.response().final_url

    @property
    def status_code(self) -> int:
        return self.response().status_code

    def get(self, url: str, **kwargs: Any):
        """Perform a secondary GET using the shared HTTP client's settings."""
        return self._client._client.get(url, **kwargs)

    def _cached_module(self, key: str, module_class: type):
        """Instantiate and cache one module result."""
        if key not in self._results:
            self._results[key] = module_class(self).analyze()
        return self._results[key]

    def http_result(self):
        from .modules.http import HTTPModule
        return self._cached_module("http", HTTPModule)

    def headers_result(self):
        from .modules.headers import HeadersModule
        return self._cached_module("headers", HeadersModule)

    def cookies_result(self):
        from .modules.cookies import CookiesModule
        return self._cached_module("cookies", CookiesModule)

    def html_result(self):
        from .modules.html import HTMLModule
        return self._cached_module("html", HTMLModule)

    def robots_result(self):
        from .modules.robots import RobotsModule
        return self._cached_module("robots", RobotsModule)

    def dns_result(self):
        from .modules.dns import DNSModule
        return self._cached_module("dns", DNSModule)

    def tls_result(self):
        from .modules.tls import TLSModule
        return self._cached_module("tls", TLSModule)

    def tech_result(self):
        from .modules.tech import TechModule
        return self._cached_module("tech", TechModule)

    def sitemap_result(self):
        from .modules.sitemap import SitemapModule
        return self._cached_module("sitemap", SitemapModule)

    def cors_result(self):
        from .modules.cors import CORSModule
        return self._cached_module("cors", CORSModule)

    def csp_result(self):
        from .modules.csp import CSPModule
        return self._cached_module("csp", CSPModule)

    def sri_result(self):
        from .modules.sri import SRIModule
        return self._cached_module("sri", SRIModule)

    def security_txt_result(self):
        from .modules.security_txt import SecurityTxtModule
        return self._cached_module("security_txt", SecurityTxtModule)

    def metadata_result(self):
        from .modules.metadata import MetadataModule
        return self._cached_module("metadata", MetadataModule)

    def resources_result(self):
        from .modules.resources import ResourcesModule
        return self._cached_module("resources", ResourcesModule)

    def endpoints_result(self):
        from .modules.endpoints import EndpointsModule
        return self._cached_module("endpoints", EndpointsModule)

    def attack_surface_result(self):
        from .modules.attack_surface import AttackSurfaceModule
        return self._cached_module("attack_surface", AttackSurfaceModule)

    def score_result(self):
        from .modules.score import ScoreModule
        return self._cached_module("score", ScoreModule)

    def clear_cache(self) -> None:
        """Clear the response, HTML, and module-result caches."""
        self._response = None
        self._soup = None
        self._results.clear()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AnalysisContext":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
