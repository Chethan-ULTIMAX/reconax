"""
Shared analysis context for ReconAx.

AnalysisContext owns the target URL, HTTP client, cached response,
and lazily-created HTML representation used by multiple analysis modules.

The context is intentionally lightweight. It does not perform analysis
itself; it provides shared resources to analysis modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from bs4 import BeautifulSoup

from .http_client import HTTPClient, HTTPResponse


@dataclass
class AnalysisContext:
    """
    Shared state for one ReconAx analysis.

    A context should normally represent one target URL. Modules receive
    the same context so they can reuse HTTP and HTML data rather than
    repeatedly fetching the target.

    Parameters
    ----------
    url:
        Target website URL.
    timeout:
        HTTP timeout in seconds.
    verify_ssl:
        Whether TLS certificate verification should be performed by the
        HTTP client.
    """

    url: str
    timeout: float = 10.0
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        self._client = HTTPClient(
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
        )
        self._response: Optional[HTTPResponse] = None
        self._soup: Optional[BeautifulSoup] = None

    @property
    def normalized_url(self) -> str:
        """
        Return the normalized URL that the HTTP client would request.
        """
        return self._client.normalize_url(self.url)

    def response(self, refresh: bool = False) -> HTTPResponse:
        """
        Return the cached HTTP response.

        The first call performs the HTTP request. Subsequent calls return
        the cached response unless refresh=True is explicitly requested.
        """
        if self._response is None or refresh:
            self._response = self._client.fetch(self.url)

            # The response has changed, so cached HTML must be discarded.
            self._soup = None

        return self._response

    def html(self) -> BeautifulSoup:
        """
        Return a BeautifulSoup representation of the cached response body.

        HTML is parsed lazily and cached for reuse by HTML, metadata,
        resource, endpoint, technology, CSP, SRI, and attack-surface
        modules.
        """
        if self._soup is None:
            response = self.response()

            content = response.content or ""

            self._soup = BeautifulSoup(
                content,
                "lxml",
            )

        return self._soup

    @property
    def body(self) -> str:
        """
        Return the response body as text.
        """
        return self.response().content

    @property
    def response_headers(self) -> dict[str, str]:
        """
        Return response headers from the cached HTTP response.
        """
        return self.response().headers

    @property
    def final_url(self) -> str:
        """
        Return the final URL after redirects.
        """
        return self.response().final_url

    @property
    def status_code(self) -> int:
        """
        Return the HTTP status code.
        """
        return self.response().status_code

    def clear_cache(self) -> None:
        """
        Clear cached response and HTML data.

        The HTTP client itself remains available and can be reused.
        """
        self._response = None
        self._soup = None

    def close(self) -> None:
        """
        Close the underlying HTTP client.
        """
        self._client.close()

    def __enter__(self) -> "AnalysisContext":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()