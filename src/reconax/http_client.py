"""HTTP client used by ReconAx."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import httpx

from .models import HTTPResponse


class HTTPClient:
    """Small, respectful HTTP client with redirect support."""

    DEFAULT_USER_AGENT = "ReconAx/0.1.0"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_ssl: bool = True,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=verify_ssl,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
        )

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize and validate an HTTP/HTTPS URL."""
        url = url.strip()
        if not url:
            raise ValueError("URL cannot be empty.")

        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        if not parsed.netloc:
            raise ValueError("Invalid URL: hostname is missing.")

        return url

    def raw_get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform a raw GET for secondary public resources."""
        return self._client.get(self.normalize_url(url), **kwargs)

    def fetch(self, url: str) -> HTTPResponse:
        """Perform the primary GET and return a structured HTTPResponse."""
        requested_url = self.normalize_url(url)
        started = time.perf_counter()

        try:
            response = self._client.get(requested_url)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        except httpx.RequestError as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            return HTTPResponse(
                requested_url=requested_url,
                final_url=requested_url,
                status_code=0,
                response_time_ms=elapsed_ms,
                http_version="",
                content_type="",
                content_length=None,
                content="",
                headers={},
                redirect_chain=[],
                error=str(exc),
            )

        redirect_chain = [str(item.url) for item in response.history]
        raw_length = response.headers.get("content-length")
        content_length = (
            int(raw_length)
            if raw_length and raw_length.isdigit()
            else len(response.content)
        )

        return HTTPResponse(
            requested_url=requested_url,
            final_url=str(response.url),
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            http_version=response.http_version,
            content_type=response.headers.get("content-type", ""),
            content_length=content_length,
            content=response.text,
            headers=dict(response.headers),
            redirect_chain=redirect_chain,
        )

    def get(self, url: str) -> HTTPResponse:
        """Backward-compatible alias for the structured primary request."""
        return self.fetch(url)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
