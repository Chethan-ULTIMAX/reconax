from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import httpx


@dataclass(slots=True)
class HTTPResponse:
    """Normalized information about an HTTP response."""

    requested_url: str
    final_url: str
    status_code: int
    reason_phrase: str
    http_version: str
    content_type: str | None
    content_length: int | None
    elapsed_ms: float
    headers: dict[str, str]
    body: str


class HTTPClient:
    """Small and respectful HTTP client for ReconAx."""

    DEFAULT_USER_AGENT = "ReconAx/0.1.0"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.timeout = timeout
        self.user_agent = user_agent

    @staticmethod
    def normalize_url(url: str) -> str:
        """
        Normalize and validate a URL.

        If the user provides:
            example.com

        it becomes:
            https://example.com
        """

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

    def get(self, url: str) -> HTTPResponse:
        """
        Perform one GET request and follow redirects.

        Returns a structured HTTPResponse object.
        """

        requested_url = self.normalize_url(url)

        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        }

        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:

            response = client.get(
                requested_url,
                headers=request_headers,
            )

        content_length = None

        raw_content_length = response.headers.get("content-length")

        if raw_content_length and raw_content_length.isdigit():
            content_length = int(raw_content_length)

        return HTTPResponse(
            requested_url=requested_url,
            final_url=str(response.url),
            status_code=response.status_code,
            reason_phrase=response.reason_phrase,
            http_version=response.http_version,
            content_type=response.headers.get("content-type"),
            content_length=content_length,
            elapsed_ms=round(response.elapsed.total_seconds() * 1000, 2),
            headers=dict(response.headers),
            body=response.text,
        )