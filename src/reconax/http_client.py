from __future__ import annotations

from dataclasses import dataclass
import time
from urllib.parse import urlparse

import httpx


@dataclass(slots=True)
class HTTPResponse:
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
    """Small, respectful HTTP client used by ReconAx."""

    def __init__(self, timeout: float = 10.0, user_agent: str = "ReconAx/0.1.0"):
        self.timeout = timeout
        self.user_agent = user_agent

    @staticmethod
    def normalize_url(url: str) -> str:
        url = url.strip()
        if not url:
            raise ValueError("URL cannot be empty")
        if not urlparse(url).scheme:
            url = f"https://{url}"
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("URL must be a valid HTTP or HTTPS URL")
        return url

    def get(self, url: str) -> HTTPResponse:
        requested_url = self.normalize_url(url)
        headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}

        started = time.perf_counter()
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            response = client.get(requested_url, headers=headers)
        elapsed_ms = (time.perf_counter() - started) * 1000

        content_length = None
        raw_length = response.headers.get("content-length")
        if raw_length and raw_length.isdigit():
            content_length = int(raw_length)

        return HTTPResponse(
            requested_url=requested_url,
            final_url=str(response.url),
            status_code=response.status_code,
            reason_phrase=response.reason_phrase,
            http_version=response.http_version,
            content_type=response.headers.get("content-type"),
            content_length=content_length,
            elapsed_ms=round(elapsed_ms, 2),
            headers=dict(response.headers),
            body=response.text,
        )
