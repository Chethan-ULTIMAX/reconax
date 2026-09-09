from __future__ import annotations

from urllib.parse import urljoin, urlparse

from ..http_client import HTTPClient
from ..models import RobotsAnalysis


def _get_origin(url: str) -> str:
    """Return scheme + hostname + optional port."""

    parsed = urlparse(url)

    return f"{parsed.scheme}://{parsed.netloc}"


def _parse_robots(
    text: str,
) -> RobotsAnalysis:
    """Parse robots.txt content."""

    disallow_rules: list[str] = []
    sitemap_urls: list[str] = []

    seen_disallow: set[str] = set()
    seen_sitemaps: set[str] = set()

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        # Remove comments.
        if "#" in line:
            line = line.split(
                "#",
                1,
            )[0].strip()

        if not line:
            continue

        if ":" not in line:
            continue

        directive, value = line.split(
            ":",
            1,
        )

        directive = directive.strip().lower()
        value = value.strip()

        if directive == "disallow":

            if value and value not in seen_disallow:
                seen_disallow.add(value)
                disallow_rules.append(value)

        elif directive == "sitemap":

            if value and value not in seen_sitemaps:
                seen_sitemaps.add(value)
                sitemap_urls.append(value)

    return RobotsAnalysis(
        found=True,
        disallow_rules=disallow_rules,
        sitemap_urls=sitemap_urls,
    )


def fetch_robots(
    client: HTTPClient,
    base_url: str,
) -> RobotsAnalysis:
    """
    Fetch and parse robots.txt.

    Only one request is made.
    """

    origin = _get_origin(base_url)

    robots_url = urljoin(
        origin + "/",
        "robots.txt",
    )

    try:
        response = client.get(
            robots_url,
        )
    except Exception:
        return RobotsAnalysis(
            found=False,
        )

    if response.status_code != 200:
        return RobotsAnalysis(
            found=False,
        )

    content_type = (
        response.content_type or ""
    ).lower()

    # robots.txt is normally text/plain.
    # Some servers omit Content-Type, so we don't reject
    # a successful response solely because of the header.
    if content_type and not (
        "text/plain" in content_type
        or "text" in content_type
        or "application/octet-stream" in content_type
    ):
        return RobotsAnalysis(
            found=False,
        )

    return _parse_robots(
        response.body,
    )