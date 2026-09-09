from __future__ import annotations

from urllib.parse import urljoin, urlparse

from ..http_client import HTTPClient
from ..models import RobotsAnalysis


def _get_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _parse_robots(text: str) -> RobotsAnalysis:
    disallow_rules: list[str] = []
    allow_rules: list[str] = []
    sitemap_urls: list[str] = []
    user_agents: list[str] = []
    seen_disallow: set[str] = set()
    seen_allow: set[str] = set()
    seen_sitemaps: set[str] = set()
    seen_agents: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue

        directive, value = line.split(":", 1)
        directive = directive.strip().lower()
        value = value.strip()

        if directive == "user-agent" and value and value not in seen_agents:
            seen_agents.add(value)
            user_agents.append(value)
        elif directive == "allow" and value and value not in seen_allow:
            seen_allow.add(value)
            allow_rules.append(value)
        elif directive == "disallow" and value and value not in seen_disallow:
            seen_disallow.add(value)
            disallow_rules.append(value)
        elif directive == "sitemap" and value and value not in seen_sitemaps:
            seen_sitemaps.add(value)
            sitemap_urls.append(value)

    return RobotsAnalysis(
        found=True,
        user_agents=user_agents,
        allow_rules=allow_rules,
        disallow_rules=disallow_rules,
        sitemap_urls=sitemap_urls,
        raw_content=text,
    )


def fetch_robots(client: HTTPClient, base_url: str) -> RobotsAnalysis:
    """Fetch and parse robots.txt with one request."""
    origin = _get_origin(base_url)
    robots_url = urljoin(origin + "/", "robots.txt")

    try:
        response = client.get(robots_url)
    except Exception:
        return RobotsAnalysis(found=False)

    if response.status_code != 200:
        return RobotsAnalysis(status_code=response.status_code)

    content_type = (response.content_type or "").lower()
    if content_type and not any(
        value in content_type
        for value in ("text/plain", "text", "application/octet-stream")
    ):
        return RobotsAnalysis(status_code=response.status_code)

    result = _parse_robots(response.content)
    result.status_code = response.status_code
    return result
