from __future__ import annotations

from urllib.parse import urljoin

from ..http_client import HTTPClient
from ..models import RobotsReport


def fetch_robots(client: HTTPClient, base_url: str) -> RobotsReport:
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        response = client.get(robots_url)
    except Exception:
        return RobotsReport()
    if response.status_code != 200:
        return RobotsReport(found=False)

    disallow: list[str] = []
    sitemaps: list[str] = []
    for raw_line in response.body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "disallow" and value:
            disallow.append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
    return RobotsReport(True, disallow, sitemaps)
