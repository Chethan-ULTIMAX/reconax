"""Sitemap analysis module."""

from __future__ import annotations

from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from ..context import AnalysisContext
from ..models import SitemapAnalysis
from .base import Module


class SitemapModule(Module[SitemapAnalysis]):
    """Analyze publicly accessible XML sitemaps."""

    name = "sitemap"
    MAX_SITEMAPS = 10
    MAX_URLS = 5000

    def _fetch(self, url: str) -> httpx.Response:
        return self.context.get(
            url,
            headers={
                "Accept": "application/xml, text/xml, text/plain, */*"
            },
        )

    @staticmethod
    def _parse(content: str, base_url: str) -> tuple[str | None, list[str]]:
        soup = BeautifulSoup(content, "xml")
        root = soup.find()
        if root is None:
            return None, []

        root_name = root.name.lower()
        if root_name == "sitemapindex":
            sitemap_type = "index"
        elif root_name == "urlset":
            sitemap_type = "urlset"
        else:
            return None, []

        values = [
            loc.get_text(strip=True)
            for loc in soup.find_all("loc")
            if loc.get_text(strip=True)
        ]
        return sitemap_type, [urljoin(base_url, value) for value in values]

    def analyze(self) -> SitemapAnalysis:
        base_url = self.context.final_url
        candidates = [urljoin(base_url, "/sitemap.xml")]

        try:
            for sitemap_url in self.context.robots_result().sitemap_urls:
                if sitemap_url not in candidates:
                    candidates.append(sitemap_url)
        except Exception:
            pass

        checked: set[str] = set()
        discovered_urls: list[str] = []
        queue = candidates[:]
        found = False
        sitemap_type: str | None = None
        status_code: int | None = None
        error: str | None = None

        while queue and len(checked) < self.MAX_SITEMAPS and len(discovered_urls) < self.MAX_URLS:
            sitemap_url = queue.pop(0)
            if sitemap_url in checked:
                continue
            checked.add(sitemap_url)

            try:
                response = self._fetch(sitemap_url)
            except httpx.RequestError as exc:
                error = str(exc)
                continue

            status_code = response.status_code
            if response.status_code != 200:
                continue

            current_type, values = self._parse(response.text, sitemap_url)
            if current_type is None:
                continue

            found = True
            if sitemap_type is None:
                sitemap_type = current_type

            if current_type == "index":
                for value in values:
                    if value not in checked and value not in queue:
                        queue.append(value)
            else:
                for value in values:
                    if value not in discovered_urls:
                        discovered_urls.append(value)

        flags: list[str] = []
        explanations: list[str] = []
        if not found:
            flags.append("No readable sitemap was found.")
            explanations.append(
                "ReconAx checked sitemap.xml and sitemap URLs publicly referenced by robots.txt."
            )

        return SitemapAnalysis(
            found=found,
            sitemap_type=sitemap_type,
            status_code=status_code,
            sitemap_urls=list(dict.fromkeys(candidates)),
            discovered_urls=discovered_urls,
            url_count=len(discovered_urls),
            verdict="INFO",
            flags=flags,
            explanations=explanations,
            error=error,
        )
