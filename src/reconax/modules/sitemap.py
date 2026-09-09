"""
Sitemap analysis module.

Discovers and parses the standard sitemap.xml location and sitemap
URLs referenced by robots.txt. Sitemap indexes are supported.
"""

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

    def _fetch(
        self,
        url: str,
    ) -> httpx.Response:
        return self.context._client._client.get(
            url,
            headers={
                "Accept": (
                    "application/xml,"
                    "text/xml,"
                    "text/plain,"
                    "*/*"
                )
            },
        )

    @staticmethod
    def _parse(
        content: str,
        base_url: str,
    ) -> tuple[
        str | None,
        list[str],
    ]:
        soup = BeautifulSoup(
            content,
            "xml",
        )

        root = soup.find()

        if root is None:
            return None, []

        root_name = root.name.lower()

        if root_name == "sitemapindex":
            sitemap_type = "index"
            values = [
                str(loc.get_text(strip=True))
                for loc in soup.find_all("loc")
                if loc.get_text(strip=True)
            ]
        elif root_name == "urlset":
            sitemap_type = "urlset"
            values = [
                str(loc.get_text(strip=True))
                for loc in soup.find_all("loc")
                if loc.get_text(strip=True)
            ]
        else:
            return None, []

        urls = [
            urljoin(
                base_url,
                value,
            )
            for value in values
        ]

        return sitemap_type, urls

    def analyze(self) -> SitemapAnalysis:
        base_url = self.context.final_url

        candidates: list[str] = [
            urljoin(
                base_url,
                "/sitemap.xml",
            )
        ]

        # Robots is already cached if the module was previously called.
        # Calling it here also keeps sitemap discovery useful standalone.
        try:
            robots_result = self.context.robots_result()

            for sitemap_url in (
                robots_result.sitemap_urls
            ):
                if sitemap_url not in candidates:
                    candidates.append(
                        sitemap_url
                    )
        except Exception:
            pass

        checked: set[str] = set()
        discovered_urls: list[str] = []
        found = False
        sitemap_type: str | None = None
        status_code: int | None = None
        error: str | None = None

        queue = candidates[:]

        while (
            queue
            and len(checked) < self.MAX_SITEMAPS
            and len(discovered_urls)
            < self.MAX_URLS
        ):
            sitemap_url = queue.pop(0)

            if sitemap_url in checked:
                continue

            checked.add(sitemap_url)

            try:
                response = self._fetch(
                    sitemap_url
                )
            except httpx.RequestError as exc:
                error = str(exc)
                continue

            status_code = response.status_code

            if response.status_code != 200:
                continue

            found = True

            current_type, values = self._parse(
                response.text,
                sitemap_url,
            )

            if current_type is None:
                continue

            if sitemap_type is None:
                sitemap_type = current_type

            if current_type == "index":
                for value in values:
                    if (
                        value not in checked
                        and value not in queue
                    ):
                        queue.append(value)

            else:
                for value in values:
                    if (
                        value not in discovered_urls
                    ):
                        discovered_urls.append(
                            value
                        )

        flags: list[str] = []
        explanations: list[str] = []

        if not found:
            flags.append(
                "No readable sitemap was found."
            )
            explanations.append(
                "ReconAx checked the standard sitemap.xml path "
                "and sitemap URLs publicly referenced by robots.txt."
            )

        return SitemapAnalysis(
            found=found,
            sitemap_type=sitemap_type,
            status_code=status_code,
            sitemap_urls=list(
                dict.fromkeys(
                    candidates
                )
            ),
            discovered_urls=discovered_urls,
            url_count=len(
                discovered_urls
            ),
            verdict="INFO",
            flags=flags,
            explanations=explanations,
            error=error,
        )