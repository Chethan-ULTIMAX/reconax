"""
Passive endpoint intelligence module.

Endpoints are extracted only from URLs already exposed by the
returned HTML. ReconAx does not discover hidden directories or
brute-force paths.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup

from ..context import AnalysisContext
from ..models import EndpointAnalysis, EndpointInfo
from .base import Module


class EndpointsModule(Module[EndpointAnalysis]):
    """Extract publicly exposed endpoint-like URLs."""

    name = "endpoints"

    API_MARKERS = (
        "/api/",
        "/api",
        "/graphql",
        "/rest/",
        "/v1/",
        "/v2/",
        "/v3/",
        ".json",
    )

    PAGE_EXTENSIONS = (
        ".html",
        ".htm",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
    )

    ASSET_EXTENSIONS = (
        ".js",
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
    )

    @staticmethod
    def _category(
        url: str,
    ) -> str:
        parsed = urlparse(url)
        path = parsed.path.lower()

        if any(
            marker in path
            for marker in EndpointsModule.API_MARKERS
        ):
            return "api"

        if any(
            path.endswith(extension)
            for extension in EndpointsModule.ASSET_EXTENSIONS
        ):
            return "asset"

        if (
            "?" in url
            or any(
                path.endswith(extension)
                for extension in EndpointsModule.PAGE_EXTENSIONS
            )
            or path in {
                "",
                "/",
            }
        ):
            return "page"

        return "endpoint"

    @staticmethod
    def _add_url(
        collection: dict[str, EndpointInfo],
        base_url: str,
        raw_url: str,
        source: str,
    ) -> None:
        raw_url = raw_url.strip()

        if not raw_url:
            return

        if raw_url.startswith(
            (
                "#",
                "javascript:",
                "mailto:",
                "tel:",
                "data:",
            )
        ):
            return

        absolute = urljoin(
            base_url,
            raw_url,
        )

        parsed = urlparse(
            absolute
        )

        if parsed.scheme not in {
            "http",
            "https",
        }:
            return

        path = (
            parsed.path
            or "/"
        )

        # Avoid treating external sites as target endpoints.
        base = urlparse(base_url)

        if (
            parsed.hostname
            and base.hostname
            and parsed.hostname.lower()
            != base.hostname.lower()
        ):
            return

        category = EndpointsModule._category(
            absolute
        )

        key = absolute

        if key not in collection:
            collection[key] = EndpointInfo(
                url=absolute,
                path=path,
                source=source,
                category=category,
            )

    def analyze(self) -> EndpointAnalysis:
        response = self.context.response()
        soup: BeautifulSoup = self.context.html()

        found: dict[str, EndpointInfo] = {}

        pages: list[str] = []
        api_like: list[str] = []
        forms: list[str] = []
        assets: list[str] = []

        for anchor in soup.find_all(
            "a",
            href=True,
        ):
            self._add_url(
                found,
                response.final_url,
                str(anchor.get("href")),
                "HTML link",
            )

        for script in soup.find_all(
            "script",
            src=True,
        ):
            self._add_url(
                found,
                response.final_url,
                str(script.get("src")),
                "script",
            )

        for link in soup.find_all(
            "link",
            href=True,
        ):
            self._add_url(
                found,
                response.final_url,
                str(link.get("href")),
                "link",
            )

        for image in soup.find_all(
            "img",
            src=True,
        ):
            self._add_url(
                found,
                response.final_url,
                str(image.get("src")),
                "image",
            )

        for form in soup.find_all(
            "form",
        ):
            action = str(
                form.get("action")
                or response.final_url
            )

            self._add_url(
                found,
                response.final_url,
                action,
                "HTML form",
            )

            absolute = urljoin(
                response.final_url,
                action,
            )

            forms.append(
                absolute
            )

        for endpoint in found.values():
            if endpoint.category == "page":
                pages.append(
                    endpoint.url
                )
            elif endpoint.category == "api":
                api_like.append(
                    endpoint.url
                )
            elif endpoint.category == "asset":
                assets.append(
                    endpoint.url
                )

        return EndpointAnalysis(
            endpoints=list(
                found.values()
            ),
            pages=list(
                dict.fromkeys(pages)
            ),
            api_like=list(
                dict.fromkeys(api_like)
            ),
            forms=list(
                dict.fromkeys(forms)
            ),
            assets=list(
                dict.fromkeys(assets)
            ),
            verdict="INFO",
            flags=[],
            explanations=[
                "Endpoints are collected only from URLs already "
                "exposed by the public HTML response."
            ],
        )