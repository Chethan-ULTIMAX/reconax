"""
HTML resource analysis module.

Discovers resources referenced directly by the returned HTML.
No discovered resource is downloaded.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..context import AnalysisContext
from ..models import ResourceAnalysis, ResourceInfo
from .base import Module


class ResourcesModule(Module[ResourceAnalysis]):
    """Analyze first-party and third-party page resources."""

    name = "resources"

    RESOURCE_RULES = (
        ("script", "src", "script"),
        ("img", "src", "image"),
        ("iframe", "src", "iframe"),
        ("video", "src", "video"),
        ("audio", "src", "audio"),
        ("source", "src", "media"),
        ("link", "href", "link"),
    )

    @staticmethod
    def _origin(
        url: str,
    ) -> str:
        parsed = urlparse(url)

        hostname = (
            parsed.hostname
            or ""
        ).lower()

        port = parsed.port

        if port is None:
            if parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80

        if port:
            return (
                f"{parsed.scheme}://"
                f"{hostname}:{port}"
            )

        return (
            f"{parsed.scheme}://"
            f"{hostname}"
        )

    def analyze(self) -> ResourceAnalysis:
        response = self.context.response()
        soup: BeautifulSoup = self.context.html()

        page_origin = self._origin(
            response.final_url
        )

        resources: list[ResourceInfo] = []

        for tag_name, attribute, resource_type in (
            self.RESOURCE_RULES
        ):
            for tag in soup.find_all(
                tag_name,
                attrs={attribute: True},
            ):
                raw_url = str(
                    tag.get(attribute)
                ).strip()

                if not raw_url:
                    continue

                absolute_url = urljoin(
                    response.final_url,
                    raw_url,
                )

                parsed = urlparse(
                    absolute_url
                )

                if parsed.scheme not in {
                    "http",
                    "https",
                }:
                    continue

                origin = self._origin(
                    absolute_url
                )

                resources.append(
                    ResourceInfo(
                        url=absolute_url,
                        resource_type=resource_type,
                        origin=origin,
                        tag=tag_name,
                        attribute=attribute,
                    )
                )

        # Deduplicate resources while retaining order.
        unique_resources: list[ResourceInfo] = []
        seen: set[tuple[str, str]] = set()

        for resource in resources:
            key = (
                resource.url,
                resource.resource_type,
            )

            if key in seen:
                continue

            seen.add(key)
            unique_resources.append(
                resource
            )

        first_party_count = 0
        third_party_count = 0
        by_type: dict[str, int] = {}

        for resource in unique_resources:
            if resource.origin == page_origin:
                first_party_count += 1
            else:
                third_party_count += 1

            by_type[
                resource.resource_type
            ] = (
                by_type.get(
                    resource.resource_type,
                    0,
                )
                + 1
            )

        flags: list[str] = []

        if third_party_count:
            flags.append(
                f"{third_party_count} third-party resource(s) "
                "were observed."
            )

        return ResourceAnalysis(
            resources=unique_resources,
            first_party_count=first_party_count,
            third_party_count=third_party_count,
            by_type=by_type,
            verdict="INFO",
            flags=flags,
            explanations=[
                "Resource analysis only examines URLs exposed "
                "directly in the returned HTML."
            ],
        )