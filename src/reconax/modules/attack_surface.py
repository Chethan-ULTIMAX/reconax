"""
Passive attack-surface summary module.

The term attack surface here means publicly observable application
surface, not a set of instructions for attacking the target.

No hidden-path discovery, brute forcing, exploitation, or active
endpoint probing is performed.
"""

from __future__ import annotations

from ..context import AnalysisContext
from ..models import AttackSurfaceAnalysis
from .base import Module


class AttackSurfaceModule(
    Module[AttackSurfaceAnalysis]
):
    """Build a passive public attack-surface summary."""

    name = "attack_surface"

    def analyze(self) -> AttackSurfaceAnalysis:
        html = self.context.html_result()
        endpoints = self.context.endpoints_result()
        resources = self.context.resources_result()
        robots = self.context.robots_result()
        sitemap = self.context.sitemap_result()

        pages = list(
            dict.fromkeys(
                endpoints.pages
                + [
                    self.context.final_url
                ]
            )
        )

        forms = list(
            dict.fromkeys(
                endpoints.forms
            )
        )

        api_like_urls = list(
            dict.fromkeys(
                endpoints.api_like
            )
        )

        scripts = [
            resource.url
            for resource in resources.resources
            if resource.resource_type == "script"
        ]

        external_domains = []

        for resource in resources.resources:
            if resource.origin not in external_domains:
                if (
                    resource.origin
                    != self._page_origin()
                ):
                    external_domains.append(
                        resource.origin
                    )

        iframes = [
            resource.url
            for resource in resources.resources
            if resource.resource_type == "iframe"
        ]

        sitemap_urls = list(
            dict.fromkeys(
                sitemap.discovered_urls
            )
        )

        robots_rules = list(
            dict.fromkeys(
                robots.disallow_rules
            )
        )

        flags: list[str] = []

        if forms:
            flags.append(
                f"{len(forms)} public form endpoint(s) "
                "were observed."
            )

        if api_like_urls:
            flags.append(
                f"{len(api_like_urls)} API-like URL(s) "
                "were observed in public content."
            )

        if external_domains:
            flags.append(
                f"{len(external_domains)} external resource origin(s) "
                "were observed."
            )

        if iframes:
            flags.append(
                f"{len(iframes)} iframe(s) "
                "were observed."
            )

        return AttackSurfaceAnalysis(
            pages=pages,
            forms=forms,
            api_like_urls=api_like_urls,
            scripts=scripts,
            external_domains=external_domains,
            iframes=iframes,
            sitemap_urls=sitemap_urls,
            robots_rules=robots_rules,
            verdict="INFO",
            flags=flags,
            explanations=[
                "This is a passive inventory of public application "
                "surface. It is not a vulnerability assessment."
            ],
        )

    def _page_origin(self) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(
            self.context.final_url
        )

        hostname = (
            parsed.hostname
            or ""
        )

        port = parsed.port

        if port is None:
            port = (
                443
                if parsed.scheme == "https"
                else 80
            )

        return (
            f"{parsed.scheme}://"
            f"{hostname}:{port}"
        )