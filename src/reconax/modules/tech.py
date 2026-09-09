"""
Passive technology detection module.

Technology detection is based only on information already exposed by
the HTTP response and returned HTML. ReconAx does not probe product
specific paths or perform active fingerprinting.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ..context import AnalysisContext
from ..models import TechAnalysis, Technology
from .base import Module


class TechModule(Module[TechAnalysis]):
    """Detect common technologies from passive public evidence."""

    name = "tech"

    SIGNATURES = (
        {
            "name": "Next.js",
            "category": "Framework",
            "patterns": (
                "__NEXT_DATA__",
                "/_next/",
            ),
        },
        {
            "name": "Nuxt",
            "category": "Framework",
            "patterns": (
                "__NUXT__",
                "/_nuxt/",
            ),
        },
        {
            "name": "React",
            "category": "JavaScript Framework",
            "patterns": (
                "react",
                "_reactRootContainer",
            ),
        },
        {
            "name": "Vue.js",
            "category": "JavaScript Framework",
            "patterns": (
                "vue",
                "__vue__",
                "data-v-",
            ),
        },
        {
            "name": "Angular",
            "category": "JavaScript Framework",
            "patterns": (
                "ng-version",
                "angular",
            ),
        },
        {
            "name": "WordPress",
            "category": "CMS",
            "patterns": (
                "wp-content",
                "wp-includes",
                "wordpress",
            ),
        },
        {
            "name": "Drupal",
            "category": "CMS",
            "patterns": (
                "drupal-settings-json",
                "/sites/default/",
                "drupal",
            ),
        },
        {
            "name": "Joomla",
            "category": "CMS",
            "patterns": (
                "/media/system/",
                "joomla",
            ),
        },
        {
            "name": "Bootstrap",
            "category": "UI Framework",
            "patterns": (
                "bootstrap.min.css",
                "bootstrap.min.js",
                "bootstrap.css",
            ),
        },
        {
            "name": "jQuery",
            "category": "JavaScript Library",
            "patterns": (
                "jquery",
            ),
        },
        {
            "name": "Google Analytics",
            "category": "Analytics",
            "patterns": (
                "google-analytics.com",
                "googletagmanager.com",
                "gtag(",
            ),
        },
        {
            "name": "Google Tag Manager",
            "category": "Analytics",
            "patterns": (
                "googletagmanager.com",
            ),
        },
        {
            "name": "Cloudflare",
            "category": "Infrastructure",
            "patterns": (
                "cf-ray",
                "cloudflare",
            ),
        },
        {
            "name": "Vercel",
            "category": "Hosting",
            "patterns": (
                "x-vercel-id",
                "vercel",
            ),
        },
        {
            "name": "Netlify",
            "category": "Hosting",
            "patterns": (
                "netlify",
                "x-nf-request-id",
            ),
        },
    )

    def analyze(self) -> TechAnalysis:
        response = self.context.response()
        soup: BeautifulSoup = self.context.html()

        html = response.content or ""

        # Include metadata, URLs, scripts, and visible HTML as passive
        # evidence. Lowercasing makes matching predictable.
        html_lower = html.lower()

        evidence_sources: list[str] = [
            html_lower,
        ]

        for script in soup.find_all("script"):
            src = script.get("src")

            if src:
                evidence_sources.append(
                    str(src).lower()
                )

            script_text = script.get_text(
                " ",
                strip=True,
            )

            if script_text:
                evidence_sources.append(
                    script_text.lower()
                )

        for link in soup.find_all(
            "link",
            href=True,
        ):
            evidence_sources.append(
                str(
                    link.get("href")
                ).lower()
            )

        headers = {
            key.lower(): value.lower()
            for key, value in response.headers.items()
        }

        technologies: list[Technology] = []

        for signature in self.SIGNATURES:
            matched_patterns: list[str] = []

            for pattern in signature["patterns"]:
                pattern_lower = pattern.lower()

                if any(
                    pattern_lower in source
                    for source in evidence_sources
                ):
                    matched_patterns.append(
                        pattern
                    )

            # Header-specific evidence.
            if (
                signature["name"] == "Cloudflare"
                and (
                    "cf-ray" in headers
                    or "server" in headers
                    and "cloudflare"
                    in headers["server"]
                )
            ):
                matched_patterns.append(
                    "HTTP response headers"
                )

            if (
                signature["name"] == "Vercel"
                and (
                    "x-vercel-id" in headers
                    or "server" in headers
                    and "vercel"
                    in headers["server"]
                )
            ):
                matched_patterns.append(
                    "HTTP response headers"
                )

            if matched_patterns:
                unique_patterns = list(
                    dict.fromkeys(
                        matched_patterns
                    )
                )

                technologies.append(
                    Technology(
                        name=signature["name"],
                        category=signature["category"],
                        confidence="likely",
                        evidence=unique_patterns,
                    )
                )

        # Generator metadata is especially useful for CMS detection.
        generator = soup.find(
            "meta",
            attrs={
                "name": re.compile(
                    r"^generator$",
                    re.IGNORECASE,
                )
            },
        )

        if generator:
            generator_value = generator.get(
                "content"
            )

            if generator_value:
                technologies.append(
                    Technology(
                        name=str(
                            generator_value
                        ),
                        category="Generator",
                        confidence="observed",
                        evidence=[
                            "meta[name=generator]"
                        ],
                    )
                )

        # Remove duplicate technology names.
        unique: dict[str, Technology] = {}

        for technology in technologies:
            key = technology.name.lower()

            if key not in unique:
                unique[key] = technology
            else:
                unique[key].evidence = list(
                    dict.fromkeys(
                        unique[key].evidence
                        + technology.evidence
                    )
                )

        final_technologies = list(
            unique.values()
        )

        return TechAnalysis(
            technologies=final_technologies,
            verdict="INFO",
            flags=[],
            explanations=[
                "Technology detection is passive and based only "
                "on publicly exposed response or HTML evidence."
            ],
        )