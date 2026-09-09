"""
Subresource Integrity analysis module.

This module inspects external scripts and stylesheets in the returned
HTML and checks whether they contain an integrity attribute.

No external resources are downloaded.
"""

from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..context import AnalysisContext
from ..models import SRIAnalysis
from .base import Module


class SRIModule(Module[SRIAnalysis]):
    """Analyze SRI attributes on external scripts and stylesheets."""

    name = "sri"

    @staticmethod
    def _is_external(
        base_url: str,
        resource_url: str,
    ) -> bool:
        base = urlparse(base_url)
        resource = urlparse(resource_url)

        return (
            resource.hostname is not None
            and base.hostname is not None
            and resource.hostname.lower()
            != base.hostname.lower()
        )

    def analyze(self) -> SRIAnalysis:
        response = self.context.response()
        soup: BeautifulSoup = self.context.html()

        external_scripts = 0
        external_stylesheets = 0
        protected_resources = 0
        unprotected_resources = 0

        resources: list[dict] = []

        for script in soup.find_all(
            "script",
            src=True,
        ):
            src = str(
                script.get("src")
            ).strip()

            if not src:
                continue

            parsed = urlparse(src)

            if not parsed.scheme:
                # Relative resources are first-party and therefore
                # not counted as external.
                continue

            if parsed.scheme not in {
                "http",
                "https",
            }:
                continue

            if not self._is_external(
                response.final_url,
                src,
            ):
                continue

            external_scripts += 1

            integrity = (
                script.get("integrity")
            )

            protected = bool(
                integrity
                and str(integrity).strip()
            )

            if protected:
                protected_resources += 1
            else:
                unprotected_resources += 1

            resources.append(
                {
                    "url": src,
                    "type": "script",
                    "integrity": (
                        str(integrity)
                        if integrity
                        else None
                    ),
                    "protected": protected,
                }
            )

        for link in soup.find_all(
            "link",
            href=True,
        ):
            rel = link.get("rel", [])

            if isinstance(rel, str):
                rel_values = [
                    rel.lower()
                ]
            else:
                rel_values = [
                    str(value).lower()
                    for value in rel
                ]

            if "stylesheet" not in rel_values:
                continue

            href = str(
                link.get("href")
            ).strip()

            if not href:
                continue

            parsed = urlparse(href)

            if parsed.scheme not in {
                "http",
                "https",
            }:
                continue

            if not self._is_external(
                response.final_url,
                href,
            ):
                continue

            external_stylesheets += 1

            integrity = (
                link.get("integrity")
            )

            protected = bool(
                integrity
                and str(integrity).strip()
            )

            if protected:
                protected_resources += 1
            else:
                unprotected_resources += 1

            resources.append(
                {
                    "url": href,
                    "type": "stylesheet",
                    "integrity": (
                        str(integrity)
                        if integrity
                        else None
                    ),
                    "protected": protected,
                }
            )

        flags: list[str] = []
        explanations: list[str] = []

        if unprotected_resources:
            flags.append(
                f"{unprotected_resources} external resource(s) "
                "do not declare SRI."
            )
            explanations.append(
                "Subresource Integrity can help browsers detect "
                "unexpected changes to supported external resources."
            )

        if not resources:
            verdict = "INFO"
            explanations.append(
                "No external script or stylesheet resources "
                "were observed."
            )
        elif unprotected_resources:
            verdict = "WARN"
        else:
            verdict = "PASS"

        return SRIAnalysis(
            external_scripts=external_scripts,
            external_stylesheets=external_stylesheets,
            protected_resources=protected_resources,
            unprotected_resources=unprotected_resources,
            resources=resources,
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )