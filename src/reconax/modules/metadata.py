"""
HTML metadata analysis module.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from ..context import AnalysisContext
from ..models import MetadataAnalysis
from .base import Module


class MetadataModule(Module[MetadataAnalysis]):
    """Extract public HTML metadata."""

    name = "metadata"

    @staticmethod
    def _meta_content(
        soup: BeautifulSoup,
        *,
        name: str | None = None,
        property_name: str | None = None,
    ) -> str | None:
        for meta in soup.find_all("meta"):
            if name:
                candidate = meta.get("name")

                if (
                    isinstance(candidate, str)
                    and candidate.lower()
                    == name.lower()
                ):
                    return meta.get("content")

            if property_name:
                candidate = meta.get("property")

                if (
                    isinstance(candidate, str)
                    and candidate.lower()
                    == property_name.lower()
                ):
                    return meta.get("content")

        return None

    def analyze(self) -> MetadataAnalysis:
        soup: BeautifulSoup = self.context.html()

        title_tag = soup.find("title")

        title = (
            title_tag.get_text(
                " ",
                strip=True,
            )
            if title_tag
            else None
        )

        description = self._meta_content(
            soup,
            name="description",
        )

        generator = self._meta_content(
            soup,
            name="generator",
        )

        viewport = self._meta_content(
            soup,
            name="viewport",
        )

        robots = self._meta_content(
            soup,
            name="robots",
        )

        charset = None

        for meta in soup.find_all("meta"):
            if meta.get("charset"):
                charset = str(
                    meta.get("charset")
                )
                break

        html_tag = soup.find("html")

        language = (
            html_tag.get("lang")
            if html_tag
            else None
        )

        canonical = None

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
                    str(item).lower()
                    for item in rel
                ]

            if "canonical" in rel_values:
                canonical = str(
                    link.get("href")
                )
                break

        open_graph: dict[str, str] = {}

        for meta in soup.find_all(
            "meta",
            property=True,
        ):
            property_name = meta.get(
                "property"
            )

            content = meta.get(
                "content"
            )

            if (
                isinstance(property_name, str)
                and property_name.lower().startswith(
                    "og:"
                )
                and content
            ):
                open_graph[
                    property_name
                ] = str(content)

        twitter: dict[str, str] = {}

        for meta in soup.find_all(
            "meta",
            attrs={"name": True},
        ):
            name = meta.get("name")
            content = meta.get("content")

            if (
                isinstance(name, str)
                and name.lower().startswith(
                    "twitter:"
                )
                and content
            ):
                twitter[name] = str(
                    content
                )

        flags: list[str] = []

        if not title:
            flags.append(
                "No page title was observed."
            )

        if not description:
            flags.append(
                "No meta description was observed."
            )

        return MetadataAnalysis(
            title=title,
            description=description,
            canonical=canonical,
            generator=generator,
            charset=charset,
            language=language,
            viewport=viewport,
            robots=robots,
            open_graph=open_graph,
            twitter=twitter,
            verdict=(
                "WARN"
                if flags
                else "PASS"
            ),
            flags=flags,
            explanations=[],
        )