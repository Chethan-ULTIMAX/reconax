"""
HTML analysis module.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..context import AnalysisContext
from ..models import HTMLAnalysis
from .base import Module


class HTMLModule(Module[HTMLAnalysis]):
    """Analyze the publicly returned HTML document."""

    name = "html"

    @staticmethod
    def _absolute_url(
        base_url: str,
        value: str,
    ) -> str:
        """Convert a relative URL into an absolute URL."""
        return urljoin(base_url, value)

    @staticmethod
    def _is_http_url(value: str) -> bool:
        """Return True when a URL uses HTTP or HTTPS."""
        parsed = urlparse(value)
        return parsed.scheme in {
            "http",
            "https",
        }

    @staticmethod
    def _same_origin(
        first_url: str,
        second_url: str,
    ) -> bool:
        """Compare scheme, hostname, and port."""
        first = urlparse(first_url)
        second = urlparse(second_url)

        first_port = first.port
        second_port = second.port

        if first_port is None:
            first_port = (
                443
                if first.scheme == "https"
                else 80
            )

        if second_port is None:
            second_port = (
                443
                if second.scheme == "https"
                else 80
            )

        return (
            first.scheme == second.scheme
            and first.hostname == second.hostname
            and first_port == second_port
        )

    def analyze(self) -> HTMLAnalysis:
        response = self.context.response()

        content_type = (
            response.content_type.lower()
        )

        if (
            content_type
            and "html" not in content_type
        ):
            return HTMLAnalysis(
                verdict="INFO",
                flags=[
                    "Primary response does not appear to be HTML."
                ],
                explanations=[
                    "HTML-specific analysis was limited because "
                    "the response Content-Type does not indicate HTML."
                ],
            )

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

        description = None

        description_tag = soup.find(
            "meta",
            attrs={
                "name": lambda value: (
                    isinstance(value, str)
                    and value.lower() == "description"
                )
            },
        )

        if description_tag:
            description = (
                description_tag.get("content")
                or None
            )

        canonical = None

        canonical_tag = soup.find(
            "link",
            attrs={
                "rel": lambda value: (
                    (
                        "canonical" in value
                        if isinstance(value, list)
                        else (
                            isinstance(value, str)
                            and value.lower() == "canonical"
                        )
                    )
                )
            },
        )

        if canonical_tag:
            canonical = (
                canonical_tag.get("href")
                or None
            )

        html_tag = soup.find("html")

        language = (
            html_tag.get("lang")
            if html_tag
            else None
        )

        charset = None

        charset_tag = soup.find("meta")

        for meta in soup.find_all("meta"):
            if meta.get("charset"):
                charset = meta.get("charset")
                break

            http_equiv = meta.get(
                "http-equiv"
            )

            if (
                isinstance(http_equiv, str)
                and http_equiv.lower()
                == "content-type"
            ):
                content = meta.get("content")

                if content:
                    charset = content
                break

        viewport = None

        viewport_tag = soup.find(
            "meta",
            attrs={
                "name": lambda value: (
                    isinstance(value, str)
                    and value.lower() == "viewport"
                )
            },
        )

        if viewport_tag:
            viewport = (
                viewport_tag.get("content")
                or None
            )

        base_url = response.final_url

        internal_links: list[str] = []
        external_links: list[str] = []

        for anchor in soup.find_all(
            "a",
            href=True,
        ):
            href = str(
                anchor.get("href")
            ).strip()

            if not href:
                continue

            if href.startswith(
                (
                    "#",
                    "mailto:",
                    "tel:",
                    "javascript:",
                )
            ):
                continue

            absolute = self._absolute_url(
                base_url,
                href,
            )

            if not self._is_http_url(
                absolute
            ):
                continue

            if self._same_origin(
                base_url,
                absolute,
            ):
                internal_links.append(
                    absolute
                )
            else:
                external_links.append(
                    absolute
                )

        flags: list[str] = []
        explanations: list[str] = []

        if not title:
            flags.append(
                "HTML document has no title element."
            )

        if not description:
            flags.append(
                "HTML document has no meta description."
            )

        verdict = (
            "WARN"
            if flags
            else "PASS"
        )

        return HTMLAnalysis(
            title=title,
            meta_description=description,
            canonical=canonical,
            language=language,
            charset=charset,
            viewport=viewport,
            link_count=(
                len(internal_links)
                + len(external_links)
            ),
            internal_links=internal_links,
            external_links=external_links,
            script_count=len(
                soup.find_all("script")
            ),
            style_count=len(
                soup.find_all(
                    "link",
                    rel=lambda value: (
                        "stylesheet" in value
                        if isinstance(value, list)
                        else (
                            isinstance(value, str)
                            and "stylesheet"
                            in value.lower()
                        )
                    ),
                )
            ),
            image_count=len(
                soup.find_all("img")
            ),
            iframe_count=len(
                soup.find_all("iframe")
            ),
            form_count=len(
                soup.find_all("form")
            ),
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )