from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..models import HTMLAnalysis


def _normalize_url(base_url: str, value: str) -> str:
    """Convert a relative URL into an absolute URL."""

    return urljoin(base_url, value.strip())


def _is_http_url(url: str) -> bool:
    """Return True for HTTP/HTTPS URLs."""

    parsed = urlparse(url)

    return parsed.scheme in {"http", "https"}


def _is_internal(url: str, base_url: str) -> bool:
    """Determine whether a URL belongs to the same hostname."""

    target = urlparse(url)
    base = urlparse(base_url)

    if not target.netloc:
        return True

    return target.netloc.lower() == base.netloc.lower()


def parse_html(
    html: str,
    base_url: str,
) -> HTMLAnalysis:
    """
    Parse HTML and extract useful public information.

    No additional network requests are made here.
    """

    soup = BeautifulSoup(
        html,
        "lxml",
    )

    # ---------------------------------------------------------
    # Title
    # ---------------------------------------------------------

    title = None

    if soup.title:
        title_text = soup.title.get_text(
            strip=True,
        )

        if title_text:
            title = title_text

    # ---------------------------------------------------------
    # Meta description
    # ---------------------------------------------------------

    meta_description = None

    meta = soup.find(
        "meta",
        attrs={
            "name": lambda value: (
                isinstance(value, str)
                and value.lower() == "description"
            )
        },
    )

    if meta:
        content = meta.get("content")

        if content:
            meta_description = content.strip()

    # ---------------------------------------------------------
    # Links
    # ---------------------------------------------------------

    links: list[str] = []
    internal_links: list[str] = []
    external_links: list[str] = []

    seen_links: set[str] = set()

    for tag in soup.find_all("a", href=True):
        href = tag.get("href")

        if not isinstance(href, str):
            continue

        href = href.strip()

        if not href:
            continue

        # Ignore non-web links.
        if href.startswith(
            (
                "#",
                "mailto:",
                "tel:",
                "javascript:",
                "data:",
            )
        ):
            continue

        absolute_url = _normalize_url(
            base_url,
            href,
        )

        if not _is_http_url(absolute_url):
            continue

        if absolute_url in seen_links:
            continue

        seen_links.add(absolute_url)
        links.append(absolute_url)

        if _is_internal(
            absolute_url,
            base_url,
        ):
            internal_links.append(absolute_url)
        else:
            external_links.append(absolute_url)

    # ---------------------------------------------------------
    # Scripts
    # ---------------------------------------------------------

    scripts: list[str] = []

    seen_scripts: set[str] = set()

    for tag in soup.find_all("script"):
        src = tag.get("src")

        if not src:
            continue

        if not isinstance(src, str):
            continue

        src = src.strip()

        if not src:
            continue

        absolute_url = _normalize_url(
            base_url,
            src,
        )

        if not _is_http_url(absolute_url):
            continue

        if absolute_url in seen_scripts:
            continue

        seen_scripts.add(absolute_url)
        scripts.append(absolute_url)

    # ---------------------------------------------------------
    # Images
    # ---------------------------------------------------------

    images: list[str] = []

    seen_images: set[str] = set()

    for tag in soup.find_all("img"):
        src = tag.get("src")

        if not src:
            continue

        if not isinstance(src, str):
            continue

        src = src.strip()

        if not src:
            continue

        absolute_url = _normalize_url(
            base_url,
            src,
        )

        if not _is_http_url(absolute_url):
            continue

        if absolute_url in seen_images:
            continue

        seen_images.add(absolute_url)
        images.append(absolute_url)

    return HTMLAnalysis(
        title=title,
        meta_description=meta_description,
        links=links,
        internal_links=internal_links,
        external_links=external_links,
        scripts=scripts,
        images=images,
    )