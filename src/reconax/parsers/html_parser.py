from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..models import HTMLAnalysis


def _normalize_url(base_url: str, value: str) -> str:
    return urljoin(base_url, value.strip())


def _is_http_url(url: str) -> bool:
    return urlparse(url).scheme in {"http", "https"}


def _is_internal(url: str, base_url: str) -> bool:
    target = urlparse(url)
    base = urlparse(base_url)
    if not target.netloc:
        return True
    return target.netloc.lower() == base.netloc.lower()


def _extract_urls(soup: BeautifulSoup, tag_name: str, attribute: str, base_url: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for tag in soup.find_all(tag_name):
        value = tag.get(attribute)
        if not isinstance(value, str) or not value.strip():
            continue
        absolute = _normalize_url(base_url, value)
        if not _is_http_url(absolute) or absolute in seen:
            continue
        seen.add(absolute)
        values.append(absolute)
    return values


def parse_html(html: str, base_url: str) -> HTMLAnalysis:
    """Parse HTML without making network requests."""
    soup = BeautifulSoup(html, "lxml")

    title = None
    if soup.title:
        text = soup.title.get_text(strip=True)
        title = text or None

    meta_description = None
    meta = soup.find(
        "meta",
        attrs={"name": lambda value: isinstance(value, str) and value.lower() == "description"},
    )
    if meta and meta.get("content"):
        meta_description = str(meta.get("content")).strip()

    links: list[str] = []
    internal_links: list[str] = []
    external_links: list[str] = []
    seen_links: set[str] = set()

    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if not isinstance(href, str):
            continue
        href = href.strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = _normalize_url(base_url, href)
        if not _is_http_url(absolute) or absolute in seen_links:
            continue
        seen_links.add(absolute)
        links.append(absolute)
        if _is_internal(absolute, base_url):
            internal_links.append(absolute)
        else:
            external_links.append(absolute)

    scripts = _extract_urls(soup, "script", "src", base_url)
    images = _extract_urls(soup, "img", "src", base_url)

    html_tag = soup.find("html")
    language = html_tag.get("lang") if html_tag else None
    charset = None
    for meta_tag in soup.find_all("meta"):
        if meta_tag.get("charset"):
            charset = str(meta_tag.get("charset"))
            break
        if str(meta_tag.get("http-equiv", "")).lower() == "content-type" and meta_tag.get("content"):
            charset = str(meta_tag.get("content"))
            break

    viewport_tag = soup.find(
        "meta",
        attrs={"name": lambda value: isinstance(value, str) and value.lower() == "viewport"},
    )
    viewport = str(viewport_tag.get("content")) if viewport_tag and viewport_tag.get("content") else None

    canonical_tag = soup.find("link", rel=lambda value: "canonical" in value if isinstance(value, list) else str(value).lower() == "canonical")
    canonical = str(canonical_tag.get("href")) if canonical_tag and canonical_tag.get("href") else None

    return HTMLAnalysis(
        title=title,
        meta_description=meta_description,
        canonical=canonical,
        language=language,
        charset=charset,
        viewport=viewport,
        link_count=len(links),
        internal_links=internal_links,
        external_links=external_links,
        script_count=len(soup.find_all("script")),
        style_count=len(soup.find_all("link", rel=lambda value: "stylesheet" in value if isinstance(value, list) else "stylesheet" in str(value).lower())),
        image_count=len(soup.find_all("img")),
        iframe_count=len(soup.find_all("iframe")),
        form_count=len(soup.find_all("form")),
    )
