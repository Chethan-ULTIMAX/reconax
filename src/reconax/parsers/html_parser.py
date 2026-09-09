from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..models import HTMLReport


def parse_html(html: str, base_url: str) -> HTMLReport:
    soup = BeautifulSoup(html, "lxml")
    title = soup.title.get_text(" ", strip=True) if soup.title else None
    meta = soup.find("meta", attrs={"name": lambda value: value and value.lower() == "description"})
    description = meta.get("content", "").strip() if meta else None

    base_host = urlparse(base_url).netloc.lower()
    internal: list[str] = []
    external: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = urljoin(base_url, tag["href"])
        if urlparse(href).netloc.lower() == base_host:
            internal.append(href)
        else:
            external.append(href)

    scripts = [urljoin(base_url, tag["src"]) for tag in soup.find_all("script", src=True)]
    images = [urljoin(base_url, tag["src"]) for tag in soup.find_all("img", src=True)]
    return HTMLReport(title, description, internal, external, scripts, images)
