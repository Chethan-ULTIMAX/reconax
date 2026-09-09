from unittest.mock import Mock

from bs4 import BeautifulSoup

from reconax.models import HTTPResponse
from reconax.modules.html import HTMLModule


def test_html_module_analyzes_document():
    html = '<html lang="en"><head><title>Demo</title><meta name="description" content="A demo"></head><body><a href="/about">About</a><script src="/app.js"></script><img src="/logo.png"></body></html>'
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.response.return_value = HTTPResponse(
        "https://example.com/", "https://example.com/", 200, 1,
        "HTTP/2", "text/html", len(html), content=html,
    )
    context.html.return_value = BeautifulSoup(html, "lxml")
    result = HTMLModule(context).analyze()
    assert result.title == "Demo"
    assert result.meta_description == "A demo"
    assert result.link_count == 1
    assert result.script_count == 1
    assert result.image_count == 1
