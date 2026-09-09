from unittest.mock import Mock
from bs4 import BeautifulSoup

from reconax.modules.html import HTMLModule


def test_html_module_analyzes_document():
    context = Mock()
    context.html.return_value = BeautifulSoup('<html lang="en"><head><title>Demo</title><meta name="description" content="A demo"></head><body><a href="/about">About</a><script src="/app.js"></script><img src="/logo.png"></body></html>', "lxml")
    context.normalized_url = "https://example.com/"
    result = HTMLModule(context).analyze()
    assert result.title == "Demo"
    assert result.link_count == 1
    assert result.script_count == 1
    assert result.image_count == 1
