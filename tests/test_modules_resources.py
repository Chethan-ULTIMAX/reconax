from unittest.mock import Mock

from bs4 import BeautifulSoup

from reconax.models import HTTPResponse
from reconax.modules.resources import ResourcesModule


def test_resources_module_classifies_first_and_third_party():
    html = '<html><script src="/app.js"></script><img src="https://cdn.example.net/logo.png"></html>'
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.response.return_value = HTTPResponse(
        "https://example.com/", "https://example.com/", 200, 1,
        "HTTP/2", "text/html", len(html), content=html,
    )
    context.html.return_value = BeautifulSoup(html, "lxml")
    result = ResourcesModule(context).analyze()
    assert result.first_party_count == 1
    assert result.third_party_count == 1
    assert result.by_type.get("script") == 1
    assert result.by_type.get("image") == 1
