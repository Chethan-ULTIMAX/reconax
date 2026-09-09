from unittest.mock import Mock

from bs4 import BeautifulSoup

from reconax.models import HTTPResponse
from reconax.modules.endpoints import EndpointsModule


def test_endpoints_module_extracts_public_urls():
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.response.return_value = HTTPResponse(
        "https://example.com/",
        "https://example.com/",
        200,
        1,
        "HTTP/2",
        "text/html",
        200,
        content="<html></html>",
    )
    context.html.return_value = BeautifulSoup(
        '<html><body><a href="/about">About</a><a href="/api/users">API</a><form action="/login"></form><script src="/app.js"></script></body></html>',
        "lxml",
    )
    result = EndpointsModule(context).analyze()
    urls = [endpoint.url for endpoint in result.endpoints]
    assert any(url.endswith("/about") for url in urls)
    assert any(url.endswith("/api/users") for url in urls)
    assert any(url.endswith("/login") for url in urls)
    assert result.pages
