from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.http import HTTPModule


def test_http_module_returns_context_response():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 8.2, "HTTP/2", "text/html", 42, headers={})
    context = Mock()
    context.response.return_value = response
    result = HTTPModule(context).analyze()
    assert result is response
    assert result.status_code == 200
    assert result.redirect_count == 0


def test_http_response_redirect_count():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 1, redirect_chain=["https://example.com"])
    assert response.redirect_count == 1
