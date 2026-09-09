from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.csp import CSPModule


def test_csp_module_parses_directives():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 1, headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src *"})
    context = Mock()
    context.response.return_value = response
    result = CSPModule(context).analyze()
    assert result.present is True
    assert "default-src" in result.directives
    assert result.unsafe_inline is True
    assert result.wildcard_sources


def test_csp_module_reports_absent_policy():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 1, headers={})
    context = Mock()
    context.response.return_value = response
    result = CSPModule(context).analyze()
    assert result.present is False
