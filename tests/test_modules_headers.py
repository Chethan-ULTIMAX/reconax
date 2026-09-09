from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.headers import HeadersModule


def test_headers_module_reports_missing_security_headers():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 10, headers={"content-type": "text/html"})
    context = Mock()
    context.response.return_value = response
    result = HeadersModule(context).analyze()
    assert result.verdict == "WARN"
    assert "Content-Security-Policy" in result.missing


def test_headers_module_passes_when_required_headers_exist():
    headers = {name: "present" for name in HeadersModule.SECURITY_HEADERS}
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 10, headers=headers)
    context = Mock()
    context.response.return_value = response
    result = HeadersModule(context).analyze()
    assert result.verdict == "PASS"
    assert not result.missing
