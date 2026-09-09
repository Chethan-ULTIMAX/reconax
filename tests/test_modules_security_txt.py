from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.security_txt import SecurityTxtModule


def test_security_txt_module_parses_fields():
    response = HTTPResponse("https://example.com/.well-known/security.txt", "https://example.com/.well-known/security.txt", 200, 1, "HTTP/2", "text/plain", 100, content="Contact: mailto:security@example.com\nPolicy: https://example.com/security\nCanonical: https://example.com/.well-known/security.txt")
    context = Mock()
    context.get.return_value = response
    result = SecurityTxtModule(context).analyze()
    assert result.found is True
    assert result.contact == ["mailto:security@example.com"]
    assert result.policy == ["https://example.com/security"]


def test_security_txt_module_handles_404():
    response = HTTPResponse("https://example.com/.well-known/security.txt", "https://example.com/.well-known/security.txt", 404, 1, "HTTP/2", "text/plain", 0, content="")
    context = Mock()
    context.get.return_value = response
    result = SecurityTxtModule(context).analyze()
    assert result.found is False
