from unittest.mock import Mock

from bs4 import BeautifulSoup

from reconax.models import HTTPResponse
from reconax.modules.sri import SRIModule


def _context(html: str):
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.final_url = "https://example.com/"
    context.response.return_value = HTTPResponse(
        "https://example.com/", "https://example.com/", 200, 1,
        "HTTP/2", "text/html", len(html), content=html,
    )
    context.html.return_value = BeautifulSoup(html, "lxml")
    return context


def test_sri_module_counts_external_script_without_integrity():
    result = SRIModule(_context('<html><script src="https://cdn.example.net/app.js"></script></html>')).analyze()
    assert result.external_scripts == 1
    assert result.unprotected_resources == 1


def test_sri_module_recognizes_integrity_attribute():
    result = SRIModule(_context('<html><script src="https://cdn.example.net/app.js" integrity="sha256-abc"></script></html>')).analyze()
    assert result.external_scripts == 1
    assert result.protected_resources == 1
