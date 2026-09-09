from unittest.mock import Mock
from bs4 import BeautifulSoup

from reconax.modules.sri import SRIModule


def test_sri_module_counts_external_script_without_integrity():
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.html.return_value = BeautifulSoup('<html><script src="https://cdn.example.net/app.js"></script></html>', "lxml")
    result = SRIModule(context).analyze()
    assert result.external_scripts == 1
    assert result.unprotected_resources == 1


def test_sri_module_recognizes_integrity_attribute():
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.html.return_value = BeautifulSoup('<html><script src="https://cdn.example.net/app.js" integrity="sha256-abc"></script></html>', "lxml")
    result = SRIModule(context).analyze()
    assert result.external_scripts == 1
    assert result.protected_resources == 1
