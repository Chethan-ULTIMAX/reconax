from unittest.mock import Mock
from bs4 import BeautifulSoup

from reconax.modules.resources import ResourcesModule


def test_resources_module_classifies_first_and_third_party():
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.html.return_value = BeautifulSoup('<html><script src="/app.js"></script><img src="https://cdn.example.net/logo.png"></html>', "lxml")
    result = ResourcesModule(context).analyze()
    assert result.first_party_count == 1
    assert result.third_party_count == 1
    assert result.by_type.get("script") == 1
    assert result.by_type.get("image") == 1
