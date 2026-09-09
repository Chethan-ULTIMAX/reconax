from unittest.mock import Mock
from bs4 import BeautifulSoup

from reconax.modules.metadata import MetadataModule


def test_metadata_module_extracts_common_metadata():
    context = Mock()
    context.html.return_value = BeautifulSoup('<html lang="en"><head><title>Demo</title><meta name="description" content="Description"><meta name="generator" content="TestCMS"><meta property="og:title" content="OG Demo"><meta name="twitter:card" content="summary"></head></html>', "lxml")
    context.normalized_url = "https://example.com/"
    result = MetadataModule(context).analyze()
    assert result.title == "Demo"
    assert result.description == "Description"
    assert result.generator == "TestCMS"
    assert result.language == "en"
    assert result.open_graph.get("title") == "OG Demo"
    assert result.twitter.get("card") == "summary"
